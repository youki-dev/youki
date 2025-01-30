use std::os::fd::FromRawFd;

use libcgroups::common::CgroupManager;
use nix::unistd::{close, write, Gid, Pid, Uid};
use oci_spec::runtime::{LinuxNamespace, LinuxNamespaceType, LinuxResources};
use procfs::process::Process;

use super::args::{ContainerArgs, ContainerType};
use super::channel::{IntermediateReceiver, MainSender};
use super::container_init_process::container_init_process;
use super::fork::CloneCb;
use crate::error::MissingSpecError;
use crate::namespaces::Namespaces;
use crate::process::{channel, fork};

#[derive(Debug, thiserror::Error)]
pub enum IntermediateProcessError {
    #[error(transparent)]
    Channel(#[from] channel::ChannelError),
    #[error(transparent)]
    Namespace(#[from] crate::namespaces::NamespaceError),
    #[error(transparent)]
    Syscall(#[from] crate::syscall::SyscallError),
    #[error("failed to launch init process")]
    InitProcess(#[source] fork::CloneError),
    #[error("cgroup error: {0}")]
    Cgroup(String),
    #[error(transparent)]
    Procfs(#[from] procfs::ProcError),
    #[error("exec notify failed")]
    ExecNotify(#[source] nix::Error),
    #[error(transparent)]
    MissingSpec(#[from] crate::error::MissingSpecError),
    #[error("other error")]
    Other(String),
}

type Result<T> = std::result::Result<T, IntermediateProcessError>;

pub fn container_intermediate_process(
    args: &ContainerArgs,
    intermediate_chan: &mut (channel::IntermediateSender, channel::IntermediateReceiver),
    init_chan: &mut (channel::InitSender, channel::InitReceiver),
    main_sender: &mut channel::MainSender,
) -> Result<()> {
    let (inter_sender, inter_receiver) = intermediate_chan;
    let (init_sender, init_receiver) = init_chan;
    let command = args.syscall.create_syscall();
    let spec = &args.spec;
    let linux = spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;
    let namespaces = Namespaces::try_from(linux.namespaces().as_ref())?;

    // this needs to be done before we create the init process, so that the init
    // process will already be captured by the cgroup. It also needs to be done
    // before we enter the user namespace because if a privileged user starts a
    // rootless container on a cgroup v1 system we can still fulfill resource
    // restrictions through the cgroup fs support (delegation through systemd is
    // not supported for v1 by us). This only works if the user has not yet been
    // mapped to an unprivileged user by the user namespace however.
    // In addition this needs to be done before we enter the cgroup namespace as
    // the cgroup of the process will form the root of the cgroup hierarchy in
    // the cgroup namespace.
    if let Some(cgroup_config) = &args.cgroup_config {
        let cgroup_manager = libcgroups::common::create_cgroup_manager(cgroup_config.to_owned())
            .map_err(|e| IntermediateProcessError::Cgroup(e.to_string()))?;
        apply_cgroups(
            &cgroup_manager,
            linux.resources().as_ref(),
            matches!(args.container_type, ContainerType::InitContainer { .. }),
        )?;
    }

    // if new user is specified in specification, this will be true and new
    // namespace will be created, check
    // https://man7.org/linux/man-pages/man7/user_namespaces.7.html for more
    // information
    if let Some(user_namespace) = namespaces.get(LinuxNamespaceType::User)? {
        setup_userns(&namespaces, user_namespace, main_sender, inter_receiver)?;

        // After UID and GID mapping is configured correctly in the Youki main
        // process, We want to make sure continue as the root user inside the
        // new user namespace. This is required because the process of
        // configuring the container process will require root, even though the
        // root in the user namespace likely is mapped to an non-privileged user
        // on the parent user namespace.
        command.set_id(Uid::from_raw(0), Gid::from_raw(0))?;
    }

    // set limits and namespaces to the process
    let proc = spec.process().as_ref().ok_or(MissingSpecError::Process)?;
    if let Some(rlimits) = proc.rlimits() {
        for rlimit in rlimits {
            command.set_rlimit(rlimit).map_err(|err| {
                tracing::error!(?err, ?rlimit, "failed to set rlimit");
                err
            })?;
        }
    }

    // Pid namespace requires an extra fork to enter, so we enter pid namespace now.
    if let Some(pid_namespace) = namespaces.get(LinuxNamespaceType::Pid)? {
        namespaces.unshare_or_setns(pid_namespace)?;
    }

    let cb: CloneCb = {
        Box::new(|| {
            if let Err(ret) = prctl::set_name("youki:[2:INIT]") {
                tracing::error!(?ret, "failed to set name for child process");
                return ret;
            }

            // We are inside the forked process here. The first thing we have to do
            // is to close any unused senders, since fork will make a dup for all
            // the socket.
            if let Err(err) = init_sender.close() {
                tracing::error!(?err, "failed to close receiver in init process");
                return -1;
            }
            if let Err(err) = inter_sender.close() {
                tracing::error!(?err, "failed to close sender in the intermediate process");
                return -1;
            }
            match container_init_process(args, main_sender, init_receiver) {
                Ok(_) => 0,
                Err(e) => {
                    tracing::error!("failed to initialize container process: {e}");
                    if let Err(err) = main_sender.exec_failed(e.to_string()) {
                        tracing::error!(?err, "failed sending error to main sender");
                    }
                    if let ContainerType::TenantContainer { exec_notify_fd } = args.container_type {
                        let buf = format!("{e}");
                        let exec_notify_fd =
                            unsafe { std::os::fd::OwnedFd::from_raw_fd(exec_notify_fd) };
                        if let Err(err) = write(&exec_notify_fd, buf.as_bytes()) {
                            tracing::error!(?err, "failed to write to exec notify fd");
                        }

                        // After sending the error through the exec_notify_fd,
                        // we need to explicitly close the pipe.
                        drop(exec_notify_fd);
                    }
                    -1
                }
            }
        })
    };

    // We have to record the pid of the init process. The init process will be
    // inside the pid namespace, so we can't rely on the init process to send us
    // the correct pid. We also want to clone the init process as a sibling
    // process to the intermediate process. The intermediate process is only
    // used as a jumping board to set the init process to the correct
    // configuration. The youki main process can decide what to do with the init
    // process and the intermediate process can just exit safely after the job
    // is done.
    let pid = fork::container_clone_sibling(cb).map_err(|err| {
        tracing::error!("failed to fork init process: {}", err);
        IntermediateProcessError::InitProcess(err)
    })?;

    // Close the exec_notify_fd in this process
    if let ContainerType::TenantContainer { exec_notify_fd } = args.container_type {
        close(exec_notify_fd).map_err(|err| {
            tracing::error!("failed to close exec notify fd: {}", err);
            IntermediateProcessError::ExecNotify(err)
        })?;
    }

    main_sender.intermediate_ready(pid).map_err(|err| {
        tracing::error!("failed to wait on intermediate process: {}", err);
        err
    })?;

    // Close unused senders here so we don't have lingering socket around.
    main_sender.close().map_err(|err| {
        tracing::error!("failed to close unused main sender: {}", err);
        err
    })?;
    inter_sender.close().map_err(|err| {
        tracing::error!(
            "failed to close sender in the intermediate process: {}",
            err
        );
        err
    })?;
    init_sender.close().map_err(|err| {
        tracing::error!("failed to close unused init sender: {}", err);
        err
    })?;

    Ok(())
}

fn setup_userns(
    namespaces: &Namespaces,
    user_namespace: &LinuxNamespace,
    sender: &mut MainSender,
    receiver: &mut IntermediateReceiver,
) -> Result<()> {
    namespaces.unshare_or_setns(user_namespace)?;
    if user_namespace.path().is_some() {
        return Ok(());
    }

    tracing::debug!("creating new user namespace");
    // child needs to be dumpable, otherwise the non root parent is not
    // allowed to write the uid/gid maps
    prctl::set_dumpable(true).map_err(|e| {
        IntermediateProcessError::Other(format!(
            "error in setting dumpable to true : {}",
            nix::errno::Errno::from_raw(e)
        ))
    })?;
    sender.identifier_mapping_request().map_err(|err| {
        tracing::error!("failed to send id mapping request: {}", err);
        err
    })?;
    receiver.wait_for_mapping_ack().map_err(|err| {
        tracing::error!("failed to receive id mapping ack: {}", err);
        err
    })?;
    prctl::set_dumpable(false).map_err(|e| {
        IntermediateProcessError::Other(format!(
            "error in setting dumplable to false : {}",
            nix::errno::Errno::from_raw(e)
        ))
    })?;
    Ok(())
}

fn apply_cgroups<
    C: CgroupManager<Error = E> + ?Sized,
    E: std::error::Error + Send + Sync + 'static,
>(
    cmanager: &C,
    resources: Option<&LinuxResources>,
    init: bool,
) -> Result<()> {
    let pid = Pid::from_raw(Process::myself()?.pid());
    cmanager.add_task(pid).map_err(|err| {
        tracing::error!(?pid, ?err, ?init, "failed to add task to cgroup");
        IntermediateProcessError::Cgroup(err.to_string())
    })?;

    if let Some(resources) = resources {
        if init {
            let controller_opt = libcgroups::common::ControllerOpt {
                resources,
                freezer_state: None,
                oom_score_adj: None,
                disable_oom_killer: false,
            };

            cmanager.apply(&controller_opt).map_err(|err| {
                tracing::error!(?pid, ?err, ?init, "failed to apply cgroup");
                IntermediateProcessError::Cgroup(err.to_string())
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use libcgroups::test_manager::TestManager;
    use nix::unistd::Pid;
    use oci_spec::runtime::LinuxResources;
    use procfs::process::Process;

    use super::*;

    #[test]
    fn apply_cgroup_init() -> Result<()> {
        // arrange
        let cmanager = TestManager::default();
        let resources = LinuxResources::default();

        // act
        apply_cgroups(&cmanager, Some(&resources), true)?;

        // assert
        assert!(cmanager.get_add_task_args().len() == 1);
        assert_eq!(
            cmanager.get_add_task_args()[0],
            Pid::from_raw(Process::myself()?.pid())
        );
        assert!(cmanager.apply_called());
        Ok(())
    }

    #[test]
    fn apply_cgroup_tenant() -> Result<()> {
        // arrange
        let cmanager = TestManager::default();
        let resources = LinuxResources::default();

        // act
        apply_cgroups(&cmanager, Some(&resources), false)?;

        // assert
        assert_eq!(
            cmanager.get_add_task_args()[0],
            Pid::from_raw(Process::myself()?.pid())
        );
        assert!(!cmanager.apply_called());
        Ok(())
    }

    #[test]
    fn apply_cgroup_no_resources() -> Result<()> {
        // arrange
        let cmanager = TestManager::default();

        // act
        apply_cgroups(&cmanager, None, true)?;
        // assert
        assert_eq!(
            cmanager.get_add_task_args()[0],
            Pid::from_raw(Process::myself()?.pid())
        );
        assert!(!cmanager.apply_called());
        Ok(())
    }
}
