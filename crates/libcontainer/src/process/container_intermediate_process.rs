use std::os::fd::FromRawFd;

use libcgroups::common::{AnyCgroupManager, CgroupAttachment, CgroupManager};
use nix::unistd::{Gid, Pid, Uid, close, getpid, write};
use oci_spec::runtime::{LinuxNamespace, LinuxNamespaceType, LinuxResources};

use super::args::{ContainerArgs, ContainerType};
use super::channel::{IntermediateReceiver, MainSender};
use super::fork::CloneCb;
use super::init::process as init_process;
use crate::error::MissingSpecError;
use crate::namespaces::Namespaces;
use crate::process::message::format_error_chain;
use crate::process::{channel, cpu_affinity, fork};
use crate::utils::rootless_required;

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
    #[error("cgroup error: {0}")]
    CgroupEntry(String),
    #[error(transparent)]
    Procfs(#[from] procfs::ProcError),
    #[error("exec notify failed")]
    ExecNotify(#[source] nix::Error),
    #[error(transparent)]
    MissingSpec(#[from] crate::error::MissingSpecError),
    #[error("CPU affinity error {0}")]
    CpuAffinity(#[from] cpu_affinity::CPUAffinityError),
    #[error("other error")]
    Other(String),
}

type Result<T> = std::result::Result<T, IntermediateProcessError>;

pub fn container_intermediate_process(
    args: &ContainerArgs,
    intermediate_chan: &mut (channel::IntermediateSender, channel::IntermediateReceiver),
    init_chan: &mut (channel::InitSender, channel::InitReceiver),
    intermediate_main_sender: &mut channel::MainSender,
    init_main_sender: &mut channel::MainSender,
) -> Result<()> {
    let (inter_sender, inter_receiver) = intermediate_chan;
    let (init_sender, init_receiver) = init_chan;
    let command = args.syscall.create_syscall();
    let spec = &args.spec;
    let linux = spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;
    let namespaces = Namespaces::try_from(linux.namespaces().as_ref())?;

    let current_pid = Pid::this();
    // setting CPU affinity for tenant container before cgroup move
    if matches!(args.container_type, ContainerType::TenantContainer { .. }) {
        if let Some(exec_cpu_affinity) = spec
            .process()
            .as_ref()
            .and_then(|p| p.exec_cpu_affinity().as_ref())
        {
            if let Some(initial) = exec_cpu_affinity.initial() {
                cpu_affinity::set_cpuset_affinity_from_string(current_pid, initial)?;
            }
        }
    }
    let _ = cpu_affinity::log_cpu_affinity();

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
    let saved_attachment = match args.container_type {
        ContainerType::InitContainer => None,
        ContainerType::TenantContainer {
            cgroup_attachment, ..
        } => cgroup_attachment,
    };
    let cgroup_attachment = if saved_attachment == Some(CgroupAttachment::Skipped) {
        CgroupAttachment::Skipped
    } else {
        let cgroup_manager =
            libcgroups::common::create_cgroup_manager(args.cgroup_config.to_owned())
                .map_err(|e| IntermediateProcessError::Cgroup(e.to_string()))?;
        let rootless = rootless_required(command.as_ref()).unwrap_or(false);
        let init = matches!(args.container_type, ContainerType::InitContainer);
        let needs_cgroup =
            rootless && init && !tolerate_rootless_cgroup_errors(&cgroup_manager, &namespaces)?;
        let attached_tenant = !init
            && matches!(cgroup_manager, AnyCgroupManager::V2(_))
            && saved_attachment == Some(CgroupAttachment::Attached);
        let limits_need_cgroup = rootless
            && init
            && matches!(cgroup_manager, AnyCgroupManager::V2(_))
            && resources_require_cgroup(linux.resources().as_ref());
        let is_v2 = matches!(cgroup_manager, AnyCgroupManager::V2(_));
        let cgroup_manager = cgroup_manager
            .with_rootless(rootless && !needs_cgroup && !attached_tenant && !limits_need_cgroup);
        apply_cgroups(&cgroup_manager, linux.resources().as_ref(), init).map_err(|err| {
            let (message, entry_failed) = match err {
                IntermediateProcessError::CgroupEntry(message) => (message, is_v2),
                IntermediateProcessError::Cgroup(message) => (message, false),
                other => return other,
            };
            let message = if needs_cgroup {
                format!("a container without a private PID namespace needs a cgroup to kill all its processes: {message}")
            } else if limits_need_cgroup {
                format!("requested resource limits require a cgroup: {message}")
            } else {
                message
            };
            if entry_failed {
                IntermediateProcessError::CgroupEntry(message)
            } else {
                IntermediateProcessError::Cgroup(message)
            }
        })?
    };

    // setting CPU affinity for tenant container after cgroup move
    if matches!(args.container_type, ContainerType::TenantContainer { .. }) {
        if let Some(exec_cpu_affinity) = spec
            .process()
            .as_ref()
            .and_then(|p| p.exec_cpu_affinity().as_ref())
        {
            if let Some(cpu_affinity_final) = exec_cpu_affinity.cpu_affinity_final() {
                cpu_affinity::set_cpuset_affinity_from_string(current_pid, cpu_affinity_final)?;
            }
        }
    }

    // if new user is specified in specification, this will be true and new
    // namespace will be created, check
    // https://man7.org/linux/man-pages/man7/user_namespaces.7.html for more
    // information
    if let Some(user_namespace) = namespaces.get(LinuxNamespaceType::User)? {
        setup_userns(
            &namespaces,
            user_namespace,
            intermediate_main_sender,
            inter_receiver,
        )?;

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

    if let Some(time_namespace) = namespaces.get(LinuxNamespaceType::Time)? {
        namespaces.unshare_or_setns(time_namespace)?;
        if time_namespace.path().is_none()
            && linux
                .time_offsets()
                .as_ref()
                .is_some_and(|offsets| !offsets.is_empty())
        {
            setup_time_offsets(intermediate_main_sender, inter_receiver)?;
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
            if let Err(err) = intermediate_main_sender.close() {
                tracing::error!(
                    ?err,
                    "failed to close intermediate main sender in init process"
                );
                return -1;
            }
            match init_process::container_init_process(args, init_main_sender, init_receiver) {
                Ok(_) => 0,
                Err(e) => {
                    let error_report = format_error_chain(&e);
                    tracing::error!("failed to initialize container process: {error_report}");
                    if let Err(err) = init_main_sender.exec_failed(error_report.clone()) {
                        tracing::error!(?err, "failed sending error to main sender");
                    }
                    if let ContainerType::TenantContainer { exec_notify_fd, .. } =
                        args.container_type
                    {
                        let exec_notify_fd =
                            unsafe { std::os::fd::OwnedFd::from_raw_fd(exec_notify_fd) };
                        if let Err(err) = write(&exec_notify_fd, error_report.as_bytes()) {
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
    if let ContainerType::TenantContainer { exec_notify_fd, .. } = args.container_type {
        close(exec_notify_fd).map_err(|err| {
            tracing::error!("failed to close exec notify fd: {}", err);
            IntermediateProcessError::ExecNotify(err)
        })?;
    }

    intermediate_main_sender
        .intermediate_ready(pid, cgroup_attachment)
        .map_err(|err| {
            tracing::error!("failed to wait on intermediate process: {}", err);
            err
        })?;

    // Close unused senders here so we don't have lingering socket around.
    intermediate_main_sender.close().map_err(|err| {
        tracing::error!("failed to close unused main sender: {}", err);
        err
    })?;
    init_main_sender.close().map_err(|err| {
        tracing::error!("failed to close unused init main sender: {}", err);
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

fn setup_time_offsets(sender: &mut MainSender, receiver: &mut IntermediateReceiver) -> Result<()> {
    tracing::debug!("requesting parent to write time namespace offsets");

    prctl::set_dumpable(true).map_err(|e| {
        IntermediateProcessError::Other(format!(
            "error in setting dumpable to true for time offsets: {}",
            nix::errno::Errno::from_raw(e)
        ))
    })?;

    sender.time_offset_request().map_err(|err| {
        tracing::error!("failed to send time offset request: {}", err);
        err
    })?;

    receiver.wait_for_time_offsets_ack().map_err(|err| {
        tracing::error!("failed to receive time offsets ack: {}", err);
        err
    })?;

    prctl::set_dumpable(false).map_err(|e| {
        IntermediateProcessError::Other(format!(
            "error in setting dumpable to false after time offsets: {}",
            nix::errno::Errno::from_raw(e)
        ))
    })?;

    Ok(())
}

/// Whether the cgroup manager may tolerate the cgroup permission errors of a
/// rootless container.
///
/// The v2 manager then leaves the processes of the container in its parent
/// cgroup, so that killing the container can only signal its init. A container
/// without a private PID namespace needs a cgroup to kill all of its processes.
/// The systemd manager only uses rootless to treat device rules as best effort,
/// and the v1 manager ignores it.
fn tolerate_rootless_cgroup_errors(
    cgroup_manager: &AnyCgroupManager,
    namespaces: &Namespaces,
) -> Result<bool> {
    Ok(!matches!(cgroup_manager, AnyCgroupManager::V2(_))
        || namespaces
            .get(LinuxNamespaceType::Pid)?
            .is_some_and(|pid_ns| pid_ns.path().is_none()))
}

// Do not turn explicitly requested cgroup settings into best-effort limits.
fn resources_require_cgroup(resources: Option<&LinuxResources>) -> bool {
    fn has_items<T>(items: &Option<Vec<T>>) -> bool {
        items.as_ref().is_some_and(|items| !items.is_empty())
    }

    let Some(resources) = resources else {
        return false;
    };
    resources.memory().as_ref().is_some_and(|r| r != &Default::default())
        || resources.cpu().as_ref().is_some_and(|r| r != &Default::default())
        // Even the default pids value is applied by the v2 pids controller.
        || resources.pids().is_some()
        || resources.block_io().as_ref().is_some_and(|io| {
            io.weight().is_some()
                || io.leaf_weight().is_some()
                || has_items(io.weight_device())
                || has_items(io.throttle_read_bps_device())
                || has_items(io.throttle_write_bps_device())
                || has_items(io.throttle_read_iops_device())
                || has_items(io.throttle_write_iops_device())
        })
        || has_items(resources.devices())
        || has_items(resources.hugepage_limits())
        || resources.network().as_ref().is_some_and(|network| {
            network.class_id().is_some() || has_items(network.priorities())
        })
        || resources.rdma().as_ref().is_some_and(|rdma| {
            rdma.values().any(|limits| limits != &Default::default())
        })
        || resources.unified().as_ref().is_some_and(|unified| !unified.is_empty())
}

fn apply_cgroups<
    C: CgroupManager<Error = E> + ?Sized,
    E: std::error::Error + Send + Sync + 'static,
>(
    cmanager: &C,
    resources: Option<&LinuxResources>,
    init: bool,
) -> Result<CgroupAttachment> {
    let pid = getpid();
    let attachment = cmanager.add_task_with_status(pid).map_err(|err| {
        tracing::error!(?pid, ?err, ?init, "failed to add task to cgroup");
        IntermediateProcessError::CgroupEntry(err.to_string())
    })?;

    if attachment == CgroupAttachment::Attached
        && init
        && let Some(resources) = resources
    {
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

    Ok(attachment)
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
    fn empty_resources_allow_no_cgroup() -> Result<()> {
        assert!(!resources_require_cgroup(None));
        for value in [
            serde_json::json!({}),
            serde_json::json!({
                "devices": [], "memory": {}, "cpu": {},
                "blockIO": {
                    "weightDevice": [], "throttleReadBpsDevice": [],
                    "throttleWriteBpsDevice": [], "throttleReadIOPSDevice": [],
                    "throttleWriteIOPSDevice": []
                },
                "hugepageLimits": [], "network": {"priorities": []},
                "rdma": {"device": {}}, "unified": {}
            }),
        ] {
            let resources: LinuxResources = serde_json::from_value(value)?;
            assert!(!resources_require_cgroup(Some(&resources)));
        }
        Ok(())
    }

    #[test]
    fn requested_resources_require_cgroup() -> Result<()> {
        for value in [
            serde_json::json!({"memory": {"limit": 67108864}}),
            serde_json::json!({"memory": {"limit": 0}}),
            serde_json::json!({"cpu": {"quota": 10000}}),
            serde_json::json!({"cpu": {"cpus": "0"}}),
            serde_json::json!({"pids": {"limit": 16}}),
            serde_json::json!({"pids": {}}),
            serde_json::json!({"blockIO": {"weight": 100}}),
            serde_json::json!({"blockIO": {"throttleReadBpsDevice": [
                {"major": 8, "minor": 0, "rate": 1024}
            ]}}),
            serde_json::json!({"devices": [{"allow": false}]}),
            serde_json::json!({"hugepageLimits": [{"pageSize": "2MB", "limit": 0}]}),
            serde_json::json!({"network": {"classID": 1}}),
            serde_json::json!({"rdma": {"device": {"hcaHandles": 0}}}),
            serde_json::json!({"unified": {"memory.max": ""}}),
        ] {
            let resources: LinuxResources = serde_json::from_value(value.clone())?;
            assert!(resources_require_cgroup(Some(&resources)), "{value}");
        }
        Ok(())
    }

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
    fn apply_cgroup_skipped() -> Result<()> {
        let mut cmanager = TestManager::default();
        cmanager.attachment = CgroupAttachment::Skipped;
        assert_eq!(
            apply_cgroups(&cmanager, Some(&LinuxResources::default()), true)?,
            CgroupAttachment::Skipped
        );
        assert_eq!(cmanager.get_add_task_args().len(), 1);
        assert!(!cmanager.apply_called());
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

    #[cfg(feature = "v2")]
    fn pid_namespaces(path: Option<&str>) -> Result<Vec<LinuxNamespace>> {
        let mut builder =
            oci_spec::runtime::LinuxNamespaceBuilder::default().typ(LinuxNamespaceType::Pid);
        if let Some(path) = path {
            builder = builder.path(path);
        }
        Ok(vec![builder.build()?])
    }

    #[test]
    #[cfg(feature = "v2")]
    fn tolerate_rootless_cgroup_errors_v2() -> Result<()> {
        let v2 = AnyCgroupManager::V2(libcgroups::v2::manager::Manager::new(
            "/sys/fs/cgroup".into(),
            "/youki".into(),
        )?);

        let host = Namespaces::try_from(Some(&Vec::<LinuxNamespace>::new()))?;
        assert!(!tolerate_rootless_cgroup_errors(&v2, &host)?);

        let new = Namespaces::try_from(Some(&pid_namespaces(None)?))?;
        assert!(tolerate_rootless_cgroup_errors(&v2, &new)?);

        let joined = Namespaces::try_from(Some(&pid_namespaces(Some("/proc/1/ns/pid"))?))?;
        assert!(!tolerate_rootless_cgroup_errors(&v2, &joined)?);
        Ok(())
    }
}
