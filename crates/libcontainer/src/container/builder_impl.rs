use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::rc::Rc;

use libcgroups::common::CgroupManager;
use nix::unistd::Pid;
use oci_spec::runtime::Spec;

use super::{Container, ContainerStatus};
use crate::error::{CreateContainerError, LibcontainerError, MissingSpecError};
use crate::notify_socket::NotifyListener;
use crate::process::args::{ContainerArgs, ContainerType};
use crate::process::intel_rdt::{cleanup_intel_rdt, setup_intel_rdt};
use crate::process::{self};
use crate::syscall::syscall::SyscallType;
use crate::user_ns::UserNamespaceConfig;
use crate::utils::PathBufExt;
use crate::workload::Executor;

pub(super) struct ContainerBuilderImpl {
    /// Flag indicating if an init or a tenant container should be created
    pub container_type: ContainerType,
    /// Interface to operating system primitives
    pub syscall: SyscallType,
    /// Flag indicating if systemd should be used for cgroup management
    pub use_systemd: bool,
    /// Id of the container
    pub container_id: String,
    /// OCI compliant runtime spec
    pub spec: Rc<Spec>,
    /// Root filesystem of the container
    pub rootfs: PathBuf,
    /// File which will be used to communicate the pid of the
    /// container process to the higher level runtime
    pub pid_file: Option<PathBuf>,
    /// Socket to communicate the file descriptor of the ptty
    pub console_socket: Option<OwnedFd>,
    /// Options for new user namespace
    pub user_ns_config: Option<UserNamespaceConfig>,
    /// Path to the Unix Domain Socket to communicate container start
    pub notify_path: PathBuf,
    /// Container state
    pub container: Option<Container>,
    /// File descriptos preserved/passed to the container init process.
    pub preserve_fds: i32,
    /// If the container is to be run in detached mode
    pub detached: bool,
    /// Default executes the specified execution of a generic command
    pub executor: Box<dyn Executor>,
    /// If do not use pivot root to jail process inside rootfs
    pub no_pivot: bool,
    // RawFd set to stdin of the container init process.
    pub stdin: Option<OwnedFd>,
    // RawFd set to stdout of the container init process.
    pub stdout: Option<OwnedFd>,
    // RawFd set to stderr of the container init process.
    pub stderr: Option<OwnedFd>,
    // Indicate if the init process should be a sibling of the main process.
    pub as_sibling: bool,
    /// Base cgroup path of the container, decided by the caller: the init
    /// builder derives it from the spec and the cgroup manager and saves it in
    /// the container's config; a tenant (exec) loads that saved path, so both
    /// end up in the same cgroup.
    pub cgroup_path: PathBuf,
    // Run the process in an (existing) sub-cgroup(s)
    pub sub_cgroup_path: Option<String>,
    // Asm process label for the process commonly used with selinux.
    // TODO: youki does not support selinux yet
    #[allow(dead_code)]
    pub process_label: Option<String>,
}

impl ContainerBuilderImpl {
    pub(super) fn create(&mut self) -> Result<(Pid, Option<OwnedFd>), LibcontainerError> {
        match self.run_container() {
            Ok(ret) => Ok(ret),
            Err(outer) => {
                // Only the init container should be cleaned up in the case of
                // an error.
                let cleanup_err = if self.is_init_container() {
                    self.cleanup_container(&outer).err()
                } else {
                    None
                };

                Err(CreateContainerError::new(outer, cleanup_err).into())
            }
        }
    }

    fn is_init_container(&self) -> bool {
        matches!(self.container_type, ContainerType::InitContainer)
    }

    fn run_container(&mut self) -> Result<(Pid, Option<OwnedFd>), LibcontainerError> {
        let linux = self.spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;
        let mut final_cgroups_path = self.cgroup_path.clone();

        if let Some(sub_cgroup_path) = &self.sub_cgroup_path
            && sub_cgroup_path != "/"
        {
            let potential_path = final_cgroups_path.join(sub_cgroup_path);
            let normalized = potential_path.normalize();

            if !normalized.starts_with(&final_cgroups_path) {
                return Err(LibcontainerError::OtherCgroup(format!(
                    "{} is not a sub cgroup path",
                    sub_cgroup_path
                )));
            }
            final_cgroups_path = normalized;
        }

        let cgroup_config = libcgroups::common::CgroupConfig {
            cgroup_path: final_cgroups_path,
            systemd_cgroup: self.use_systemd || self.user_ns_config.is_some(),
            container_name: self.container_id.to_owned(),
        };
        let process = self
            .spec
            .process()
            .as_ref()
            .ok_or(MissingSpecError::Process)?;

        // Need to create the notify socket before we pivot root, since the unix
        // domain socket used here is outside of the rootfs of container. During
        // exec, need to create the socket before we enter into existing mount
        // namespace. We also need to create to socket before entering into the
        // user namespace in the case that the path is located in paths only
        // root can access.
        let notify_listener = NotifyListener::new(&self.notify_path)?;

        // If Out-of-memory score adjustment is set in specification.  set the score
        // value for the current process check
        // https://dev.to/rrampage/surviving-the-linux-oom-killer-2ki9 for some more
        // information.
        //
        // This has to be done before !dumpable because /proc/self/oom_score_adj
        // is not writeable unless you're an privileged user (if !dumpable is
        // set). All children inherit their parent's oom_score_adj value on
        // fork(2) so this will always be propagated properly.
        if let Some(oom_score_adj) = process.oom_score_adj() {
            tracing::debug!("Set OOM score to {}", oom_score_adj);
            let mut f = fs::File::create("/proc/self/oom_score_adj").map_err(|err| {
                tracing::error!("failed to open /proc/self/oom_score_adj: {}", err);
                LibcontainerError::OtherIO(err)
            })?;
            f.write_all(oom_score_adj.to_string().as_bytes())
                .map_err(|err| {
                    tracing::error!("failed to write to /proc/self/oom_score_adj: {}", err);
                    LibcontainerError::OtherIO(err)
                })?;
        }

        // Make the process non-dumpable, to avoid various race conditions that
        // could cause processes in namespaces we're joining to access host
        // resources (or potentially execute code).
        //
        // However, if the number of namespaces we are joining is 0, we are not
        // going to be switching to a different security context. Thus setting
        // ourselves to be non-dumpable only breaks things (like rootless
        // containers), which is the recommendation from the kernel folks.
        if linux.namespaces().is_some() {
            prctl::set_dumpable(false).map_err(|e| {
                LibcontainerError::Other(format!(
                    "error in setting dumpable to false : {}",
                    nix::errno::Errno::from_raw(e)
                ))
            })?;
        }

        // This container_args will be passed to the container processes,
        // therefore we will have to move all the variable by value. Since self
        // is a shared reference, we have to clone these variables here.
        let container_args = ContainerArgs {
            container_type: self.container_type,
            syscall: self.syscall,
            spec: Rc::clone(&self.spec),
            rootfs: self.rootfs.to_owned(),
            console_socket: self.console_socket.as_ref().map(|c| c.as_raw_fd()),
            notify_listener,
            preserve_fds: self.preserve_fds,
            container: self.container.to_owned(),
            user_ns_config: self.user_ns_config.to_owned(),
            cgroup_config,
            detached: self.detached,
            executor: self.executor.clone(),
            no_pivot: self.no_pivot,
            stdin: self.stdin.as_ref().map(|x| x.as_raw_fd()),
            stdout: self.stdout.as_ref().map(|x| x.as_raw_fd()),
            stderr: self.stderr.as_ref().map(|x| x.as_raw_fd()),
            as_sibling: self.as_sibling,
            pid_file: self.pid_file.to_owned(),
        };

        let (init_pid, foreground_pty_fd) =
            process::container_main_process::container_main_process(
                &container_args,
                |init_pid, cgroup_attachment| {
                    // Retain init ownership before any later startup step can fail.
                    if let Some(container) = &mut self.container {
                        container.state.cgroup_attachment = Some(cgroup_attachment);
                        container
                            .set_status(ContainerStatus::Created)
                            .set_creator(nix::unistd::geteuid().as_raw())
                            .set_pid(init_pid.as_raw());
                    }
                },
            )
            .map_err(|err| {
                tracing::error!("failed to run container process {}", err);
                LibcontainerError::MainProcess(err)
            })?;

        let mut intel_rdt_dir = None;
        let mut intel_rdt_monitoring_dir = None;
        if let Some(linux) = self.spec.linux() {
            if let Some(intel_rdt) = linux.intel_rdt() {
                let container_id = self.container.as_ref().map(|c| c.id());
                let (dir, mon_dir) = setup_intel_rdt(container_id, &init_pid, intel_rdt)?;
                intel_rdt_dir = dir;
                intel_rdt_monitoring_dir = mon_dir;
            }
        }

        if let Some(container) = &mut self.container {
            container
                .set_intel_rdt_dir(intel_rdt_dir)
                .set_intel_rdt_monitoring_dir(intel_rdt_monitoring_dir)
                .save()?;
        }

        Ok((init_pid, foreground_pty_fd))
    }

    fn cleanup_container(&self, error: &LibcontainerError) -> Result<(), LibcontainerError> {
        cleanup_failed_container(error, self.container.as_ref(), || {
            let cmanager =
                libcgroups::common::create_cgroup_manager(libcgroups::common::CgroupConfig {
                    cgroup_path: self.cgroup_path.clone(),
                    systemd_cgroup: self.use_systemd || self.user_ns_config.is_some(),
                    container_name: self.container_id.to_string(),
                })?;
            cmanager.remove().map_err(LibcontainerError::CgroupManager)
        })
    }
}

fn cleanup_failed_container<F>(
    error: &LibcontainerError,
    container: Option<&Container>,
    cleanup_cgroup: F,
) -> Result<(), LibcontainerError>
where
    F: FnOnce() -> Result<(), LibcontainerError>,
{
    let mut errors = Vec::new();

    // Only v2 reports this stage, after undoing its own new directories.
    // No attachment took place: generic removal could kill someone else's
    // tasks. Other failures can follow attachment before state is saved.
    if let Some(container) = container.filter(|container| container.has_no_cgroup()) {
        if let Err(e) = terminate_failed_init(container) {
            tracing::error!(pid = ?container.pid(), error = ?e, "failed to terminate ungrouped init");
            errors.push(e.to_string());
        }
    } else if !matches!(
        error,
        LibcontainerError::MainProcess(process::container_main_process::ProcessError::Channel(
            process::channel::ChannelError::CgroupEntry(_)
        ))
    ) && let Err(e) = cleanup_cgroup()
    {
        tracing::error!(error = ?e, "failed to remove cgroup manager");
        errors.push(e.to_string());
    }

    if let Some(container) = container {
        if let Err(e) = cleanup_intel_rdt(
            container.intel_rdt_dir().map(|p| p.as_path()),
            container.intel_rdt_monitoring_dir().map(|p| p.as_path()),
            container.clean_up_intel_rdt_subdirectory(),
            container.id(),
        ) {
            tracing::error!(id = ?container.id(), error = ?e, "failed to cleanup intel rdt");
            errors.push(e.to_string());
        }

        if container.root.exists() {
            if let Err(e) = fs::remove_dir_all(&container.root) {
                tracing::error!(container_root = ?container.root, error = ?e, "failed to delete container root");
                errors.push(e.to_string());
            }
        }
    }

    if !errors.is_empty() {
        return Err(LibcontainerError::Other(format!(
            "failed to cleanup container: {}",
            errors.join(";")
        )));
    }

    Ok(())
}

fn terminate_failed_init(container: &Container) -> Result<(), LibcontainerError> {
    use nix::errno::Errno;
    use nix::sys::wait::{WaitPidFlag, waitpid};

    let mut init = container.clone();
    let pid = init
        .pid()
        .ok_or_else(|| LibcontainerError::Other("startup init pid is missing".into()))?;
    init.refresh_status()?;
    let flags = if init.can_kill() {
        init.do_kill(nix::sys::signal::Signal::SIGKILL, true)?;
        None
    } else {
        let stat =
            match procfs::process::Process::new(pid.as_raw()).and_then(|process| process.stat()) {
                Ok(stat) => stat,
                Err(procfs::ProcError::NotFound(_)) => return Ok(()),
                Err(error) => return Err(error.into()),
            };
        // Stopped can mean a reused PID, not an exited init that we own.
        if init.state.init_start_time != Some(stat.starttime) {
            return Ok(());
        }
        Some(WaitPidFlag::WNOHANG)
    };
    loop {
        match waitpid(pid, flags) {
            // An as-sibling init belongs to the caller, which must reap it.
            Ok(_) | Err(Errno::ECHILD) => return Ok(()),
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(LibcontainerError::OtherSyscall(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::process::Command;

    use super::*;
    use crate::container::State;
    use crate::process::container_main_process::ProcessError;

    fn assert_cleanup_after_error(entered: bool) {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("existing-cgroup");
        let state_dir = tmp.path().join("state");
        let rdt_dir = tmp.path().join("rdt");
        for dir in [&target, &state_dir, &rdt_dir] {
            fs::create_dir(dir).unwrap();
        }
        let kill_file = target.join("cgroup.kill");
        fs::write(&kill_file, "0").unwrap();
        let container = Container {
            root: state_dir.clone(),
            state: State {
                intel_rdt_dir: Some(rdt_dir.clone()),
                // Readiness has not saved attachment even if entry succeeded.
                ..State::default()
            },
        };
        let mut task = scopeguard::guard(
            Command::new("sleep").arg("60").spawn().unwrap(),
            |mut task| {
                let _ = task.kill();
                let _ = task.wait();
            },
        );

        let (mut sender, mut receiver) = process::channel::main_channel().unwrap();
        let channel_error = if entered {
            sender.send_error("resource apply failed".into()).unwrap();
            receiver.wait_for_intermediate_ready().unwrap_err()
        } else {
            sender
                .send_cgroup_entry_error("attach denied".into())
                .unwrap();
            receiver.wait_for_mapping_request().unwrap_err()
        };
        sender.close().unwrap();
        receiver.close().unwrap();
        let error = LibcontainerError::MainProcess(ProcessError::Channel(channel_error));
        let cleanup_called = Cell::new(false);
        // This callback models the destructive manager.remove boundary, using
        // only a test-owned process and regular files, not a real cgroup.
        cleanup_failed_container(&error, Some(&container), || {
            cleanup_called.set(true);
            fs::write(&kill_file, "1").unwrap();
            task.kill().unwrap();
            fs::remove_dir_all(&target).unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(cleanup_called.get(), entered);
        assert!(!state_dir.exists());
        assert!(!rdt_dir.exists());
        if entered {
            assert!(!target.exists());
            task.wait().unwrap();
        } else {
            assert!(target.is_dir());
            assert_eq!(fs::read_to_string(&kill_file).unwrap(), "0");
            assert!(task.try_wait().unwrap().is_none());
        }
    }

    fn assert_exited_init_cleanup(identity_matches: bool) {
        use libcgroups::common::CgroupAttachment;
        use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid, waitpid};

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("state");
        fs::create_dir(&root).unwrap();
        let task = Command::new("true").spawn().unwrap();
        let pid = Pid::from_raw(task.id() as i32);
        let mut task = scopeguard::guard(task, |mut task| {
            if matches!(
                waitpid(pid, Some(WaitPidFlag::WNOHANG)),
                Ok(WaitStatus::StillAlive)
            ) {
                let _ = task.kill();
                let _ = task.wait();
            }
        });
        assert_eq!(
            waitid(Id::Pid(pid), WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT).unwrap(),
            WaitStatus::Exited(pid, 0)
        );
        let mut container = Container {
            root,
            state: State {
                cgroup_attachment: Some(CgroupAttachment::Skipped),
                ..State::default()
            },
        };
        container
            .set_status(ContainerStatus::Created)
            .set_pid(pid.as_raw());
        if !identity_matches {
            container.state.init_start_time = Some(container.state.init_start_time.unwrap() + 1);
        }
        cleanup_failed_container(
            &LibcontainerError::Other("startup failed".into()),
            Some(&container),
            || {
                panic!("Skipped cleanup must not remove a cgroup");
            },
        )
        .unwrap();
        if identity_matches {
            assert_eq!(
                waitpid(pid, Some(WaitPidFlag::WNOHANG)),
                Err(nix::errno::Errno::ECHILD)
            );
        } else {
            assert_eq!(
                task.wait()
                    .expect("must not reap another process identity")
                    .code(),
                Some(0)
            );
        }
    }

    #[test]
    fn test_skipped_cleanup_does_not_reap_different_identity() {
        assert_exited_init_cleanup(false);
    }

    #[test]
    fn test_skipped_cleanup_reaps_matching_exited_init() {
        assert_exited_init_cleanup(true);
    }

    #[test]
    fn test_skipped_startup_failure_terminates_init_without_cgroup_removal() {
        use libcgroups::common::CgroupAttachment;
        use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
        use nix::unistd::Pid;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("state");
        fs::create_dir(&root).unwrap();
        let task = Command::new("sleep").arg("60").spawn().unwrap();
        let pid = Pid::from_raw(task.id() as i32);
        let _task = scopeguard::guard(task, |mut task| {
            // The production cleanup may already have reaped this PID.
            if matches!(
                waitpid(pid, Some(WaitPidFlag::WNOHANG)),
                Ok(WaitStatus::StillAlive)
            ) {
                let _ = task.kill();
                let _ = task.wait();
            }
        });
        let mut container = Container {
            root: root.clone(),
            state: State {
                cgroup_attachment: Some(CgroupAttachment::Skipped),
                ..State::default()
            },
        };
        container
            .set_status(ContainerStatus::Created)
            .set_pid(pid.as_raw());
        let cgroup_removed = Cell::new(false);
        cleanup_failed_container(
            &LibcontainerError::Other("startup failed".into()),
            Some(&container),
            || {
                cgroup_removed.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            waitpid(pid, Some(WaitPidFlag::WNOHANG)),
            Err(nix::errno::Errno::ECHILD)
        );
        assert!(!cgroup_removed.get());
        assert!(!root.exists());
    }

    #[test]
    fn test_before_entry_failure_preserves_existing_cgroup() {
        assert_cleanup_after_error(false);
    }

    #[test]
    fn test_after_entry_failure_keeps_normal_cleanup() {
        assert_cleanup_after_error(true);
    }
}
