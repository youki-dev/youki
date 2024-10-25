use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::prelude::RawFd;
use std::path::PathBuf;
use std::rc::Rc;

use libcgroups::common::CgroupManager;
use nix::unistd::Pid;
use oci_spec::runtime::Spec;

use super::{Container, ContainerStatus};
use crate::error::{LibcontainerError, MissingSpecError};
use crate::notify_socket::NotifyListener;
use crate::process::args::{ContainerArgs, ContainerType};
use crate::process::intel_rdt::delete_resctrl_subdirectory;
use crate::process::{self};
use crate::syscall::syscall::SyscallType;
use crate::user_ns::UserNamespaceConfig;
use crate::workload::Executor;
use crate::{hooks, utils};

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
    pub console_socket: Option<RawFd>,
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
}

impl ContainerBuilderImpl {
    pub(super) fn create(&mut self) -> Result<Pid, LibcontainerError> {
        match self.run_container() {
            Ok(pid) => Ok(pid),
            Err(outer) => {
                // Only the init container should be cleaned up in the case of
                // an error.
                if matches!(self.container_type, ContainerType::InitContainer) {
                    self.cleanup_container()?;
                }

                Err(outer)
            }
        }
    }

    fn run_container(&mut self) -> Result<Pid, LibcontainerError> {
        let linux = self.spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;
        let cgroups_path = utils::get_cgroup_path(linux.cgroups_path(), &self.container_id);
        let cgroup_config = libcgroups::common::CgroupConfig {
            cgroup_path: cgroups_path,
            systemd_cgroup: self.use_systemd || self.user_ns_config.is_some(),
            container_name: self.container_id.to_owned(),
        };
        let process = self
            .spec
            .process()
            .as_ref()
            .ok_or(MissingSpecError::Process)?;

        if matches!(self.container_type, ContainerType::InitContainer) {
            if let Some(hooks) = self.spec.hooks() {
                hooks::run_hooks(
                    hooks.create_runtime().as_ref(),
                    self.container.as_ref(),
                    None,
                )?
            }
        }

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
            console_socket: self.console_socket,
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
        };

        let (init_pid, need_to_clean_up_intel_rdt_dir) =
            process::container_main_process::container_main_process(&container_args).map_err(
                |err| {
                    tracing::error!("failed to run container process {}", err);
                    LibcontainerError::MainProcess(err)
                },
            )?;

        // if file to write the pid to is specified, write pid of the child
        if let Some(pid_file) = &self.pid_file {
            fs::write(pid_file, format!("{init_pid}")).map_err(|err| {
                tracing::error!("failed to write pid to file: {}", err);
                LibcontainerError::OtherIO(err)
            })?;
        }

        if let Some(container) = &mut self.container {
            // update status and pid of the container process
            container
                .set_status(ContainerStatus::Created)
                .set_creator(nix::unistd::geteuid().as_raw())
                .set_pid(init_pid.as_raw())
                .set_clean_up_intel_rdt_directory(need_to_clean_up_intel_rdt_dir)
                .save()?;
        }

        Ok(init_pid)
    }

    fn cleanup_container(&self) -> Result<(), LibcontainerError> {
        let linux = self.spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;
        let cgroups_path = utils::get_cgroup_path(linux.cgroups_path(), &self.container_id);
        let cmanager =
            libcgroups::common::create_cgroup_manager(libcgroups::common::CgroupConfig {
                cgroup_path: cgroups_path,
                systemd_cgroup: self.use_systemd || self.user_ns_config.is_some(),
                container_name: self.container_id.to_string(),
            })?;

        let mut errors = Vec::new();

        if let Err(e) = cmanager.remove() {
            tracing::error!(error = ?e, "failed to remove cgroup manager");
            errors.push(e.to_string());
        }

        if let Some(container) = &self.container {
            if let Some(true) = container.clean_up_intel_rdt_subdirectory() {
                if let Err(e) = delete_resctrl_subdirectory(container.id()) {
                    tracing::error!(id = ?container.id(), error = ?e, "failed to delete resctrl subdirectory");
                    errors.push(e.to_string());
                }
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
}
