use std::fs;

use libcgroups::common::CgroupManager;
use libcgroups::{self};
use nix::sys::signal;

use super::{Container, ContainerStatus};
use crate::config::YoukiConfig;
use crate::error::LibcontainerError;
use crate::hooks;
use crate::process::intel_rdt::delete_resctrl_subdirectory;
use crate::signal::Signal;

impl Container {
    /// Deletes the container
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libcontainer::container::builder::ContainerBuilder;
    /// use libcontainer::syscall::syscall::SyscallType;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// let mut container = ContainerBuilder::new(
    ///     "74f1a4cb3801".to_owned(),
    ///     SyscallType::default(),
    /// )
    /// .as_init("/var/run/docker/bundle")
    /// .build()?;
    ///
    /// container.delete(true)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn delete(&mut self, force: bool) -> Result<(), LibcontainerError> {
        self.refresh_status()?;

        tracing::debug!("container status: {:?}", self.status());

        // Check if container is allowed to be deleted based on container status.
        match self.status() {
            ContainerStatus::Stopped(_) => {}
            ContainerStatus::Created => {
                // Here, we differ from the OCI spec, but matches the same
                // behavior as `runc` and `crun`. The OCI spec does not allow
                // deletion of status `created` without `force` flag. But both
                // `runc` and `crun` allows deleting `created`. Therefore we
                // decided to follow `runc` and `crun`.
                self.do_kill(signal::Signal::SIGKILL, true)?;
                let exit_code = Signal::from(signal::Signal::SIGKILL).exit_code();
                self.set_status(ContainerStatus::Stopped(Some(exit_code)))
                    .save()?;
            }
            ContainerStatus::Creating | ContainerStatus::Running | ContainerStatus::Paused => {
                // Containers can't be deleted while in these status, unless
                // force flag is set. In the force case, we need to clean up any
                // processes associated with containers.
                if force {
                    self.do_kill(signal::Signal::SIGKILL, true)?;
                    let exit_code = Signal::from(signal::Signal::SIGKILL).exit_code();
                    self.set_status(ContainerStatus::Stopped(Some(exit_code)))
                        .save()?;
                } else {
                    tracing::error!(
                        id = ?self.id(),
                        status = ?self.status(),
                        "delete requires the container state to be stopped or created",
                    );
                    return Err(LibcontainerError::IncorrectStatus);
                }
            }
        }

        // Once reached here, the container is verified that it can be deleted.
        debug_assert!(self.status().can_delete());

        if let Some(true) = &self.clean_up_intel_rdt_subdirectory() {
            if let Err(err) = delete_resctrl_subdirectory(self.id()) {
                tracing::warn!(
                    "failed to delete resctrl subdirectory due to: {err:?}, continue to delete"
                );
            }
        }

        if self.root.exists() {
            match YoukiConfig::load(&self.root) {
                Ok(config) => {
                    tracing::debug!("config: {:?}", config);

                    // remove the cgroup created for the container
                    // check https://man7.org/linux/man-pages/man7/cgroups.7.html
                    // creating and removing cgroups section for more information on cgroups
                    let cmanager = libcgroups::common::create_cgroup_manager(
                        libcgroups::common::CgroupConfig {
                            cgroup_path: config.cgroup_path.to_owned(),
                            systemd_cgroup: self.systemd(),
                            container_name: self.id().to_string(),
                        },
                    )?;
                    cmanager.remove().map_err(|err| {
                        tracing::error!(cgroup_path = ?config.cgroup_path, "failed to remove cgroup due to: {err:?}");
                        err
                    })?;

                    if let Some(hooks) = config.hooks.as_ref() {
                        hooks::run_hooks(hooks.poststop().as_ref(), Some(self), None).map_err(
                            |err| {
                                tracing::error!(err = ?err, "failed to run post stop hooks");
                                err
                            },
                        )?;
                    }
                }
                Err(err) => {
                    // There is a brief window where the container state is
                    // created, but the container config is not yet generated
                    // from the OCI spec. In this case, we assume as if we
                    // successfully deleted the config and moving on.
                    tracing::warn!(
                        "skipping loading youki config due to: {err:?}, continue to delete"
                    );
                }
            }

            // remove the directory storing container state
            tracing::debug!("remove dir {:?}", self.root);
            fs::remove_dir_all(&self.root).map_err(|err| {
                tracing::error!(?err, path = ?self.root, "failed to remove container dir");
                LibcontainerError::OtherIO(err)
            })?;
        }

        Ok(())
    }
}
