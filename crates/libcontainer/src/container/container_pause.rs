use libcgroups::common::{CgroupManager, FreezerState};

use super::{Container, ContainerStatus};
use crate::error::LibcontainerError;

impl Container {
    /// Suspends all processes within the container
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
    /// container.pause()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn pause(&mut self) -> Result<(), LibcontainerError> {
        self.refresh_status()?;

        if !self.can_pause() {
            tracing::error!(status = ?self.status(), id = ?self.id(), "cannot pause container");
            return Err(LibcontainerError::IncorrectStatus(self.status()));
        }

        let cmanager =
            libcgroups::common::create_cgroup_manager(libcgroups::common::CgroupConfig {
                cgroup_path: self.spec()?.cgroup_path,
                systemd_cgroup: self.systemd(),
                container_name: self.id().to_string(),
            })?;
        cmanager.freeze(FreezerState::Frozen)?;

        tracing::debug!("saving paused status");
        self.set_status(ContainerStatus::Paused).save()?;

        tracing::debug!("container {} paused", self.id());
        Ok(())
    }
}
