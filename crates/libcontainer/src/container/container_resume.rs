use libcgroups::common::{CgroupManager, FreezerState};

use super::{Container, ContainerStatus};
use crate::error::LibcontainerError;

impl Container {
    /// Resumes all processes within the container
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
    /// container.resume()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn resume(&mut self) -> Result<(), LibcontainerError> {
        self.refresh_status()?;
        // check if container can be resumed :
        // for example, a running process cannot be resumed
        if !self.can_resume() {
            tracing::error!(status = ?self.status(), id = ?self.id(), "cannot resume container");
            return Err(LibcontainerError::IncorrectStatus(self.status()));
        }

        let cmanager =
            libcgroups::common::create_cgroup_manager(libcgroups::common::CgroupConfig {
                cgroup_path: self.spec()?.cgroup_path,
                systemd_cgroup: self.systemd(),
                container_name: self.id().to_string(),
            })?;
        // resume the frozen container
        cmanager.freeze(FreezerState::Thawed)?;

        tracing::debug!("saving running status");
        self.set_status(ContainerStatus::Running).save()?;

        tracing::debug!("container {} resumed", self.id());
        Ok(())
    }
}
