use crate::common::{AnyCgroupManager, CgroupManager};

#[derive(thiserror::Error, Debug)]
pub enum SystemdManagerError {
    #[error("systemd cgroup feature is required, but was not enabled during compile time")]
    NotEnabled,
}

pub struct Manager {}

impl Manager {
    pub fn any(self) -> AnyCgroupManager {
        AnyCgroupManager::Systemd(Box::new(self))
    }
}

impl CgroupManager for Manager {
    type Error = SystemdManagerError;

    fn add_task(&self, _pid: nix::unistd::Pid) -> Result<(), Self::Error> {
        Err(SystemdManagerError::NotEnabled)
    }

    fn apply(&self, _controller_opt: &crate::common::ControllerOpt) -> Result<(), Self::Error> {
        Err(SystemdManagerError::NotEnabled)
    }

    fn remove(&self) -> Result<(), Self::Error> {
        Err(SystemdManagerError::NotEnabled)
    }

    fn freeze(&self, _state: crate::common::FreezerState) -> Result<(), Self::Error> {
        Err(SystemdManagerError::NotEnabled)
    }

    fn get_freezer_state(&self) -> Result<crate::common::FreezerState, Self::Error> {
        Err(SystemdManagerError::NotEnabled)
    }

    fn stats(&self) -> Result<crate::stats::Stats, Self::Error> {
        Err(SystemdManagerError::NotEnabled)
    }

    fn get_all_pids(&self) -> Result<Vec<nix::unistd::Pid>, Self::Error> {
        Err(SystemdManagerError::NotEnabled)
    }
}
