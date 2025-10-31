use crate::common::{AnyCgroupManager, CgroupManager};

#[derive(thiserror::Error, Debug)]
pub enum V1ManagerError {
    #[error("v1 cgroup feature is required, but was not enabled during compile time")]
    NotEnabled,
}

pub struct Manager {}

impl Manager {
    pub fn any(self) -> AnyCgroupManager {
        crate::common::AnyCgroupManager::V1(self)
    }
}

impl CgroupManager for Manager {
    type Error = V1ManagerError;

    fn add_task(&self, _pid: nix::unistd::Pid) -> Result<(), Self::Error> {
        Err(V1ManagerError::NotEnabled)
    }

    fn apply(&self, _controller_opt: &crate::common::ControllerOpt) -> Result<(), Self::Error> {
        Err(V1ManagerError::NotEnabled)
    }

    fn remove(&self) -> Result<(), Self::Error> {
        Err(V1ManagerError::NotEnabled)
    }

    fn freeze(&self, _state: crate::common::FreezerState) -> Result<(), Self::Error> {
        Err(V1ManagerError::NotEnabled)
    }

    fn get_freezer_state(&self) -> Result<crate::common::FreezerState, Self::Error> {
        Err(V1ManagerError::NotEnabled)
    }

    fn stats(&self) -> Result<crate::stats::Stats, Self::Error> {
        Err(V1ManagerError::NotEnabled)
    }

    fn get_all_pids(&self) -> Result<Vec<nix::unistd::Pid>, Self::Error> {
        Err(V1ManagerError::NotEnabled)
    }
}
