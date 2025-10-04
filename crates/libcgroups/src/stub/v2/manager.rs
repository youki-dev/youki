use crate::common::{AnyCgroupManager, CgroupManager};

#[derive(thiserror::Error, Debug)]
pub enum V2ManagerError {
    #[error("v2 cgroup feature is required, but was not enabled during compile time")]
    NotEnabled,
}

pub struct Manager {}

impl Manager {
    pub fn any(self) -> AnyCgroupManager {
        crate::common::AnyCgroupManager::V2(self)
    }
}

impl CgroupManager for Manager {
    type Error = V2ManagerError;

    fn add_task(&self, _pid: nix::unistd::Pid) -> Result<(), Self::Error> {
        Err(V2ManagerError::NotEnabled)
    }

    fn apply(&self, _controller_opt: &crate::common::ControllerOpt) -> Result<(), Self::Error> {
        Err(V2ManagerError::NotEnabled)
    }

    fn remove(&self) -> Result<(), Self::Error> {
        Err(V2ManagerError::NotEnabled)
    }

    fn freeze(&self, _state: crate::common::FreezerState) -> Result<(), Self::Error> {
        Err(V2ManagerError::NotEnabled)
    }

    fn get_freezer_state(&self) -> Result<crate::common::FreezerState, Self::Error> {
        Err(V2ManagerError::NotEnabled)
    }

    fn stats(&self) -> Result<crate::stats::Stats, Self::Error> {
        Err(V2ManagerError::NotEnabled)
    }

    fn get_all_pids(&self) -> Result<Vec<nix::unistd::Pid>, Self::Error> {
        Err(V2ManagerError::NotEnabled)
    }
}
