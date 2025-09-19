use std::path::{Path, PathBuf};

use procfs::ProcError;
use procfs::process::Process;

use super::controller_type::ControllerType;
use crate::common::{self, WrappedIoError};

pub const CGROUP_CONTROLLERS: &str = "cgroup.controllers";
pub const CGROUP_SUBTREE_CONTROL: &str = "cgroup.subtree_control";

#[derive(thiserror::Error, Debug)]
pub enum V2UtilError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("proc error: {0}")]
    Proc(#[from] ProcError),
    #[error("could not find mountpoint for unified")]
    CouldNotFind,
    #[error("cannot get available controllers. {0} does not exist")]
    DoesNotExist(PathBuf),
}

// Reads the `/proc/self/mountinfo` to get the mount point of this cgroup
pub fn get_unified_mount_point() -> Result<PathBuf, V2UtilError> {
    Process::myself()?
        .mountinfo()?
        .into_iter()
        .find(|m| m.fs_type == "cgroup2")
        .map(|m| m.mount_point)
        .ok_or(V2UtilError::CouldNotFind)
}

/// Reads the `{root_path}/cgroup.controllers` file to get the list of the controllers that are
/// available in this cgroup
pub fn get_available_controllers<P: AsRef<Path>>(
    root_path: P,
) -> Result<Vec<ControllerType>, V2UtilError> {
    let root_path = root_path.as_ref();
    let controllers_path = root_path.join(CGROUP_CONTROLLERS);
    if !controllers_path.exists() {
        return Err(V2UtilError::DoesNotExist(controllers_path));
    }

    let mut controllers = Vec::new();
    for controller in common::read_cgroup_file(controllers_path)?.split_whitespace() {
        match controller {
            "cpu" => controllers.push(ControllerType::Cpu),
            "cpuset" => controllers.push(ControllerType::CpuSet),
            "hugetlb" => controllers.push(ControllerType::HugeTlb),
            "io" => controllers.push(ControllerType::Io),
            "memory" => controllers.push(ControllerType::Memory),
            "pids" => controllers.push(ControllerType::Pids),
            tpe => tracing::warn!("Controller {} is not yet implemented.", tpe),
        }
    }

    Ok(controllers)
}
