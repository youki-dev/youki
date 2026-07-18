use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use pathrs::flags::OpenFlags;
use pathrs::procfs::{ProcfsBase, ProcfsHandle};
use procfs::ProcError;
use procfs::process::MountInfo;

use super::controller_type::ControllerType;
use crate::common::{self, WrappedIoError};

pub const CGROUP_CONTROLLERS: &str = "cgroup.controllers";
pub const CGROUP_SUBTREE_CONTROL: &str = "cgroup.subtree_control";

#[derive(thiserror::Error, Debug)]
pub enum V2UtilError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("proc error: {0}")]
    Proc(#[from] ProcError),
    #[error("could not find mountpoint for unified")]
    CouldNotFind,
    #[error("cannot get available controllers. {0} does not exist")]
    DoesNotExist(PathBuf),
    #[error(transparent)]
    Pathrs(#[from] pathrs::error::Error),
}

// Reads the `/proc/self/mountinfo` to get the mount point of this cgroup
pub fn get_unified_mount_point() -> Result<PathBuf, V2UtilError> {
    let reader = BufReader::new(ProcfsHandle::new()?.open(
        ProcfsBase::ProcSelf,
        "mountinfo",
        OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC,
    )?);

    reader
        .lines()
        .map(|lr| {
            lr.map_err(V2UtilError::Io)
                .and_then(|s| MountInfo::from_line(&s).map_err(V2UtilError::from))
        })
        .find_map(|r| match r {
            Ok(mi) if mi.fs_type == "cgroup2" => Some(Ok(mi.mount_point)),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .transpose()?
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
