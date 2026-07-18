use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use pathrs::flags::OpenFlags;
use pathrs::procfs::{ProcfsBase, ProcfsHandle};
use procfs::ProcError;
use procfs::process::MountInfo;

use super::ControllerType;
use super::controller_type::CONTROLLERS;

#[derive(thiserror::Error, Debug)]
pub enum V1MountPointError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to get mountinfo: {0}")]
    MountInfo(ProcError),
    #[error("could not find mountpoint for {subsystem}")]
    NotFound { subsystem: ControllerType },
    #[error(transparent)]
    Pathrs(#[from] pathrs::error::Error),
}

/// List all cgroup v1 subsystem mount points on the system. This can include unsupported
/// subsystems, comounted controllers and named hierarchies.
pub fn list_subsystem_mount_points() -> Result<Vec<PathBuf>, V1MountPointError> {
    let reader = BufReader::new(ProcfsHandle::new()?.open(
        ProcfsBase::ProcSelf,
        "mountinfo",
        OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC,
    )?);

    reader
        .lines()
        .map(|lr| {
            lr.map_err(V1MountPointError::Io)
                .and_then(|line| MountInfo::from_line(&line).map_err(V1MountPointError::MountInfo))
        })
        .try_fold(Vec::new(), |mut mount_points, r| {
            r.map(|m| {
                if m.fs_type == "cgroup" {
                    mount_points.push(m.mount_point);
                }
                mount_points
            })
        })
}

/// List the mount points of all currently supported cgroup subsystems.
pub fn list_supported_mount_points() -> Result<HashMap<ControllerType, PathBuf>, V1MountPointError>
{
    let mut mount_paths = HashMap::with_capacity(CONTROLLERS.len());

    for controller in CONTROLLERS {
        if let Ok(mount_point) = get_subsystem_mount_point(controller) {
            mount_paths.insert(controller.to_owned(), mount_point);
        }
    }

    Ok(mount_paths)
}

pub fn get_subsystem_mount_point(subsystem: &ControllerType) -> Result<PathBuf, V1MountPointError> {
    let subsystem_name = subsystem.to_string();
    let reader = BufReader::new(ProcfsHandle::new()?.open(
        ProcfsBase::ProcSelf,
        "mountinfo",
        OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC,
    )?);

    reader
        .lines()
        .map(|lr| {
            lr.map_err(V1MountPointError::Io)
                .and_then(|line| MountInfo::from_line(&line).map_err(V1MountPointError::MountInfo))
        })
        .find_map(|r| match r {
            Err(e) => Some(Err(e)),
            Ok(m) if m.fs_type == "cgroup" => {
                // Some systems mount net_prio and net_cls in the same directory
                // other systems mount them in their own directories. This
                // should handle both cases.
                let ok = match subsystem_name.as_str() {
                    "net_cls" => ["net_cls,net_prio", "net_prio,net_cls", "net_cls"]
                        .iter()
                        .any(|s| m.mount_point.ends_with(s)),
                    "net_prio" => ["net_cls,net_prio", "net_prio,net_cls", "net_prio"]
                        .iter()
                        .any(|s| m.mount_point.ends_with(s)),
                    "cpu" => ["cpu,cpuacct", "cpu"]
                        .iter()
                        .any(|s| m.mount_point.ends_with(s)),
                    "cpuacct" => ["cpu,cpuacct", "cpuacct"]
                        .iter()
                        .any(|s| m.mount_point.ends_with(s)),
                    _ => m.mount_point.ends_with(&subsystem_name),
                };
                if ok { Some(Ok(m.mount_point)) } else { None }
            }
            Ok(_) => None,
        })
        .transpose()?
        .ok_or(V1MountPointError::NotFound {
            subsystem: *subsystem,
        })
}
