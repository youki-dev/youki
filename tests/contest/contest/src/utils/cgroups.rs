use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use libcgroups::common::{self, CgroupSetup};
use libcgroups::v2::controller_type::ControllerType;
use tracing::debug;

use crate::utils::test_utils::CGROUP_ROOT;

/// Checks if the host is running with the unified cgroup hierarchy (cgroup v2).
pub fn is_cgroup_v2() -> bool {
    let setup_result = common::get_cgroup_setup();
    if !matches!(setup_result, Ok(CgroupSetup::Unified)) {
        debug!("cgroup setup is not v2, was {:?}", setup_result);
        return false;
    }

    true
}

/// Checks if the host is running cgroup v2 and the given controller is
/// available on the root hierarchy (i.e. listed in `cgroup.controllers`).
pub fn is_cgroup_v2_with_controller(controller: ControllerType) -> bool {
    if !is_cgroup_v2() {
        return false;
    }

    let controllers_result = libcgroups::v2::util::get_available_controllers(CGROUP_ROOT);
    let controllers = match controllers_result {
        Ok(controllers) => controllers,
        Err(err) => {
            debug!("could not retrieve cgroup controllers: {:?}", err);
            return false;
        }
    };

    if !controllers.into_iter().any(|c| c == controller) {
        debug!("{controller} controller is not attached to the v2 hierarchy");
        return false;
    }

    true
}

/// Check whether the cgroup v2 interface file exists.
pub fn cgroup_has_file(cgroup_file: &str) -> bool {
    let self_cgroup = match fs::read_to_string("/proc/self/cgroup") {
        Ok(self_cgroup) => self_cgroup,
        Err(err) => {
            debug!("could not read /proc/self/cgroup: {:?}", err);
            return false;
        }
    };

    let Some(cgroup_path) = self_cgroup
        .lines()
        .find_map(|line| line.rsplit_once(':').map(|(_, path)| path))
    else {
        debug!("could not determine the cgroup of this process");
        return false;
    };

    let path = Path::new(CGROUP_ROOT)
        .join(cgroup_path.trim().trim_start_matches('/'))
        .join(cgroup_file);
    if !path.exists() {
        debug!("{cgroup_file} is not available, {path:?} does not exist");
        return false;
    }

    true
}

/// Lists the block devices the kernel exposes, sorted by name.
pub fn block_devices() -> Result<Vec<PathBuf>> {
    let mut entries: Vec<_> = fs::read_dir("/sys/block")
        .context("failed to read /sys/block")?
        .flatten()
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    Ok(entries)
}

/// Reads a /sys/block device's major:minor pair from its `dev` file.
pub fn device_numbers(dev_dir: &Path) -> Option<(i64, i64)> {
    let content = fs::read_to_string(dev_dir.join("dev")).ok()?;
    let (major, minor) = content.trim().split_once(':')?;
    Some((major.trim().parse().ok()?, minor.trim().parse().ok()?))
}

/// The first `count` block devices that expose a `dev` file, as
/// (major, minor) pairs. Device numbers are host-dependent, so tests that
/// key cgroup files by device derive them this way rather than hardcoding.
pub fn block_device_numbers(count: usize) -> Result<Vec<(i64, i64)>> {
    let mut numbers = Vec::with_capacity(count);
    for dev_dir in block_devices()? {
        if let Some(pair) = device_numbers(&dev_dir) {
            numbers.push(pair);
            if numbers.len() == count {
                return Ok(numbers);
            }
        }
    }

    anyhow::bail!("needed {count} block devices with a dev file, found fewer")
}
