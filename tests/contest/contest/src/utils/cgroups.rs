use std::fs;
use std::path::Path;

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
