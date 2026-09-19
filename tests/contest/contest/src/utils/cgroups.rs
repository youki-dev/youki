use libcgroups::common::{self, CgroupSetup};
use libcgroups::v2::controller_type::ControllerType;
use tracing::debug;

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

    let controllers_result =
        libcgroups::v2::util::get_available_controllers(common::DEFAULT_CGROUP_ROOT);
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
