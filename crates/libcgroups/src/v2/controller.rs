use std::path::Path;

use crate::common::ControllerOpt;

pub(super) trait Controller {
    type Error;
    type Resource;

    fn apply(controller_opt: &ControllerOpt, cgroup_path: &Path) -> Result<(), Self::Error>;

    /// Returns the setting this controller would write for the request, or
    /// `None` when there is nothing for it to do
    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource>;
}
