use std::path::Path;

use crate::common::ControllerOpt;

pub(crate) trait Controller {
    type Error;

    fn apply(controller_opt: &ControllerOpt, cgroup_path: &Path) -> Result<(), Self::Error>;
}
