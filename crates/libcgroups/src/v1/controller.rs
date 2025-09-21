use std::fs;
use std::path::Path;

use nix::unistd::Pid;

use crate::common::{self, CGROUP_PROCS, ControllerOpt, WrapIoResult, WrappedIoError};

pub(super) trait Controller {
    type Error: From<WrappedIoError>;
    type Resource;

    /// Adds a new task specified by its pid to the cgroup
    fn add_task(pid: Pid, cgroup_path: &Path) -> Result<(), Self::Error> {
        fs::create_dir_all(cgroup_path).wrap_create_dir(cgroup_path)?;
        common::write_cgroup_file(cgroup_path.join(CGROUP_PROCS), pid)?;
        Ok(())
    }

    /// Applies resource restrictions to the cgroup
    fn apply(controller_opt: &ControllerOpt, cgroup_root: &Path) -> Result<(), Self::Error>;

    /// Checks if the controller needs to handle this request
    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource>;
}
