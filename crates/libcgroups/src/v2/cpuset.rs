use std::path::Path;

use oci_spec::runtime::LinuxCpu;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};

const CGROUP_CPUSET_CPUS: &str = "cpuset.cpus";
const CGROUP_CPUSET_MEMS: &str = "cpuset.mems";

pub struct CpuSet {}

impl Controller for CpuSet {
    type Error = WrappedIoError;
    type Resource = LinuxCpu;

    fn apply(controller_opt: &ControllerOpt, cgroup_path: &Path) -> Result<(), Self::Error> {
        if let Some(cpuset) = Self::needs_to_handle(controller_opt) {
            Self::apply(cgroup_path, cpuset)?;
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        controller_opt.resources.cpu().as_ref().filter(|c| {
            c.cpus().as_ref().is_some_and(|s| !s.is_empty())
                || c.mems().as_ref().is_some_and(|s| !s.is_empty())
        })
    }
}

impl CpuSet {
    fn apply(path: &Path, cpuset: &LinuxCpu) -> Result<(), WrappedIoError> {
        if let Some(cpus) = &cpuset.cpus() {
            common::write_cgroup_file_str(path.join(CGROUP_CPUSET_CPUS), cpus)?;
        }

        if let Some(mems) = &cpuset.mems() {
            common::write_cgroup_file_str(path.join(CGROUP_CPUSET_MEMS), mems)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use oci_spec::runtime::LinuxCpuBuilder;

    use super::*;
    use crate::test::setup;

    #[test]
    fn test_set_cpus() {
        // arrange
        let (tmp, cpus) = setup(CGROUP_CPUSET_CPUS);
        let cpuset = LinuxCpuBuilder::default()
            .cpus("1-3".to_owned())
            .build()
            .unwrap();

        // act
        CpuSet::apply(tmp.path(), &cpuset).expect("apply cpuset");

        // assert
        let content = fs::read_to_string(cpus)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPUSET_CPUS} file content"));
        assert_eq!(content, "1-3");
    }

    #[test]
    fn test_set_mems() {
        // arrange
        let (tmp, mems) = setup(CGROUP_CPUSET_MEMS);
        let cpuset = LinuxCpuBuilder::default()
            .mems("1-3".to_owned())
            .build()
            .unwrap();

        // act
        CpuSet::apply(tmp.path(), &cpuset).expect("apply cpuset");

        // assert
        let content = fs::read_to_string(mems)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPUSET_MEMS} file content"));
        assert_eq!(content, "1-3");
    }
}
