use std::fs;
use std::path::{Path, PathBuf, StripPrefixError};

use nix::unistd;
use oci_spec::runtime::LinuxCpu;
use unistd::Pid;

use super::ControllerType;
use super::controller::Controller;
use super::util::{self, V1MountPointError};
use crate::common::{self, CGROUP_PROCS, ControllerOpt, WrapIoResult, WrappedIoError};

const CGROUP_CPUSET_CPUS: &str = "cpuset.cpus";
const CGROUP_CPUSET_MEMS: &str = "cpuset.mems";

#[derive(thiserror::Error, Debug)]
pub enum V1CpuSetControllerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("bad cgroup path {path}: {err}")]
    BadCgroupPath {
        err: StripPrefixError,
        path: PathBuf,
    },
    #[error("cpuset parent value is empty")]
    EmptyParent,
    #[error("mount point error: {0}")]
    MountPoint(#[from] V1MountPointError),
}

pub struct CpuSet {}

impl Controller for CpuSet {
    type Error = V1CpuSetControllerError;
    type Resource = LinuxCpu;

    fn add_task(pid: Pid, cgroup_path: &Path) -> Result<(), Self::Error> {
        fs::create_dir_all(cgroup_path).wrap_create_dir(cgroup_path)?;

        Self::ensure_not_empty(cgroup_path, CGROUP_CPUSET_CPUS)?;
        Self::ensure_not_empty(cgroup_path, CGROUP_CPUSET_MEMS)?;

        common::write_cgroup_file(cgroup_path.join(CGROUP_PROCS), pid)?;
        Ok(())
    }

    fn apply(controller_opt: &ControllerOpt, cgroup_path: &Path) -> Result<(), Self::Error> {
        tracing::debug!("Apply CpuSet cgroup config");

        if let Some(cpuset) = Self::needs_to_handle(controller_opt) {
            Self::apply(cgroup_path, cpuset)?;
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        if let Some(cpuset) = &controller_opt.resources.cpu() {
            if cpuset.cpus().is_some() || cpuset.mems().is_some() {
                return Some(cpuset);
            }
        }

        None
    }
}

impl CpuSet {
    fn apply(cgroup_path: &Path, cpuset: &LinuxCpu) -> Result<(), V1CpuSetControllerError> {
        if let Some(cpus) = &cpuset.cpus() {
            common::write_cgroup_file_str(cgroup_path.join(CGROUP_CPUSET_CPUS), cpus)?;
        }

        if let Some(mems) = &cpuset.mems() {
            common::write_cgroup_file_str(cgroup_path.join(CGROUP_CPUSET_MEMS), mems)?;
        }

        Ok(())
    }

    // if a task is moved into the cgroup and a value has not been set for cpus and mems
    // Errno 28 (no space left on device) will be returned. Therefore we set the value from the parent if required.
    fn ensure_not_empty(
        cgroup_path: &Path,
        interface_file: &str,
    ) -> Result<(), V1CpuSetControllerError> {
        let mut current = util::get_subsystem_mount_point(&ControllerType::CpuSet)?;
        let relative_cgroup_path = cgroup_path.strip_prefix(&current).map_err(|err| {
            V1CpuSetControllerError::BadCgroupPath {
                err,
                path: cgroup_path.to_path_buf(),
            }
        })?;

        for component in relative_cgroup_path.components() {
            let parent_value =
                fs::read_to_string(current.join(interface_file)).wrap_read(cgroup_path)?;
            if parent_value.trim().is_empty() {
                return Err(V1CpuSetControllerError::EmptyParent);
            }

            current.push(component);
            let child_path = current.join(interface_file);
            let child_value = fs::read_to_string(&child_path).wrap_read(&child_path)?;
            // the file can contain a newline character. Need to trim it away,
            // otherwise it is not considered empty and value will not be written
            if child_value.trim().is_empty() {
                common::write_cgroup_file_str(&child_path, &parent_value)?;
            }
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
