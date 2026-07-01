use std::path::Path;

use oci_spec::runtime::LinuxPids;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{self, PidStats, PidStatsError, StatsProvider};

// Contains the maximum allowed number of active pids
const CGROUP_PIDS_MAX: &str = "pids.max";

pub struct Pids {}

impl Controller for Pids {
    type Error = WrappedIoError;
    type Resource = LinuxPids;

    fn apply(controller_opt: &ControllerOpt, cgroup_root: &Path) -> Result<(), Self::Error> {
        tracing::debug!("Apply pids cgroup config");

        if let Some(pids) = &controller_opt.resources.pids() {
            Self::apply(cgroup_root, pids)?;
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        controller_opt.resources.pids().as_ref()
    }
}

impl StatsProvider for Pids {
    type Error = PidStatsError;
    type Stats = PidStats;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        stats::pid_stats(cgroup_path)
    }
}

impl Pids {
    fn apply(root_path: &Path, pids: &LinuxPids) -> Result<(), WrappedIoError> {
        // Per the runtime-spec, a negative limit (e.g. -1) means no limit ("max"),
        // while 0 is a valid limit value and must be honored as-is.
        let limit = if pids.limit() < 0 {
            "max".to_string()
        } else {
            pids.limit().to_string()
        };

        common::write_cgroup_file_str(root_path.join(CGROUP_PIDS_MAX), &limit)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use oci_spec::runtime::LinuxPidsBuilder;

    use super::*;
    use crate::test::set_fixture;

    // Contains the current number of active pids
    const CGROUP_PIDS_CURRENT: &str = "pids.current";

    #[test]
    fn test_set_pids() {
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), CGROUP_PIDS_MAX, "1000").expect("Set fixture for 1000 pids");

        let pids = LinuxPidsBuilder::default().limit(1000).build().unwrap();

        Pids::apply(tmp.path(), &pids).expect("apply pids");
        let content =
            std::fs::read_to_string(tmp.path().join(CGROUP_PIDS_MAX)).expect("Read pids contents");
        assert_eq!(pids.limit().to_string(), content);
    }

    #[test]
    fn test_set_pids_max() {
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), CGROUP_PIDS_MAX, "0").expect("set fixture for -1 pids");

        // A negative limit (e.g. -1) means no limit ("max").
        let pids = LinuxPidsBuilder::default().limit(-1).build().unwrap();

        Pids::apply(tmp.path(), &pids).expect("apply pids");

        let content =
            std::fs::read_to_string(tmp.path().join(CGROUP_PIDS_MAX)).expect("Read pids contents");
        assert_eq!("max".to_string(), content);
    }

    #[test]
    fn test_set_pids_zero_is_a_valid_limit() {
        // Per the runtime-spec, 0 is a valid limit value and must be written
        // literally rather than being treated as "max".
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), CGROUP_PIDS_MAX, "max").expect("set fixture for 0 pids");

        let pids = LinuxPidsBuilder::default().limit(0).build().unwrap();

        Pids::apply(tmp.path(), &pids).expect("apply pids");

        let content =
            std::fs::read_to_string(tmp.path().join(CGROUP_PIDS_MAX)).expect("Read pids contents");
        assert_eq!("0".to_string(), content);
    }

    #[test]
    fn test_stat_pids() {
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), CGROUP_PIDS_CURRENT, "5\n").unwrap();
        set_fixture(tmp.path(), CGROUP_PIDS_MAX, "30\n").unwrap();

        let stats = Pids::stats(tmp.path()).expect("get cgroup stats");

        assert_eq!(stats.current, 5);
        assert_eq!(stats.limit, 30);
    }

    #[test]
    fn test_stat_pids_max() {
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), CGROUP_PIDS_CURRENT, "5\n").unwrap();
        set_fixture(tmp.path(), CGROUP_PIDS_MAX, "max\n").unwrap();

        let stats = Pids::stats(tmp.path()).expect("get cgroup stats");

        assert_eq!(stats.current, 5);
        assert_eq!(stats.limit, 0);
    }
}
