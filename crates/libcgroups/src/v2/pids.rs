use std::path::Path;

use oci_spec::runtime::LinuxPids;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{self, PidStats, PidStatsError, StatsProvider};

pub struct Pids {}

impl Controller for Pids {
    type Error = WrappedIoError;

    fn apply(
        controller_opt: &ControllerOpt,
        cgroup_root: &std::path::Path,
    ) -> Result<(), Self::Error> {
        tracing::debug!("Apply pids cgroup v2 config");
        if let Some(pids) = &controller_opt.resources.pids() {
            Self::apply(cgroup_root, pids)?;
        }
        Ok(())
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
        // follow runc's behavior of mapping 0 to 1 due to systemd limitations
        let limit = match pids.limit() {
            0 => "1".to_string(),
            1.. => pids.limit().to_string(),
            _ => "max".to_string(),
        };

        common::write_cgroup_file(root_path.join("pids.max"), limit)
    }
}

#[cfg(test)]
mod tests {
    use oci_spec::runtime::LinuxPidsBuilder;

    use super::*;
    use crate::test::set_fixture;

    #[test]
    fn test_set_pids() {
        let pids_file_name = "pids.max";
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), pids_file_name, "1000").expect("Set fixture for 1000 pids");

        let pids = LinuxPidsBuilder::default().limit(1000).build().unwrap();

        Pids::apply(tmp.path(), &pids).expect("apply pids");
        let content =
            std::fs::read_to_string(tmp.path().join(pids_file_name)).expect("Read pids contents");
        assert_eq!(pids.limit().to_string(), content);
    }

    #[test]
    fn test_set_pids_zero() {
        let pids_file_name = "pids.max";
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), pids_file_name, "0").expect("set fixture for 0 pids");

        let pids = LinuxPidsBuilder::default().limit(0).build().unwrap();

        Pids::apply(tmp.path(), &pids).expect("apply pids");

        let content =
            std::fs::read_to_string(tmp.path().join(pids_file_name)).expect("Read pids contents");
        assert_eq!("1".to_string(), content);
    }

    #[test]
    fn test_set_pids_max() {
        let pids_file_name = "pids.max";
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), pids_file_name, "-1").expect("set fixture for -1 pids");

        let pids = LinuxPidsBuilder::default().limit(-1).build().unwrap();

        Pids::apply(tmp.path(), &pids).expect("apply pids");
        let content =
            std::fs::read_to_string(tmp.path().join(pids_file_name)).expect("Read pids contents");
        assert_eq!("max".to_string(), content);
    }
}
