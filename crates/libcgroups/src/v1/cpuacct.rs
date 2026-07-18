use std::num::ParseIntError;
use std::path::{Path, PathBuf};

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{CpuUsage, ParseFlatKeyedDataError, StatsProvider, parse_flat_keyed_data};

// Contains user mode and kernel mode cpu consumption
const CGROUP_CPUACCT_STAT: &str = "cpuacct.stat";
// Contains overall cpu consumption
const CGROUP_CPUACCT_USAGE: &str = "cpuacct.usage";
// Contains user mode and kernel mode cpu consumption differentiated by core
const CGROUP_CPUACCT_USAGE_ALL: &str = "cpuacct.usage_all";
// Contains overall cpu consumption differentiated by core
const CGROUP_CPUACCT_PERCPU: &str = "cpuacct.usage_percpu";

pub struct CpuAcct {}

impl Controller for CpuAcct {
    type Error = WrappedIoError;
    type Resource = ();

    fn apply(_controller_opt: &ControllerOpt, _cgroup_path: &Path) -> Result<(), Self::Error> {
        Ok(())
    }

    fn needs_to_handle<'a>(_controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        None
    }
}

#[derive(thiserror::Error, Debug)]
pub enum V1CpuAcctStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("error parsing data: {0}")]
    ParseData(#[from] ParseFlatKeyedDataError),
    #[error("missing field {field} from {path}")]
    MissingField { field: &'static str, path: PathBuf },
    #[error("failed to parse total cpu usage: {0}")]
    ParseTotalCpu(ParseIntError),
    #[error("failed to parse per core {mode} mode cpu usage in {path}: {err}")]
    FailedToParseField {
        mode: &'static str,
        path: PathBuf,
        err: ParseIntError,
    },
    #[error("failed to parse per core cpu usage: {0}")]
    ParsePerCore(ParseIntError),
}

impl StatsProvider for CpuAcct {
    type Error = V1CpuAcctStatsError;
    type Stats = CpuUsage;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, V1CpuAcctStatsError> {
        let mut stats = CpuUsage::default();
        Self::get_total_cpu_usage(cgroup_path, &mut stats)?;
        Self::get_per_core_usage(cgroup_path, &mut stats)?;

        Ok(stats)
    }
}

impl CpuAcct {
    fn get_total_cpu_usage(
        cgroup_path: &Path,
        stats: &mut CpuUsage,
    ) -> Result<(), V1CpuAcctStatsError> {
        let stat_file_path = cgroup_path.join(CGROUP_CPUACCT_STAT);
        let stat_table = parse_flat_keyed_data(&stat_file_path)?;

        macro_rules! get {
            ($name: expr => $field: ident) => {
                stats.$field =
                    *stat_table
                        .get($name)
                        .ok_or_else(|| V1CpuAcctStatsError::MissingField {
                            field: $name,
                            path: stat_file_path.clone(),
                        })?;
            };
        }

        get!("user" => usage_user);
        get!("system" => usage_kernel);

        let total = common::read_cgroup_file(cgroup_path.join(CGROUP_CPUACCT_USAGE))?;
        stats.usage_total = total
            .trim()
            .parse()
            .map_err(V1CpuAcctStatsError::ParseTotalCpu)?;

        Ok(())
    }

    fn get_per_core_usage(
        cgroup_path: &Path,
        stats: &mut CpuUsage,
    ) -> Result<(), V1CpuAcctStatsError> {
        let path = cgroup_path.join(CGROUP_CPUACCT_USAGE_ALL);
        let all_content = common::read_cgroup_file(&path)?;
        // first line is header, skip it
        for entry in all_content.lines().skip(1) {
            let entry_parts: Vec<&str> = entry.split_ascii_whitespace().collect();
            if entry_parts.len() != 3 {
                continue;
            }

            stats
                .per_core_usage_user
                .push(entry_parts[1].parse().map_err(|err| {
                    V1CpuAcctStatsError::FailedToParseField {
                        mode: "user",
                        path: path.clone(),
                        err,
                    }
                })?);
            stats
                .per_core_usage_kernel
                .push(entry_parts[2].parse().map_err(|err| {
                    V1CpuAcctStatsError::FailedToParseField {
                        mode: "kernel",
                        path: path.clone(),
                        err,
                    }
                })?);
        }

        let percpu_content = common::read_cgroup_file(cgroup_path.join(CGROUP_CPUACCT_PERCPU))?;
        stats.per_core_usage_total = percpu_content
            .split_ascii_whitespace()
            .map(|v| v.parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(V1CpuAcctStatsError::ParsePerCore)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use nix::unistd::Pid;
    use tempfile::TempDir;

    use super::*;
    use crate::common::CGROUP_PROCS;
    use crate::test::{set_fixture, setup};

    fn setup_total_cpu(stat_content: &str, usage_content: &str) -> TempDir {
        let tmp = tempfile::tempdir().unwrap();

        let _ = set_fixture(tmp.path(), CGROUP_CPUACCT_STAT, stat_content)
            .unwrap_or_else(|_| panic!("create {CGROUP_CPUACCT_STAT} file"));
        let _ = set_fixture(tmp.path(), CGROUP_CPUACCT_USAGE, usage_content)
            .unwrap_or_else(|_| panic!("create {CGROUP_CPUACCT_USAGE} file"));

        tmp
    }

    fn setup_per_core(percpu_content: &str, usage_all_content: &str) -> TempDir {
        let tmp = tempfile::tempdir().unwrap();

        let _ = set_fixture(tmp.path(), CGROUP_CPUACCT_PERCPU, percpu_content)
            .unwrap_or_else(|_| panic!("create {CGROUP_CPUACCT_PERCPU} file"));
        let _ = set_fixture(tmp.path(), CGROUP_CPUACCT_USAGE_ALL, usage_all_content)
            .unwrap_or_else(|_| panic!("create {CGROUP_CPUACCT_USAGE_ALL} file"));

        tmp
    }

    #[test]
    fn test_add_task() {
        let (tmp, procs) = setup(CGROUP_PROCS);
        let pid = Pid::from_raw(1000);

        CpuAcct::add_task(pid, tmp.path()).expect("apply cpuacct");

        let content = fs::read_to_string(procs)
            .unwrap_or_else(|_| panic!("read {CGROUP_PROCS} file content"));
        assert_eq!(content, "1000");
    }

    #[test]
    fn test_stat_total_cpu_usage() {
        let stat_content = &["user 1300888", "system 364592"].join("\n");
        let usage_content = "18198092369681";
        let tmp = setup_total_cpu(stat_content, usage_content);

        let mut stats = CpuUsage::default();
        CpuAcct::get_total_cpu_usage(tmp.path(), &mut stats).expect("get cgroup stats");

        assert_eq!(stats.usage_user, 1300888);
        assert_eq!(stats.usage_kernel, 364592);
        assert_eq!(stats.usage_total, 18198092369681);
    }

    #[test]
    fn test_stat_per_cpu_usage() {
        let percpu_content = "989683000640 4409567860144 4439880333849 4273328034121";
        let usage_all_content = &[
            "cpu user system",
            "0 5838999815217 295316023007",
            "1 4139072325517 325194619244",
            "2 4175712075766 323435639997",
            "3 4021385867300 304269989810",
        ]
        .join("\n");
        let tmp = setup_per_core(percpu_content, usage_all_content);

        let mut stats = CpuUsage::default();
        CpuAcct::get_per_core_usage(tmp.path(), &mut stats).expect("get cgroup stats");

        assert_eq!(
            stats.per_core_usage_user,
            [5838999815217, 4139072325517, 4175712075766, 4021385867300]
        );

        assert_eq!(
            stats.per_core_usage_kernel,
            [295316023007, 325194619244, 323435639997, 304269989810]
        );

        assert_eq!(
            stats.per_core_usage_total,
            [989683000640, 4409567860144, 4439880333849, 4273328034121]
        );
    }
}
