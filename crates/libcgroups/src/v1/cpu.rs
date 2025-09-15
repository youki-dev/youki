use std::path::{Path, PathBuf};

use oci_spec::runtime::LinuxCpu;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{CpuThrottling, ParseFlatKeyedDataError, StatsProvider, parse_flat_keyed_data};

const CGROUP_CPU_SHARES: &str = "cpu.shares";
const CGROUP_CPU_QUOTA: &str = "cpu.cfs_quota_us";
const CGROUP_CPU_PERIOD: &str = "cpu.cfs_period_us";
const CGROUP_CPU_BURST: &str = "cpu.cfs_burst_us";
const CGROUP_CPU_RT_RUNTIME: &str = "cpu.rt_runtime_us";
const CGROUP_CPU_RT_PERIOD: &str = "cpu.rt_period_us";
const CGROUP_CPU_STAT: &str = "cpu.stat";
const CGROUP_CPU_IDLE: &str = "cpu.idle";

pub struct Cpu {}

impl Controller for Cpu {
    type Error = WrappedIoError;
    type Resource = LinuxCpu;

    fn apply(controller_opt: &ControllerOpt, cgroup_root: &Path) -> Result<(), Self::Error> {
        tracing::debug!("Apply Cpu cgroup config");

        if let Some(cpu) = Self::needs_to_handle(controller_opt) {
            Self::apply(cgroup_root, cpu)?;
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        if let Some(cpu) = &controller_opt.resources.cpu() {
            if cpu.shares().is_some()
                || cpu.period().is_some()
                || cpu.quota().is_some()
                || cpu.realtime_period().is_some()
                || cpu.realtime_runtime().is_some()
                || cpu.idle().is_some()
            {
                return Some(cpu);
            }
        }

        None
    }
}

#[derive(thiserror::Error, Debug)]
pub enum V1CpuStatsError {
    #[error("error parsing data: {0}")]
    ParseData(#[from] ParseFlatKeyedDataError),
    #[error("missing field {field} from {path}")]
    MissingField { field: &'static str, path: PathBuf },
}

impl StatsProvider for Cpu {
    type Error = V1CpuStatsError;
    type Stats = CpuThrottling;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        let mut stats = CpuThrottling::default();
        let stat_path = cgroup_path.join(CGROUP_CPU_STAT);

        let stat_table = parse_flat_keyed_data(&stat_path)?;

        macro_rules! get {
            ($name: expr => $field: ident) => {
                stats.$field =
                    *stat_table
                        .get($name)
                        .ok_or_else(|| V1CpuStatsError::MissingField {
                            field: $name,
                            path: stat_path.clone(),
                        })?;
            };
        }

        get!("nr_periods" => periods);
        get!("nr_throttled" => throttled_periods);
        get!("throttled_time" => throttled_time);

        Ok(stats)
    }
}

impl Cpu {
    fn apply(root_path: &Path, cpu: &LinuxCpu) -> Result<(), WrappedIoError> {
        if let Some(cpu_shares) = cpu.shares() {
            if cpu_shares != 0 {
                common::write_cgroup_file(root_path.join(CGROUP_CPU_SHARES), cpu_shares)?;
            }
        }

        if let Some(cpu_period) = cpu.period() {
            if cpu_period != 0 {
                common::write_cgroup_file(root_path.join(CGROUP_CPU_PERIOD), cpu_period)?;
            }
        }

        if let Some(cpu_quota) = cpu.quota() {
            if cpu_quota != 0 {
                common::write_cgroup_file(root_path.join(CGROUP_CPU_QUOTA), cpu_quota)?;
            }
        }

        if let Some(cpu_burst) = cpu.burst() {
            common::write_cgroup_file(root_path.join(CGROUP_CPU_BURST), cpu_burst)?;
        }

        if let Some(rt_runtime) = cpu.realtime_runtime() {
            if rt_runtime != 0 {
                common::write_cgroup_file(root_path.join(CGROUP_CPU_RT_RUNTIME), rt_runtime)?;
            }
        }

        if let Some(rt_period) = cpu.realtime_period() {
            if rt_period != 0 {
                common::write_cgroup_file(root_path.join(CGROUP_CPU_RT_PERIOD), rt_period)?;
            }
        }

        if let Some(idle) = cpu.idle() {
            common::write_cgroup_file(root_path.join(CGROUP_CPU_IDLE), idle)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use oci_spec::runtime::LinuxCpuBuilder;

    use super::*;
    use crate::test::{set_fixture, setup};

    #[test]
    fn test_set_shares() {
        // arrange
        let (tmp, shares) = setup(CGROUP_CPU_SHARES);
        let _ = set_fixture(tmp.path(), CGROUP_CPU_SHARES, "")
            .unwrap_or_else(|_| panic!("set test fixture for {CGROUP_CPU_SHARES}"));
        let cpu = LinuxCpuBuilder::default().shares(2048u64).build().unwrap();

        // act
        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        // assert
        let content = fs::read_to_string(shares)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPU_SHARES} file content"));
        assert_eq!(content, 2048.to_string());
    }

    #[test]
    fn test_set_quota() {
        // arrange
        const QUOTA: i64 = 200000;
        let (tmp, max) = setup(CGROUP_CPU_QUOTA);
        let cpu = LinuxCpuBuilder::default().quota(QUOTA).build().unwrap();

        // act
        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        // assert
        let content = fs::read_to_string(max)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPU_QUOTA} file content"));
        assert_eq!(content, QUOTA.to_string());
    }

    #[test]
    fn test_set_period() {
        // arrange
        const PERIOD: u64 = 100000;
        let (tmp, max) = setup(CGROUP_CPU_PERIOD);
        let cpu = LinuxCpuBuilder::default().period(PERIOD).build().unwrap();

        // act
        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        // assert
        let content = fs::read_to_string(max)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPU_PERIOD} file content"));
        assert_eq!(content, PERIOD.to_string());
    }

    #[test]
    fn test_set_rt_runtime() {
        // arrange
        const RUNTIME: i64 = 100000;
        let (tmp, max) = setup(CGROUP_CPU_RT_RUNTIME);
        let cpu = LinuxCpuBuilder::default()
            .realtime_runtime(RUNTIME)
            .build()
            .unwrap();

        // act
        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        // assert
        let content = fs::read_to_string(max)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPU_RT_RUNTIME} file content"));
        assert_eq!(content, RUNTIME.to_string());
    }

    #[test]
    fn test_set_cpu_idle() {
        // arrange
        const IDLE: i64 = 1;
        const CPU: &str = "cpu";

        if !Path::new(common::DEFAULT_CGROUP_ROOT)
            .join(CPU)
            .join(CGROUP_CPU_IDLE)
            .exists()
        {
            // skip test_set_cpu_idle due to not found cpu.idle, maybe due to old kernel version
            return;
        }

        let (tmp, max) = setup(CGROUP_CPU_IDLE);
        let cpu = LinuxCpuBuilder::default().idle(IDLE).build().unwrap();

        // act
        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        // assert
        let content = fs::read_to_string(max)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPU_IDLE} file content"));
        assert_eq!(content, IDLE.to_string());
    }

    #[test]
    fn test_set_rt_period() {
        // arrange
        const PERIOD: u64 = 100000;
        let (tmp, max) = setup(CGROUP_CPU_RT_PERIOD);
        let cpu = LinuxCpuBuilder::default()
            .realtime_period(PERIOD)
            .build()
            .unwrap();

        // act
        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        // assert
        let content = fs::read_to_string(max)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPU_RT_PERIOD} file content"));
        assert_eq!(content, PERIOD.to_string());
    }

    #[test]
    fn test_stat_cpu_throttling() {
        let tmp = tempfile::tempdir().unwrap();
        let stat_content = &[
            "nr_periods 165000",
            "nr_throttled 27",
            "throttled_time 1080",
        ]
        .join("\n");
        set_fixture(tmp.path(), CGROUP_CPU_STAT, stat_content).expect("create stat file");

        let actual = Cpu::stats(tmp.path()).expect("get cgroup stats");
        let expected = CpuThrottling {
            periods: 165000,
            throttled_periods: 27,
            throttled_time: 1080,
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_set_burst() {
        // arrange
        let expected_burst: u64 = 100_000;
        let (tmp, max) = setup(CGROUP_CPU_BURST);
        let cpu = LinuxCpuBuilder::default()
            .burst(expected_burst)
            .build()
            .unwrap();

        // act
        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        // assert
        let actual_burst = fs::read_to_string(max).expect("read burst");
        assert_eq!(actual_burst, expected_burst.to_string());
    }
}
