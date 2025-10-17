use std::borrow::Cow;
use std::path::{Path, PathBuf};

use oci_spec::runtime::LinuxCpu;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{self, CpuStats, ParseFlatKeyedDataError, StatsProvider};

const CGROUP_CPU_WEIGHT: &str = "cpu.weight";
const CGROUP_CPU_MAX: &str = "cpu.max";
const CGROUP_CPU_BURST: &str = "cpu.max.burst";
const CGROUP_CPU_IDLE: &str = "cpu.idle";
const UNRESTRICTED_QUOTA: &str = "max";
const MAX_CPU_WEIGHT: u64 = 10000;

const CPU_STAT: &str = "cpu.stat";
const CPU_PSI: &str = "cpu.pressure";

#[derive(thiserror::Error, Debug)]
pub enum V2CpuControllerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("realtime is not supported on v2 yet")]
    RealtimeV2,
}

pub struct Cpu {}

impl Controller for Cpu {
    type Error = V2CpuControllerError;

    fn apply(controller_opt: &ControllerOpt, path: &Path) -> Result<(), Self::Error> {
        if let Some(cpu) = &controller_opt.resources.cpu() {
            Self::apply(path, cpu)?;
        }

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum V2CpuStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("while parsing stat table: {0}")]
    ParseNestedKeyedData(#[from] ParseFlatKeyedDataError),
    #[error("missing field {field} from {path}")]
    MissingField { field: &'static str, path: PathBuf },
}

impl StatsProvider for Cpu {
    type Error = V2CpuStatsError;
    type Stats = CpuStats;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        let mut stats = CpuStats::default();
        let stats_path = cgroup_path.join(CPU_STAT);

        let stats_table = stats::parse_flat_keyed_data(&stats_path)?;

        macro_rules! get {
            ($name: expr => $field1:ident.$field2:ident) => {
                stats.$field1.$field2 =
                    *stats_table
                        .get($name)
                        .ok_or_else(|| V2CpuStatsError::MissingField {
                            field: $name,
                            path: stats_path.clone(),
                        })?;
            };
        }

        get!("usage_usec" => usage.usage_total);
        get!("user_usec" => usage.usage_user);
        get!("system_usec" => usage.usage_kernel);
        get!("nr_periods" => throttling.periods);
        get!("nr_throttled" => throttling.throttled_periods);
        get!("throttled_usec" => throttling.throttled_time);

        stats.psi = stats::psi_stats(&cgroup_path.join(CPU_PSI))?;
        Ok(stats)
    }
}

impl Cpu {
    fn apply(path: &Path, cpu: &LinuxCpu) -> Result<(), V2CpuControllerError> {
        if Self::is_realtime_requested(cpu) {
            let runtime = cpu.realtime_runtime().unwrap_or(0);
            let period = cpu.realtime_period().unwrap_or(0);

            if runtime > 0 || period > 0 {
                return Err(V2CpuControllerError::RealtimeV2);
            }
        }

        if let Some(mut shares) = cpu.shares() {
            shares = Self::convert_shares_to_cgroup2(shares);
            if shares != 0 {
                // will result in Erno 34 (numerical result out of range) otherwise
                common::write_cgroup_file(path.join(CGROUP_CPU_WEIGHT), shares)?;
            }
        }

        let cpu_max_file = path.join(CGROUP_CPU_MAX);
        let new_cpu_max: Option<Cow<str>> = match (cpu.quota(), cpu.period()) {
            (None, Some(period)) => Self::create_period_only_value(&cpu_max_file, period)?,
            (Some(quota), None) if quota > 0 => Some(quota.to_string().into()),
            (Some(quota), None) if quota <= 0 => Some(UNRESTRICTED_QUOTA.into()),
            (Some(quota), Some(period)) if quota > 0 => Some(format!("{quota} {period}").into()),
            (Some(quota), Some(period)) if quota <= 0 => {
                Some(format!("{UNRESTRICTED_QUOTA} {period}").into())
            }
            _ => None,
        };

        // format is 'quota period'
        // the kernel default is 'max 100000'
        // 250000 250000 -> 1 CPU worth of runtime every 250ms
        // 10000 50000 -> 20% of one CPU every 50ms
        if let Some(cpu_max) = new_cpu_max {
            common::write_cgroup_file_str(&cpu_max_file, &cpu_max)?;
        }

        if let Some(burst) = cpu.burst() {
            common::write_cgroup_file(path.join(CGROUP_CPU_BURST), burst)?;
        }

        if let Some(idle) = cpu.idle() {
            common::write_cgroup_file(path.join(CGROUP_CPU_IDLE), idle)?;
        }

        Ok(())
    }

    fn convert_shares_to_cgroup2(shares: u64) -> u64 {
        if shares == 0 {
            return 0;
        }

        const MIN_SHARES: u64 = 2;
        const MAX_SHARES: u64 = 262_144;

        if shares <= MIN_SHARES {
            return 1;
        }

        if shares >= MAX_SHARES {
            return MAX_CPU_WEIGHT;
        }

        let log_shares = (shares as f64).log2();
        let exponent = (log_shares * log_shares + 125.0 * log_shares) / 612.0 - 7.0 / 34.0;
        let weight = (10f64.powf(exponent)).ceil() as u64;

        weight.clamp(1, MAX_CPU_WEIGHT)
    }

    fn is_realtime_requested(cpu: &LinuxCpu) -> bool {
        if cpu.realtime_period().is_some() {
            return true;
        }

        if cpu.realtime_runtime().is_some() {
            return true;
        }

        false
    }

    fn create_period_only_value(
        cpu_max_file: &Path,
        period: u64,
    ) -> Result<Option<Cow<'_, str>>, V2CpuControllerError> {
        let old_cpu_max = common::read_cgroup_file(cpu_max_file)?;
        if let Some(old_quota) = old_cpu_max.split_whitespace().next() {
            return Ok(Some(format!("{old_quota} {period}").into()));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use oci_spec::runtime::LinuxCpuBuilder;

    use super::*;
    use crate::stats::{CpuThrottling, CpuUsage};
    use crate::test::{set_fixture, setup};

    #[test]
    fn test_set_valid_shares() {
        // arrange
        let (tmp, weight) = setup(CGROUP_CPU_WEIGHT);
        let _ = set_fixture(tmp.path(), CGROUP_CPU_MAX, "")
            .unwrap_or_else(|_| panic!("set test fixture for {CGROUP_CPU_MAX}"));
        let cpu = LinuxCpuBuilder::default().shares(22000u64).build().unwrap();

        // act
        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        // assert
        let content = fs::read_to_string(weight)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPU_WEIGHT} file content"));
        assert_eq!(content, 1204.to_string());
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
        assert_eq!(content, format!("{IDLE}"))
    }

    #[test]
    fn test_set_positive_quota() {
        // arrange
        const QUOTA: i64 = 200000;
        let (tmp, max) = setup(CGROUP_CPU_MAX);
        let cpu = LinuxCpuBuilder::default().quota(QUOTA).build().unwrap();

        // act
        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        // assert
        let content = fs::read_to_string(max)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPU_MAX} file content"));
        assert_eq!(content, format!("{QUOTA}"))
    }

    #[test]
    fn test_set_negative_quota() {
        // arrange
        let (tmp, max) = setup(CGROUP_CPU_MAX);
        let cpu = LinuxCpuBuilder::default().quota(-500).build().unwrap();

        // act
        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        // assert
        let content = fs::read_to_string(max)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPU_MAX} file content"));
        assert_eq!(content, UNRESTRICTED_QUOTA)
    }

    #[test]
    fn test_set_positive_period() {
        // arrange
        const QUOTA: u64 = 50000;
        const PERIOD: u64 = 100000;
        let (tmp, max) = setup(CGROUP_CPU_MAX);
        common::write_cgroup_file(&max, QUOTA).unwrap();
        let cpu = LinuxCpuBuilder::default().period(PERIOD).build().unwrap();

        // act
        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        // assert
        let content = fs::read_to_string(max)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPU_MAX} file content"));
        assert_eq!(content, format!("{QUOTA} {PERIOD}"))
    }

    #[test]
    fn test_set_quota_and_period() {
        // arrange
        const QUOTA: i64 = 200000;
        const PERIOD: u64 = 100000;
        let (tmp, max) = setup(CGROUP_CPU_MAX);
        let cpu = LinuxCpuBuilder::default()
            .quota(QUOTA)
            .period(PERIOD)
            .build()
            .unwrap();

        // act
        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        // assert
        let content = fs::read_to_string(max)
            .unwrap_or_else(|_| panic!("read {CGROUP_CPU_MAX} file content"));
        assert_eq!(content, format!("{QUOTA} {PERIOD}"));
    }

    #[test]
    fn test_realtime_runtime_not_supported() {
        // arrange
        let tmp = tempfile::tempdir().unwrap();
        let cpu = LinuxCpuBuilder::default()
            .realtime_runtime(5)
            .build()
            .unwrap();

        // act
        let result = Cpu::apply(tmp.path(), &cpu);

        // assert
        assert!(
            result.is_err(),
            "realtime runtime is not supported and should return an error"
        );
    }

    #[test]
    fn test_realtime_period_not_supported() {
        // arrange
        let tmp = tempfile::tempdir().unwrap();
        let cpu = LinuxCpuBuilder::default()
            .realtime_period(5u64)
            .build()
            .unwrap();

        // act
        let result = Cpu::apply(tmp.path(), &cpu);

        // assert
        assert!(
            result.is_err(),
            "realtime period is not supported and should return an error"
        );
    }

    #[test]
    fn test_stat_usage() {
        let tmp = tempfile::tempdir().unwrap();
        let content = [
            "usage_usec 7730",
            "user_usec 4387",
            "system_usec 3498",
            "nr_periods 400",
            "nr_throttled 20",
            "throttled_usec 5000",
        ]
        .join("\n");
        set_fixture(tmp.path(), CPU_STAT, &content).expect("create stat file");
        set_fixture(tmp.path(), CPU_PSI, "").expect("create psi file");

        let actual = Cpu::stats(tmp.path()).expect("get cgroup stats");
        let expected = CpuStats {
            usage: CpuUsage {
                usage_total: 7730,
                usage_user: 4387,
                usage_kernel: 3498,
                ..Default::default()
            },
            throttling: CpuThrottling {
                periods: 400,
                throttled_periods: 20,
                throttled_time: 5000,
            },
            ..Default::default()
        };

        assert_eq!(actual.usage, expected.usage);
        assert_eq!(actual.throttling, expected.throttling);
    }

    #[test]
    fn test_burst() {
        let expected = 100000u64;
        let (tmp, burst_file) = setup(CGROUP_CPU_BURST);
        let cpu = LinuxCpuBuilder::default().burst(expected).build().unwrap();

        Cpu::apply(tmp.path(), &cpu).expect("apply cpu");

        let actual = fs::read_to_string(burst_file).expect("read burst file");
        assert_eq!(actual, expected.to_string());
    }

    #[test]
    fn test_cgroupsv2_but_runtime_set_to_zero() {
        // arrange
        let tmp = tempfile::tempdir().unwrap();
        let cpu = LinuxCpuBuilder::default()
            .realtime_runtime(0i64)
            .build()
            .unwrap();

        // act
        let result = Cpu::apply(tmp.path(), &cpu);

        // assert
        assert!(result.is_ok())
    }

    #[test]
    fn test_cgroupsv2_but_period_set_to_zero() {
        // arrange
        let tmp = tempfile::tempdir().unwrap();
        let cpu = LinuxCpuBuilder::default()
            .realtime_period(0u64)
            .build()
            .unwrap();

        // act
        let result = Cpu::apply(tmp.path(), &cpu);

        // assert
        assert!(result.is_ok())
    }

    #[test]
    fn test_cgroupsv2_but_period_and_runtime_set_to_zero() {
        // arrange
        let tmp = tempfile::tempdir().unwrap();
        let cpu = LinuxCpuBuilder::default()
            .realtime_period(0u64)
            .realtime_runtime(0i64)
            .build()
            .unwrap();

        // act
        let result = Cpu::apply(tmp.path(), &cpu);

        // assert
        assert!(result.is_ok())
    }
}
