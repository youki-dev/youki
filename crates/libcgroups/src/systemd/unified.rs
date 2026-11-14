use std::collections::HashMap;
use std::num::ParseIntError;

use super::controller::Controller;
use super::cpuset::{self, BitmaskError, to_bitmask};
use super::dbus_native::serialize::Variant;
use super::{cpu, memory, pids};
use crate::common::ControllerOpt;

// The systemd version each property first appeared in, as in runc.
const CPU_WEIGHT_IDLE_MIN_VERSION: u32 = 252;
const MEMORY_ZSWAP_MAX_MIN_VERSION: u32 = 253;
const MEMORY_ZSWAP_WRITEBACK_MIN_VERSION: u32 = 256;

#[derive(thiserror::Error, Debug)]
pub enum SystemdUnifiedError {
    #[error("failed to parse cpu weight {value}: {err}")]
    CpuWeight { err: ParseIntError, value: String },
    #[error("invalid format for cpu.max: {0}")]
    CpuMax(String),
    #[error("failed to to parse cpu quota {value}: {err}")]
    CpuQuota { err: ParseIntError, value: String },
    #[error("failed to to parse cpu period {value}: {err}")]
    CpuPeriod { err: ParseIntError, value: String },
    #[error("cpu period must not be 0: {0}")]
    CpuPeriodZero(String),
    #[error("setting {0} requires systemd version greater than 243")]
    OldSystemd(String),
    #[error("invalid value for cpuset.cpus {0}")]
    CpuSetCpu(BitmaskError),
    #[error("failed to parse {name} {value}: {err}")]
    Memory {
        err: ParseIntError,
        name: String,
        value: String,
    },
    #[error("invalid value for memory.zswap.writeback, expected 0 or 1: {0}")]
    MemoryZswapWriteback(String),
    #[error("failed to to parse pids.max {value}: {err}")]
    PidsMax { err: ParseIntError, value: String },
    #[error("unified resource {filename} must be a file name (no slashes)")]
    InvalidFilename { filename: String },
    #[error("unified resource {filename} must be in the form CONTROLLER.PARAMETER")]
    InvalidFormat { filename: String },
}

pub struct Unified {}

impl Controller for Unified {
    type Error = SystemdUnifiedError;

    fn apply(
        options: &ControllerOpt,
        systemd_version: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), Self::Error> {
        if let Some(unified) = options.resources.unified() {
            tracing::debug!("applying unified resource restrictions");
            Self::apply(unified, systemd_version, properties)?;
        }

        Ok(())
    }
}

impl Unified {
    fn apply(
        unified: &HashMap<String, String>,
        systemd_version: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), SystemdUnifiedError> {
        // systemd has no property for cpu.idle itself; a CPUWeight of 0 makes it set cpu.idle
        // to 1. There is no value that sets it to 0, so only 1 is sent.
        let cpu_idle = systemd_version >= CPU_WEIGHT_IDLE_MIN_VERSION
            && unified
                .get("cpu.idle")
                .is_some_and(|idle| idle.trim() == "1");

        for (key, value) in unified {
            if key.contains('/') {
                return Err(SystemdUnifiedError::InvalidFilename {
                    filename: key.into(),
                });
            }
            if !key.contains('.') || key.starts_with('.') {
                return Err(SystemdUnifiedError::InvalidFormat {
                    filename: key.into(),
                });
            }
            match key.as_str() {
                "cpu.idle" => {
                    if cpu_idle {
                        properties.insert(cpu::CPU_WEIGHT, Variant::U64(0));
                    }
                }
                "cpu.weight" => {
                    if cpu_idle {
                        // both keys map to CPUWeight, and cpu.idle takes it
                        tracing::warn!(
                            "cannot apply both cpu.weight and cpu.idle to systemd, ignoring cpu.weight"
                        );
                        continue;
                    }

                    // already a cgroup v2 weight, unlike the cgroup v1 shares in resources.cpu
                    let weight =
                        value
                            .parse::<u64>()
                            .map_err(|err| SystemdUnifiedError::CpuWeight {
                                err,
                                value: value.into(),
                            })?;
                    properties.insert(cpu::CPU_WEIGHT, Variant::U64(weight));
                }
                "cpu.max" => {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.is_empty() || parts.len() > 2 {
                        return Err(SystemdUnifiedError::CpuMax(value.into()));
                    }

                    let mut period = 100_000;
                    if parts.len() == 2 {
                        period = parts[1].parse::<u64>().map_err(|err| {
                            SystemdUnifiedError::CpuPeriod {
                                err,
                                value: parts[1].into(),
                            }
                        })?;
                        if period == 0 {
                            return Err(SystemdUnifiedError::CpuPeriodZero(value.into()));
                        }
                        properties.insert(cpu::CPU_PERIOD, Variant::U64(period));
                    }

                    // systemd takes the quota as microseconds per second of cpu time
                    let quota = match parts[0] {
                        "max" => u64::MAX,
                        quota => {
                            quota
                                .parse::<u64>()
                                .map_err(|err| SystemdUnifiedError::CpuQuota {
                                    err,
                                    value: quota.into(),
                                })?
                                .saturating_mul(cpu::MICROSECS_PER_SEC)
                                / period
                        }
                    };
                    properties.insert(cpu::CPU_QUOTA, Variant::U64(quota));
                }
                cpuset @ ("cpuset.cpus" | "cpuset.mems") => {
                    if systemd_version <= 243 {
                        return Err(SystemdUnifiedError::OldSystemd(cpuset.into()));
                    }

                    let bitmask: Vec<u64> = to_bitmask(value)
                        .map_err(SystemdUnifiedError::CpuSetCpu)?
                        .into_iter()
                        .map(|v| v as u64)
                        .collect();

                    let systemd_cpuset = match cpuset {
                        "cpuset.cpus" => cpuset::ALLOWED_CPUS,
                        "cpuset.mems" => cpuset::ALLOWED_NODES,
                        file_name => unreachable!("{} was not matched", file_name),
                    };

                    properties.insert(systemd_cpuset, Variant::ArrayU64(bitmask));
                }
                memory @ ("memory.min" | "memory.low" | "memory.high" | "memory.max"
                | "memory.swap.max" | "memory.zswap.max") => {
                    if memory == "memory.zswap.max"
                        && systemd_version < MEMORY_ZSWAP_MAX_MIN_VERSION
                    {
                        tracing::debug!(
                            "systemd {systemd_version} does not support {}",
                            memory::MEMORY_ZSWAP_MAX
                        );
                        continue;
                    }

                    let value = match value.as_str() {
                        "max" => u64::MAX,
                        value => {
                            value
                                .parse::<u64>()
                                .map_err(|err| SystemdUnifiedError::Memory {
                                    err,
                                    name: memory.into(),
                                    value: value.into(),
                                })?
                        }
                    };
                    let systemd_memory = match memory {
                        "memory.min" => memory::MEMORY_MIN,
                        "memory.low" => memory::MEMORY_LOW,
                        "memory.high" => memory::MEMORY_HIGH,
                        "memory.max" => memory::MEMORY_MAX,
                        "memory.swap.max" => memory::MEMORY_SWAP,
                        "memory.zswap.max" => memory::MEMORY_ZSWAP_MAX,
                        file_name => unreachable!("{} was not matched", file_name),
                    };
                    properties.insert(systemd_memory, Variant::U64(value));
                }
                "memory.zswap.writeback" => {
                    let writeback = match value.trim() {
                        "0" => false,
                        "1" => true,
                        _ => return Err(SystemdUnifiedError::MemoryZswapWriteback(value.into())),
                    };
                    if systemd_version < MEMORY_ZSWAP_WRITEBACK_MIN_VERSION {
                        tracing::debug!(
                            "systemd {systemd_version} does not support {}",
                            memory::MEMORY_ZSWAP_WRITEBACK
                        );
                        continue;
                    }
                    properties.insert(memory::MEMORY_ZSWAP_WRITEBACK, Variant::Bool(writeback));
                }
                "pids.max" => {
                    let pids =
                        match value.trim() {
                            "max" => u64::MAX,
                            value => value.parse::<i64>().map_err(|err| {
                                SystemdUnifiedError::PidsMax {
                                    err,
                                    value: value.into(),
                                }
                            })? as u64,
                        };
                    properties.insert(pids::TASKS_MAX, Variant::U64(pids));
                }

                // the systemd manager writes every unified key to cgroupfs after setting the
                // properties, so a key with no property still takes effect
                unknown => tracing::debug!("no systemd property for {}", unknown),
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};

    use super::super::dbus_native::serialize::DbusSerialize;
    use super::*;
    use crate::recast;

    #[test]
    fn test_set() -> Result<()> {
        // arrange
        let unified: HashMap<String, String> = [
            ("cpu.weight", "42"),
            ("cpuset.cpus", "0-3"),
            ("cpuset.mems", "0-3"),
            ("memory.min", "100000"),
            ("memory.low", "200000"),
            ("memory.high", "300000"),
            ("memory.max", "400000"),
            ("pids.max", "100"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

        let mut expected: HashMap<&str, Variant> = HashMap::new();
        expected.insert(cpu::CPU_WEIGHT, Variant::U64(42));
        expected.insert(cpuset::ALLOWED_CPUS, Variant::ArrayU64(vec![15u64]));
        expected.insert(cpuset::ALLOWED_NODES, Variant::ArrayU64(vec![15u64]));
        expected.insert(memory::MEMORY_MIN, Variant::U64(100000u64));
        expected.insert(memory::MEMORY_LOW, Variant::U64(200000u64));
        expected.insert(memory::MEMORY_HIGH, Variant::U64(300000u64));
        expected.insert(memory::MEMORY_MAX, Variant::U64(400000u64));
        expected.insert(pids::TASKS_MAX, Variant::U64(100u64));

        // act
        let mut actual: HashMap<&str, Variant> = HashMap::new();
        Unified::apply(&unified, 245, &mut actual).context("apply unified")?;

        // assert
        for (setting, value) in expected {
            assert!(actual.contains_key(setting));
            let mut value_buf = Vec::new();
            let mut actual_buf = Vec::new();
            value.serialize(&mut value_buf);
            actual[setting].serialize(&mut actual_buf);
            assert_eq!(value_buf, actual_buf, "{setting}");
        }

        Ok(())
    }

    #[test]
    fn test_cpu_max_quota_and_period() -> Result<()> {
        // arrange
        let unified: HashMap<String, String> = [("cpu.max", "500000 250000")]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let mut actual: HashMap<&str, Variant> = HashMap::new();

        // act
        Unified::apply(&unified, 245, &mut actual).context("apply unified")?;

        // assert
        assert!(actual.contains_key(cpu::CPU_PERIOD));
        assert!(actual.contains_key(cpu::CPU_QUOTA));

        let cpu_period = &actual[cpu::CPU_PERIOD];
        let cpu_quota = &actual[cpu::CPU_QUOTA];
        assert_eq!(recast!(cpu_period, Variant)?, Variant::U64(250000));
        assert_eq!(recast!(cpu_quota, Variant)?, Variant::U64(2_000_000));

        Ok(())
    }

    #[test]
    fn test_cpu_max_quota_only() -> Result<()> {
        // arrange
        let unified: HashMap<String, String> = [("cpu.max", "500000")]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let mut actual: HashMap<&str, Variant> = HashMap::new();

        // act
        Unified::apply(&unified, 245, &mut actual).context("apply unified")?;

        // assert
        assert!(!actual.contains_key(cpu::CPU_PERIOD));
        assert!(actual.contains_key(cpu::CPU_QUOTA));

        let cpu_quota = &actual[cpu::CPU_QUOTA];
        assert_eq!(recast!(cpu_quota, Variant)?, Variant::U64(5_000_000));

        Ok(())
    }

    #[test]
    fn test_max_values() -> Result<()> {
        // arrange
        let unified: HashMap<String, String> = [
            ("cpu.max", "max 100000"),
            ("memory.min", "max"),
            ("memory.low", "max"),
            ("memory.high", "max"),
            ("memory.max", "max"),
            ("pids.max", "max"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let mut actual: HashMap<&str, Variant> = HashMap::new();

        // act
        Unified::apply(&unified, 245, &mut actual).context("apply unified")?;

        // assert
        for setting in [
            cpu::CPU_QUOTA,
            memory::MEMORY_MIN,
            memory::MEMORY_LOW,
            memory::MEMORY_HIGH,
            memory::MEMORY_MAX,
            pids::TASKS_MAX,
        ] {
            let value = &actual[setting];
            assert_eq!(
                recast!(value, Variant)?,
                Variant::U64(u64::MAX),
                "{setting}"
            );
        }
        let cpu_period = &actual[cpu::CPU_PERIOD];
        assert_eq!(recast!(cpu_period, Variant)?, Variant::U64(100_000));

        Ok(())
    }

    #[test]
    fn test_cpu_max_zero_period_returns_error() {
        // arrange
        let unified: HashMap<String, String> = [("cpu.max", "50000 0")]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let mut actual: HashMap<&str, Variant> = HashMap::new();

        // act
        let result = Unified::apply(&unified, 245, &mut actual);

        // assert
        assert!(matches!(result, Err(SystemdUnifiedError::CpuPeriodZero(_))));
    }

    fn unified_map(values: &[(&str, &str)]) -> HashMap<String, String> {
        values
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_memory_swap_max() -> Result<()> {
        for (value, expected) in [("104857600", 104_857_600), ("max", u64::MAX)] {
            // arrange
            let unified = unified_map(&[("memory.swap.max", value)]);
            let mut actual: HashMap<&str, Variant> = HashMap::new();

            // act
            Unified::apply(&unified, 245, &mut actual).context("apply unified")?;

            // assert
            let swap = &actual[memory::MEMORY_SWAP];
            assert_eq!(recast!(swap, Variant)?, Variant::U64(expected), "{value}");
        }

        Ok(())
    }

    #[test]
    fn test_memory_zswap_max() -> Result<()> {
        for (value, expected) in [("52428800", 52_428_800), ("max", u64::MAX)] {
            // arrange
            let unified = unified_map(&[("memory.zswap.max", value)]);
            let mut actual: HashMap<&str, Variant> = HashMap::new();

            // act
            Unified::apply(&unified, MEMORY_ZSWAP_MAX_MIN_VERSION, &mut actual)
                .context("apply unified")?;

            // assert
            let zswap = &actual[memory::MEMORY_ZSWAP_MAX];
            assert_eq!(recast!(zswap, Variant)?, Variant::U64(expected), "{value}");
        }

        Ok(())
    }

    #[test]
    fn test_memory_zswap_max_needs_systemd_253() -> Result<()> {
        // arrange
        let unified = unified_map(&[("memory.zswap.max", "52428800")]);
        let mut actual: HashMap<&str, Variant> = HashMap::new();

        // act
        Unified::apply(&unified, MEMORY_ZSWAP_MAX_MIN_VERSION - 1, &mut actual)
            .context("apply unified")?;

        // assert
        assert!(actual.is_empty());
        Ok(())
    }

    #[test]
    fn test_memory_zswap_writeback() -> Result<()> {
        for (value, expected) in [("0", false), ("1", true)] {
            // arrange
            let unified = unified_map(&[("memory.zswap.writeback", value)]);
            let mut actual: HashMap<&str, Variant> = HashMap::new();

            // act
            Unified::apply(&unified, MEMORY_ZSWAP_WRITEBACK_MIN_VERSION, &mut actual)
                .context("apply unified")?;

            // assert
            let writeback = &actual[memory::MEMORY_ZSWAP_WRITEBACK];
            assert_eq!(
                recast!(writeback, Variant)?,
                Variant::Bool(expected),
                "{value}"
            );
        }

        Ok(())
    }

    #[test]
    fn test_memory_zswap_writeback_needs_systemd_256() -> Result<()> {
        // arrange
        let unified = unified_map(&[("memory.zswap.writeback", "0")]);
        let mut actual: HashMap<&str, Variant> = HashMap::new();

        // act
        Unified::apply(
            &unified,
            MEMORY_ZSWAP_WRITEBACK_MIN_VERSION - 1,
            &mut actual,
        )
        .context("apply unified")?;

        // assert
        assert!(actual.is_empty());
        Ok(())
    }

    #[test]
    fn test_memory_zswap_writeback_invalid_value_returns_error() {
        // arrange
        let unified = unified_map(&[("memory.zswap.writeback", "2")]);
        let mut actual: HashMap<&str, Variant> = HashMap::new();

        // act
        let result = Unified::apply(&unified, MEMORY_ZSWAP_WRITEBACK_MIN_VERSION, &mut actual);

        // assert
        assert!(matches!(
            result,
            Err(SystemdUnifiedError::MemoryZswapWriteback(_))
        ));
    }

    #[test]
    fn test_cpu_idle_sets_cpu_weight_to_zero() -> Result<()> {
        // arrange: with or without cpu.weight, which maps to the same property
        for unified in [
            unified_map(&[("cpu.idle", "1")]),
            unified_map(&[("cpu.idle", "1"), ("cpu.weight", "42")]),
        ] {
            let mut actual: HashMap<&str, Variant> = HashMap::new();

            // act
            Unified::apply(&unified, CPU_WEIGHT_IDLE_MIN_VERSION, &mut actual)
                .context("apply unified")?;

            // assert
            let weight = &actual[cpu::CPU_WEIGHT];
            assert_eq!(recast!(weight, Variant)?, Variant::U64(0), "{unified:?}");
        }

        Ok(())
    }

    #[test]
    fn test_cpu_idle_without_property_keeps_cpu_weight() -> Result<()> {
        // arrange: cpu.idle 0 has no property, and neither has cpu.idle 1 before systemd 252
        for (idle, systemd_version) in [
            ("0", CPU_WEIGHT_IDLE_MIN_VERSION),
            ("1", CPU_WEIGHT_IDLE_MIN_VERSION - 1),
        ] {
            let unified = unified_map(&[("cpu.idle", idle), ("cpu.weight", "42")]);
            let mut actual: HashMap<&str, Variant> = HashMap::new();

            // act
            Unified::apply(&unified, systemd_version, &mut actual).context("apply unified")?;

            // assert
            let weight = &actual[cpu::CPU_WEIGHT];
            assert_eq!(
                recast!(weight, Variant)?,
                Variant::U64(42),
                "cpu.idle {idle} on systemd {systemd_version}"
            );
        }

        Ok(())
    }

    #[test]
    fn test_key_without_property_is_skipped() -> Result<()> {
        // arrange: these are written to cgroupfs by the manager, not set as properties
        let unified: HashMap<String, String> = [
            ("io.max", "259:0 riops=333 wiops=444"),
            ("memory.oom.group", "1"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let mut actual: HashMap<&str, Variant> = HashMap::new();

        // act
        Unified::apply(&unified, 245, &mut actual).context("apply unified")?;

        // assert
        assert!(actual.is_empty());
        Ok(())
    }

    #[test]
    fn test_key_with_slash_returns_error() {
        let unified: HashMap<String, String> = [("/memory/max", "100000")]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let mut actual: HashMap<&str, Variant> = HashMap::new();

        let result = Unified::apply(&unified, 245, &mut actual);

        assert!(matches!(
            result,
            Err(SystemdUnifiedError::InvalidFilename { .. })
        ));
        assert!(actual.is_empty());
    }

    #[test]
    fn test_key_without_dot_returns_error() {
        // arrange
        let unified: HashMap<String, String> = [("foo", "100000")]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let mut actual: HashMap<&str, Variant> = HashMap::new();

        // act
        let result = Unified::apply(&unified, 245, &mut actual);

        // assert
        assert!(matches!(
            result,
            Err(SystemdUnifiedError::InvalidFormat { .. })
        ));
        assert!(actual.is_empty());
    }

    #[test]
    fn test_key_starting_with_dot_returns_error() {
        // arrange
        let unified: HashMap<String, String> = [(".max", "100000")]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let mut actual: HashMap<&str, Variant> = HashMap::new();

        // act
        let result = Unified::apply(&unified, 245, &mut actual);

        // assert
        assert!(matches!(
            result,
            Err(SystemdUnifiedError::InvalidFormat { .. })
        ));
        assert!(actual.is_empty());
    }
}
