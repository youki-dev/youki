use std::collections::HashMap;
use std::num::ParseIntError;

use super::controller::Controller;
use super::cpu::{self, convert_shares_to_cgroup2};
use super::cpuset::{self, BitmaskError, to_bitmask};
use super::dbus_native::serialize::Variant;
use super::{memory, pids};
use crate::common::ControllerOpt;

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
    #[error("failed to to parse pids.max {value}: {err}")]
    PidsMax { err: ParseIntError, value: String },
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
        for (key, value) in unified {
            match key.as_str() {
                "cpu.weight" => {
                    let shares =
                        value
                            .parse::<u64>()
                            .map_err(|err| SystemdUnifiedError::CpuWeight {
                                err,
                                value: value.into(),
                            })?;
                    properties.insert(
                        cpu::CPU_WEIGHT,
                        Variant::U64(convert_shares_to_cgroup2(shares)),
                    );
                }
                "cpu.max" => {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.is_empty() || parts.len() > 2 {
                        return Err(SystemdUnifiedError::CpuMax(value.into()));
                    }

                    let quota =
                        parts[0]
                            .parse::<u64>()
                            .map_err(|err| SystemdUnifiedError::CpuQuota {
                                err,
                                value: parts[0].into(),
                            })?;
                    properties.insert(cpu::CPU_QUOTA, Variant::U64(quota));

                    if parts.len() == 2 {
                        let period = parts[1].parse::<u64>().map_err(|err| {
                            SystemdUnifiedError::CpuPeriod {
                                err,
                                value: parts[1].into(),
                            }
                        })?;
                        properties.insert(cpu::CPU_PERIOD, Variant::U64(period));
                    }
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
                memory @ ("memory.min" | "memory.low" | "memory.high" | "memory.max") => {
                    let value =
                        value
                            .parse::<u64>()
                            .map_err(|err| SystemdUnifiedError::Memory {
                                err,
                                name: memory.into(),
                                value: value.into(),
                            })?;
                    let systemd_memory = match memory {
                        "memory.min" => memory::MEMORY_MIN,
                        "memory.low" => memory::MEMORY_LOW,
                        "memory.high" => memory::MEMORY_HIGH,
                        "memory.max" => memory::MEMORY_MAX,
                        file_name => unreachable!("{} was not matched", file_name),
                    };
                    properties.insert(systemd_memory, Variant::U64(value));
                }
                "pids.max" => {
                    let pids = value.trim().parse::<i64>().map_err(|err| {
                        SystemdUnifiedError::PidsMax {
                            err,
                            value: value.into(),
                        }
                    })?;
                    properties.insert(pids::TASKS_MAX, Variant::U64(pids as u64));
                }

                unknown => tracing::warn!("could not apply {}. Unknown property.", unknown),
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
            ("cpu.weight", "22000"),
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
        expected.insert(cpu::CPU_WEIGHT, Variant::U64(1204));
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
        assert_eq!(recast!(cpu_quota, Variant)?, Variant::U64(500000));

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
        assert_eq!(recast!(cpu_quota, Variant)?, Variant::U64(500000));

        Ok(())
    }
}
