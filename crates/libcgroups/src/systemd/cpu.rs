use std::collections::HashMap;

use oci_spec::runtime::LinuxCpu;

use super::controller::Controller;
use super::dbus_native::serialize::Variant;
use crate::common::ControllerOpt;

pub const CPU_WEIGHT: &str = "CPUWeight";
pub const CPU_QUOTA: &str = "CPUQuotaPerSecUSec";
pub const CPU_PERIOD: &str = "CPUQuotaPeriodUSec";
const MICROSECS_PER_SEC: u64 = 1_000_000;

#[derive(thiserror::Error, Debug)]
pub enum SystemdCpuError {
    #[error("realtime is not supported on systemd v2 yet")]
    RealtimeSystemd,
}

pub(crate) struct Cpu {}

impl Controller for Cpu {
    type Error = SystemdCpuError;

    fn apply(
        options: &ControllerOpt,
        _: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), Self::Error> {
        if let Some(cpu) = options.resources.cpu() {
            tracing::debug!("Applying cpu resource restrictions");
            Self::apply(cpu, properties)?;
        }

        Ok(())
    }
}

impl Cpu {
    fn apply(
        cpu: &LinuxCpu,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), SystemdCpuError> {
        if Self::is_realtime_requested(cpu) {
            let runtime = cpu.realtime_runtime().unwrap_or(0);
            let period = cpu.realtime_period().unwrap_or(0);

            if runtime > 0 || period > 0 {
                return Err(SystemdCpuError::RealtimeSystemd);
            }
        }

        if let Some(mut shares) = cpu.shares() {
            shares = convert_shares_to_cgroup2(shares);
            if shares != 0 {
                properties.insert(CPU_WEIGHT, Variant::U64(shares));
            }
        }

        // if quota is unrestricted set to 'max'
        let mut quota = u64::MAX;
        if let Some(specified_quota) = cpu.quota() {
            if specified_quota > 0 {
                let period = cpu.period().unwrap_or(100_000);

                // cpu quota in systemd must be specified as number of
                // microseconds per second of cpu time.
                quota = specified_quota as u64 * MICROSECS_PER_SEC / period;
            }
        }
        properties.insert(CPU_QUOTA, Variant::U64(quota));

        let mut period: u64 = 100_000;
        if let Some(specified_period) = cpu.period() {
            if specified_period > 0 {
                period = specified_period;
            }
        }
        properties.insert(CPU_PERIOD, Variant::U64(period));

        Ok(())
    }

    fn is_realtime_requested(cpu: &LinuxCpu) -> bool {
        cpu.realtime_period().is_some() || cpu.realtime_runtime().is_some()
    }
}

pub fn convert_shares_to_cgroup2(shares: u64) -> u64 {
    if shares == 0 {
        return 0;
    }

    const MIN_SHARES: u64 = 2;
    const MAX_SHARES: u64 = 262_144;
    const MAX_WEIGHT: u64 = 10_000;

    if shares <= MIN_SHARES {
        return 1;
    }

    if shares >= MAX_SHARES {
        return MAX_WEIGHT;
    }

    let log_shares = (shares as f64).log2();
    let exponent = (log_shares * log_shares + 125.0 * log_shares) / 612.0 - 7.0 / 34.0;

    (10f64.powf(exponent)).ceil() as u64
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};
    use oci_spec::runtime::LinuxCpuBuilder;

    use super::super::dbus_native::serialize::DbusSerialize;
    use super::*;
    use crate::recast;

    #[test]
    fn test_set_shares() -> Result<()> {
        // arrange
        let cpu = LinuxCpuBuilder::default()
            .shares(22000u64)
            .build()
            .context("build cpu spec")?;
        let mut properties: HashMap<&str, Variant> = HashMap::new();

        // act
        Cpu::apply(&cpu, &mut properties)?;

        // assert
        assert!(properties.contains_key(CPU_WEIGHT));

        let cpu_weight = &properties[CPU_WEIGHT];
        let val = recast!(cpu_weight, Variant)?;
        assert_eq!(val, Variant::U64(1204));

        Ok(())
    }

    #[test]
    fn test_set_quota() -> Result<()> {
        let quotas: Vec<(i64, u64)> = vec![(200_000, 2_000_000), (0, u64::MAX), (-50000, u64::MAX)];

        for quota in quotas {
            // arrange
            let cpu = LinuxCpuBuilder::default().quota(quota.0).build().unwrap();
            let mut properties: HashMap<&str, Variant> = HashMap::new();

            // act
            Cpu::apply(&cpu, &mut properties)?;

            // assert
            assert!(properties.contains_key(CPU_QUOTA));
            let cpu_quota = &properties[CPU_QUOTA];
            let val = recast!(cpu_quota, Variant)?;
            assert_eq!(val, Variant::U64(quota.1));
        }

        Ok(())
    }

    #[test]
    fn test_set_period() -> Result<()> {
        let periods: Vec<(u64, u64)> = vec![(200_000, 200_000), (0, 100_000)];

        for period in periods {
            let cpu = LinuxCpuBuilder::default()
                .period(period.0)
                .build()
                .context("build cpu spec")?;
            let mut properties: HashMap<&str, Variant> = HashMap::new();

            // act
            Cpu::apply(&cpu, &mut properties)?;

            // assert
            assert!(properties.contains_key(CPU_PERIOD));
            let cpu_quota = &properties[CPU_PERIOD];
            let val = recast!(cpu_quota, Variant)?;
            assert_eq!(val, Variant::U64(period.1));
        }

        Ok(())
    }
}
