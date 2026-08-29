use std::collections::HashMap;
use std::path::Path;

use oci_spec::runtime::{LinuxCpu, LinuxResources};

use super::controller::Controller;
use super::dbus_native::serialize::Variant;
use crate::common::{self, ControllerOpt, WrappedIoError};

pub const CPU_WEIGHT: &str = "CPUWeight";
pub const CPU_QUOTA: &str = "CPUQuotaPerSecUSec";
pub const CPU_PERIOD: &str = "CPUQuotaPeriodUSec";
const MICROSECS_PER_SEC: u64 = 1_000_000;

#[derive(thiserror::Error, Debug)]
pub enum SystemdCpuError {
    #[error("realtime is not supported on systemd v2 yet")]
    RealtimeSystemd,
    #[error(transparent)]
    Io(#[from] WrappedIoError),
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

    // systemd re-realizes the unit on any property change, so a side the caller
    // left out has to be carried over from the current cpu.max to survive.
    pub(super) fn resolve_pair(
        resources: &LinuxResources,
        full_path: &Path,
    ) -> Result<LinuxResources, SystemdCpuError> {
        let mut resolved = resources.clone();
        if let Some(cpu) = resolved.cpu_mut() {
            if cpu.quota().is_none() || cpu.period().is_none() {
                let (current_quota, current_period) = Self::read_current_cpu_max(full_path)?;
                if cpu.quota().is_none() {
                    cpu.set_quota(Some(current_quota));
                }
                if cpu.period().is_none() {
                    cpu.set_period(Some(current_period));
                }
            }
        }
        Ok(resolved)
    }

    // Returns the kernel defaults when cpu.max is absent, which is the case on
    // the first apply at container creation.
    fn read_current_cpu_max(full_path: &Path) -> Result<(i64, u64), SystemdCpuError> {
        let content = match common::read_cgroup_file(full_path.join("cpu.max")) {
            Ok(content) => content,
            Err(WrappedIoError::Read { err, .. }) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok((-1, 100_000));
            }
            Err(err) => return Err(err.into()),
        };

        // "max" parses as an error, which is the unlimited quota we want.
        let mut parts = content.split_whitespace();
        let quota = parts.next().and_then(|q| q.parse().ok()).unwrap_or(-1);
        let period = parts.next().and_then(|p| p.parse().ok()).unwrap_or(100_000);

        Ok((quota, period))
    }
}

// Convert CPU shares (cgroup v1) into CPU weight (cgroup v2).
// cgroup v1 shares span [2, 262_144] with a default of 1_024.
// cgroup v2 weight spans [1, 10_000] with a default of 100.
// A shares value of 0 keeps the field unset.
// The quadratic fit matches runc's mapping and preserves the defaults.
// For reference, see:
// https://github.com/opencontainers/runc/releases/tag/v1.3.2
// https://github.com/opencontainers/cgroups/pull/20
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
    use oci_spec::runtime::{LinuxCpuBuilder, LinuxResourcesBuilder};

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

    #[test]
    fn resolve_pair_fills_in_the_side_the_caller_left_out() -> Result<()> {
        // (cpu.max, requested quota, requested period, expected pair)
        let cases = [
            (None, Some(70000i64), None, (70000i64, 100_000u64)),
            (Some("50000 200000"), Some(70000), None, (70000, 200000)),
            (Some("50000 200000"), None, Some(300000u64), (50000, 300000)),
            (Some("max 100000"), None, Some(200000), (-1, 200000)),
            (Some("50000 200000"), None, None, (50000, 200000)),
            (None, Some(70000), Some(150000), (70000, 150000)),
        ];

        for (cpu_max, quota, period, expected) in cases {
            let tmp = tempfile::tempdir().context("create temp dir")?;
            if let Some(cpu_max) = cpu_max {
                crate::test::set_fixture(tmp.path(), "cpu.max", cpu_max)
                    .context("set cpu.max fixture")?;
            }

            let mut builder = LinuxCpuBuilder::default();
            if let Some(quota) = quota {
                builder = builder.quota(quota);
            }
            if let Some(period) = period {
                builder = builder.period(period);
            }
            let resources = LinuxResourcesBuilder::default()
                .cpu(builder.build().context("build cpu spec")?)
                .build()
                .context("build resources")?;

            let resolved = Cpu::resolve_pair(&resources, tmp.path())?;
            let cpu = resolved.cpu().as_ref().unwrap();
            assert_eq!((cpu.quota().unwrap(), cpu.period().unwrap()), expected);
        }

        Ok(())
    }

    #[test]
    fn resolve_pair_leaves_resources_without_cpu_untouched() -> Result<()> {
        // the path is never read, since there is no cpu section to resolve.
        let resources = LinuxResourcesBuilder::default()
            .build()
            .context("build resources")?;

        let resolved = Cpu::resolve_pair(&resources, Path::new("/does/not/exist"))?;
        assert!(resolved.cpu().is_none());

        Ok(())
    }
}
