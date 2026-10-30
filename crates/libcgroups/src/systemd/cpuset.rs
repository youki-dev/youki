use std::collections::HashMap;

use fixedbitset::FixedBitSet;
use oci_spec::runtime::LinuxCpu;

use super::controller::Controller;
use super::dbus_native::serialize::Variant;
use crate::common::ControllerOpt;

pub const ALLOWED_CPUS: &str = "AllowedCPUs";
pub const ALLOWED_NODES: &str = "AllowedMemoryNodes";

#[derive(thiserror::Error, Debug)]
pub enum SystemdCpuSetError {
    #[error("setting cpuset restrictions requires systemd version greater than 243")]
    OldSystemd,
    #[error("could not create bitmask for cpus: {0}")]
    CpusBitmask(BitmaskError),
    #[error("could not create bitmask for memory nodes: {0}")]
    MemoryNodesBitmask(BitmaskError),
}

pub struct CpuSet {}

impl Controller for CpuSet {
    type Error = SystemdCpuSetError;

    fn apply(
        options: &ControllerOpt,
        systemd_version: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), Self::Error> {
        if let Some(cpu) = options.resources.cpu() {
            tracing::debug!("Applying cpuset resource restrictions");
            return Self::apply(cpu, systemd_version, properties);
        }

        Ok(())
    }
}

impl CpuSet {
    fn apply(
        cpu: &LinuxCpu,
        systemd_version: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), SystemdCpuSetError> {
        if systemd_version <= 243 {
            return Err(SystemdCpuSetError::OldSystemd);
        }

        if let Some(cpus) = cpu.cpus() {
            let cpu_mask: Vec<_> = to_bitmask(cpus)
                .map_err(SystemdCpuSetError::CpusBitmask)?
                .into_iter()
                .map(|v| v as u64)
                .collect();
            properties.insert(ALLOWED_CPUS, Variant::ArrayU64(cpu_mask));
        }

        if let Some(mems) = cpu.mems() {
            let mems_mask: Vec<_> = to_bitmask(mems)
                .map_err(SystemdCpuSetError::MemoryNodesBitmask)?
                .into_iter()
                .map(|v| v as u64)
                .collect();
            properties.insert(ALLOWED_NODES, Variant::ArrayU64(mems_mask));
        }

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BitmaskError {
    #[error("invalid index {index}: {err}")]
    InvalidIndex {
        err: std::num::ParseIntError,
        index: String,
    },
    #[error("invalid cpu range {0}")]
    InvalidRange(String),
}

pub fn to_bitmask(range: &str) -> Result<Vec<u8>, BitmaskError> {
    let mut bitset = FixedBitSet::with_capacity(8);

    for cpu_set in range.split_terminator(',') {
        let cpu_set = cpu_set.trim();
        if cpu_set.is_empty() {
            continue;
        }

        let cpus: Vec<&str> = cpu_set.split('-').map(|s| s.trim()).collect();
        if cpus.len() == 1 {
            let cpu_index: usize = cpus[0].parse().map_err(|err| BitmaskError::InvalidIndex {
                err,
                index: cpus[0].into(),
            })?;
            if cpu_index >= bitset.len() {
                bitset.grow(
                    cpu_index
                        .checked_add(1)
                        .ok_or_else(|| BitmaskError::InvalidRange(cpu_set.into()))?,
                );
            }
            bitset.set(cpu_index, true);
        } else {
            let start_index = cpus[0].parse().map_err(|err| BitmaskError::InvalidIndex {
                err,
                index: cpus[0].into(),
            })?;
            let end_index: usize = cpus[1].parse().map_err(|err| BitmaskError::InvalidIndex {
                err,
                index: cpus[1].into(),
            })?;
            if start_index > end_index {
                return Err(BitmaskError::InvalidRange(cpu_set.into()));
            }

            let end = end_index
                .checked_add(1)
                .ok_or_else(|| BitmaskError::InvalidRange(cpu_set.into()))?;
            if end_index >= bitset.len() {
                bitset.grow(end);
            }
            bitset.set_range(start_index..end, true);
        }
    }

    // Keep the controller representation compact and big-endian.
    // The D-Bus client converts it to systemd's little-endian byte array.
    Ok(bitset
        .as_slice()
        .iter()
        .rev()
        .flat_map(|b| b.to_be_bytes())
        .skip_while(|b| *b == 0u8)
        .collect())
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};
    use oci_spec::runtime::LinuxCpuBuilder;

    use super::super::dbus_native::serialize::DbusSerialize;
    use super::*;
    use crate::recast;

    #[test]
    fn to_bitmask_single_value() -> Result<()> {
        let cpus = "0"; // 0000 0001

        let bitmask = to_bitmask(cpus).context("to bitmask")?;

        assert_eq!(bitmask.len(), 1);
        assert_eq!(bitmask[0], 1);
        Ok(())
    }

    #[test]
    fn to_bitmask_sparse_single_values() -> Result<()> {
        assert_eq!(to_bitmask("16")?, vec![1, 0, 0]);
        assert_eq!(to_bitmask("64")?, vec![1, 0, 0, 0, 0, 0, 0, 0, 0]);
        Ok(())
    }

    #[test]
    fn to_bitmask_across_words() -> Result<()> {
        assert_eq!(to_bitmask("0,64-65")?, vec![3, 0, 0, 0, 0, 0, 0, 0, 1]);
        Ok(())
    }

    #[test]
    fn to_bitmask_overflowing_single_value() {
        assert!(to_bitmask(&usize::MAX.to_string()).is_err());
    }

    #[test]
    fn to_bitmask_overflowing_range() {
        assert!(to_bitmask(&format!("0-{}", usize::MAX)).is_err());
    }

    #[test]
    fn to_bitmask_multiple_single_values() -> Result<()> {
        let cpus = "0,1,2"; // 0000 0111

        let bitmask = to_bitmask(cpus).context("to bitmask")?;

        assert_eq!(bitmask.len(), 1);
        assert_eq!(bitmask[0], 7);
        Ok(())
    }

    #[test]
    fn to_bitmask_range_value() -> Result<()> {
        let cpus = "0-2"; // 0000 0111

        let bitmask = to_bitmask(cpus).context("to bitmask")?;

        assert_eq!(bitmask.len(), 1);
        assert_eq!(bitmask[0], 7);
        Ok(())
    }

    #[test]
    fn to_bitmask_interchanged_range() -> Result<()> {
        let cpus = "2-0";

        let result = to_bitmask(cpus).context("to bitmask");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn to_bitmask_incomplete_range() -> Result<()> {
        let cpus = vec!["2-", "-2"];

        for c in cpus {
            let result = to_bitmask(c).context("to bitmask");
            assert!(result.is_err());
        }

        Ok(())
    }

    #[test]
    fn to_bitmask_mixed() -> Result<()> {
        let cpus = "0,2-4,7,9-10"; // 0000 0110 1001 1101

        let bitmask = to_bitmask(cpus).context("to bitmask")?;

        assert_eq!(bitmask.len(), 2);
        assert_eq!(bitmask[0], 6);
        assert_eq!(bitmask[1], 157);
        Ok(())
    }

    #[test]
    fn to_bitmask_extra_characters() -> Result<()> {
        let cpus = "0, 2- 4,,7   ,,9-10"; // 0000 0110 1001 1101

        let bitmask = to_bitmask(cpus).context("to bitmask")?;
        assert_eq!(bitmask.len(), 2);
        assert_eq!(bitmask[0], 6);
        assert_eq!(bitmask[1], 157);

        Ok(())
    }

    #[test]
    fn test_cpuset_systemd_too_old() -> Result<()> {
        let systemd_version = 235;
        let cpu = LinuxCpuBuilder::default()
            .build()
            .context("build cpu spec")?;
        let mut properties: HashMap<&str, Variant> = HashMap::new();

        let result = CpuSet::apply(&cpu, systemd_version, &mut properties);

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_cpuset_set() -> Result<()> {
        let systemd_version = 245;
        let cpu = LinuxCpuBuilder::default()
            .cpus("0-3")
            .mems("0-3")
            .build()
            .context("build cpu spec")?;
        let mut properties: HashMap<&str, Variant> = HashMap::new();

        CpuSet::apply(&cpu, systemd_version, &mut properties).context("apply cpuset")?;

        assert_eq!(properties.len(), 2);
        assert!(properties.contains_key(ALLOWED_CPUS));
        let cpus = properties.get(ALLOWED_CPUS).unwrap();
        let v = recast!(cpus, Variant)?;
        assert!(matches!(v, Variant::ArrayU64(_)));

        assert!(properties.contains_key(ALLOWED_NODES));
        let mems = properties.get(ALLOWED_NODES).unwrap();
        let v = recast!(mems, Variant)?;
        assert!(matches!(v, Variant::ArrayU64(_)));

        Ok(())
    }
}
