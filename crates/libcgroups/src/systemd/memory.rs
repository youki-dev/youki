use std::collections::HashMap;

use oci_spec::runtime::LinuxMemory;

use super::controller::Controller;
use super::dbus_native::serialize::Variant;
use crate::common::ControllerOpt;

pub const MEMORY_MIN: &str = "MemoryMin";
pub const MEMORY_LOW: &str = "MemoryLow";
pub const MEMORY_HIGH: &str = "MemoryHigh";
pub const MEMORY_MAX: &str = "MemoryMax";
pub const MEMORY_SWAP: &str = "MemorySwapMax";

#[derive(thiserror::Error, Debug)]
pub enum SystemdMemoryError {
    #[error("invalid memory reservation value: {0}")]
    ReservationValue(i64),
    #[error("invalid memory limit value: {0}")]
    MemoryLimit(i64),
    #[error("cgroup v2 swap value cannot be calculated from swap of {swap} and limit of {limit}")]
    SwapValue { swap: i64, limit: String },
}

pub struct Memory {}

impl Controller for Memory {
    type Error = SystemdMemoryError;

    fn apply(
        options: &ControllerOpt,
        _: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), Self::Error> {
        if let Some(memory) = options.resources.memory() {
            tracing::debug!("applying memory resource restrictions");
            return Self::apply(memory, properties);
        }

        Ok(())
    }
}

impl Memory {
    fn apply(
        memory: &LinuxMemory,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), SystemdMemoryError> {
        if let Some(reservation) = memory.reservation() {
            match reservation {
                1..=i64::MAX => {
                    properties.insert(MEMORY_LOW, Variant::U64(reservation as u64));
                }
                -1 => {
                    properties.insert(MEMORY_LOW, Variant::U64(u64::MAX));
                }
                _ => return Err(SystemdMemoryError::ReservationValue(reservation)),
            }
        }

        if let Some(limit) = memory.limit() {
            match limit {
                1..=i64::MAX => {
                    properties.insert(MEMORY_MAX, Variant::U64(limit as u64));
                }
                -1 => {
                    properties.insert(MEMORY_MAX, Variant::U64(u64::MAX));
                }
                _ => return Err(SystemdMemoryError::MemoryLimit(limit)),
            }
        }

        Self::apply_swap(memory.swap(), memory.limit(), properties)?;
        Ok(())
    }

    // Swap needs to be converted as the runtime spec defines swap as the total of memory + swap,
    // which corresponds to memory.memsw.limit_in_bytes in cgroup v1. In v2 however swap is a
    // separate value (memory.swap.max). Therefore swap needs to be calculated from memory limit
    // and swap. Specified values could be None (no value specified), -1 (unlimited), zero or a
    // positive value. Swap needs to be bigger than the memory limit (due to swap being memory + swap)
    fn apply_swap(
        swap: Option<i64>,
        limit: Option<i64>,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), SystemdMemoryError> {
        let value: Variant = match (limit, swap) {
            // memory is unlimited and swap not specified -> assume swap unlimited
            (Some(-1), None) => Variant::U64(u64::MAX),
            // if swap is unlimited it can be set to unlimited regardless of memory limit value
            (_, Some(-1)) => Variant::U64(u64::MAX),
            // if swap is zero, then it needs to be rejected regardless of memory limit value
            // as memory limit would be either bigger (invariant violation) or zero which would
            // leave the container with no memory and no swap.
            // if swap is greater than zero and memory limit is unspecified swap cannot be
            // calculated. If memory limit is zero the container would have only swap. If
            // memory is unlimited it would be bigger than swap.
            (_, Some(0)) | (None | Some(0) | Some(-1), Some(1..=i64::MAX)) => {
                return Err(SystemdMemoryError::SwapValue {
                    swap: swap.unwrap(),
                    limit: limit.map_or("none".to_owned(), |v| v.to_string()),
                });
            }

            (Some(l), Some(s)) if l < s => Variant::U64((s - l) as u64),
            _ => return Ok(()),
        };

        properties.insert(MEMORY_SWAP, value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};
    use oci_spec::runtime::LinuxMemoryBuilder;

    use super::super::dbus_native::serialize::DbusSerialize;
    use super::*;
    use crate::recast;

    #[test]
    fn test_set_valid_memory_low() -> Result<()> {
        let values = vec![(536870912, 536870912u64), (-1, u64::MAX)];

        for (reservation, expected) in values {
            // arrange
            let memory = LinuxMemoryBuilder::default()
                .reservation(reservation)
                .build()
                .context("build memory spec")?;
            let mut properties: HashMap<&str, Variant> = HashMap::new();

            // act
            Memory::apply(&memory, &mut properties).context("apply memory")?;

            // assert
            assert_eq!(properties.len(), 1);
            assert!(properties.contains_key(MEMORY_LOW));
            let memory_low = &properties[MEMORY_LOW];
            let val = recast!(memory_low, Variant)?;
            assert_eq!(val, Variant::U64(expected));
        }

        Ok(())
    }

    #[test]
    fn test_set_valid_memory_max() -> Result<()> {
        let values = vec![(536870912, 536870912u64, 1), (-1, u64::MAX, 2)];

        for (reservation, mem_low, prop_count) in values {
            // arrange
            let memory = LinuxMemoryBuilder::default()
                .limit(reservation)
                .build()
                .context("build memory spec")?;
            let mut properties: HashMap<&str, Variant> = HashMap::new();

            // act
            Memory::apply(&memory, &mut properties).context("apply memory")?;

            // assert
            assert_eq!(properties.len(), prop_count);
            assert!(properties.contains_key(MEMORY_MAX));
            let actual = &properties[MEMORY_MAX];
            let val = recast!(actual, Variant)?;
            assert_eq!(val, Variant::U64(mem_low));
        }

        Ok(())
    }
}
