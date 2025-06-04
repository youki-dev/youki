use std::path::Path;

use oci_spec::runtime::LinuxMemory;

use crate::{
    common::{self, ControllerOpt, WrappedIoError},
    stats::{self, MemoryData, MemoryStats, ParseFlatKeyedDataError, StatsProvider},
};

use super::controller::Controller;

const CGROUP_MEMORY_SWAP: &str = "memory.swap.max";
const CGROUP_MEMORY_MAX: &str = "memory.max";
const CGROUP_MEMORY_LOW: &str = "memory.low";
const MEMORY_STAT: &str = "memory.stat";
const MEMORY_PSI: &str = "memory.pressure";

#[derive(thiserror::Error, Debug)]
pub enum V2MemoryControllerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("invalid memory value {0}")]
    MemoryValue(i64),
    #[error("invalid swap value {0}")]
    SwapValue(i64),
    #[error("swap memory ({swap}) should be bigger than memory limit ({limit})")]
    SwapTooSmall { swap: i64, limit: i64 },
    #[error("unable to set swap limit without memory limit")]
    SwapWithoutLimit,
    #[error("invalid memory reservation value: {0}")]
    MemoryReservation(i64),
}

pub struct Memory {}

impl Controller for Memory {
    type Error = V2MemoryControllerError;

    fn apply(controller_opt: &ControllerOpt, cgroup_path: &Path) -> Result<(), Self::Error> {
        if let Some(memory) = &controller_opt.resources.memory() {
            Self::apply(cgroup_path, memory)?;
        }

        Ok(())
    }
}
#[derive(thiserror::Error, Debug)]
pub enum V2MemoryStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("while parsing stat table: {0}")]
    ParseNestedKeyedData(#[from] ParseFlatKeyedDataError),
}

impl StatsProvider for Memory {
    type Error = V2MemoryStatsError;
    type Stats = MemoryStats;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        let stats = MemoryStats {
            memory: Self::get_memory_data(cgroup_path, "memory", "oom")?,
            memswap: Self::get_memory_data(cgroup_path, "memory.swap", "fail")?,
            hierarchy: true,
            stats: stats::parse_flat_keyed_data(&cgroup_path.join(MEMORY_STAT))?,
            psi: stats::psi_stats(&cgroup_path.join(MEMORY_PSI))?,
            ..Default::default()
        };

        Ok(stats)
    }
}

impl Memory {
    fn get_memory_data(
        cgroup_path: &Path,
        file_prefix: &str,
        fail_event: &str,
    ) -> Result<MemoryData, V2MemoryStatsError> {
        let usage =
            stats::parse_single_value(&cgroup_path.join(format!("{}.{}", file_prefix, "current")))?;
        let limit =
            stats::parse_single_value(&cgroup_path.join(format!("{}.{}", file_prefix, "max")))?;

        let events = stats::parse_flat_keyed_data(
            &cgroup_path.join(format!("{}.{}", file_prefix, "events")),
        )?;
        let fail_count = if let Some((_, v)) = events.get_key_value(fail_event) {
            *v
        } else {
            Default::default()
        };

        Ok(MemoryData {
            usage,
            fail_count,
            limit,
            ..Default::default()
        })
    }

    fn set<P: AsRef<Path>>(path: P, val: i64) -> Result<(), WrappedIoError> {
        if val == 0 {
            Ok(())
        } else if val == -1 {
            Ok(common::write_cgroup_file_str(path, "max")?)
        } else {
            Ok(common::write_cgroup_file(path, val)?)
        }
    }

    fn apply(path: &Path, memory: &LinuxMemory) -> Result<(), V2MemoryControllerError> {
        // if nothing is set just exit right away
        if memory.reservation().is_none() && memory.limit().is_none() && memory.swap().is_none() {
            return Ok(());
        }
        // TODO(YJDoc2) check memory before setting new values
        // specifically used for update command 

        match memory.limit() {
            Some(limit) if limit < -1 => {
                return Err(V2MemoryControllerError::MemoryValue(limit));
            }
            Some(limit) => match memory.swap() {
                Some(swap) if swap < -1 => {
                    return Err(V2MemoryControllerError::SwapValue(swap));
                }
                Some(swap) => {
                    // -1 means max
                    if swap == -1 || limit == -1 {
                        Memory::set(path.join(CGROUP_MEMORY_SWAP), swap)?;
                    } else {
                        if swap < limit {
                            return Err(V2MemoryControllerError::SwapTooSmall { swap, limit });
                        }

                        // In cgroup v1 swap is memory+swap, but in cgroup v2 swap is
                        // a separate value, so the swap value in the runtime spec needs
                        // to be converted from the cgroup v1 value to the cgroup v2 value
                        // by subtracting limit from swap
                        Memory::set(path.join(CGROUP_MEMORY_SWAP), swap - limit)?;
                    }
                    Memory::set(path.join(CGROUP_MEMORY_MAX), limit)?;
                }
                None => {
                    if limit == -1 {
                        Memory::set(path.join(CGROUP_MEMORY_SWAP), -1)?;
                    }
                    Memory::set(path.join(CGROUP_MEMORY_MAX), limit)?;
                }
            },
            None => {
                if memory.swap().is_some() {
                    return Err(V2MemoryControllerError::SwapWithoutLimit);
                }
            }
        };

        if let Some(reservation) = memory.reservation() {
            if reservation < -1 {
                return Err(V2MemoryControllerError::MemoryReservation(reservation));
            }
            Memory::set(path.join(CGROUP_MEMORY_LOW), reservation)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::set_fixture;
    use oci_spec::runtime::LinuxMemoryBuilder;
    use std::fs::read_to_string;

    #[test]
    fn test_set_memory() {
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), CGROUP_MEMORY_MAX, "0").expect("set fixture for memory limit");
        set_fixture(tmp.path(), CGROUP_MEMORY_LOW, "0")
            .expect("set fixture for memory reservation");
        set_fixture(tmp.path(), CGROUP_MEMORY_SWAP, "0").expect("set fixture for swap limit");

        let limit = 1024;
        let reservation = 512;
        let swap = 2048;

        let memory_limits = LinuxMemoryBuilder::default()
            .limit(limit)
            .reservation(reservation)
            .swap(swap)
            .build()
            .unwrap();

        Memory::apply(tmp.path(), &memory_limits).expect("apply memory limits");

        let limit_content =
            read_to_string(tmp.path().join(CGROUP_MEMORY_MAX)).expect("read memory limit");
        assert_eq!(limit_content, limit.to_string());

        let swap_content =
            read_to_string(tmp.path().join(CGROUP_MEMORY_SWAP)).expect("read swap limit");
        assert_eq!(swap_content, (swap - limit).to_string());

        let reservation_content =
            read_to_string(tmp.path().join(CGROUP_MEMORY_LOW)).expect("read memory reservation");
        assert_eq!(reservation_content, reservation.to_string());
    }

    #[test]
    fn test_set_memory_unlimited() {
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), CGROUP_MEMORY_MAX, "0").expect("set fixture for memory limit");
        set_fixture(tmp.path(), CGROUP_MEMORY_LOW, "0")
            .expect("set fixture for memory reservation");
        set_fixture(tmp.path(), CGROUP_MEMORY_SWAP, "0").expect("set fixture for swap limit");

        let memory_limits = LinuxMemoryBuilder::default().limit(-1).build().unwrap();

        Memory::apply(tmp.path(), &memory_limits).expect("apply memory limits");

        let limit_content =
            read_to_string(tmp.path().join(CGROUP_MEMORY_MAX)).expect("read memory limit");
        assert_eq!(limit_content, "max");

        let swap_content =
            read_to_string(tmp.path().join(CGROUP_MEMORY_SWAP)).expect("read swap limit");
        assert_eq!(swap_content, "max");
    }

    #[test]
    fn test_err_swap_no_memory() {
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), CGROUP_MEMORY_MAX, "0").expect("set fixture for memory limit");
        set_fixture(tmp.path(), CGROUP_MEMORY_LOW, "0")
            .expect("set fixture for memory reservation");
        set_fixture(tmp.path(), CGROUP_MEMORY_SWAP, "0").expect("set fixture for swap limit");

        let memory_limits = LinuxMemoryBuilder::default().swap(512).build().unwrap();

        let result = Memory::apply(tmp.path(), &memory_limits);

        assert!(result.is_err());
    }

    #[test]
    fn test_err_bad_limit() {
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), CGROUP_MEMORY_MAX, "0").expect("set fixture for memory limit");
        set_fixture(tmp.path(), CGROUP_MEMORY_LOW, "0")
            .expect("set fixture for memory reservation");
        set_fixture(tmp.path(), CGROUP_MEMORY_SWAP, "0").expect("set fixture for swap limit");

        let memory_limits = LinuxMemoryBuilder::default().limit(-2).build().unwrap();

        let result = Memory::apply(tmp.path(), &memory_limits);

        assert!(result.is_err());
    }

    #[test]
    fn test_err_bad_swap() {
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), CGROUP_MEMORY_MAX, "0").expect("set fixture for memory limit");
        set_fixture(tmp.path(), CGROUP_MEMORY_LOW, "0")
            .expect("set fixture for memory reservation");
        set_fixture(tmp.path(), CGROUP_MEMORY_SWAP, "0").expect("set fixture for swap limit");

        let memory_limits = LinuxMemoryBuilder::default()
            .limit(512)
            .swap(-3)
            .build()
            .unwrap();

        let result = Memory::apply(tmp.path(), &memory_limits);

        assert!(result.is_err());
    }

    quickcheck! {
        fn property_test_set_memory(linux_memory: LinuxMemory) -> bool {
            let tmp = tempfile::tempdir().unwrap();
            set_fixture(tmp.path(), CGROUP_MEMORY_MAX, "0").expect("set fixture for memory limit");
            set_fixture(tmp.path(), CGROUP_MEMORY_LOW, "0").expect("set fixture for memory reservation");
            set_fixture(tmp.path(), CGROUP_MEMORY_SWAP, "0").expect("set fixture for swap limit");

            let result = Memory::apply(tmp.path(), &linux_memory);

            // we need to check for expected errors first and foremost or we'll get false negatives
            // later
            if let Some(limit) = linux_memory.limit() {
                if limit < -1 {
                    return result.is_err();
                }
            }

            if let Some(swap) = linux_memory.swap() {
                if swap < -1 {
                    return result.is_err();
                }
                if linux_memory.limit().is_none() {
                    return result.is_err();
                }
                if let Some(limit) = linux_memory.limit() {
                    if limit != -1 && swap != -1 && swap < limit {
                        return result.is_err();
                    }
                }
            }

            if let Some(reservation) = linux_memory.reservation() {
                if reservation < -1 {
                    return result.is_err();
                }
            }

            // check the limit file is set as expected
            let limit_content = read_to_string(tmp.path().join(CGROUP_MEMORY_MAX)).expect("read memory limit to string");
            let limit_check = match linux_memory.limit() {
                Some(limit) if limit == -1 => limit_content == "max",
                Some(limit) => limit_content == limit.to_string(),
                None => limit_content == "0",
            };

            // check the swap file is set as expected
            let swap_content = read_to_string(tmp.path().join(CGROUP_MEMORY_SWAP)).expect("read swap limit to string");
            let swap_check = match linux_memory.swap() {
                Some(swap) if swap == -1 => swap_content == "max",
                Some(swap) => {
                    if let Some(limit) = linux_memory.limit() {
                        if limit == -1 {
                            swap_content == swap.to_string()
                        } else {
                            swap_content == (swap - linux_memory.limit().unwrap()).to_string()
                        }
                    } else {
                        false
                    }
                }
                None => {
                    match linux_memory.limit() {
                        Some(limit) if limit == -1 => swap_content == "max",
                        _ => swap_content == "0",
                    }
                }
            };


            // check the resevation file is set as expected
            let reservation_content = read_to_string(tmp.path().join(CGROUP_MEMORY_LOW)).expect("read memory reservation to string");
            let reservation_check = match linux_memory.reservation() {
                Some(reservation) if reservation == -1 => reservation_content == "max",
                Some(reservation) => reservation_content == reservation.to_string(),
                None => reservation_content == "0",
            };

            println!("limit_check: {limit_check}");
            println!("swap_check: {swap_check}");
            println!("reservation_check: {reservation_check}");
            limit_check && swap_check && reservation_check
        }
    }

    #[test]
    fn test_get_memory_data() {
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), "memory.current", "12500\n").unwrap();
        set_fixture(tmp.path(), "memory.max", "25000\n").unwrap();
        let events = ["slab 5", "anon 13", "oom 3"].join("\n");
        set_fixture(tmp.path(), "memory.events", &events).unwrap();

        let actual =
            Memory::get_memory_data(tmp.path(), "memory", "oom").expect("get cgroup stats");
        let expected = MemoryData {
            usage: 12500,
            limit: 25000,
            fail_count: 3,
            ..Default::default()
        };

        assert_eq!(actual, expected);
    }
}
