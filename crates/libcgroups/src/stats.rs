use std::collections::HashMap;
use std::fmt::Display;
use std::fs;
use std::num::ParseIntError;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::common;
use crate::common::{WrapIoResult, WrappedIoError};

pub(crate) trait StatsProvider {
    type Error;
    type Stats;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error>;
}

/// Reports the statistics for a cgroup
#[derive(Debug, Serialize, Default)]
pub struct Stats {
    /// Cpu statistics for the cgroup
    pub cpu: CpuStats,
    /// Pid statistics for the cgroup
    pub pids: PidStats,
    /// Hugetlb statistics for the cgroup
    pub hugetlb: HashMap<String, HugeTlbStats>,
    /// Blkio statistics for the cgroup
    pub blkio: BlkioStats,
    /// Memory statistics for the cgroup
    pub memory: MemoryStats,
}

/// Reports the cpu statistics for a cgroup
#[derive(Debug, Default, Serialize)]
pub struct CpuStats {
    /// Cpu usage statistics for the cgroup
    pub usage: CpuUsage,
    /// Cpu Throttling statistics for the cgroup
    pub throttling: CpuThrottling,
    /// Pressure Stall Information
    pub psi: PSIStats,
}

/// Reports the cpu usage for a cgroup
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct CpuUsage {
    /// Cpu time consumed by tasks in total
    pub usage_total: u64,
    /// Cpu time consumed by tasks in user mode
    pub usage_user: u64,
    /// Cpu time consumed by tasks in kernel mode
    pub usage_kernel: u64,
    /// Cpu time consumed by tasks itemized per core
    pub per_core_usage_total: Vec<u64>,
    /// Cpu time consumed by tasks in user mode itemized per core
    pub per_core_usage_user: Vec<u64>,
    /// Cpu time consumed by tasks in kernel mode itemized per core
    pub per_core_usage_kernel: Vec<u64>,
}

/// Reports the cpu throttling for a cgroup
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct CpuThrottling {
    /// Number of period intervals (as specified in cpu.cfs_period_us) that have elapsed
    pub periods: u64,
    /// Number of period intervals where tasks have been throttled because they exhausted their quota
    pub throttled_periods: u64,
    /// Total time duration for which tasks have been throttled
    pub throttled_time: u64,
}

/// Reports memory stats for a cgroup
#[derive(Debug, Default, Serialize)]
pub struct MemoryStats {
    /// Usage of memory
    pub memory: MemoryData,
    /// Usage of memory and swap
    pub memswap: MemoryData,
    /// Usage of kernel memory
    pub kernel: MemoryData,
    /// Usage of kernel tcp memory
    pub kernel_tcp: MemoryData,
    /// Page cache in bytes
    pub cache: u64,
    /// Returns true if hierarchical accounting is enabled
    pub hierarchy: bool,
    /// Various memory statistics
    pub stats: HashMap<String, u64>,
    /// Pressure Stall Information
    pub psi: PSIStats,
}

/// Reports memory stats for one type of memory
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct MemoryData {
    /// Usage in bytes
    pub usage: u64,
    /// Maximum recorded usage in bytes
    pub max_usage: u64,
    /// Number of times memory usage hit limits
    pub fail_count: u64,
    /// Memory usage limit
    pub limit: u64,
}

/// Reports pid stats for a cgroup
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct PidStats {
    /// Current number of active pids
    pub current: u64,
    /// Allowed number of active pids (0 means no limit)
    pub limit: u64,
}

/// Reports block io stats for a cgroup
#[derive(Debug, Default, PartialEq, Serialize)]
pub struct BlkioStats {
    // Number of bytes transferred to/from a device by the cgroup
    pub service_bytes: Vec<BlkioDeviceStat>,
    // Number of I/O operations performed on a device by the cgroup
    pub serviced: Vec<BlkioDeviceStat>,
    // Time in milliseconds that the cgroup had access to a device
    pub time: Vec<BlkioDeviceStat>,
    // Number of sectors transferred to/from a device by the cgroup
    pub sectors: Vec<BlkioDeviceStat>,
    // Total time between request dispatch and request completion
    pub service_time: Vec<BlkioDeviceStat>,
    // Total time spend waiting in the scheduler queues for service
    pub wait_time: Vec<BlkioDeviceStat>,
    // Number of requests queued for I/O operations
    pub queued: Vec<BlkioDeviceStat>,
    // Number of requests merged into requests for I/O operations
    pub merged: Vec<BlkioDeviceStat>,
    /// Pressure Stall Information
    pub psi: PSIStats,
}

/// Reports single stat value for a specific device
#[derive(Debug, PartialEq, Eq, Clone, Serialize, PartialOrd, Ord)]
pub struct BlkioDeviceStat {
    /// Major device number
    pub major: u64,
    /// Minor device number
    pub minor: u64,
    /// Operation type
    pub op_type: Option<String>,
    /// Stat value
    pub value: u64,
}

impl Display for BlkioDeviceStat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(op_type) = &self.op_type {
            write!(
                f,
                "{}:{} {} {}",
                self.major, self.minor, op_type, self.value
            )
        } else {
            write!(f, "{}:{} {}", self.major, self.minor, self.value)
        }
    }
}

/// Reports hugetlb stats for a cgroup
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct HugeTlbStats {
    /// Current usage in bytes
    pub usage: u64,
    /// Maximum recorded usage in bytes
    pub max_usage: u64,
    /// Number of allocation failures due to HugeTlb usage limit
    pub fail_count: u64,
}

/// Reports Pressure Stall Information for a cgroup
#[derive(Debug, Default, PartialEq, Serialize)]
pub struct PSIStats {
    /// Percentage of walltime that some (one or more) tasks were delayed due to lack of resources
    pub some: PSIData,
    /// Percentage of walltime in which all tasks were delayed by lack of resources
    pub full: PSIData,
}

#[derive(Debug, Default, PartialEq, Serialize)]
pub struct PSIData {
    /// Running average over the last 10 seconds
    pub avg10: f64,
    /// Running average over the last 60 seconds
    pub avg60: f64,
    /// Running average over the last 300 seconds
    pub avg300: f64,
}

#[derive(thiserror::Error, Debug)]
pub enum SupportedPageSizesError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse value {value}: {err}")]
    Parse { value: String, err: ParseIntError },
    #[error("failed to determine page size from {dir_name}")]
    Failed { dir_name: String },
}

/// Reports which hugepage sizes are supported by the system
pub fn supported_page_sizes() -> Result<Vec<String>, SupportedPageSizesError> {
    let mut sizes = Vec::new();
    for hugetlb_entry in fs::read_dir("/sys/kernel/mm/hugepages")? {
        let hugetlb_entry = hugetlb_entry?;
        if !hugetlb_entry.path().is_dir() {
            continue;
        }

        let dir_name = hugetlb_entry.file_name();
        // this name should always be valid utf-8,
        // so can unwrap without any checks
        let dir_name = dir_name.to_str().unwrap();

        sizes.push(extract_page_size(dir_name)?);
    }

    Ok(sizes)
}

fn extract_page_size(dir_name: &str) -> Result<String, SupportedPageSizesError> {
    if let Some(size) = dir_name
        .strip_prefix("hugepages-")
        .and_then(|name_stripped| name_stripped.strip_suffix("kB"))
    {
        let size: u64 = size.parse().map_err(|err| SupportedPageSizesError::Parse {
            value: size.into(),
            err,
        })?;

        let size_moniker = if size >= (1 << 20) {
            (size >> 20).to_string() + "GB"
        } else if size >= (1 << 10) {
            (size >> 10).to_string() + "MB"
        } else {
            size.to_string() + "KB"
        };

        return Ok(size_moniker);
    }

    Err(SupportedPageSizesError::Failed {
        dir_name: dir_name.into(),
    })
}

/// Parses this string slice into an u64
/// # Example
/// ```
/// use libcgroups::stats::parse_value;
///
/// let value = parse_value("32").unwrap();
/// assert_eq!(value, 32);
/// ```
pub fn parse_value(value: &str) -> Result<u64, ParseIntError> {
    value.parse()
}

/// Parses a single valued file to an u64
/// # Example
/// ```no_run
/// use std::path::Path;
/// use libcgroups::stats::parse_single_value;
///
/// let value = parse_single_value(&Path::new("memory.current")).unwrap();
/// assert_eq!(value, 32);
/// ```
pub fn parse_single_value(file_path: &Path) -> Result<u64, WrappedIoError> {
    let value = common::read_cgroup_file(file_path)?;
    let value = value.trim();
    if value == "max" {
        return Ok(u64::MAX);
    }

    value
        .parse()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
        .wrap_other(file_path)
}

#[derive(thiserror::Error, Debug)]
pub enum ParseFlatKeyedDataError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("flat keyed data at {path} contains entries that do not conform to 'key value'")]
    DoesNotConform { path: PathBuf },
    #[error("failed to parse value {value} from {path}")]
    FailedToParse {
        value: String,
        path: PathBuf,
        err: ParseIntError,
    },
}

/// Parses a file that is structured according to the flat keyed format
pub(crate) fn parse_flat_keyed_data(
    file_path: &Path,
) -> Result<HashMap<String, u64>, ParseFlatKeyedDataError> {
    let mut stats = HashMap::new();
    let keyed_data = common::read_cgroup_file(file_path)?;
    for entry in keyed_data.lines() {
        let entry_fields: Vec<&str> = entry.split_ascii_whitespace().collect();
        if entry_fields.len() != 2 {
            return Err(ParseFlatKeyedDataError::DoesNotConform {
                path: file_path.to_path_buf(),
            });
        }

        stats.insert(
            entry_fields[0].to_owned(),
            entry_fields[1]
                .parse()
                .map_err(|err| ParseFlatKeyedDataError::FailedToParse {
                    value: entry_fields[0].into(),
                    path: file_path.to_path_buf(),
                    err,
                })?,
        );
    }

    Ok(stats)
}

#[derive(thiserror::Error, Debug)]
pub enum ParseNestedKeyedDataError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("nested keyed data at {path} contains entries that do not conform to key format")]
    DoesNotConform { path: PathBuf },
}

/// Parses a file that is structured according to the nested keyed format
pub fn parse_nested_keyed_data(
    file_path: &Path,
) -> Result<HashMap<String, Vec<String>>, ParseNestedKeyedDataError> {
    let mut stats: HashMap<String, Vec<String>> = HashMap::new();
    let keyed_data = common::read_cgroup_file(file_path)?;
    for entry in keyed_data.lines() {
        let entry_fields: Vec<&str> = entry.split_ascii_whitespace().collect();
        if entry_fields.len() < 2 || !entry_fields[1..].iter().all(|p| p.contains('=')) {
            return Err(ParseNestedKeyedDataError::DoesNotConform {
                path: file_path.to_path_buf(),
            });
        }

        stats.insert(
            entry_fields[0].to_owned(),
            entry_fields[1..]
                .iter()
                .copied()
                .map(|p| p.to_owned())
                .collect(),
        );
    }

    Ok(stats)
}

#[derive(thiserror::Error, Debug)]
pub enum ParseDeviceNumberError {
    #[error("failed to parse device number from {device}: expected 2 parts, found {numbers}")]
    TooManyNumbers { device: String, numbers: usize },
    #[error("failed to parse device number from {device}: {err}")]
    MalformedNumber { device: String, err: ParseIntError },
}

pub(crate) fn parse_device_number(device: &str) -> Result<(u64, u64), ParseDeviceNumberError> {
    let numbers: Vec<&str> = device.split_terminator(':').collect();
    if numbers.len() != 2 {
        return Err(ParseDeviceNumberError::TooManyNumbers {
            device: device.into(),
            numbers: numbers.len(),
        });
    }

    Ok((
        numbers[0]
            .parse()
            .map_err(|err| ParseDeviceNumberError::MalformedNumber {
                device: device.into(),
                err,
            })?,
        numbers[1]
            .parse()
            .map_err(|err| ParseDeviceNumberError::MalformedNumber {
                device: device.into(),
                err,
            })?,
    ))
}

#[derive(thiserror::Error, Debug)]
pub enum PidStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("failed to parse current pids: {0}")]
    ParseCurrent(ParseIntError),
    #[error("failed to parse pids limit: {0}")]
    ParseLimit(ParseIntError),
}

/// Returns cgroup pid statistics
pub fn pid_stats(cgroup_path: &Path) -> Result<PidStats, PidStatsError> {
    let mut stats = PidStats::default();

    let current = common::read_cgroup_file(cgroup_path.join("pids.current"))?;
    stats.current = current
        .trim()
        .parse()
        .map_err(PidStatsError::ParseCurrent)?;

    let limit =
        common::read_cgroup_file(cgroup_path.join("pids.max")).map(|l| l.trim().to_owned())?;
    if limit != "max" {
        stats.limit = limit.parse().map_err(PidStatsError::ParseLimit)?;
    }

    Ok(stats)
}

pub fn psi_stats(psi_file: &Path) -> Result<PSIStats, WrappedIoError> {
    let mut stats = PSIStats::default();

    // The pressure files are missing when the kernel has no PSI or it is
    // turned off for the cgroup (cgroup.pressure set to 0), and some kernels
    // return EOPNOTSUPP on read unless booted with psi=1. runc returns empty
    // PSI in these cases too.
    let psi = match common::read_cgroup_file(psi_file) {
        Ok(psi) => psi,
        Err(err)
            if err.inner().kind() == std::io::ErrorKind::NotFound
                || err.inner().raw_os_error() == Some(nix::errno::Errno::EOPNOTSUPP as i32) =>
        {
            return Ok(stats);
        }
        Err(err) => return Err(err),
    };
    for line in psi.lines() {
        match &line[0..4] {
            "some" => stats.some = parse_psi(&line[4..], psi_file)?,
            "full" => stats.full = parse_psi(&line[4..], psi_file)?,
            _ => continue,
        }
    }

    Ok(stats)
}

fn parse_psi(stat_line: &str, path: &Path) -> Result<PSIData, WrappedIoError> {
    use std::io::{Error, ErrorKind};

    let mut psi_data = PSIData::default();

    for kv in stat_line.split_ascii_whitespace() {
        match kv.split_once('=') {
            Some(("avg10", v)) => {
                psi_data.avg10 = v
                    .parse()
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))
                    .wrap_other(path)?
            }
            Some(("avg60", v)) => {
                psi_data.avg60 = v
                    .parse()
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))
                    .wrap_other(path)?
            }
            Some(("avg300", v)) => {
                psi_data.avg300 = v
                    .parse()
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))
                    .wrap_other(path)?
            }
            _ => continue,
        }
    }

    Ok(psi_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::set_fixture;

    #[test]
    fn test_supported_page_sizes_gigabyte() {
        let page_size = extract_page_size("hugepages-1048576kB").unwrap();
        assert_eq!(page_size, "1GB");
    }

    #[test]
    fn test_supported_page_sizes_megabyte() {
        let page_size = extract_page_size("hugepages-2048kB").unwrap();
        assert_eq!(page_size, "2MB");
    }

    #[test]
    fn test_supported_page_sizes_kilobyte() {
        let page_size = extract_page_size("hugepages-512kB").unwrap();
        assert_eq!(page_size, "512KB");
    }

    #[test]
    fn test_parse_single_value_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = set_fixture(tmp.path(), "single_valued_file", "1200\n").unwrap();

        let value = parse_single_value(&file_path).unwrap();
        assert_eq!(value, 1200);
    }

    #[test]
    fn test_parse_single_value_invalid_number() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = set_fixture(tmp.path(), "single_invalid_file", "noop\n").unwrap();

        let value = parse_single_value(&file_path);
        assert!(value.is_err());
    }

    #[test]
    fn test_parse_single_value_multiple_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = set_fixture(tmp.path(), "multi_valued_file", "1200\n1400\n1600").unwrap();

        let value = parse_single_value(&file_path);
        assert!(value.is_err());
    }

    #[test]
    fn test_parse_flat_keyed_data() {
        let tmp = tempfile::tempdir().unwrap();
        let file_content = ["key1 1", "key2 2", "key3 3"].join("\n");
        let file_path = set_fixture(tmp.path(), "flat_keyed_data", &file_content).unwrap();

        let actual = parse_flat_keyed_data(&file_path).unwrap();
        let mut expected = HashMap::with_capacity(3);
        expected.insert("key1".to_owned(), 1);
        expected.insert("key2".to_owned(), 2);
        expected.insert("key3".to_owned(), 3);

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parse_flat_keyed_data_with_characters() {
        let tmp = tempfile::tempdir().unwrap();
        let file_content = ["key1 1", "key2 a", "key3 b"].join("\n");
        let file_path = set_fixture(tmp.path(), "flat_keyed_data", &file_content).unwrap();

        let result = parse_flat_keyed_data(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_space_separated_as_flat_keyed_data() {
        let tmp = tempfile::tempdir().unwrap();
        let file_content = ["key1", "key2", "key3", "key4"].join(" ");
        let file_path = set_fixture(tmp.path(), "space_separated", &file_content).unwrap();

        let result = parse_flat_keyed_data(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_newline_separated_as_flat_keyed_data() {
        let tmp = tempfile::tempdir().unwrap();
        let file_content = ["key1", "key2", "key3", "key4"].join("\n");
        let file_path = set_fixture(tmp.path(), "newline_separated", &file_content).unwrap();

        let result = parse_flat_keyed_data(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_nested_keyed_data_as_flat_keyed_data() {
        let tmp = tempfile::tempdir().unwrap();
        let file_content = [
            "key1 subkey1=value1 subkey2=value2 subkey3=value3",
            "key2 subkey1=value1 subkey2=value2 subkey3=value3",
            "key3 subkey1=value1 subkey2=value2 subkey3=value3",
        ]
        .join("\n");
        let file_path = set_fixture(tmp.path(), "nested_keyed_data", &file_content).unwrap();

        let result = parse_flat_keyed_data(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_nested_keyed_data() {
        let tmp = tempfile::tempdir().unwrap();
        let file_content = [
            "key1 subkey1=value1 subkey2=value2 subkey3=value3",
            "key2 subkey1=value1 subkey2=value2 subkey3=value3",
            "key3 subkey1=value1 subkey2=value2 subkey3=value3",
        ]
        .join("\n");
        let file_path = set_fixture(tmp.path(), "nested_keyed_data", &file_content).unwrap();

        let actual = parse_nested_keyed_data(&file_path).unwrap();
        let mut expected = HashMap::with_capacity(3);
        expected.insert(
            "key1".to_owned(),
            vec![
                "subkey1=value1".to_owned(),
                "subkey2=value2".to_owned(),
                "subkey3=value3".to_owned(),
            ],
        );
        expected.insert(
            "key2".to_owned(),
            vec![
                "subkey1=value1".to_owned(),
                "subkey2=value2".to_owned(),
                "subkey3=value3".to_owned(),
            ],
        );
        expected.insert(
            "key3".to_owned(),
            vec![
                "subkey1=value1".to_owned(),
                "subkey2=value2".to_owned(),
                "subkey3=value3".to_owned(),
            ],
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parse_space_separated_as_nested_keyed_data() {
        let tmp = tempfile::tempdir().unwrap();
        let file_content = ["key1", "key2", "key3", "key4"].join(" ");
        let file_path = set_fixture(tmp.path(), "space_separated", &file_content).unwrap();

        let result = parse_nested_keyed_data(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_newline_separated_as_nested_keyed_data() {
        let tmp = tempfile::tempdir().unwrap();
        let file_content = ["key1", "key2", "key3", "key4"].join("\n");
        let file_path = set_fixture(tmp.path(), "newline_separated", &file_content).unwrap();

        let result = parse_nested_keyed_data(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_flat_keyed_as_nested_keyed_data() {
        let tmp = tempfile::tempdir().unwrap();
        let file_content = ["key1 1", "key2 2", "key3 3"].join("\n");
        let file_path = set_fixture(tmp.path(), "newline_separated", &file_content).unwrap();

        let result = parse_nested_keyed_data(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_device_number() {
        let (major, minor) = parse_device_number("8:0").unwrap();
        assert_eq!((major, minor), (8, 0));
    }

    #[test]
    fn test_parse_invalid_device_number() {
        let result = parse_device_number("a:b");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_psi_full_stats() {
        let tmp = tempfile::tempdir().unwrap();
        let file_content = [
            "some avg10=80.00 avg60=50.00 avg300=90.00 total=0",
            "full avg10=10.00 avg60=30.00 avg300=50.00 total=0",
        ]
        .join("\n");
        let psi_file = set_fixture(tmp.path(), "psi.pressure", &file_content).unwrap();

        let result = psi_stats(&psi_file).unwrap();
        assert_eq!(
            result,
            PSIStats {
                some: PSIData {
                    avg10: 80.0,
                    avg60: 50.0,
                    avg300: 90.0
                },
                full: PSIData {
                    avg10: 10.0,
                    avg60: 30.0,
                    avg300: 50.0
                },
            }
        )
    }

    #[test]
    fn test_parse_psi_only_some() {
        let tmp = tempfile::tempdir().unwrap();
        let file_content = ["some avg10=80.00 avg60=50.00 avg300=90.00 total=0"].join("\n");
        let psi_file = set_fixture(tmp.path(), "psi.pressure", &file_content).unwrap();

        let result = psi_stats(&psi_file).unwrap();
        assert_eq!(
            result,
            PSIStats {
                some: PSIData {
                    avg10: 80.0,
                    avg60: 50.0,
                    avg300: 90.0
                },
                full: PSIData::default(),
            }
        )
    }

    #[test]
    fn test_psi_stats_missing_file() {
        let tmp = tempfile::tempdir().unwrap();

        let result = psi_stats(&tmp.path().join("cpu.pressure")).unwrap();
        assert_eq!(result, PSIStats::default());
    }
}
