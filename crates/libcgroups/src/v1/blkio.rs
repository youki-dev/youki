use std::num::ParseIntError;
use std::path::{Path, PathBuf};

use oci_spec::runtime::LinuxBlockIo;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{self, BlkioDeviceStat, BlkioStats, ParseDeviceNumberError, StatsProvider};

// Throttling/upper limit policy
// ---------------------------------------
// Upper limit on the number of read operations a device can perform specified in bytes
// Format: Major:Minor Bytes
const BLKIO_THROTTLE_READ_BPS: &str = "blkio.throttle.read_bps_device";
// Upper limit on the number of write operations a device can perform specified in bytes
// Format: Major:Minor Bytes
const BLKIO_THROTTLE_WRITE_BPS: &str = "blkio.throttle.write_bps_device";
// Upper limit on the number of read operations a device can perform specified in operations per second
// Format: Major:Minor Ops
const BLKIO_THROTTLE_READ_IOPS: &str = "blkio.throttle.read_iops_device";
// Upper limit on the number of write operations a device can perform specified in operations per second
// Format: Major:Minor Ops
const BLKIO_THROTTLE_WRITE_IOPS: &str = "blkio.throttle.write_iops_device";
// Number of I/O operations performed on a device by the cgroup
// Format: Major:Minor Type Ops
const BLKIO_THROTTLE_IO_SERVICED: &str = "blkio.throttle.io_serviced";
// Number of bytes transferred to/from a device by the cgroup
// Format: Major:Minor Type Bytes
const BLKIO_THROTTLE_IO_SERVICE_BYTES: &str = "blkio.throttle.io_service_bytes";

// Proportional weight division policy
// ---------------------------------------
// Specifies the relative proportion of block I/O access available to the cgroup
// Format: weight (weight can range from 10 to 1000)
const BLKIO_WEIGHT: &str = "blkio.weight";
// Similar to BLKIO_WEIGHT, but is only available in kernels starting with version 5.0
// with blk-mq and when using BFQ I/O scheduler
// Format: weight (weight can range from 1 to 10000)
const BLKIO_BFQ_WEIGHT: &str = "blkio.bfq.weight";
// Specifies the relative proportion of block I/O access for specific devices available
// to the cgroup. This overrides the the blkio.weight value for the specified device
// Format: Major:Minor weight (weight can range from 100 to 1000)
#[allow(dead_code)]
const BLKIO_WEIGHT_DEVICE: &str = "blkio.weight_device";

// Common parameters which may be used for either policy but seem to be used only for
// proportional weight division policy in practice
// ---------------------------------------
// Time in milliseconds that the cgroup had access to a device
// Format: Major:Minor Time(ms)
const BLKIO_TIME: &str = "blkio.time_recursive";
// Number of sectors transferred to/from a device by the cgroup
// Format: Major:Minor Sectors
const BLKIO_SECTORS: &str = "blkio.sectors_recursive";
// Number of bytes transferred to/from a device by the cgroup
/// Format: Major:Minor Type Bytes
const BLKIO_IO_SERVICE_BYTES: &str = "blkio.io_service_bytes_recursive";
// Number of I/O operations performed on a device by the cgroup
// Format: Major:Minor Type Ops
const BLKIO_IO_SERVICED: &str = "blkio.io_serviced_recursive";
// Total time between request dispatch and request completion
/// Format: Major:Minor Type Time(ns)
const BLKIO_IO_SERVICE_TIME: &str = "blkio.io_service_time_recursive";
// Total time spend waiting in the scheduler queues for service
// Format: Major:Minor Type Time(ns)
const BLKIO_WAIT_TIME: &str = "blkio.io_wait_time_recursive";
// Number of requests queued for I/O operations
// Format: Requests Type
const BLKIO_QUEUED: &str = "blkio.io_queued_recursive";
// Number of requests merged into requests for I/O operations
// Format: Requests Type
const BLKIO_MERGED: &str = "blkio.io_merged_recursive";

pub struct Blkio {}

impl Controller for Blkio {
    type Error = WrappedIoError;
    type Resource = LinuxBlockIo;

    fn apply(controller_opt: &ControllerOpt, cgroup_root: &Path) -> Result<(), Self::Error> {
        tracing::debug!("Apply blkio cgroup config");

        if let Some(blkio) = Self::needs_to_handle(controller_opt) {
            Self::apply(cgroup_root, blkio)?;
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        controller_opt.resources.block_io().as_ref()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum V1BlkioStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("failed to parse device value {value} in {path}: {err}")]
    FailedParseValue {
        value: String,
        path: PathBuf,
        err: ParseIntError,
    },
    #[error("failed to parse device number: {0}")]
    FailedParseNumber(#[from] ParseDeviceNumberError),
}

impl StatsProvider for Blkio {
    type Error = V1BlkioStatsError;
    type Stats = BlkioStats;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        if cgroup_path.join(BLKIO_WEIGHT).exists() {
            return Self::get_weight_division_policy_stats(cgroup_path);
        }

        Self::get_throttling_policy_stats(cgroup_path)
    }
}

impl Blkio {
    fn apply(root_path: &Path, blkio: &LinuxBlockIo) -> Result<(), WrappedIoError> {
        if let Some(blkio_weight) = blkio.weight() {
            // be aligned with what runc does
            // See also: https://github.com/opencontainers/runc/blob/81044ad7c902f3fc153cb8ffadaf4da62855193f/libcontainer/cgroups/fs/blkio.go#L28-L33
            if blkio_weight != 0 {
                let cgroup_file = root_path.join(BLKIO_WEIGHT);
                if cgroup_file.exists() {
                    common::write_cgroup_file(&cgroup_file, blkio_weight)?;
                } else {
                    common::write_cgroup_file(root_path.join(BLKIO_BFQ_WEIGHT), blkio_weight)?;
                }
            }
        }

        if let Some(throttle_read_bps_device) = blkio.throttle_read_bps_device().as_ref() {
            for trbd in throttle_read_bps_device {
                common::write_cgroup_file_str(
                    root_path.join(BLKIO_THROTTLE_READ_BPS),
                    &format!("{}:{} {}", trbd.major(), trbd.minor(), trbd.rate()),
                )?;
            }
        }

        if let Some(throttle_write_bps_device) = blkio.throttle_write_bps_device().as_ref() {
            for twbd in throttle_write_bps_device {
                common::write_cgroup_file_str(
                    root_path.join(BLKIO_THROTTLE_WRITE_BPS),
                    &format!("{}:{} {}", twbd.major(), twbd.minor(), twbd.rate()),
                )?;
            }
        }

        if let Some(throttle_read_iops_device) = blkio.throttle_read_iops_device().as_ref() {
            for trid in throttle_read_iops_device {
                common::write_cgroup_file_str(
                    root_path.join(BLKIO_THROTTLE_READ_IOPS),
                    &format!("{}:{} {}", trid.major(), trid.minor(), trid.rate()),
                )?;
            }
        }

        if let Some(throttle_write_iops_device) = blkio.throttle_write_iops_device().as_ref() {
            for twid in throttle_write_iops_device {
                common::write_cgroup_file_str(
                    root_path.join(BLKIO_THROTTLE_WRITE_IOPS),
                    &format!("{}:{} {}", twid.major(), twid.minor(), twid.rate()),
                )?;
            }
        }

        Ok(())
    }

    fn get_throttling_policy_stats(cgroup_path: &Path) -> Result<BlkioStats, V1BlkioStatsError> {
        let stats = BlkioStats {
            service_bytes: Self::parse_blkio_file(
                &cgroup_path.join(BLKIO_THROTTLE_IO_SERVICE_BYTES),
            )?,
            serviced: Self::parse_blkio_file(&cgroup_path.join(BLKIO_THROTTLE_IO_SERVICED))?,
            ..Default::default()
        };

        Ok(stats)
    }

    fn get_weight_division_policy_stats(
        cgroup_path: &Path,
    ) -> Result<BlkioStats, V1BlkioStatsError> {
        let stats = BlkioStats {
            time: Self::parse_blkio_file(&cgroup_path.join(BLKIO_TIME))?,
            sectors: Self::parse_blkio_file(&cgroup_path.join(BLKIO_SECTORS))?,
            service_bytes: Self::parse_blkio_file(&cgroup_path.join(BLKIO_IO_SERVICE_BYTES))?,
            serviced: Self::parse_blkio_file(&cgroup_path.join(BLKIO_IO_SERVICED))?,
            service_time: Self::parse_blkio_file(&cgroup_path.join(BLKIO_IO_SERVICE_TIME))?,
            wait_time: Self::parse_blkio_file(&cgroup_path.join(BLKIO_WAIT_TIME))?,
            queued: Self::parse_blkio_file(&cgroup_path.join(BLKIO_QUEUED))?,
            merged: Self::parse_blkio_file(&cgroup_path.join(BLKIO_MERGED))?,
            ..Default::default()
        };

        Ok(stats)
    }

    fn parse_blkio_file(blkio_file: &Path) -> Result<Vec<BlkioDeviceStat>, V1BlkioStatsError> {
        let content = common::read_cgroup_file(blkio_file)?;
        let mut stats = Vec::new();
        for entry in content.lines() {
            let entry_fields: Vec<&str> = entry.split_ascii_whitespace().collect();
            if entry_fields.len() <= 2 {
                continue;
            }

            let (major, minor) = stats::parse_device_number(entry_fields[0])?;
            let op_type = if entry_fields.len() == 3 {
                Some(entry_fields[1].to_owned())
            } else {
                None
            };
            let value = if entry_fields.len() == 3 {
                entry_fields[2]
                    .parse()
                    .map_err(|err| V1BlkioStatsError::FailedParseValue {
                        value: entry_fields[2].into(),
                        path: blkio_file.to_path_buf(),
                        err,
                    })?
            } else {
                entry_fields[1]
                    .parse()
                    .map_err(|err| V1BlkioStatsError::FailedParseValue {
                        value: entry_fields[1].into(),
                        path: blkio_file.to_path_buf(),
                        err,
                    })?
            };

            let stat = BlkioDeviceStat {
                major,
                minor,
                op_type,
                value,
            };

            stats.push(stat);
        }

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use oci_spec::runtime::{LinuxBlockIoBuilder, LinuxThrottleDeviceBuilder};

    use super::*;
    use crate::test::{set_fixture, setup};

    #[test]
    fn test_set_blkio_weight() {
        for cgroup_file in &[BLKIO_WEIGHT, BLKIO_BFQ_WEIGHT] {
            let (tmp, weight_file) = setup(cgroup_file);
            let blkio = LinuxBlockIoBuilder::default()
                .weight(200_u16)
                .build()
                .unwrap();

            Blkio::apply(tmp.path(), &blkio).expect("apply blkio");
            let content = fs::read_to_string(weight_file).expect("read blkio weight");
            assert_eq!("200", content);
        }
    }

    #[test]
    fn test_set_blkio_read_bps() {
        let (tmp, throttle) = setup(BLKIO_THROTTLE_READ_BPS);

        let blkio = LinuxBlockIoBuilder::default()
            .throttle_read_bps_device(vec![
                LinuxThrottleDeviceBuilder::default()
                    .major(8)
                    .minor(0)
                    .rate(102400u64)
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap();

        Blkio::apply(tmp.path(), &blkio).expect("apply blkio");
        let content = fs::read_to_string(throttle)
            .unwrap_or_else(|_| panic!("read {BLKIO_THROTTLE_READ_BPS} content"));

        assert_eq!("8:0 102400", content);
    }

    #[test]
    fn test_set_blkio_write_bps() {
        let (tmp, throttle) = setup(BLKIO_THROTTLE_WRITE_BPS);

        let blkio = LinuxBlockIoBuilder::default()
            .throttle_write_bps_device(vec![
                LinuxThrottleDeviceBuilder::default()
                    .major(8)
                    .minor(0)
                    .rate(102400u64)
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap();

        Blkio::apply(tmp.path(), &blkio).expect("apply blkio");
        let content = fs::read_to_string(throttle)
            .unwrap_or_else(|_| panic!("read {BLKIO_THROTTLE_WRITE_BPS} content"));

        assert_eq!("8:0 102400", content);
    }

    #[test]
    fn test_set_blkio_read_iops() {
        let (tmp, throttle) = setup(BLKIO_THROTTLE_READ_IOPS);

        let blkio = LinuxBlockIoBuilder::default()
            .throttle_read_iops_device(vec![
                LinuxThrottleDeviceBuilder::default()
                    .major(8)
                    .minor(0)
                    .rate(102400u64)
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap();

        Blkio::apply(tmp.path(), &blkio).expect("apply blkio");
        let content = fs::read_to_string(throttle)
            .unwrap_or_else(|_| panic!("read {BLKIO_THROTTLE_READ_IOPS} content"));

        assert_eq!("8:0 102400", content);
    }

    #[test]
    fn test_set_blkio_write_iops() {
        let (tmp, throttle) = setup(BLKIO_THROTTLE_WRITE_IOPS);

        let blkio = LinuxBlockIoBuilder::default()
            .throttle_write_iops_device(vec![
                LinuxThrottleDeviceBuilder::default()
                    .major(8)
                    .minor(0)
                    .rate(102400u64)
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap();

        Blkio::apply(tmp.path(), &blkio).expect("apply blkio");
        let content = fs::read_to_string(throttle)
            .unwrap_or_else(|_| panic!("read {BLKIO_THROTTLE_WRITE_IOPS} content"));

        assert_eq!("8:0 102400", content);
    }

    #[test]
    fn test_stat_throttling_policy() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir().unwrap();
        let content = &[
            "8:0 Read 20",
            "8:0 Write 20",
            "8:0 Sync 20",
            "8:0 Async 20",
            "8:0 Discard 20",
            "8:0 Total 20",
            "Total 0",
        ]
        .join("\n");
        set_fixture(tmp.path(), BLKIO_THROTTLE_IO_SERVICE_BYTES, content).unwrap();
        set_fixture(tmp.path(), BLKIO_THROTTLE_IO_SERVICED, content).unwrap();

        let actual = Blkio::stats(tmp.path()).expect("get cgroup stats");
        let mut expected = BlkioStats::default();
        let devices: Vec<BlkioDeviceStat> = ["Read", "Write", "Sync", "Async", "Discard", "Total"]
            .iter()
            .copied()
            .map(|op| BlkioDeviceStat {
                major: 8,
                minor: 0,
                op_type: Some(op.to_owned()),
                value: 20,
            })
            .collect();

        expected.service_bytes = devices.clone();
        expected.serviced = devices;

        assert_eq!(expected, actual);
        Ok(())
    }
}
