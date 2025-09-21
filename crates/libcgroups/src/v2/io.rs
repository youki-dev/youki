use std::num::ParseIntError;
use std::path::{Path, PathBuf};

use oci_spec::runtime::LinuxBlockIo;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{
    self, BlkioDeviceStat, BlkioStats, ParseDeviceNumberError, ParseNestedKeyedDataError,
    StatsProvider, psi_stats,
};

const CGROUP_BFQ_IO_WEIGHT: &str = "io.bfq.weight";
const CGROUP_IO_WEIGHT: &str = "io.weight";
const CGROUP_IO_STAT: &str = "io.stat";
const CGROUP_IO_PSI: &str = "io.pressure";

#[derive(thiserror::Error, Debug)]
pub enum V2IoControllerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("cannot set leaf_weight with cgroupv2")]
    LeafWeight,
}

pub struct Io {}

impl Controller for Io {
    type Error = V2IoControllerError;

    fn apply(controller_opt: &ControllerOpt, cgroup_root: &Path) -> Result<(), Self::Error> {
        tracing::debug!("Apply io cgroup v2 config");
        if let Some(io) = &controller_opt.resources.block_io() {
            Self::apply(cgroup_root, io)?;
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum V2IoStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("while parsing stat table: {0}")]
    ParseNestedKeyedData(#[from] ParseNestedKeyedDataError),
    #[error("while parsing device number: {0}")]
    ParseDeviceNumber(#[from] ParseDeviceNumberError),
    #[error("while parsing table value: {0}")]
    ParseInt(#[from] ParseIntError),
}

impl StatsProvider for Io {
    type Error = V2IoStatsError;
    type Stats = BlkioStats;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        let keyed_data = stats::parse_nested_keyed_data(&cgroup_path.join(CGROUP_IO_STAT))?;
        let mut service_bytes = Vec::with_capacity(keyed_data.len());
        let mut serviced = Vec::with_capacity(keyed_data.len());
        for entry in keyed_data {
            let (major, minor) = stats::parse_device_number(&entry.0)?;
            for value in entry.1 {
                if value.starts_with("rbytes") {
                    service_bytes.push(BlkioDeviceStat {
                        major,
                        minor,
                        op_type: Some("read".to_owned()),
                        value: stats::parse_value(&value[7..])?,
                    });
                } else if value.starts_with("wbytes") {
                    service_bytes.push(BlkioDeviceStat {
                        major,
                        minor,
                        op_type: Some("write".to_owned()),
                        value: stats::parse_value(&value[7..])?,
                    });
                } else if value.starts_with("rios") {
                    serviced.push(BlkioDeviceStat {
                        major,
                        minor,
                        op_type: Some("read".to_owned()),
                        value: stats::parse_value(&value[5..])?,
                    });
                } else if value.starts_with("wios") {
                    serviced.push(BlkioDeviceStat {
                        major,
                        minor,
                        op_type: Some("write".to_owned()),
                        value: stats::parse_value(&value[5..])?,
                    });
                }
            }
        }

        let stats = BlkioStats {
            service_bytes,
            serviced,
            psi: psi_stats(&cgroup_path.join(CGROUP_IO_PSI))?,
            ..Default::default()
        };

        Ok(stats)
    }
}

impl Io {
    // Since the OCI spec is designed for cgroup v1, in some cases
    // there is need to convert from the cgroup v1 configuration to cgroup v2
    // the formula for BlkIOWeight to IOWeight is y = (1 + (x - 10) * 9999 / 990)
    // convert linearly from [10-1000] to [1-10000]
    fn convert_cfq_io_weight_to_bfq(v: u16) -> u16 {
        if v == 0 {
            return 0;
        }
        1 + (v.saturating_sub(10)) * 9999 / 990
    }

    fn io_max_path(path: &Path) -> PathBuf {
        path.join("io.max")
    }

    // linux kernel doc: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#io
    fn apply(root_path: &Path, blkio: &LinuxBlockIo) -> Result<(), V2IoControllerError> {
        if let Some(weight_device) = blkio.weight_device() {
            for wd in weight_device {
                if let Some(weight) = wd.weight() {
                    common::write_cgroup_file(
                        root_path.join(CGROUP_BFQ_IO_WEIGHT),
                        format!("{}:{} {}", wd.major(), wd.minor(), weight),
                    )?;
                }
            }
        }
        if let Some(leaf_weight) = blkio.leaf_weight() {
            if leaf_weight > 0 {
                return Err(V2IoControllerError::LeafWeight);
            }
        }
        if let Some(io_weight) = blkio.weight() {
            // be aligned with what runc does
            // See also: https://github.com/opencontainers/runc/blob/81044ad7c902f3fc153cb8ffadaf4da62855193f/libcontainer/cgroups/fs2/io.go#L57-L69
            if io_weight > 0 {
                let cgroup_file = root_path.join(CGROUP_BFQ_IO_WEIGHT);
                if cgroup_file.exists() {
                    common::write_cgroup_file(cgroup_file, io_weight)?;
                } else {
                    common::write_cgroup_file(
                        root_path.join(CGROUP_IO_WEIGHT),
                        Self::convert_cfq_io_weight_to_bfq(io_weight),
                    )?;
                }
            }
        }

        if let Some(throttle_read_bps_device) = blkio.throttle_read_bps_device() {
            for trbd in throttle_read_bps_device {
                common::write_cgroup_file(
                    Self::io_max_path(root_path),
                    format!("{}:{} rbps={}", trbd.major(), trbd.minor(), trbd.rate()),
                )?;
            }
        }

        if let Some(throttle_write_bps_device) = blkio.throttle_write_bps_device() {
            for twbd in throttle_write_bps_device {
                common::write_cgroup_file(
                    Self::io_max_path(root_path),
                    format!("{}:{} wbps={}", twbd.major(), twbd.minor(), twbd.rate()),
                )?;
            }
        }

        if let Some(throttle_read_iops_device) = blkio.throttle_read_iops_device() {
            for trid in throttle_read_iops_device {
                common::write_cgroup_file(
                    Self::io_max_path(root_path),
                    format!("{}:{} riops={}", trid.major(), trid.minor(), trid.rate()),
                )?;
            }
        }

        if let Some(throttle_write_iops_device) = blkio.throttle_write_iops_device() {
            for twid in throttle_write_iops_device {
                common::write_cgroup_file(
                    Self::io_max_path(root_path),
                    format!("{}:{} wiops={}", twid.major(), twid.minor(), twid.rate()),
                )?;
            }
        }

        Ok(())
    }
}
#[cfg(test)]
mod test {
    use std::fs;

    use oci_spec::runtime::{
        LinuxBlockIoBuilder, LinuxThrottleDeviceBuilder, LinuxWeightDeviceBuilder,
    };

    use super::*;
    use crate::test::{set_fixture, setup};

    #[test]
    fn test_set_io_read_bps() {
        let (tmp, throttle) = setup("io.max");

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

        Io::apply(tmp.path(), &blkio).expect("apply blkio");
        let content = fs::read_to_string(throttle).unwrap_or_else(|_| panic!("read rbps content"));

        assert_eq!("8:0 rbps=102400", content);
    }

    #[test]
    fn test_set_io_write_bps() {
        let (tmp, throttle) = setup("io.max");

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

        Io::apply(tmp.path(), &blkio).expect("apply blkio");
        let content = fs::read_to_string(throttle).unwrap_or_else(|_| panic!("read rbps content"));

        assert_eq!("8:0 wbps=102400", content);
    }

    #[test]
    fn test_set_io_read_iops() {
        let (tmp, throttle) = setup("io.max");

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

        Io::apply(tmp.path(), &blkio).expect("apply blkio");
        let content = fs::read_to_string(throttle).unwrap_or_else(|_| panic!("read riops content"));

        assert_eq!("8:0 riops=102400", content);
    }

    #[test]
    fn test_set_io_write_iops() {
        let (tmp, throttle) = setup("io.max");

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

        Io::apply(tmp.path(), &blkio).expect("apply blkio");
        let content = fs::read_to_string(throttle).unwrap_or_else(|_| panic!("read wiops content"));

        assert_eq!("8:0 wiops=102400", content);
    }

    #[test]
    fn test_set_ioweight_device() {
        let (tmp, throttle) = setup(CGROUP_BFQ_IO_WEIGHT);
        let blkio = LinuxBlockIoBuilder::default()
            .weight_device(vec![
                LinuxWeightDeviceBuilder::default()
                    .major(8)
                    .minor(0)
                    .weight(80u16)
                    .leaf_weight(0u16)
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap();

        Io::apply(tmp.path(), &blkio).expect("apply blkio");
        let content =
            fs::read_to_string(throttle).unwrap_or_else(|_| panic!("read bfq_io_weight content"));

        assert_eq!("8:0 80", content);
    }

    #[test]
    fn test_set_ioweight() {
        struct TestCase {
            cgroup_file: &'static str,
            weight: u16,
            expected_weight: String,
        }
        for case in &[
            TestCase {
                cgroup_file: CGROUP_BFQ_IO_WEIGHT,
                weight: 100,
                expected_weight: String::from("100"),
            },
            TestCase {
                cgroup_file: CGROUP_IO_WEIGHT,
                weight: 10,
                expected_weight: String::from("1"),
            },
        ] {
            let (tmp, weight_file) = setup(case.cgroup_file);
            let blkio = LinuxBlockIoBuilder::default()
                .weight(case.weight)
                .build()
                .unwrap();

            Io::apply(tmp.path(), &blkio).expect("apply blkio");
            let content = fs::read_to_string(weight_file).expect("read blkio weight");
            assert_eq!(case.expected_weight, content);
        }
    }

    #[test]
    fn test_stat_io() {
        let tmp = tempfile::tempdir().unwrap();
        let stat_content = [
            "7:10 rbytes=18432 wbytes=16842 rios=12 wios=0 dbytes=0 dios=0",
            "7:9 rbytes=34629632 wbytes=274965 rios=1066 wios=319 dbytes=0 dios=0",
        ]
        .join("\n");
        set_fixture(tmp.path(), "io.stat", &stat_content).unwrap();
        set_fixture(tmp.path(), CGROUP_IO_PSI, "").expect("create psi file");

        let mut actual = Io::stats(tmp.path()).expect("get cgroup stats");
        let expected = BlkioStats {
            service_bytes: vec![
                BlkioDeviceStat {
                    major: 7,
                    minor: 9,
                    op_type: Some("read".to_owned()),
                    value: 34629632,
                },
                BlkioDeviceStat {
                    major: 7,
                    minor: 9,
                    op_type: Some("write".to_owned()),
                    value: 274965,
                },
                BlkioDeviceStat {
                    major: 7,
                    minor: 10,
                    op_type: Some("read".to_owned()),
                    value: 18432,
                },
                BlkioDeviceStat {
                    major: 7,
                    minor: 10,
                    op_type: Some("write".to_owned()),
                    value: 16842,
                },
            ],
            serviced: vec![
                BlkioDeviceStat {
                    major: 7,
                    minor: 9,
                    op_type: Some("read".to_owned()),
                    value: 1066,
                },
                BlkioDeviceStat {
                    major: 7,
                    minor: 9,
                    op_type: Some("write".to_owned()),
                    value: 319,
                },
                BlkioDeviceStat {
                    major: 7,
                    minor: 10,
                    op_type: Some("read".to_owned()),
                    value: 12,
                },
                BlkioDeviceStat {
                    major: 7,
                    minor: 10,
                    op_type: Some("write".to_owned()),
                    value: 0,
                },
            ],
            ..Default::default()
        };

        actual.service_bytes.sort();
        actual.serviced.sort();

        assert_eq!(actual, expected);
    }
}
