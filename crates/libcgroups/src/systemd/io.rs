use std::collections::HashMap;
use std::fs;
use std::path::Path;

use oci_spec::runtime::{LinuxBlockIo, LinuxThrottleDevice};

use crate::systemd::controller::Controller;
use crate::systemd::dbus_native::serialize::{Structure, Variant};
pub struct Io {}

pub const IO_READ_BANDWIDTH_MAX: &str = "IOReadBandwidthMax";
pub const IO_WRITE_BANDWIDTH_MAX: &str = "IOWriteBandwidthMax";
pub const IO_READ_IOPS_MAX: &str = "IOReadIOPSMax";
pub const IO_WRITE_IOPS_MAX: &str = "IOWriteIOPSMax";

#[derive(thiserror::Error, Debug)]
pub enum SystemdIoError {
    #[error("File path for specified device with major:{0} , minor:{1} not found")]
    DeviceNotFound(i64, i64),
}
impl Controller for Io {
    type Error = SystemdIoError;
    fn apply(
        options: &crate::common::ControllerOpt,
        _: u32,
        properties: &mut HashMap<&str, super::dbus_native::serialize::Variant>,
    ) -> Result<(), Self::Error> {
        if let Some(blkio) = options.resources.block_io() {
            tracing::debug!("applying blkio resource restrictions");
            Self::apply(blkio, properties)?;
        }
        Ok(())
    }
}
impl Io {
    fn apply(
        blkio: &LinuxBlockIo,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), SystemdIoError> {
        // anonymous function for applying limits
        let mut apply_limits =
            |devices: &Vec<LinuxThrottleDevice>, key| -> Result<(), SystemdIoError> {
                let mut limits = Vec::new();
                for d in devices {
                    let rate = d.rate();
                    let Some(dev) = dev_path_from_major_minor(d.major(), d.minor()) else {
                        return Err(SystemdIoError::DeviceNotFound(d.major(), d.minor()));
                    };
                    limits.push(Structure::new(dev, rate));
                }
                if !limits.is_empty() {
                    properties.insert(key, Variant::ArrayStructU64(limits));
                }
                Ok(())
            };
        if let Some(devices) = blkio.throttle_read_bps_device() {
            apply_limits(devices, IO_READ_BANDWIDTH_MAX)?;
        }

        if let Some(devices) = blkio.throttle_write_bps_device() {
            apply_limits(devices, IO_WRITE_BANDWIDTH_MAX)?;
        }

        if let Some(devices) = blkio.throttle_read_iops_device() {
            apply_limits(devices, IO_READ_IOPS_MAX)?;
        }

        if let Some(devices) = blkio.throttle_write_iops_device() {
            apply_limits(devices, IO_WRITE_IOPS_MAX)?;
        }
        Ok(())
    }
}

fn dev_path_from_major_minor(major: i64, minor: i64) -> Option<String> {
    // Try block devices first: /sys/dev/block/<major>:<minor> -> .../block/<name>[/<part>]
    let block_path = format!("/sys/dev/block/{}:{}", major, minor);
    if let Ok(target) = fs::read_link(Path::new(&block_path)) {
        if let Some(name) = target.file_name() {
            return Some(format!("/dev/{}", name.to_string_lossy()));
        }
    }

    // Fallback to char devices if applicable: /sys/dev/char/<major>:<minor>
    let char_path = format!("/sys/dev/char/{}:{}", major, minor);
    if let Ok(target) = fs::read_link(Path::new(&char_path)) {
        if let Some(name) = target.file_name() {
            return Some(format!("/dev/{}", name.to_string_lossy()));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use nix::sys::stat::{major, minor, stat};
    use oci_spec::runtime::{LinuxBlockIoBuilder, LinuxThrottleDeviceBuilder};

    use super::*;

    #[test]
    fn dev_path_from_char_device_null() {
        let st = stat("/dev/null").expect("stat /dev/null");
        let maj = major(st.st_rdev) as i64;
        let min = minor(st.st_rdev) as i64;
        let path = dev_path_from_major_minor(maj, min).expect("resolve char device path");
        assert_eq!(path, "/dev/null");
    }

    #[test]
    fn apply_inserts_structs_for_positive_rates() {
        let st = stat("/dev/null").expect("stat /dev/null");
        let maj = major(st.st_rdev) as i64;
        let min = minor(st.st_rdev) as i64;
        // set random bytes
        let read_bps = 111u64;
        let write_bps = 222u64;
        let read_iops = 333u64;
        let write_iops = 444u64;

        let blkio = LinuxBlockIoBuilder::default()
            .throttle_read_bps_device(vec![
                LinuxThrottleDeviceBuilder::default()
                    .major(maj)
                    .minor(min)
                    .rate(read_bps)
                    .build()
                    .unwrap(),
            ])
            .throttle_write_bps_device(vec![
                LinuxThrottleDeviceBuilder::default()
                    .major(maj)
                    .minor(min)
                    .rate(write_bps)
                    .build()
                    .unwrap(),
            ])
            .throttle_read_iops_device(vec![
                LinuxThrottleDeviceBuilder::default()
                    .major(maj)
                    .minor(min)
                    .rate(read_iops)
                    .build()
                    .unwrap(),
            ])
            .throttle_write_iops_device(vec![
                LinuxThrottleDeviceBuilder::default()
                    .major(maj)
                    .minor(min)
                    .rate(write_iops)
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap();
        let mut props: HashMap<&str, Variant> = HashMap::new();
        Io::apply(&blkio, &mut props).expect("apply blkio to props");

        assert_eq!(
            props.get(IO_READ_BANDWIDTH_MAX),
            Some(&Variant::ArrayStructU64(vec![Structure::new(
                "/dev/null".into(),
                read_bps
            )]))
        );
        assert_eq!(
            props.get(IO_WRITE_BANDWIDTH_MAX),
            Some(&Variant::ArrayStructU64(vec![Structure::new(
                "/dev/null".into(),
                write_bps
            )]))
        );
        assert_eq!(
            props.get(IO_READ_IOPS_MAX),
            Some(&Variant::ArrayStructU64(vec![Structure::new(
                "/dev/null".into(),
                read_iops
            )]))
        );
        assert_eq!(
            props.get(IO_WRITE_IOPS_MAX),
            Some(&Variant::ArrayStructU64(vec![Structure::new(
                "/dev/null".into(),
                write_iops
            )]))
        );
    }

    #[test]
    fn test_io_apply() {
        let st = stat("/dev/null").expect("stat /dev/null");
        let maj = major(st.st_rdev) as i64;
        let min = minor(st.st_rdev) as i64;
        let rate = 000u64;
        let blkio = LinuxBlockIoBuilder::default()
            .throttle_read_bps_device(vec![
                LinuxThrottleDeviceBuilder::default()
                    .major(maj)
                    .minor(min)
                    .rate(rate)
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap();

        let mut props: HashMap<&str, Variant> = HashMap::new();
        Io::apply(&blkio, &mut props).expect("apply blkio with zero rate");
        assert_eq!(props.len(), 1);
        assert!(props.contains_key(IO_READ_BANDWIDTH_MAX));
        let dbus_struct = props.get(IO_READ_BANDWIDTH_MAX).unwrap();
        assert!(matches!(dbus_struct, Variant::ArrayStructU64(_)))
    }
}
