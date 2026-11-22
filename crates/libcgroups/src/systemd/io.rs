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
pub const IO_WEIGHT: &str = "IOWeight";

#[derive(thiserror::Error, Debug)]
pub enum SystemdIoError {
    #[error("File path for specified device with major:{0} , minor:{1} not found")]
    DeviceNotFound(i64, i64),
    #[error("invalid weight {0}: must be in range [10, 1000]")]
    InvalidWeight(u16),
}

/// Converts a weight in the BFQ scale ([1, 1000], e.g. a `resources.blockIO.weight` or a
/// plain `io.bfq.weight` value) to the `IOWeight` property such that systemd writes the
/// given weight to `io.bfq.weight`.
///
/// systemd scales `IOWeight` for BFQ in `BFQ_WEIGHT()` (src/basic/cgroup-util.h): identity
/// up to the default of 100, then `100 + (io_weight - 100) * 900 / 9900`, which is exactly
/// `100 + (io_weight - 100) / 11`. Sending the pre-image `100 + (weight - 100) * 11` above
/// 100 therefore makes the scaled value equal the requested weight for every integer weight
/// in [1, 1000] (the multiplication and division are exact, so no rounding is involved).
/// The property is also what keeps the weight after systemd applies the unit again: a value
/// written to cgroupfs only is reset to the `IOWeight` systemd holds, or to the default when
/// the unit has no `IOWeight`.
pub fn bfq_weight_to_io_weight(weight: u16) -> u64 {
    if weight <= 100 {
        u64::from(weight)
    } else {
        100 + (u64::from(weight) - 100) * 11
    }
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
        if let Some(weight) = blkio.weight() {
            // A weight of 0 is unset, as in the cgroupfs driver.
            if weight != 0 {
                if !(10..=1000).contains(&weight) {
                    return Err(SystemdIoError::InvalidWeight(weight));
                }
                // Only the property is sent; the weight is not written to cgroupfs as well.
                // systemd is the single writer of the io controller's weight files and derives
                // both io.bfq.weight (where the kernel has it) and io.weight from IOWeight, so
                // the two files always stay consistent with each other.
                properties.insert(IO_WEIGHT, Variant::U64(bfq_weight_to_io_weight(weight)));
            }
        }

        let mut apply_limits = |devices: &[LinuxThrottleDevice],
                                key|
         -> Result<(), SystemdIoError> {
            let limits = devices
                .iter()
                .map(|d| {
                    let rate = d.rate();
                    let dev = match dev_path_from_major_minor(d.major(), d.minor()) {
                        Some(path) => path,
                        None => return Err(SystemdIoError::DeviceNotFound(d.major(), d.minor())),
                    };
                    Ok(Structure::new(dev, rate))
                })
                .collect::<Result<Vec<Structure<u64>>, SystemdIoError>>()?;
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

    #[test]
    fn test_apply_inserts_io_weight() {
        // The property has to hold the BFQ pre-image of the spec weight, which is what makes
        // systemd write the spec weight itself to io.bfq.weight.
        let blkio = LinuxBlockIoBuilder::default()
            .weight(500u16)
            .build()
            .expect("build blkio spec");
        let mut props: HashMap<&str, Variant> = HashMap::new();

        Io::apply(&blkio, &mut props).expect("apply blkio to props");

        assert_eq!(props.get(IO_WEIGHT), Some(&Variant::U64(4500)));
    }

    #[test]
    fn test_apply_weight_zero_is_a_noop() {
        let blkio = LinuxBlockIoBuilder::default()
            .weight(0u16)
            .build()
            .expect("build blkio spec");
        let mut props: HashMap<&str, Variant> = HashMap::new();

        Io::apply(&blkio, &mut props).expect("weight 0 must succeed as a no-op");

        assert!(props.is_empty());
    }

    #[test]
    fn test_apply_rejects_weight_out_of_range() {
        for weight in [1u16, 9, 1001, u16::MAX] {
            let blkio = LinuxBlockIoBuilder::default()
                .weight(weight)
                .build()
                .expect("build blkio spec");
            let mut props: HashMap<&str, Variant> = HashMap::new();

            let err = Io::apply(&blkio, &mut props).expect_err("weight must be rejected");

            assert!(
                matches!(err, SystemdIoError::InvalidWeight(v) if v == weight),
                "unexpected error for weight {weight}: {err:?}"
            );
            assert!(props.is_empty(), "weight {weight}");
        }
    }

    #[test]
    fn test_bfq_weight_to_io_weight() {
        // Segment boundaries of systemd's BFQ_WEIGHT() and the ends of the valid ranges.
        for (weight, expected) in [
            (1u16, 1u64),
            (10, 10),
            (100, 100),
            (101, 111),
            (500, 4500),
            (750, 7250),
            (1000, 10000),
        ] {
            assert_eq!(bfq_weight_to_io_weight(weight), expected, "weight {weight}");
        }
    }

    #[test]
    fn test_bfq_weight_to_io_weight_round_trips() {
        // What systemd does with the property (BFQ_WEIGHT() in src/basic/cgroup-util.h).
        fn systemd_bfq_weight(io_weight: u64) -> u64 {
            if io_weight <= 100 {
                io_weight
            } else {
                100 + (io_weight - 100) * 900 / 9900
            }
        }

        for weight in 1..=1000u16 {
            let io_weight = bfq_weight_to_io_weight(weight);
            assert!(
                (1..=10000).contains(&io_weight),
                "weight {weight}: IOWeight {io_weight} is out of systemd's range"
            );
            assert_eq!(
                systemd_bfq_weight(io_weight),
                u64::from(weight),
                "weight {weight}: IOWeight {io_weight} was scaled back"
            );
        }
    }
}
