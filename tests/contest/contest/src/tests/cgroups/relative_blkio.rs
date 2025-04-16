use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use oci_spec::runtime::{
    LinuxBlockIo, LinuxBlockIoBuilder, LinuxBuilder, LinuxResourcesBuilder,
    LinuxThrottleDeviceBuilder, LinuxWeightDeviceBuilder, Spec, SpecBuilder,
};
use test_framework::{test_result, ConditionalTest, TestGroup, TestResult};

use crate::utils::{
    test_outside_container,
    test_utils::{check_container_created, CGROUP_ROOT},
};

#[derive(Debug, Default)]
struct WeightDevice {
    major: i64,
    minor: i64,
    weight: Option<u16>,
    leaf_weight: Option<u16>,
}

#[derive(Debug, Default)]
struct ThrottleDevice {
    major: i64,
    minor: i64,
    rate: u64,
}

#[derive(Debug, Default)]
struct BlockIO {
    weight: u16,
    leaf_weight: u16,
    weight_devices: Vec<WeightDevice>,
    throttle_read_bps_devices: Vec<ThrottleDevice>,
    throttle_write_bps_devices: Vec<ThrottleDevice>,
    throttle_read_iops_devices: Vec<ThrottleDevice>,
    throttle_write_iops_devices: Vec<ThrottleDevice>,
}

fn can_run() -> bool {
    Path::new("/sys/fs/cgroup/blkio").exists()
}

fn supports_weight() -> bool {
    Path::new("/sys/fs/cgroup/blkio/blkio.weight").exists()
}

fn supports_weight_devices() -> bool {
    Path::new("/sys/fs/cgroup/blkio/blkio.weight_devices").exists()
}

fn supports_throttle_bps() -> bool {
    Path::new("/sys/fs/cgroup/blkio/blkio.throttle.read_bps_device").exists()
}

fn supports_throttle_iops() -> bool {
    Path::new("/sys/fs/cgroup/blkio/blkio.throttle.read_iops_device").exists()
}

fn parse_device_data<'a>(device_type: &'static str, line: &'a str) -> Result<(i64, i64, &'a str)> {
    let (device_id, value) = line
        .split_once(' ')
        .with_context(|| format!("invalid {device_type} device format : found {line}"))?;
    let (major_str, minor_str) = device_id.split_once(':').with_context(|| {
        format!("invalid major-minor number format for {device_type} device : found {device_id}")
    })?;

    let major: i64 = major_str.parse().with_context(|| {
        format!("Error in parsing {device_type} device major number : found {major_str}")
    })?;
    let minor: i64 = minor_str.parse().with_context(|| {
        format!("Error in parsing {device_type} device minor number : found {minor_str}")
    })?;

    Ok((major, minor, value))
}

fn create_spec(cgroup_name: &str, block_io: LinuxBlockIo) -> Result<Spec> {
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(Path::new("testdir/runtime-test/container").join(cgroup_name))
                .resources(
                    LinuxResourcesBuilder::default()
                        .block_io(block_io)
                        .build()
                        .context("failed to build resource spec")?,
                )
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn get_blkio_data(path: &Path) -> Result<BlockIO> {
    let mut device = BlockIO::default();

    if supports_weight() {
        let weight_path = path.join("blkio.weight");
        let weight_string = fs::read_to_string(&weight_path)
            .with_context(|| format!("error in reading block io weight from {weight_path:?}"))?;
        device.weight = weight_string
            .parse()
            .with_context(|| format!("error in parsing block io weight : found {weight_string}"))?;

        let leaf_weight_path = path.join("blkio.leaf_weight");
        let leaf_weight_string = fs::read_to_string(&leaf_weight_path).with_context(|| {
            format!("error in reading block io leaf weight from {leaf_weight_path:?}")
        })?;
        device.leaf_weight = leaf_weight_string.parse().with_context(|| {
            format!("error in parsing block io weight : found {leaf_weight_string}")
        })?;
    }

    if supports_weight_devices() {
        let device_weight_path = path.join("blkio.weight_device");
        let device_weight_string = fs::read_to_string(&device_weight_path).with_context(|| {
            format!("error in reading block io weight device from {device_weight_path:?}")
        })?;
        let mut weight_devices = Vec::new();
        for line in device_weight_string.lines() {
            let (major, minor, weight_str) = parse_device_data("weight", line)?;
            weight_devices.push(WeightDevice {
                major,
                minor,
                weight: Some(weight_str.parse().with_context(|| {
                    format!("error in parsing weight of weight device, found {weight_str}")
                })?),
                leaf_weight: None,
            });
        }

        let device_leaf_weight_path = path.join("blkio.leaf_weight_device");
        let device_leaf_weight_string =
            fs::read_to_string(&device_leaf_weight_path).with_context(|| {
                format!(
                    "error in reading block io leaf weight device from {device_leaf_weight_path:?}"
                )
            })?;

        for line in device_leaf_weight_string.lines() {
            let (major, minor, weight_str) = parse_device_data("weight", line)?;
            let leaf_weight: u16 = weight_str.parse().with_context(|| {
                format!("error in parsing leaf weight of weight device : found {weight_str}")
            })?;
            let mut found = false;
            for dev in &mut weight_devices {
                if dev.major == major && dev.minor == minor {
                    dev.leaf_weight = Some(leaf_weight);
                    found = true;
                }
            }
            if !found {
                weight_devices.push(WeightDevice {
                    major,
                    minor,
                    weight: None,
                    leaf_weight: Some(leaf_weight),
                });
            }
        }

        device.weight_devices = weight_devices;
    }

    if supports_throttle_bps() {
        let throttle_read_bps_path = path.join("blkio.throttle.read_bps_device");
        let throttle_read_bps_string =
            fs::read_to_string(&throttle_read_bps_path).with_context(|| {
                format!(
                    "error in reading block io read bps device from  {throttle_read_bps_path:?}"
                )
            })?;
        let mut throttle_devices = Vec::new();
        for line in throttle_read_bps_string.lines() {
            let (major, minor, rate_str) = parse_device_data("throttle read bps", line)?;
            throttle_devices.push(ThrottleDevice {
                major,
                minor,
                rate: rate_str.parse().with_context(|| {
                    format!("error in parsing throttle read bps rate : found {rate_str}")
                })?,
            });
        }
        device.throttle_read_bps_devices = throttle_devices;

        let throttle_write_bps_path = path.join("blkio.throttle.write_bps_device");
        let throttle_write_bps_string =
            fs::read_to_string(&throttle_write_bps_path).with_context(|| {
                format!(
                    "error in reading block io write bps device from {throttle_write_bps_path:?}"
                )
            })?;
        let mut throttle_devices = Vec::new();
        for line in throttle_write_bps_string.lines() {
            let (major, minor, rate_str) = parse_device_data("throttle write bps", line)?;
            throttle_devices.push(ThrottleDevice {
                major,
                minor,
                rate: rate_str.parse().with_context(|| {
                    format!("error in parsing throttle write bps rate : found {rate_str}")
                })?,
            });
        }
        device.throttle_write_bps_devices = throttle_devices;
    }

    if supports_throttle_iops() {
        let throttle_read_iops_path = path.join("blkio.throttle.read_iops_device");
        let throttle_read_iops_string =
            fs::read_to_string(&throttle_read_iops_path).with_context(|| {
                format!(
                    "error in reading block io read iops device from  {throttle_read_iops_path:?}"
                )
            })?;
        let mut throttle_devices = Vec::new();
        for line in throttle_read_iops_string.lines() {
            let (major, minor, rate_str) = parse_device_data("throttle read iops", line)?;
            throttle_devices.push(ThrottleDevice {
                major,
                minor,
                rate: rate_str.parse().with_context(|| {
                    format!("error in parsing throttle read iops rate : found {rate_str}")
                })?,
            });
        }
        device.throttle_read_iops_devices = throttle_devices;

        let throttle_write_iops_path = path.join("blkio.throttle.write_iops_device");
        let throttle_write_iops_string = fs::read_to_string(&throttle_write_iops_path)
            .with_context(|| {
                format!(
                    "error in reading block io write iops device from {throttle_write_iops_path:?}"
                )
            })?;
        let mut throttle_devices = Vec::new();
        for line in throttle_write_iops_string.lines() {
            let (major, minor, rate_str) = parse_device_data("throttle write iop", line)?;
            throttle_devices.push(ThrottleDevice {
                major,
                minor,
                rate: rate_str.parse().with_context(|| {
                    format!("error in parsing throttle write iops rate : found {rate_str}")
                })?,
            });
        }
        device.throttle_write_iops_devices = throttle_devices;
    }

    Ok(device)
}

fn validate_block_io(cgroup_name: &str, spec: &Spec) -> Result<()> {
    let cgroup_path = PathBuf::from(CGROUP_ROOT)
        .join("blkio/runtime-test")
        .join(cgroup_name);
    let block_io = get_blkio_data(&cgroup_path)?;

    let resources = spec.linux().as_ref().unwrap().resources().as_ref().unwrap();
    let spec_block_io = resources.block_io().as_ref().unwrap();
    if supports_weight() {
        if spec_block_io.weight().is_none() {
            bail!("spec block io weight is none");
        }
        if spec_block_io.weight().unwrap() != block_io.weight {
            bail!(
                "block io weight is set incorrectly, expected {}, actual {}",
                spec_block_io.weight().unwrap(),
                block_io.weight,
            );
        }
        if spec_block_io.leaf_weight().is_none() {
            bail!("spec block io leaf weight is none");
        }
        if spec_block_io.leaf_weight().unwrap() != block_io.leaf_weight {
            bail!(
                "block io leaf weight is set incorrectly, expected {}, actual {}",
                spec_block_io.leaf_weight().unwrap(),
                block_io.leaf_weight,
            );
        }
    }

    if supports_weight_devices() {
        for spec_device in spec_block_io.weight_device().as_ref().unwrap() {
            let spec_major = spec_device.major();
            let spec_minor = spec_device.minor();
            let mut found = false;
            for device in &block_io.weight_devices {
                if device.major == spec_major && device.minor == spec_minor {
                    found = true;
                    if device.weight != spec_device.weight() {
                        bail!(
                            "blkio weight is set incorrectly for device {}:{}, expected {:?}, found {:?}",
                            spec_major,
                            spec_minor,
                            spec_device.weight(),
                            device.weight
                        );
                    }
                    if device.leaf_weight != spec_device.leaf_weight() {
                        bail!(
                            "blkio leaf weight is set incorrectly for device {}:{}, expected {:?}, found {:?}",
                            spec_major,
                            spec_minor,
                            spec_device.leaf_weight(),
                            device.leaf_weight
                        );
                    }
                    break;
                }
            }
            if !found {
                bail!(
                    "blkio weight device {}:{} not found, exists in spec",
                    spec_major,
                    spec_minor
                );
            }
        }
    }
    if supports_throttle_bps() {
        for spec_device in spec_block_io.throttle_read_bps_device().as_ref().unwrap() {
            let spec_major = spec_device.major();
            let spec_minor = spec_device.minor();
            let mut found = false;
            for device in &block_io.throttle_read_bps_devices {
                if device.major == spec_major && device.minor == spec_minor {
                    found = true;
                    if device.rate != spec_device.rate() {
                        bail!(
                            "blkio throttle read bps rate is set incorrectly for device {}:{}, expected {}, found {}",
                            spec_major,
                            spec_minor,
                            spec_device.rate(),
                            device.rate
                        );
                    }
                    break;
                }
            }
            if !found {
                bail!(
                    "blkio throttle read bps device {}:{} not found, exists in spec",
                    spec_major,
                    spec_minor
                );
            }
        }
        for spec_device in spec_block_io.throttle_write_bps_device().as_ref().unwrap() {
            let spec_major = spec_device.major();
            let spec_minor = spec_device.minor();
            let mut found = false;
            for device in &block_io.throttle_write_bps_devices {
                if device.major == spec_major && device.minor == spec_minor {
                    found = true;
                    if device.rate != spec_device.rate() {
                        bail!(
                            "blkio throttle write bps rate is set incorrectly for device {}:{}, expected {}, found {}",
                            spec_major,
                            spec_minor,
                            spec_device.rate(),
                            device.rate
                        );
                    }
                    break;
                }
            }
            if !found {
                bail!(
                    "blkio throttle write bps device {}:{} not found, exists in spec",
                    spec_major,
                    spec_minor
                );
            }
        }
    }

    if supports_throttle_iops() {
        for spec_device in spec_block_io.throttle_read_iops_device().as_ref().unwrap() {
            let spec_major = spec_device.major();
            let spec_minor = spec_device.minor();
            let mut found = false;
            for device in &block_io.throttle_read_iops_devices {
                if device.major == spec_major && device.minor == spec_minor {
                    found = true;
                    if device.rate != spec_device.rate() {
                        bail!(
                        "blkio throttle read iops rate is set incorrectly for device {}:{}, expected {}, found {}",
                        spec_major,
                        spec_minor,
                        spec_device.rate(),
                        device.rate
                    );
                    }
                    break;
                }
            }
            if !found {
                bail!(
                    "blkio throttle read iops device {}:{} not found, exists in spec",
                    spec_major,
                    spec_minor
                );
            }
        }

        for spec_device in spec_block_io.throttle_write_iops_device().as_ref().unwrap() {
            let spec_major = spec_device.major();
            let spec_minor = spec_device.minor();
            let mut found = false;
            for device in &block_io.throttle_write_iops_devices {
                if device.major == spec_major && device.minor == spec_minor {
                    found = true;
                    if device.rate != spec_device.rate() {
                        bail!(
                        "blkio throttle write iops rate is set incorrectly for device {}:{}, expected {}, found {}",
                        spec_major,
                        spec_minor,
                        spec_device.rate(),
                        device.rate
                    );
                    }
                    break;
                }
            }
            if !found {
                bail!(
                    "blkio throttle write iops device {}:{} not found, exists in spec",
                    spec_major,
                    spec_minor
                );
            }
        }
    }

    Ok(())
}

fn test_relative_blkio(test_name: &str, rate: u64, empty: bool) -> TestResult {
    let weight: u16 = 500;
    let leaf_weight: u16 = 300;
    let major: i64 = 8;
    let minor: i64 = 0;

    let mut block_io_builder = LinuxBlockIoBuilder::default();

    if !empty && supports_weight() {
        block_io_builder = block_io_builder.weight(weight).leaf_weight(leaf_weight)
    }
    if supports_weight_devices() {
        block_io_builder = block_io_builder.weight_device(vec![
            LinuxWeightDeviceBuilder::default()
                .major(major)
                .minor(minor)
                .weight(weight)
                .build()
                .unwrap(),
            LinuxWeightDeviceBuilder::default()
                .major(major)
                .minor(minor)
                .leaf_weight(leaf_weight)
                .build()
                .unwrap(),
        ])
    }
    if supports_throttle_bps() {
        block_io_builder = block_io_builder
            .throttle_read_bps_device(vec![LinuxThrottleDeviceBuilder::default()
                .major(major)
                .minor(minor)
                .rate(rate)
                .build()
                .unwrap()])
            .throttle_write_bps_device(vec![LinuxThrottleDeviceBuilder::default()
                .major(major)
                .minor(minor)
                .rate(rate)
                .build()
                .unwrap()])
    }
    if supports_throttle_iops() {
        block_io_builder = block_io_builder
            .throttle_read_iops_device(vec![LinuxThrottleDeviceBuilder::default()
                .major(major)
                .minor(minor)
                .rate(rate)
                .build()
                .unwrap()])
            .throttle_write_iops_device(vec![LinuxThrottleDeviceBuilder::default()
                .major(major)
                .minor(minor)
                .rate(rate)
                .build()
                .unwrap()]);
    }
    let spec = create_spec(
        test_name,
        block_io_builder
            .build()
            .context("failed to build block io spec")
            .unwrap(),
    )
    .unwrap();

    test_outside_container(spec.clone(), &|data| {
        test_result!(check_container_created(&data));
        test_result!(validate_block_io(test_name, &spec));
        TestResult::Passed
    })
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v1_relative_blkio");
    let non_empty_100kb = ConditionalTest::new(
        "non_empty_100kb",
        Box::new(can_run),
        Box::new(|| test_relative_blkio("non_empty_100kb", 102400, false)),
    );
    test_group.add(vec![Box::new(non_empty_100kb)]);
    test_group
}
