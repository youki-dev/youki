use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use libcgroups::v2::controller_type::ControllerType;
use oci_spec::runtime::{
    LinuxBlockIoBuilder, LinuxThrottleDeviceBuilder, LinuxWeightDeviceBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, assert_result_eq, test_result};
use tracing::debug;

use super::create_spec;
use crate::utils::test_utils::{CGROUP_ROOT, check_container_created};
use crate::utils::{cgroup_has_file, is_cgroup_v2_with_controller, test_outside_container};

const IO_WEIGHT: &str = "io.weight";
const IO_BFQ_WEIGHT: &str = "io.bfq.weight";
const IO_MAX: &str = "io.max";

const WEIGHT: u16 = 500;
const RATE: u64 = 102400;

fn convert_blkio_weight_to_io_weight(weight: u16) -> u16 {
    (1 + (u32::from(weight) - 10) * 9999 / 990) as u16
}

fn test_device() -> Result<(i64, i64)> {
    let mut entries: Vec<_> = fs::read_dir("/sys/block")
        .context("failed to read /sys/block")?
        .flatten()
        .map(|entry| entry.path().join("dev"))
        .filter(|path| path.exists())
        .collect();
    entries.sort();
    for dev_path in entries {
        let content = fs::read_to_string(&dev_path)
            .with_context(|| format!("failed to read {dev_path:?}"))?;
        if let Some((major, minor)) = content.trim().split_once(':')
            && let (Ok(major), Ok(minor)) =
                (major.trim().parse::<i64>(), minor.trim().parse::<i64>())
        {
            return Ok((major, minor));
        }
    }
    bail!("no block device found under /sys/block")
}

fn cgroup_dir_for_pid(pid: i32) -> Result<PathBuf> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .with_context(|| format!("failed to read /proc/{pid}/cgroup"))?;
    for line in content.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            return Ok(PathBuf::from(CGROUP_ROOT).join(path.trim_start_matches('/')));
        }
    }
    bail!("no unified cgroup entry in /proc/{pid}/cgroup: {content:?}")
}

fn read_cgroup_file(dir: &Path, cgroup_file: &str) -> Result<String> {
    let path = dir.join(cgroup_file);
    debug!("reading value from {:?}", path);
    let content = fs::read_to_string(&path).with_context(|| format!("failed to read {path:?}"))?;
    Ok(content.trim().to_owned())
}

fn check_io_weight(dir: &Path, expected_weight: u16) -> Result<()> {
    if dir.join(IO_BFQ_WEIGHT).exists() {
        let data = read_cgroup_file(dir, IO_BFQ_WEIGHT)?;
        // io.bfq.weight prints `default N` on the first line, followed by any
        // per-device entries. Only the default line reflects the cgroup's
        // weight, so match it exactly.
        let expected = format!("default {expected_weight}");
        if data.lines().next() != Some(expected.as_str()) {
            bail!("unexpected io bfq weight: expected {expected:?}, got {data:?}");
        }
        return Ok(());
    }

    let data = read_cgroup_file(dir, IO_WEIGHT)?;
    // io.weight reads as e.g. "default 100" or "default 4950" — the numeric
    // token may be second, so pick the first parseable token.
    let actual: u16 = data
        .split_whitespace()
        .filter_map(|token| {
            token
                .strip_prefix("default")
                .unwrap_or(token)
                .trim()
                .parse::<u16>()
                .ok()
        })
        .next()
        .with_context(|| format!("failed to parse {data:?}"))?;
    let expected = convert_blkio_weight_to_io_weight(expected_weight);
    assert_result_eq!(expected, actual, "unexpected io weight")
}

fn check_io_weight_device(dir: &Path, major: i64, minor: i64, weight: u16) -> Result<()> {
    let data = read_cgroup_file(dir, IO_BFQ_WEIGHT)?;
    let expected = format!("{major}:{minor} {weight}");
    if !data.lines().any(|line| line.trim() == expected) {
        bail!("expected {IO_BFQ_WEIGHT} to contain {expected:?}, got {data:?}");
    }
    Ok(())
}

fn check_io_max(dir: &Path, major: i64, minor: i64, key: &str, rate: u64) -> Result<()> {
    let data = read_cgroup_file(dir, IO_MAX)?;
    // io.max prints one line per device with all keys, e.g.
    // `253:0 rbps=max wbps=max riops=102400 wiops=max`.
    let prefix = format!("{major}:{minor}");
    let expected = format!("{key}={rate}");
    if !data.lines().any(|line| {
        line.split_whitespace().next() == Some(prefix.as_str()) && line.contains(expected.as_str())
    }) {
        bail!("expected {IO_MAX} to contain {prefix} {expected}, got {data:?}");
    }
    Ok(())
}

fn check_container_in_relative_cgroup(pid: i32, cgroup_name: &str) -> Result<()> {
    let expected = cgroup_name.trim_start_matches('/');
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .with_context(|| format!("failed to read /proc/{pid}/cgroup"))?;
    if content.lines().any(|line| {
        line.strip_prefix("0::")
            .map(|path| path.trim_start_matches('/').ends_with(expected))
            .unwrap_or(false)
    }) {
        return Ok(());
    }
    bail!("expected /proc/{pid}/cgroup to end with {expected}, got {content:?}")
}

fn container_pid(data: &crate::utils::test_utils::ContainerData) -> Result<i32> {
    data.state
        .as_ref()
        .and_then(|state| state.pid)
        .with_context(|| format!("container pid missing: {:?}", data.state_err))
}

fn test_io_weight_set() -> TestResult {
    const CGROUP_NAME: &str = "runtime-test/test_io_weight_set";
    let block_io = test_result!(
        LinuxBlockIoBuilder::default()
            .weight(WEIGHT)
            .build()
            .context("failed to build block io spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, block_io));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        let pid = test_result!(container_pid(&data));
        test_result!(check_container_in_relative_cgroup(pid, CGROUP_NAME));
        let dir = test_result!(cgroup_dir_for_pid(pid));
        test_result!(check_io_weight(&dir, WEIGHT));
        TestResult::Passed
    })
}

fn test_io_weight_device_set() -> TestResult {
    const CGROUP_NAME: &str = "runtime-test/test_io_weight_device_set";
    let (major, minor) = test_result!(test_device());
    let block_io = test_result!(
        LinuxBlockIoBuilder::default()
            .weight_device(vec![test_result!(
                LinuxWeightDeviceBuilder::default()
                    .major(major)
                    .minor(minor)
                    .weight(WEIGHT)
                    .build()
                    .context("failed to build weight device spec")
            ),])
            .build()
            .context("failed to build block io spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, block_io));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        let pid = test_result!(container_pid(&data));
        test_result!(check_container_in_relative_cgroup(pid, CGROUP_NAME));
        let dir = test_result!(cgroup_dir_for_pid(pid));
        test_result!(check_io_weight_device(&dir, major, minor, WEIGHT));
        TestResult::Passed
    })
}

fn test_io_throttle_read_bps_set() -> TestResult {
    const CGROUP_NAME: &str = "runtime-test/test_io_throttle_read_bps_set";
    let (major, minor) = test_result!(test_device());
    let block_io = test_result!(
        LinuxBlockIoBuilder::default()
            .throttle_read_bps_device(vec![test_result!(
                LinuxThrottleDeviceBuilder::default()
                    .major(major)
                    .minor(minor)
                    .rate(RATE)
                    .build()
                    .context("failed to build throttle device spec")
            ),])
            .build()
            .context("failed to build block io spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, block_io));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        let pid = test_result!(container_pid(&data));
        test_result!(check_container_in_relative_cgroup(pid, CGROUP_NAME));
        let dir = test_result!(cgroup_dir_for_pid(pid));
        test_result!(check_io_max(&dir, major, minor, "rbps", RATE));
        TestResult::Passed
    })
}

fn test_io_throttle_write_bps_set() -> TestResult {
    const CGROUP_NAME: &str = "runtime-test/test_io_throttle_write_bps_set";
    let (major, minor) = test_result!(test_device());
    let block_io = test_result!(
        LinuxBlockIoBuilder::default()
            .throttle_write_bps_device(vec![test_result!(
                LinuxThrottleDeviceBuilder::default()
                    .major(major)
                    .minor(minor)
                    .rate(RATE)
                    .build()
                    .context("failed to build throttle device spec")
            ),])
            .build()
            .context("failed to build block io spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, block_io));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        let pid = test_result!(container_pid(&data));
        test_result!(check_container_in_relative_cgroup(pid, CGROUP_NAME));
        let dir = test_result!(cgroup_dir_for_pid(pid));
        test_result!(check_io_max(&dir, major, minor, "wbps", RATE));
        TestResult::Passed
    })
}

fn test_io_throttle_read_iops_set() -> TestResult {
    const CGROUP_NAME: &str = "runtime-test/test_io_throttle_read_iops_set";
    let (major, minor) = test_result!(test_device());
    let block_io = test_result!(
        LinuxBlockIoBuilder::default()
            .throttle_read_iops_device(vec![test_result!(
                LinuxThrottleDeviceBuilder::default()
                    .major(major)
                    .minor(minor)
                    .rate(RATE)
                    .build()
                    .context("failed to build throttle device spec")
            ),])
            .build()
            .context("failed to build block io spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, block_io));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        let pid = test_result!(container_pid(&data));
        test_result!(check_container_in_relative_cgroup(pid, CGROUP_NAME));
        let dir = test_result!(cgroup_dir_for_pid(pid));
        test_result!(check_io_max(&dir, major, minor, "riops", RATE));
        TestResult::Passed
    })
}

fn test_io_throttle_write_iops_set() -> TestResult {
    const CGROUP_NAME: &str = "runtime-test/test_io_throttle_write_iops_set";
    let (major, minor) = test_result!(test_device());
    let block_io = test_result!(
        LinuxBlockIoBuilder::default()
            .throttle_write_iops_device(vec![test_result!(
                LinuxThrottleDeviceBuilder::default()
                    .major(major)
                    .minor(minor)
                    .rate(RATE)
                    .build()
                    .context("failed to build throttle device spec")
            ),])
            .build()
            .context("failed to build block io spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, block_io));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        let pid = test_result!(container_pid(&data));
        test_result!(check_container_in_relative_cgroup(pid, CGROUP_NAME));
        let dir = test_result!(cgroup_dir_for_pid(pid));
        test_result!(check_io_max(&dir, major, minor, "wiops", RATE));
        TestResult::Passed
    })
}

fn test_relative_blkio() -> TestResult {
    const CGROUP_NAME: &str = "runtime-test/test_relative_blkio";
    let (major, minor) = test_result!(test_device());
    let block_io = test_result!(
        LinuxBlockIoBuilder::default()
            .weight(WEIGHT)
            .weight_device(vec![test_result!(
                LinuxWeightDeviceBuilder::default()
                    .major(major)
                    .minor(minor)
                    .weight(WEIGHT)
                    .build()
                    .context("failed to build weight device spec")
            ),])
            .throttle_read_bps_device(vec![test_result!(
                LinuxThrottleDeviceBuilder::default()
                    .major(major)
                    .minor(minor)
                    .rate(RATE)
                    .build()
                    .context("failed to build throttle device spec")
            ),])
            .throttle_write_bps_device(vec![test_result!(
                LinuxThrottleDeviceBuilder::default()
                    .major(major)
                    .minor(minor)
                    .rate(RATE)
                    .build()
                    .context("failed to build throttle device spec")
            ),])
            .throttle_read_iops_device(vec![test_result!(
                LinuxThrottleDeviceBuilder::default()
                    .major(major)
                    .minor(minor)
                    .rate(RATE)
                    .build()
                    .context("failed to build throttle device spec")
            ),])
            .throttle_write_iops_device(vec![test_result!(
                LinuxThrottleDeviceBuilder::default()
                    .major(major)
                    .minor(minor)
                    .rate(RATE)
                    .build()
                    .context("failed to build throttle device spec")
            ),])
            .build()
            .context("failed to build block io spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, block_io));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        let pid = test_result!(container_pid(&data));
        test_result!(check_container_in_relative_cgroup(pid, CGROUP_NAME));
        let dir = test_result!(cgroup_dir_for_pid(pid));
        test_result!(check_io_weight(&dir, WEIGHT));
        test_result!(check_io_weight_device(&dir, major, minor, WEIGHT));
        test_result!(check_io_max(&dir, major, minor, "rbps", RATE));
        test_result!(check_io_max(&dir, major, minor, "wbps", RATE));
        test_result!(check_io_max(&dir, major, minor, "riops", RATE));
        test_result!(check_io_max(&dir, major, minor, "wiops", RATE));
        TestResult::Passed
    })
}

fn can_run() -> bool {
    is_cgroup_v2_with_controller(ControllerType::Io)
}

fn can_run_bfq() -> bool {
    can_run() && cgroup_has_file(IO_BFQ_WEIGHT)
}

// The default io.weight may be written through either io.bfq.weight (BFQ) or
// io.weight (iocost). On kernels with the io controller but neither interface
// (no BFQ, no iocost), youki's write at crates/libcgroups/src/v2/io.rs fails and
// the container cannot start, so the test must be skipped there.
fn can_run_io_weight() -> bool {
    can_run() && (cgroup_has_file(IO_BFQ_WEIGHT) || cgroup_has_file(IO_WEIGHT))
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v2_blkio");

    let test_io_weight_set = ConditionalTest::new(
        "test_io_weight_set",
        Box::new(can_run_io_weight),
        Box::new(test_io_weight_set),
    );
    let test_io_weight_device_set = ConditionalTest::new(
        "test_io_weight_device_set",
        Box::new(can_run_bfq),
        Box::new(test_io_weight_device_set),
    );
    let test_io_throttle_read_bps_set = ConditionalTest::new(
        "test_io_throttle_read_bps_set",
        Box::new(can_run),
        Box::new(test_io_throttle_read_bps_set),
    );
    let test_io_throttle_write_bps_set = ConditionalTest::new(
        "test_io_throttle_write_bps_set",
        Box::new(can_run),
        Box::new(test_io_throttle_write_bps_set),
    );
    let test_io_throttle_read_iops_set = ConditionalTest::new(
        "test_io_throttle_read_iops_set",
        Box::new(can_run),
        Box::new(test_io_throttle_read_iops_set),
    );
    let test_io_throttle_write_iops_set = ConditionalTest::new(
        "test_io_throttle_write_iops_set",
        Box::new(can_run),
        Box::new(test_io_throttle_write_iops_set),
    );
    let test_relative_blkio = ConditionalTest::new(
        "test_linux_cgroups_relative_blkio",
        Box::new(can_run_bfq),
        Box::new(test_relative_blkio),
    );

    test_group.add(vec![
        Box::new(test_io_weight_set),
        Box::new(test_io_weight_device_set),
        Box::new(test_io_throttle_read_bps_set),
        Box::new(test_io_throttle_write_bps_set),
        Box::new(test_io_throttle_read_iops_set),
        Box::new(test_io_throttle_write_iops_set),
        Box::new(test_relative_blkio),
    ]);
    test_group
}
