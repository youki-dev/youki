//! Tests for `resources.unified` under the systemd cgroup manager.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use libcgroups::v2::controller_type::ControllerType;
use oci_spec::runtime::{LinuxBuilder, LinuxResourcesBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use super::{SCOPE_PREFIX, can_run, show_property, unit_name};
use crate::utils::test_utils::{CGROUP_ROOT, CreateOptions, check_container_created};
use crate::utils::{
    block_device_numbers, is_cgroup_v2_with_controller, test_outside_container_with_options,
};

fn create_spec(cgroup_name: &str, unified: &[(&str, &str)]) -> Result<Spec> {
    // systemd cgroupsPath notation: [slice]:[scope prefix]:[name]
    let cgroups_path = PathBuf::from(format!("system.slice:{SCOPE_PREFIX}:{cgroup_name}"));
    let unified: HashMap<String, String> = unified
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "30".to_string()])
                .build()
                .context("failed to build process spec")?,
        )
        .linux(
            LinuxBuilder::default()
                .cgroups_path(cgroups_path)
                .resources(
                    LinuxResourcesBuilder::default()
                        .unified(unified)
                        .build()
                        .context("failed to build resources spec")?,
                )
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")
}

/// Reads a file from the cgroup systemd created for the unit.
fn read_unit_cgroup_file(cgroup_name: &str, file: &str) -> Result<String> {
    let control_group = show_property(&unit_name(cgroup_name), "ControlGroup")?;
    let path = PathBuf::from(CGROUP_ROOT)
        .join(control_group.trim_start_matches('/'))
        .join(file);
    let content = fs::read_to_string(&path).with_context(|| format!("failed to read {path:?}"))?;
    Ok(content.trim().to_string())
}

fn check_file(cgroup_name: &str, file: &str, expected: &str) -> Result<()> {
    let actual = read_unit_cgroup_file(cgroup_name, file)?;
    if actual != expected {
        bail!("expected {file} to be {expected:?}, got {actual:?}");
    }
    Ok(())
}

fn check_property(cgroup_name: &str, property: &str, expected: &str) -> Result<()> {
    let actual = show_property(&unit_name(cgroup_name), property)?;
    if actual != expected {
        bail!("expected {property}={expected}, but unit has {property}={actual}");
    }
    Ok(())
}

fn run_test(
    cgroup_name: &str,
    unified: &[(&str, &str)],
    check: &dyn Fn() -> Result<()>,
) -> TestResult {
    let spec = test_result!(create_spec(cgroup_name, unified));
    let systemd_cgroup: &[&OsStr] = &[OsStr::new("--systemd-cgroup")];
    let options = CreateOptions::default().with_global_args(systemd_cgroup);

    test_outside_container_with_options(&spec, &options, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check());
        TestResult::Passed
    })
}

/// A key with no systemd property must still reach the cgroup.
fn test_key_without_property_is_written() -> TestResult {
    let cgroup_name = "systemd_unified_key_without_property";
    run_test(cgroup_name, &[("memory.oom.group", "1")], &|| {
        check_file(cgroup_name, "memory.oom.group", "1")
    })
}

/// cpu.weight is already a cgroup v2 weight and must not go through the shares conversion.
fn test_cpu_weight_is_not_converted() -> TestResult {
    let cgroup_name = "systemd_unified_cpu_weight";
    run_test(cgroup_name, &[("cpu.weight", "42")], &|| {
        check_file(cgroup_name, "cpu.weight", "42")?;
        check_property(cgroup_name, "CPUWeight", "42")
    })
}

/// systemd takes the quota per second of cpu time: 50000 of 100000 is 500ms per second.
fn test_cpu_max_quota() -> TestResult {
    let cgroup_name = "systemd_unified_cpu_max_quota";
    run_test(cgroup_name, &[("cpu.max", "50000 100000")], &|| {
        check_file(cgroup_name, "cpu.max", "50000 100000")?;
        check_property(cgroup_name, "CPUQuotaPerSecUSec", "500ms")
    })
}

/// "max" is a valid value for every key that has a systemd property.
fn test_max_values() -> TestResult {
    let cgroup_name = "systemd_unified_max_values";
    run_test(
        cgroup_name,
        &[
            ("cpu.max", "max 100000"),
            ("memory.max", "max"),
            ("pids.max", "max"),
        ],
        &|| {
            check_file(cgroup_name, "cpu.max", "max 100000")?;
            check_file(cgroup_name, "memory.max", "max")?;
            check_file(cgroup_name, "pids.max", "max")?;
            check_property(cgroup_name, "TasksMax", "infinity")
        },
    )
}

/// One io.max value with a line per device; each line needs its own write.
fn test_io_max_multi_device() -> TestResult {
    let cgroup_name = "systemd_unified_io_max_multi_device";
    let devices = test_result!(block_device_numbers(2));
    let ((major1, minor1), (major2, minor2)) = (devices[0], devices[1]);
    let value =
        format!("{major1}:{minor1} riops=333 wiops=444\n{major2}:{minor2} riops=555 wiops=666\n");

    run_test(cgroup_name, &[("io.max", &value)], &|| {
        let content = read_unit_cgroup_file(cgroup_name, "io.max")?;
        for (major, minor, read, write) in [
            (major1, minor1, "riops=333", "wiops=444"),
            (major2, minor2, "riops=555", "wiops=666"),
        ] {
            let device = format!("{major}:{minor}");
            let found = content.lines().any(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                fields.first() == Some(&device.as_str())
                    && fields.contains(&read)
                    && fields.contains(&write)
            });
            if !found {
                bail!("expected io.max to contain {device} {read} {write}, got {content:?}");
            }
        }
        Ok(())
    })
}

fn can_run_io_max_multi_device() -> bool {
    can_run() && is_cgroup_v2_with_controller(ControllerType::Io) && block_device_numbers(2).is_ok()
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_systemd_unified");
    let key_without_property = ConditionalTest::new(
        "key_without_property_is_written",
        Box::new(can_run),
        Box::new(test_key_without_property_is_written),
    );
    let cpu_weight = ConditionalTest::new(
        "cpu_weight_is_not_converted",
        Box::new(can_run),
        Box::new(test_cpu_weight_is_not_converted),
    );
    let cpu_max_quota = ConditionalTest::new(
        "cpu_max_quota",
        Box::new(can_run),
        Box::new(test_cpu_max_quota),
    );
    let max_values =
        ConditionalTest::new("max_values", Box::new(can_run), Box::new(test_max_values));
    let io_max_multi_device = ConditionalTest::new(
        "io_max_multi_device",
        Box::new(can_run_io_max_multi_device),
        Box::new(test_io_max_multi_device),
    );
    test_group.add(vec![
        Box::new(key_without_property),
        Box::new(cpu_weight),
        Box::new(cpu_max_quota),
        Box::new(max_values),
        Box::new(io_max_multi_device),
    ]);
    test_group
}
