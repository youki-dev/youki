//! Tests for `resources.unified` under the systemd cgroup manager.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use libcgroups::v2::controller_type::ControllerType;
use oci_spec::runtime::{LinuxBuilder, LinuxResourcesBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use super::{SCOPE_PREFIX, can_run, show_property, systemd_version, unit_name};
use crate::utils::test_utils::{
    CGROUP_ROOT, CreateOptions, check_container_created, start_container,
};
use crate::utils::{
    block_device_numbers, cgroup_has_file, is_cgroup_v2_with_controller, is_runtime_runc,
    test_outside_container_with_options,
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
    run_test(cgroup_name, &[("cgroup.max.depth", "5")], &|| {
        check_file(cgroup_name, "cgroup.max.depth", "5")
    })
}

/// systemd enables only the controllers it manages for the unit, so the others, such as
/// hugetlb, misc or rdma, have to be enabled for a unified key of theirs to be written.
fn test_root_controllers_are_enabled() -> TestResult {
    let cgroup_name = "systemd_unified_root_controllers";
    run_test(cgroup_name, &[], &|| {
        let root_path = PathBuf::from(CGROUP_ROOT).join("cgroup.controllers");
        let root = fs::read_to_string(&root_path)
            .with_context(|| format!("failed to read {root_path:?}"))?;
        let container = read_unit_cgroup_file(cgroup_name, "cgroup.controllers")?;
        let missing: Vec<&str> = root
            .split_whitespace()
            .filter(|controller| !container.split_whitespace().any(|c| c == *controller))
            .collect();
        if !missing.is_empty() {
            bail!("expected {missing:?} to be enabled for the container, got {container:?}");
        }
        Ok(())
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

/// memory.swap.max has a property of its own, MemorySwapMax.
fn test_memory_swap_max() -> TestResult {
    let cgroup_name = "systemd_unified_memory_swap_max";
    run_test(cgroup_name, &[("memory.swap.max", "104857600")], &|| {
        check_file(cgroup_name, "memory.swap.max", "104857600")?;
        check_property(cgroup_name, "MemorySwapMax", "104857600")
    })
}

/// systemd knows MemoryZSwapMax since 253. runc 1.5.2, which the validation job uses, does
/// not send the zswap properties yet, so only the file is checked for it.
fn test_memory_zswap_max() -> TestResult {
    let cgroup_name = "systemd_unified_memory_zswap_max";
    run_test(cgroup_name, &[("memory.zswap.max", "52428800")], &|| {
        check_file(cgroup_name, "memory.zswap.max", "52428800")?;
        if !is_runtime_runc() && systemd_version()? >= 253 {
            check_property(cgroup_name, "MemoryZSwapMax", "52428800")?;
        }
        Ok(())
    })
}

/// systemd knows MemoryZSwapWriteback since 256.
fn test_memory_zswap_writeback() -> TestResult {
    let cgroup_name = "systemd_unified_memory_zswap_writeback";
    run_test(cgroup_name, &[("memory.zswap.writeback", "0")], &|| {
        check_file(cgroup_name, "memory.zswap.writeback", "0")?;
        if !is_runtime_runc() && systemd_version()? >= 256 {
            check_property(cgroup_name, "MemoryZSwapWriteback", "no")?;
        }
        Ok(())
    })
}

/// systemd has no property for cpu.idle. Since 252 a CPUWeight of 0, shown as "idle", makes
/// it set cpu.idle to 1.
fn test_cpu_idle() -> TestResult {
    let cgroup_name = "systemd_unified_cpu_idle";
    run_test(cgroup_name, &[("cpu.idle", "1")], &|| {
        check_file(cgroup_name, "cpu.idle", "1")?;
        if systemd_version()? >= 252 {
            check_property(cgroup_name, "CPUWeight", "idle")?;
        }
        Ok(())
    })
}

/// systemd sets memory.oom.group from OOMPolicy whenever it applies the unit's cgroup
/// settings, so the key also has to reach the unit as OOMPolicy. systemd takes OOMPolicy only
/// when the unit is created; a scope accepts it since 253.
fn test_memory_oom_group() -> TestResult {
    let cgroup_name = "systemd_unified_memory_oom_group";
    run_test(cgroup_name, &[("memory.oom.group", "1")], &|| {
        check_property(cgroup_name, "OOMPolicy", "kill")?;
        check_file(cgroup_name, "memory.oom.group", "1")?;

        // changing a cgroup property makes systemd apply the unit's cgroup settings again
        let unit = unit_name(cgroup_name);
        let output = Command::new("systemctl")
            .args(["set-property", "--runtime", &unit, "CPUWeight=50"])
            .output()
            .with_context(|| format!("failed to run systemctl set-property for {unit}"))?;
        if !output.status.success() {
            bail!(
                "systemctl set-property {unit} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        check_file(cgroup_name, "memory.oom.group", "1")
    })
}

/// With OOMPolicy=kill systemd marks the scope as failed once the kernel OOM killer has
/// killed its processes, and a failed unit stays loaded. Deleting the container has to clear
/// it, or no container can be created with the same cgroupsPath again.
fn test_memory_oom_group_recreate_after_oom_kill() -> TestResult {
    let cgroup_name = "systemd_unified_memory_oom_group_recreate";
    let limit = "33554432";
    let unified = [
        ("memory.oom.group", "1"),
        ("memory.max", limit),
        ("memory.swap.max", "0"),
    ];
    let mut spec = test_result!(create_spec(cgroup_name, &unified));
    // doubles a string until the memory limit is hit
    let hog = "x=0123456789abcdef; while :; do x=$x$x; done";
    spec.set_process(Some(test_result!(
        ProcessBuilder::default()
            .args(["sh", "-c", hog].map(String::from))
            .build()
            .context("failed to build process spec")
    )));
    let systemd_cgroup: &[&OsStr] = &[OsStr::new("--systemd-cgroup")];
    let options = CreateOptions::default().with_global_args(systemd_cgroup);

    let oom_killed = test_outside_container_with_options(&spec, &options, &|data| {
        test_result!(check_container_created(&data));
        // without these the process could use up the memory or the swap of the host
        test_result!(check_file(cgroup_name, "memory.max", limit));
        test_result!(check_file(cgroup_name, "memory.swap.max", "0"));
        test_result!(
            start_container(&data.id, &data.bundle).and_then(|mut child| Ok(child.wait()?))
        );

        // the process never exits on its own, so the unit only stops being active once
        // the process has been killed
        let unit = unit_name(cgroup_name);
        let deadline = Instant::now() + Duration::from_secs(30);
        while test_result!(show_property(&unit, "ActiveState")) == "active" {
            if Instant::now() > deadline {
                return TestResult::Failed(anyhow!("{unit} was not OOM killed"));
            }
            sleep(Duration::from_millis(100));
        }
        TestResult::Passed
    });
    if !matches!(oom_killed, TestResult::Passed) {
        return oom_killed;
    }

    // the same cgroupsPath, so the new container gets a unit of the same name
    run_test(cgroup_name, &[], &|| Ok(()))
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

fn can_run_memory_swap_max() -> bool {
    can_run() && cgroup_has_file("memory.swap.max")
}

fn can_run_memory_zswap_max() -> bool {
    can_run() && cgroup_has_file("memory.zswap.max")
}

fn can_run_memory_zswap_writeback() -> bool {
    can_run() && cgroup_has_file("memory.zswap.writeback")
}

fn can_run_cpu_idle() -> bool {
    can_run() && cgroup_has_file("cpu.idle")
}

fn can_run_memory_oom_group() -> bool {
    can_run() && cgroup_has_file("memory.oom.group") && systemd_version().is_ok_and(|v| v >= 253)
}

fn can_run_memory_oom_group_recreate() -> bool {
    can_run_memory_oom_group() && cgroup_has_file("memory.swap.max")
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
    let root_controllers = ConditionalTest::new(
        "root_controllers_are_enabled",
        Box::new(can_run),
        Box::new(test_root_controllers_are_enabled),
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
    let memory_swap_max = ConditionalTest::new(
        "memory_swap_max",
        Box::new(can_run_memory_swap_max),
        Box::new(test_memory_swap_max),
    );
    let memory_zswap_max = ConditionalTest::new(
        "memory_zswap_max",
        Box::new(can_run_memory_zswap_max),
        Box::new(test_memory_zswap_max),
    );
    let memory_zswap_writeback = ConditionalTest::new(
        "memory_zswap_writeback",
        Box::new(can_run_memory_zswap_writeback),
        Box::new(test_memory_zswap_writeback),
    );
    let cpu_idle = ConditionalTest::new(
        "cpu_idle",
        Box::new(can_run_cpu_idle),
        Box::new(test_cpu_idle),
    );
    let memory_oom_group = ConditionalTest::new(
        "memory_oom_group",
        Box::new(can_run_memory_oom_group),
        Box::new(test_memory_oom_group),
    );
    let memory_oom_group_recreate = ConditionalTest::new(
        "memory_oom_group_recreate_after_oom_kill",
        Box::new(can_run_memory_oom_group_recreate),
        Box::new(test_memory_oom_group_recreate_after_oom_kill),
    );
    let io_max_multi_device = ConditionalTest::new(
        "io_max_multi_device",
        Box::new(can_run_io_max_multi_device),
        Box::new(test_io_max_multi_device),
    );
    test_group.add(vec![
        Box::new(key_without_property),
        Box::new(root_controllers),
        Box::new(cpu_weight),
        Box::new(cpu_max_quota),
        Box::new(max_values),
        Box::new(memory_swap_max),
        Box::new(memory_zswap_max),
        Box::new(memory_zswap_writeback),
        Box::new(cpu_idle),
        Box::new(memory_oom_group),
        Box::new(memory_oom_group_recreate),
        Box::new(io_max_multi_device),
    ]);
    test_group
}

test_framework::register_test_group!(get_test_group);
