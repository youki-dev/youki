//! Tests for the io weight of the systemd cgroup manager.
//!
//! A weight has to reach the unit as the `IOWeight` property, which holds the pre-image of
//! systemd's BFQ scaling. `IOWeight` is what systemd derives the cgroup weight files from
//! when it applies the unit, so without the property the weight is reset to the default the
//! next time systemd applies the unit, which any set-property triggers.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
use libcgroups::v2::controller_type::ControllerType;
use oci_spec::runtime::{
    LinuxBlockIoBuilder, LinuxBuilder, LinuxResources, LinuxResourcesBuilder, ProcessBuilder, Spec,
    SpecBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use super::{SCOPE_PREFIX, can_run, show_property, systemd_version, unit_name};
use crate::utils::test_utils::{CGROUP_ROOT, CreateOptions, check_container_created};
use crate::utils::{
    cgroup_has_file, is_cgroup_v2_with_controller, is_runtime_runc,
    test_outside_container_with_options,
};

const IO_WEIGHT: &str = "io.weight";
const IO_BFQ_WEIGHT: &str = "io.bfq.weight";

fn create_spec(cgroup_name: &str, resources: LinuxResources) -> Result<Spec> {
    // systemd cgroupsPath notation: [slice]:[scope prefix]:[name]
    let cgroups_path = PathBuf::from(format!("system.slice:{SCOPE_PREFIX}:{cgroup_name}"));

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
                .resources(resources)
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")
}

fn block_io_resources(weight: u16) -> Result<LinuxResources> {
    let block_io = LinuxBlockIoBuilder::default()
        .weight(weight)
        .build()
        .context("failed to build block io spec")?;
    LinuxResourcesBuilder::default()
        .block_io(block_io)
        .build()
        .context("failed to build resources spec")
}

fn unified_resources(key: &str, value: &str) -> Result<LinuxResources> {
    let unified: HashMap<String, String> = [(key.to_string(), value.to_string())].into();
    LinuxResourcesBuilder::default()
        .unified(unified)
        .build()
        .context("failed to build resources spec")
}

/// Checks the default weight of a cgroup file of the unit's cgroup, where the kernel has the
/// file: io.bfq.weight needs the BFQ scheduler, io.weight needs iocost.
fn check_default_weight(cgroup_name: &str, file: &str, expected: u64) -> Result<()> {
    let control_group = show_property(&unit_name(cgroup_name), "ControlGroup")?;
    let path = PathBuf::from(CGROUP_ROOT)
        .join(control_group.trim_start_matches('/'))
        .join(file);
    if !path.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&path).with_context(|| format!("failed to read {path:?}"))?;
    // "default N" comes first, followed by any per-device entries, which this test does not
    // set. systemd scales its IOWeight for io.bfq.weight and writes it 1:1 for io.weight.
    let first = content.lines().next().unwrap_or_default().trim();
    let actual: u64 = first
        .strip_prefix("default ")
        .unwrap_or(first)
        .parse()
        .with_context(|| format!("failed to parse {file} value {first:?}"))?;

    if actual != expected {
        bail!("expected {file} to default to {expected}, got {first:?}");
    }
    Ok(())
}

/// `bfq_weight` is the weight the spec asked for and `io_weight` the `IOWeight` property
/// systemd has to hold for its BFQ scaling to write `bfq_weight` to io.bfq.weight:
/// identity up to 100, then `100 + (io_weight - 100) * 900 / 9900`, so the pre-image is
/// `100 + (bfq_weight - 100) * 11`.
fn check_io_weights(cgroup_name: &str, bfq_weight: u16, io_weight: u64) -> Result<()> {
    let actual = show_property(&unit_name(cgroup_name), "IOWeight")?;
    if actual != io_weight.to_string() {
        bail!("expected IOWeight={io_weight}, but unit has IOWeight={actual}");
    }

    check_default_weight(cgroup_name, IO_BFQ_WEIGHT, u64::from(bfq_weight))?;
    check_default_weight(cgroup_name, IO_WEIGHT, io_weight)
}

fn run_test(
    cgroup_name: &str,
    resources: LinuxResources,
    check: &dyn Fn() -> Result<()>,
) -> TestResult {
    let spec = test_result!(create_spec(cgroup_name, resources));
    let systemd_cgroup: &[&OsStr] = &[OsStr::new("--systemd-cgroup")];
    let options = CreateOptions::default().with_global_args(systemd_cgroup);

    test_outside_container_with_options(&spec, &options, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check());
        TestResult::Passed
    })
}

/// A structured weight above the default of 100 goes through the BFQ pre-image.
fn test_block_io_weight() -> TestResult {
    let cgroup_name = "systemd_io_block_io_weight";
    let resources = test_result!(block_io_resources(500));
    run_test(cgroup_name, resources, &|| {
        check_io_weights(cgroup_name, 500, 4500)
    })
}

/// A structured weight up to the default of 100 is sent as it is.
fn test_block_io_weight_below_default() -> TestResult {
    let cgroup_name = "systemd_io_block_io_weight_below_default";
    let resources = test_result!(block_io_resources(50));
    run_test(cgroup_name, resources, &|| {
        check_io_weights(cgroup_name, 50, 50)
    })
}

/// A plain io.bfq.weight value from resources.unified is a weight of the same scale, so it
/// maps to IOWeight just like the structured one does.
fn test_unified_io_bfq_weight() -> TestResult {
    let cgroup_name = "systemd_io_unified_io_bfq_weight";
    let resources = test_result!(unified_resources(IO_BFQ_WEIGHT, "500"));
    run_test(cgroup_name, resources, &|| {
        check_io_weights(cgroup_name, 500, 4500)
    })
}

/// The weight has to survive systemd applying the unit's cgroup settings again, which any
/// set-property triggers. A weight that only reached cgroupfs is reset to the IOWeight
/// systemd holds, or to the default when the unit has no IOWeight at all, so this fails
/// without the property.
fn test_io_weight_survives_reapply() -> TestResult {
    let cgroup_name = "systemd_io_weight_survives_reapply";
    let resources = test_result!(block_io_resources(500));
    run_test(cgroup_name, resources, &|| {
        check_io_weights(cgroup_name, 500, 4500)?;

        // any cgroup property makes systemd apply the whole unit's cgroup settings again
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

        check_io_weights(cgroup_name, 500, 4500)
    })
}

/// The mapping targets systemd's BFQ scaling since 250; older releases derive io.bfq.weight
/// differently, so the expectations do not hold there. The systemd driver of runc 1.5.2 does
/// not send IOWeight at all, so its weight is reset by systemd and there is nothing to check
/// for it; these tests are about youki's driver.
fn can_run_io_weight() -> bool {
    can_run()
        && is_cgroup_v2_with_controller(ControllerType::Io)
        && systemd_version().is_ok_and(|v| v >= 250)
        && !is_runtime_runc()
}

/// The io controller exposes io.bfq.weight in a cgroup once the BFQ scheduler is available.
/// The contest process's own cgroup may not have the io controller enabled, so the cgroups
/// systemd manages are checked as well.
fn bfq_weight_supported() -> bool {
    if cgroup_has_file(IO_BFQ_WEIGHT) {
        return true;
    }
    let Ok(entries) = fs::read_dir(CGROUP_ROOT) else {
        return false;
    };
    entries
        .flatten()
        .any(|entry| entry.path().join(IO_BFQ_WEIGHT).exists())
}

/// A plain io.bfq.weight key from resources.unified is also written to cgroupfs, so the file
/// has to exist on this kernel for the container to be created.
fn can_run_unified_io_bfq_weight() -> bool {
    can_run_io_weight() && bfq_weight_supported()
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_systemd_io");
    let block_io_weight = ConditionalTest::new(
        "block_io_weight",
        Box::new(can_run_io_weight),
        Box::new(test_block_io_weight),
    );
    let block_io_weight_below_default = ConditionalTest::new(
        "block_io_weight_below_default",
        Box::new(can_run_io_weight),
        Box::new(test_block_io_weight_below_default),
    );
    let unified_io_bfq_weight = ConditionalTest::new(
        "unified_io_bfq_weight",
        Box::new(can_run_unified_io_bfq_weight),
        Box::new(test_unified_io_bfq_weight),
    );
    let io_weight_survives_reapply = ConditionalTest::new(
        "io_weight_survives_reapply",
        Box::new(can_run_io_weight),
        Box::new(test_io_weight_survives_reapply),
    );
    test_group.add(vec![
        Box::new(block_io_weight),
        Box::new(block_io_weight_below_default),
        Box::new(unified_io_bfq_weight),
        Box::new(io_weight_survives_reapply),
    ]);
    test_group
}

test_framework::register_test_group!(get_test_group);
