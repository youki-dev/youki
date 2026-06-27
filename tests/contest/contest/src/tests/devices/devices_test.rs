use anyhow::{Context, Ok, Result};
use libcgroups::common::{self as cgroup_common, CgroupSetup, is_cgroupsv2_devices_available};
use oci_spec::runtime::{
    LinuxBuilder, LinuxDeviceBuilder, LinuxDeviceCgroupBuilder, LinuxDeviceType,
    LinuxResourcesBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{ConditionalTest, Test, TestGroup, TestResult, test_result};
use tracing::debug;

use crate::utils::support::is_runtime_runc;
use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec() -> Result<Spec> {
    let device1 = LinuxDeviceBuilder::default()
        .path("/dev/test1")
        .typ(LinuxDeviceType::C)
        .major(10)
        .minor(666)
        .file_mode(432u32)
        .uid(0u32)
        .gid(0u32)
        .build()
        .context("failed to create device 1")?;

    let device2 = LinuxDeviceBuilder::default()
        .path("/dev/test2")
        .typ(LinuxDeviceType::B)
        .major(8)
        .minor(666)
        .file_mode(432u32)
        .uid(0u32)
        .gid(0u32)
        .build()
        .context("failed to create device 2")?;

    let device3 = LinuxDeviceBuilder::default()
        .path("/dev/test3")
        .typ(LinuxDeviceType::P)
        .file_mode(432u32)
        .build()
        .context("failed to create device 3")?;

    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "devices".to_string()])
                .build()
                .expect("error in creating process config"),
        )
        .linux(
            LinuxBuilder::default()
                .devices(vec![device1, device2, device3])
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn devices_test() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn create_spec_default_permissions() -> Result<Spec> {
    let device = LinuxDeviceBuilder::default()
        .path("/dev/kmsg")
        .typ(LinuxDeviceType::C)
        .major(1)
        .minor(11)
        .build()
        .context("failed to create device")?;

    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "devices".to_string()])
                .build()
                .expect("error in creating process config"),
        )
        .linux(
            LinuxBuilder::default()
                .devices(vec![device])
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn devices_default_permissions_test() -> TestResult {
    let spec = test_result!(create_spec_default_permissions());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

/// Check if cgroup v2 devices test can run.
/// This test requires cgroupsv2_devices feature and cgroup v2.
fn can_run_cgroup_v2_devices() -> bool {
    // Skip if cgroupsv2_devices feature is not enabled
    if !is_cgroupsv2_devices_available() {
        debug!("cgroupsv2_devices feature is not enabled");
        return false;
    }
    // Skip for runc (this test is specific to youki's implementation)
    if is_runtime_runc() {
        debug!("skipping test for runc runtime");
        return false;
    }
    let setup_result = cgroup_common::get_cgroup_setup();
    if !matches!(setup_result, std::result::Result::Ok(CgroupSetup::Unified)) {
        debug!("cgroup setup is not v2, was {:?}", setup_result);
        return false;
    }
    true
}

/// Create spec for testing device cgroup rule precedence.
/// This spec sets a rule to deny write access to /dev/zero.
fn create_spec_cgroup_rule_precedence() -> Result<Spec> {
    // Deny write access to /dev/zero (major: 1, minor: 5)
    let deny_zero_write = LinuxDeviceCgroupBuilder::default()
        .allow(false)
        .typ(LinuxDeviceType::C)
        .major(1i64)
        .minor(5i64)
        .access("w")
        .build()
        .context("failed to create device cgroup rule")?;

    let resources = LinuxResourcesBuilder::default()
        .devices(vec![deny_zero_write])
        .build()
        .context("failed to build linux resources")?;

    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec![
                    "runtimetest".to_string(),
                    "devices_cgroup_rule_precedence".to_string(),
                ])
                .build()
                .expect("error in creating process config"),
        )
        .linux(
            LinuxBuilder::default()
                .resources(resources)
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

/// Test that user-defined device cgroup rules take precedence over defaults.
fn devices_cgroup_rule_precedence_test() -> TestResult {
    let spec = test_result!(create_spec_cgroup_rule_precedence());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_devices_test() -> TestGroup {
    let mut device_test_group = TestGroup::new("devices");

    let test = Test::new("device_test", Box::new(devices_test));
    let test_default_permissions = Test::new(
        "device_default_permissions",
        Box::new(devices_default_permissions_test),
    );

    let test_cgroup_rule_precedence = ConditionalTest::new(
        "cgroup_rule_precedence",
        Box::new(can_run_cgroup_v2_devices),
        Box::new(devices_cgroup_rule_precedence_test),
    );

    device_test_group.add(vec![Box::new(test), Box::new(test_default_permissions)]);
    device_test_group.add(vec![Box::new(test_cgroup_rule_precedence)]);

    device_test_group
}
