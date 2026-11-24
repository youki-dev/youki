use anyhow::{Context, Ok, Result, ensure};
use oci_spec::runtime::{
    LinuxBuilder, LinuxDeviceBuilder, LinuxDeviceType, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult, test_result};

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

// A top-level directory name that the test bundle does not have, so that every
// parent directory of the devices below has to be created by the runtime.
const MISSING_PARENT_DIR: &str = "youki-missing-parent";

// The runtime has to create the missing parent directories of these devices,
// both on the /dev tmpfs and on the rootfs itself, two levels deep.
// runtimetest checks that none of them is left writable by group or others.
fn create_spec_missing_parent_dirs() -> Result<Spec> {
    let devices = [
        format!("/dev/{MISSING_PARENT_DIR}/dir/test"),
        format!("/{MISSING_PARENT_DIR}/nested/test"),
    ]
    .into_iter()
    .map(|path| {
        LinuxDeviceBuilder::default()
            .path(&path)
            .typ(LinuxDeviceType::C)
            .major(1)
            .minor(3)
            .file_mode(0o666u32)
            .uid(0u32)
            .gid(0u32)
            .build()
            .with_context(|| format!("failed to create device {path}"))
    })
    .collect::<Result<Vec<_>>>()?;

    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec![
                    "runtimetest".to_string(),
                    "device_missing_parent_dirs".to_string(),
                ])
                .build()
                .expect("error in creating process config"),
        )
        .linux(
            LinuxBuilder::default()
                .devices(devices)
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn devices_missing_parent_dirs_test() -> TestResult {
    let spec = test_result!(create_spec_missing_parent_dirs());
    test_inside_container(&spec, &CreateOptions::default(), &|rootfs| {
        ensure!(
            !rootfs.join(MISSING_PARENT_DIR).exists(),
            "{MISSING_PARENT_DIR} must not exist in the test bundle"
        );
        Ok(())
    })
}

pub fn get_devices_test() -> TestGroup {
    let mut device_test_group = TestGroup::new("devices");

    let test = Test::new("device_test", Box::new(devices_test));
    let test_default_permissions = Test::new(
        "device_default_permissions",
        Box::new(devices_default_permissions_test),
    );

    let test_missing_parent_dirs = Test::new(
        "device_missing_parent_dirs",
        Box::new(devices_missing_parent_dirs_test),
    );

    device_test_group.add(vec![
        Box::new(test),
        Box::new(test_default_permissions),
        Box::new(test_missing_parent_dirs),
    ]);

    device_test_group
}

test_framework::register_test_group!(get_devices_test);
