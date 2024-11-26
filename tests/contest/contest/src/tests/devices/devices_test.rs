use anyhow::{Context, Ok, Result};
use oci_spec::runtime::{
    LinuxBuilder, LinuxDeviceBuilder, LinuxDeviceType, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{test_result, Test, TestGroup, TestResult};

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
        .major(8)
        .minor(666)
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
    test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_devices_test() -> TestGroup {
    let mut device_test_group = TestGroup::new("devices");

    let test = Test::new("device_test", Box::new(devices_test));
    device_test_group.add(vec![Box::new(test)]);

    device_test_group
}
