use std::path::Path;

use anyhow::Context;
use oci_spec::runtime::{
    LinuxBuilder, LinuxDeviceCgroup, LinuxDeviceCgroupBuilder, LinuxDeviceType,
    LinuxResourcesBuilder, Spec, SpecBuilder,
};
use test_framework::{test_result, ConditionalTest, TestGroup, TestResult};

use crate::utils::test_outside_container;
use crate::utils::test_utils::check_container_created;

fn can_run() -> bool {
    Path::new("/sys/fs/cgroup/devices").exists()
}

fn linux_device_build(
    allow: bool,
    dev_type: LinuxDeviceType,
    major: i64,
    minor: i64,
    access: String,
) -> LinuxDeviceCgroup {
    LinuxDeviceCgroupBuilder::default()
        .access(allow.to_string())
        .typ(dev_type)
        .major(major)
        .minor(minor)
        .access(access)
        .build()
        .unwrap()
}

fn create_spec(cgroup_name: &str, devices: Vec<LinuxDeviceCgroup>) -> anyhow::Result<Spec> {
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(Path::new("/runtime-test").join(cgroup_name))
                .resources(
                    LinuxResourcesBuilder::default()
                        .devices(devices)
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

fn test_devices_cgroups() -> TestResult {
    let cgroup_name = "test_devices_cgroups";
    let linux_devices = vec![
        linux_device_build(true, LinuxDeviceType::C, 10, 229, "rwm".to_string()),
        linux_device_build(true, LinuxDeviceType::B, 8, 20, "rw".to_string()),
        linux_device_build(true, LinuxDeviceType::B, 10, 200, "r".to_string()),
    ];
    let spec = test_result!(create_spec(cgroup_name, linux_devices));

    let test_result = test_outside_container(spec, &|data| {
        test_result!(check_container_created(&data));
        TestResult::Passed
    });
    if let TestResult::Failed(_) = test_result {
        return test_result;
    }
    test_result
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v1_devices");
    let linux_cgroups_devices = ConditionalTest::new(
        "test_linux_cgroups_devices",
        Box::new(can_run),
        Box::new(crate::tests::cgroups::devices::test_devices_cgroups),
    );

    test_group.add(vec![Box::new(linux_cgroups_devices)]);

    test_group
}
