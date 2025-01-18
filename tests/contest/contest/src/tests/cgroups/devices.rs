use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use contest::utils::test_utils::CGROUP_ROOT;
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
    dev_type: LinuxDeviceType,
    major: i64,
    minor: i64,
    access: String,
) -> LinuxDeviceCgroup {
    LinuxDeviceCgroupBuilder::default()
        .allow(true)
        .typ(dev_type)
        .major(major)
        .minor(minor)
        .access(access)
        .build()
        .unwrap()
}

fn create_spec(cgroup_name: &str, devices: Vec<LinuxDeviceCgroup>) -> Result<Spec> {
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

fn get_allow_linux_devices(path: &Path) -> Result<Vec<LinuxDeviceCgroup>> {
    let file = File::open(path).unwrap()?;
    let reader = BufReader::new(file);
    let mut devices: Vec<LinuxDeviceCgroup> = vec![];

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 3 {
            let device_type = match parts[0] {
                "b" => LinuxDeviceType::B,
                "c" => LinuxDeviceType::C,
                "*" => LinuxDeviceType::A,
                _ => continue,
            };
            // read major, minor number
            let major_minor: Vec<&str> = parts[1].split(':').collect();
            if major_minor.len() != 2 {
                // ignore invalid format
                continue;
            }
            let major = if major_minor[0] == "*" {
                None
            } else {
                major_minor[0].parse::<i64>().ok()
            };
            let minor = if major_minor[1] == "*" {
                None
            } else {
                major_minor[1].parse::<i64>().ok()
            };
            // read access string
            let access = parts[2].to_string();
            devices.push(linux_device_build(device_type, major, minor, access))
        }
    }

    Ok(devices);
}

fn validate_linux_devices(cgroup_name: &str, spec: &Spec) -> Result<()> {
    let cgroup_path = PathBuf::from(CGROUP_ROOT)
        .join("devices")
        .join("runtime-test")
        .join(cgroup_name)
        .join("devices.list");
    let linux_devices = get_allow_linux_devices(&cgroup_path)?;

    let resources = spec.linux().as_ref().unwrap().resources().as_ref().unwrap();
    let spec_linux_devices = resources.devices().as_ref().unwrap();

    for spec_linux_device in spec_linux_devices {
        if spec_linux_device.allow() {
            let mut found = false;
            for linux_device in linux_devices.clone() {
                if linux_device.typ() == spec_linux_device.typ()
                    && linux_device.major() == spec_linux_device.major()
                    && linux_device.minor() == spec_linux_device.minor()
                    && linux_device.access() == spec_linux_device.access()
                {
                    found = true;
                }
            }
            if !found {
                bail!(
                    "allow linux device {}:{}:{}:{} not found, exists in spec",
                    spec_linux_device.typ(),
                    spec_linux_device.major(),
                    spec_linux_device.minor(),
                    spec_linux_device.access()
                );
            }
        }
    }

    Ok(())
}

fn test_devices_cgroups() -> TestResult {
    let cgroup_name = "test_devices_cgroups";
    let linux_devices = vec![
        linux_device_build(LinuxDeviceType::C, 10, 229, "rwm".to_string()),
        linux_device_build(LinuxDeviceType::B, 8, 20, "rw".to_string()),
        linux_device_build(LinuxDeviceType::B, 10, 200, "r".to_string()),
    ];
    let spec = test_result!(create_spec(cgroup_name, linux_devices));

    test_outside_container(spec.clone(), &|data| {
        test_result!(check_container_created(&data));
        test_result!(validate_linux_devices(&cgroup_name, &spec));
        TestResult::Passed
    })
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v1_devices");
    let linux_cgroups_devices = ConditionalTest::new(
        "test_linux_cgroups_devices",
        Box::new(can_run),
        Box::new(test_devices_cgroups),
    );

    test_group.add(vec![Box::new(linux_cgroups_devices)]);

    test_group
}
