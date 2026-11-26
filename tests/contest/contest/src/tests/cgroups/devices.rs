//! This group ports runc's tests/integration/dev.bats to cgroupfs v2. The deny case
//! allows then denies c 1:11, and the rules use `rw` because youki rejects the `a` in
//! runc's `rwa`.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Output;

use anyhow::{Context, Result, anyhow, ensure};
use oci_spec::runtime::{
    Capability, LinuxBuilder, LinuxCapabilitiesBuilder, LinuxDevice, LinuxDeviceBuilder,
    LinuxDeviceCgroup, LinuxDeviceCgroupBuilder, LinuxDeviceType, LinuxResourcesBuilder,
    ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_utils::{ContainerData, build_exec_command, check_container_created};
use crate::utils::{
    block_devices, device_numbers, exec_container, is_cgroup_v2, start_container,
    test_outside_container, wait_container_running,
};

fn create_spec(
    cgroup_name: &str,
    devices: Vec<LinuxDeviceCgroup>,
    node: LinuxDevice,
    capability: Capability,
) -> Result<Spec> {
    let capabilities = [
        Capability::Chown,
        Capability::DacOverride,
        Capability::Fsetid,
        Capability::Fowner,
        Capability::Mknod,
        Capability::NetRaw,
        Capability::Setgid,
        Capability::Setuid,
        Capability::Setfcap,
        Capability::Setpcap,
        Capability::NetBindService,
        Capability::SysChroot,
        Capability::Kill,
        Capability::AuditWrite,
        capability,
    ];
    let capabilities = LinuxCapabilitiesBuilder::default()
        .bounding(capabilities)
        .effective(capabilities)
        .permitted(capabilities)
        .build()
        .context("failed to build capabilities")?;

    SpecBuilder::default()
        .hostname("myhostname")
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "30".to_string()])
                .capabilities(capabilities)
                .build()
                .context("failed to build process spec")?,
        )
        .linux(
            LinuxBuilder::default()
                .cgroups_path(Path::new("/runtime-test").join(cgroup_name))
                .devices(vec![node])
                .resources(
                    LinuxResourcesBuilder::default()
                        .devices(devices)
                        .build()
                        .context("failed to build resources spec")?,
                )
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")
}

fn device_rule(
    allow: bool,
    typ: Option<LinuxDeviceType>,
    major: Option<i64>,
    minor: Option<i64>,
    access: &str,
) -> Result<LinuxDeviceCgroup> {
    let mut builder = LinuxDeviceCgroupBuilder::default()
        .allow(allow)
        .access(access);
    if let Some(typ) = typ {
        builder = builder.typ(typ);
    }
    if let Some(major) = major {
        builder = builder.major(major);
    }
    if let Some(minor) = minor {
        builder = builder.minor(minor);
    }
    builder.build().context("failed to build device rule")
}

fn device_node(
    path: impl Into<PathBuf>,
    typ: LinuxDeviceType,
    major: i64,
    minor: i64,
) -> Result<LinuxDevice> {
    LinuxDeviceBuilder::default()
        .path(path.into())
        .typ(typ)
        .major(major)
        .minor(minor)
        .build()
        .context("failed to build device node")
}

fn kmsg_node() -> Result<LinuxDevice> {
    device_node("/dev/kmsg", LinuxDeviceType::C, 1, 11)
}

// The deny checks expect EPERM from the device cgroup, so the host itself must be able
// to open /dev/kmsg.
fn host_kmsg_accessible() -> bool {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kmsg")
        .is_ok()
}

fn readable_block_device() -> Result<Option<(i64, i64)>> {
    for dev_dir in block_devices()? {
        let Some((major, minor)) = device_numbers(&dev_dir) else {
            continue;
        };
        let Some(name) = dev_dir.file_name() else {
            continue;
        };
        // Skip empty and removable devices so the host read cannot hit a floppy, CD tray
        // or empty drive.
        let size = std::fs::read_to_string(dev_dir.join("size")).unwrap_or_default();
        let removable = std::fs::read_to_string(dev_dir.join("removable")).unwrap_or_default();
        if size.trim() == "0" || removable.trim() == "1" {
            continue;
        }
        let Ok(mut device) = File::open(Path::new("/dev").join(name)) else {
            continue;
        };
        let mut byte = [0];
        if device.read_exact(&mut byte).is_ok() {
            return Ok(Some((major, minor)));
        }
    }
    Ok(None)
}

fn run_test(spec: Spec, check: &dyn Fn(&ContainerData) -> Result<()>) -> TestResult {
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        let mut start = test_result!(start_container(&data.id, &data.bundle));
        let status = test_result!(start.wait().context("failed to wait for container start"));
        if !status.success() {
            return TestResult::Failed(anyhow!("container start failed with {status}"));
        }
        test_result!(wait_container_running(&data.id, &data.bundle));
        test_result!(check(&data));
        TestResult::Passed
    })
}

fn exec_output(data: &ContainerData, command: &str) -> Result<Output> {
    build_exec_command(&data.id, &data.bundle, &["sh", "-c", command], None, &[])
        .output()
        .with_context(|| format!("failed to execute {command:?}"))
}

fn check_kmsg_denied(data: &ContainerData) -> Result<()> {
    for (command, diagnostic) in [
        ("hostname | tee /dev/kmsg", "tee:"),
        ("head -n 1 /dev/kmsg", "head:"),
    ] {
        let output = exec_output(data, command)?;
        ensure!(
            !output.status.success(),
            "{command:?} succeeded despite the device cgroup deny rule"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        ensure!(
            stderr.lines().any(|line| {
                let line = line.trim_start();
                line.starts_with(diagnostic)
                    && line.contains("/dev/kmsg")
                    && line.contains("Operation not permitted")
            }),
            "{command:?} did not report a /dev/kmsg device denial: {stderr}"
        );
    }
    Ok(())
}

fn test_device_deny() -> TestResult {
    if !host_kmsg_accessible() {
        return TestResult::Skipped(
            "host cannot open /dev/kmsg for reading and writing".to_string(),
        );
    }
    let devices = vec![
        test_result!(device_rule(
            true,
            Some(LinuxDeviceType::C),
            Some(1),
            Some(11),
            "rw"
        )),
        test_result!(device_rule(
            false,
            Some(LinuxDeviceType::C),
            Some(1),
            Some(11),
            "rw"
        )),
    ];
    let spec = test_result!(create_spec(
        "devices_deny",
        devices,
        test_result!(kmsg_node()),
        // Without CAP_SYSLOG, dmesg_restrict=1 makes the kmsg read fail with EPERM whatever
        // the device cgroup does.
        Capability::Syslog,
    ));

    run_test(spec, &check_kmsg_denied)
}

fn test_device_default_deny() -> TestResult {
    if !host_kmsg_accessible() {
        return TestResult::Skipped(
            "host cannot open /dev/kmsg for reading and writing".to_string(),
        );
    }
    let devices = vec![test_result!(device_rule(false, None, None, None, "rwm"))];
    let spec = test_result!(create_spec(
        "devices_default_deny",
        devices,
        test_result!(kmsg_node()),
        Capability::Syslog,
    ));

    run_test(spec, &check_kmsg_denied)
}

fn check_kmsg_allowed(data: &ContainerData) -> Result<()> {
    let (stdout, _) = exec_container(
        &data.id,
        &data.bundle,
        &["sh", "-c", "hostname | tee /dev/kmsg"],
        None,
        &[],
    )?;
    ensure!(
        stdout.contains("myhostname"),
        "writing to /dev/kmsg produced unexpected output: {stdout:?}"
    );
    exec_container(
        &data.id,
        &data.bundle,
        &["sh", "-c", ": </dev/kmsg"],
        None,
        &[],
    )?;
    Ok(())
}

fn test_allow_char_device() -> TestResult {
    if !host_kmsg_accessible() {
        return TestResult::Skipped(
            "host cannot open /dev/kmsg for reading and writing".to_string(),
        );
    }
    let devices = vec![
        test_result!(device_rule(false, None, None, None, "rwm")),
        test_result!(device_rule(
            true,
            Some(LinuxDeviceType::C),
            Some(1),
            Some(11),
            "rw"
        )),
    ];
    let spec = test_result!(create_spec(
        "devices_allow_char",
        devices,
        test_result!(kmsg_node()),
        Capability::Syslog,
    ));

    run_test(spec, &check_kmsg_allowed)
}

fn test_allow_block_device() -> TestResult {
    let Some((major, minor)) = test_result!(readable_block_device()) else {
        return TestResult::Skipped("no readable block device found under /sys/block".to_string());
    };
    let path = format!("/dev/test-{major}-{minor}");
    let devices = vec![
        test_result!(device_rule(false, None, None, None, "rwm")),
        test_result!(device_rule(
            true,
            Some(LinuxDeviceType::B),
            Some(major),
            Some(minor),
            "rwm"
        )),
    ];
    let spec = test_result!(create_spec(
        "devices_allow_block",
        devices,
        test_result!(device_node(&path, LinuxDeviceType::B, major, minor)),
        Capability::Mknod,
    ));

    run_test(spec, &|data| {
        let source = format!("if={path}");
        exec_container(
            &data.id,
            &data.bundle,
            &["dd", source.as_str(), "of=/dev/null", "bs=1", "count=1"],
            None,
            &[],
        )?;
        Ok(())
    })
}

fn can_run() -> bool {
    nix::unistd::geteuid().is_root() && is_cgroup_v2()
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v2_devices");
    let deny = ConditionalTest::new("device_deny", Box::new(can_run), Box::new(test_device_deny));
    let default_deny = ConditionalTest::new(
        "device_default_deny",
        Box::new(can_run),
        Box::new(test_device_default_deny),
    );
    let allow_char = ConditionalTest::new(
        "allow_char_device",
        Box::new(can_run),
        Box::new(test_allow_char_device),
    );
    let allow_block = ConditionalTest::new(
        "allow_block_device",
        Box::new(can_run),
        Box::new(test_allow_block_device),
    );
    test_group.add(vec![
        Box::new(deny),
        Box::new(default_deny),
        Box::new(allow_char),
        Box::new(allow_block),
    ]);
    test_group
}

test_framework::register_test_group!(get_test_group);
