use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use oci_spec::runtime::{
    LinuxBuilder, LinuxDevice, LinuxDeviceBuilder, LinuxDeviceCgroup, LinuxDeviceCgroupBuilder,
    LinuxDeviceType, LinuxResourcesBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{TestResult, test_result};

use super::{check_cgroup_value, update_container_and_wait};
use crate::utils::test_utils::{CreateOptions, check_container_created};
use crate::utils::{
    exec_container, is_cgroup_v2, start_container, test_outside_container_with_options,
};

fn rule(
    allow: bool,
    typ: LinuxDeviceType,
    major: Option<i64>,
    minor: Option<i64>,
    access: &str,
) -> Result<LinuxDeviceCgroup> {
    let mut builder = LinuxDeviceCgroupBuilder::default()
        .allow(allow)
        .typ(typ)
        .access(access);
    if let Some(major) = major {
        builder = builder.major(major);
    }
    if let Some(minor) = minor {
        builder = builder.minor(minor);
    }
    builder.build().context("failed to build device rule")
}

/// Deny everything, allow reading loop-control, deny writing it again. The deny
/// keeps folding on both runtimes, so a write stays denied and the read must
/// survive the update; the default rules do not cover the device either.
fn loop_rules() -> Result<Vec<LinuxDeviceCgroup>> {
    Ok(vec![
        rule(false, LinuxDeviceType::A, None, None, "rwm")?,
        rule(true, LinuxDeviceType::C, Some(10), Some(237), "rw")?,
        rule(false, LinuxDeviceType::C, Some(10), Some(237), "w")?,
    ])
}

fn loop_node() -> Result<LinuxDevice> {
    LinuxDeviceBuilder::default()
        .path(PathBuf::from("/dev/loop-control"))
        .typ(LinuxDeviceType::C)
        .major(10)
        .minor(237)
        .build()
        .context("failed to build loop-control node")
}

fn create_spec(
    cgroups_path: &Path,
    rules: Vec<LinuxDeviceCgroup>,
    node: LinuxDevice,
) -> Result<Spec> {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "1000".to_string()])
                .build()
                .context("failed to build process spec")?,
        )
        .linux(
            LinuxBuilder::default()
                .cgroups_path(cgroups_path)
                .devices(vec![node])
                .resources(
                    LinuxResourcesBuilder::default()
                        .devices(rules)
                        .build()
                        .context("failed to build resources spec")?,
                )
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")
}

enum Access {
    Allowed,
    Denied,
}

/// Runs `sh -c <command>` in the container and reads the open result: a
/// successful exec means the device opened, the shell's own open error means the
/// rules denied it. Any other failure is an error, so an exec failure or a host
/// without the loop driver cannot pass as a denial.
fn device_access(id: &str, dir: &Path, command: &str, denied_message: &str) -> Result<Access> {
    match exec_container(id, dir, &["/bin/sh", "-c", command], None, &[]) {
        Ok(_) => Ok(Access::Allowed),
        Err(err) => {
            let message = format!("{err:#}");
            if message.contains(denied_message) {
                Ok(Access::Denied)
            } else {
                Err(err.context(format!("opening device with: {command}")))
            }
        }
    }
}

fn check_device_rules(id: &str, dir: &Path) -> Result<()> {
    // /dev/null first: losing every device (systemd's own filter left attached)
    // fails here, losing only the custom rule fails on the read below.
    match device_access(
        id,
        dir,
        "true </dev/null",
        "can't open /dev/null: Operation not permitted",
    )? {
        Access::Allowed => {}
        Access::Denied => bail!("expected /dev/null to open, got EPERM"),
    }
    match device_access(
        id,
        dir,
        "true </dev/loop-control",
        "can't open /dev/loop-control: Operation not permitted",
    )? {
        Access::Allowed => {}
        Access::Denied => bail!("expected /dev/loop-control read to be allowed, got EPERM"),
    }
    match device_access(
        id,
        dir,
        "exec 3>/dev/loop-control",
        "can't create /dev/loop-control: Operation not permitted",
    )? {
        Access::Denied => Ok(()),
        Access::Allowed => bail!("expected /dev/loop-control write to be denied, but it opened"),
    }
}

fn run_update_keeps_device_rules(
    spec: Spec,
    global_args: &[&OsStr],
    cgroup_dir: &Path,
) -> TestResult {
    let options = CreateOptions::default().with_global_args(global_args);
    test_outside_container_with_options(&spec, &options, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        test_result!(check_device_rules(id, dir).map_err(|err| anyhow!("before update: {err:#}")));

        // Updating the pids limit must not touch the device rules.
        test_result!(update_container_and_wait(id, dir, &["--pids-limit", "50"]));
        test_result!(check_cgroup_value(cgroup_dir, "pids.max", "50"));

        test_result!(check_device_rules(id, dir).map_err(|err| anyhow!("after update: {err:#}")));

        TestResult::Passed
    })
}

pub(crate) fn update_keeps_device_rules_test() -> TestResult {
    let spec = test_result!(create_spec(
        Path::new("/runtime-test/update_device_rules"),
        test_result!(loop_rules()),
        test_result!(loop_node()),
    ));
    run_update_keeps_device_rules(
        spec,
        &[],
        Path::new("/sys/fs/cgroup/runtime-test/update_device_rules"),
    )
}

pub(crate) fn update_keeps_device_rules_systemd_test() -> TestResult {
    let spec = test_result!(create_spec(
        Path::new("system.slice:contest:update_device_rules_systemd"),
        test_result!(loop_rules()),
        test_result!(loop_node()),
    ));
    run_update_keeps_device_rules(
        spec,
        &[OsStr::new("--systemd-cgroup")],
        Path::new("/sys/fs/cgroup/system.slice/contest-update_device_rules_systemd.scope"),
    )
}

fn loop_control_available() -> bool {
    Path::new("/sys/class/misc/loop-control").exists()
}

pub(crate) fn can_run() -> bool {
    nix::unistd::geteuid().is_root() && is_cgroup_v2() && loop_control_available()
}

pub(crate) fn can_run_systemd() -> bool {
    nix::unistd::geteuid().is_root()
        && is_cgroup_v2()
        && Path::new("/run/systemd/system").is_dir()
        && loop_control_available()
}
