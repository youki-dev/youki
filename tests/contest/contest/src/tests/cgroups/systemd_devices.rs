//! Tests for the systemd cgroup manager's device controller.
//!
//! The runtime is invoked with `--systemd-cgroup` and a systemd-style cgroupsPath so that
//! the systemd manager is selected over the cgroupfs one, and what it asked systemd for is
//! read back off the transient unit.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use oci_spec::runtime::{
    Capability, LinuxBuilder, LinuxCapabilitiesBuilder, LinuxDeviceCgroup,
    LinuxDeviceCgroupBuilder, LinuxDeviceType, LinuxResourcesBuilder, ProcessBuilder, Spec,
    SpecBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_utils::{CreateOptions, check_container_created};
use crate::utils::{is_runtime_youki, test_inside_container, test_outside_container_with_options};

const SCOPE_PREFIX: &str = "contest";

/// The capability set docker gives a container by default, to keep the container under test
/// close to a real one. Mknod is what lets it create the device nodes it then opens.
fn docker_default_capabilities() -> HashSet<Capability> {
    HashSet::from([
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
    ])
}

fn create_spec(cgroup_name: &str, devices: Vec<LinuxDeviceCgroup>) -> Result<Spec> {
    create_spec_with_args(
        cgroup_name,
        devices,
        vec!["sleep".to_string(), "30".to_string()],
    )
}

fn create_spec_with_args(
    cgroup_name: &str,
    devices: Vec<LinuxDeviceCgroup>,
    args: Vec<String>,
) -> Result<Spec> {
    // systemd cgroupsPath notation: [slice]:[scope prefix]:[name]
    let cgroups_path = PathBuf::from(format!("system.slice:{SCOPE_PREFIX}:{cgroup_name}"));

    let capabilities = LinuxCapabilitiesBuilder::default()
        .bounding(docker_default_capabilities())
        .effective(docker_default_capabilities())
        .permitted(docker_default_capabilities())
        .inheritable(HashSet::new())
        .ambient(HashSet::new())
        .build()
        .context("failed to build capabilities")?;

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(args)
                .capabilities(capabilities)
                .build()
                .context("failed to build process spec")?,
        )
        .linux(
            LinuxBuilder::default()
                .cgroups_path(cgroups_path)
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

/// `youki-<name>.scope` style unit name, see get_unit_name() in the systemd manager.
fn unit_name(cgroup_name: &str) -> String {
    format!("{SCOPE_PREFIX}-{cgroup_name}.scope")
}

fn show_property(unit: &str, property: &str) -> Result<String> {
    let output = Command::new("systemctl")
        .args(["show", unit, "-p", property, "--value"])
        .output()
        .with_context(|| format!("failed to run systemctl show for {unit}"))?;

    if !output.status.success() {
        bail!(
            "systemctl show {unit} -p {property} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(String::from_utf8(output.stdout)
        .context("systemctl output was not utf-8")?
        .trim()
        .to_string())
}

fn device_policy(cgroup_name: &str) -> Result<String> {
    show_property(&unit_name(cgroup_name), "DevicePolicy")
}

/// The DeviceAllow entries of the unit, as `"<path> <access>"` strings.
fn device_allow(cgroup_name: &str) -> Result<Vec<String>> {
    let value = show_property(&unit_name(cgroup_name), "DeviceAllow")?;
    Ok(value
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect())
}

fn check_policy(cgroup_name: &str, expected: &str) -> Result<()> {
    let policy = device_policy(cgroup_name)?;
    if policy != expected {
        bail!("expected DevicePolicy={expected}, but unit has DevicePolicy={policy}");
    }
    Ok(())
}

fn check_allows(cgroup_name: &str, expected: &str) -> Result<()> {
    let entries = device_allow(cgroup_name)?;
    if !entries.iter().any(|entry| entry == expected) {
        bail!("expected DeviceAllow to contain {expected:?}, got {entries:?}");
    }
    Ok(())
}

fn run_test(
    cgroup_name: &str,
    devices: Vec<LinuxDeviceCgroup>,
    check: &dyn Fn() -> Result<()>,
) -> TestResult {
    let spec = test_result!(create_spec(cgroup_name, devices));
    let systemd_cgroup: &[&OsStr] = &[OsStr::new("--systemd-cgroup")];
    let options = CreateOptions::default().with_global_args(systemd_cgroup);

    test_outside_container_with_options(&spec, &options, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check());
        TestResult::Passed
    })
}

/// A whitelist rule set must become DevicePolicy=strict with an exact device node for
/// "major:minor" and a device group for "major:*".
fn test_whitelist_rules() -> TestResult {
    let cgroup_name = "systemd_devices_whitelist";
    // Devices the runtime does not add by default, so the entries can only come from these
    // rules. runc produces the same two for this rule set.
    let devices = vec![
        // deny everything, then allow single devices on top
        test_result!(device_rule(
            false,
            Some(LinuxDeviceType::A),
            None,
            None,
            "rwm"
        )),
        // first scsi disk, as an exact device node
        test_result!(device_rule(
            true,
            Some(LinuxDeviceType::B),
            Some(8),
            Some(0),
            "rw"
        )),
        // the whole i2c major, as a device group
        test_result!(device_rule(
            true,
            Some(LinuxDeviceType::C),
            Some(89),
            None,
            "rwm"
        )),
    ];

    run_test(cgroup_name, devices, &|| {
        check_policy(cgroup_name, "strict")?;
        check_allows(cgroup_name, "/dev/block/8:0 rw")?;
        check_allows(cgroup_name, "char-89 rwm")
    })
}

/// A rule set that allows everything and denies nothing is exactly DevicePolicy=auto.
fn test_allow_all_is_auto() -> TestResult {
    let cgroup_name = "systemd_devices_allow_all";
    let devices = vec![test_result!(device_rule(
        true,
        Some(LinuxDeviceType::A),
        None,
        None,
        "rwm"
    ))];

    run_test(cgroup_name, devices, &|| check_policy(cgroup_name, "auto"))
}

// NOTE: deny rules on top of an allow-all rule are left to the unit tests, which check that
// they are refused. No runtime runs such a container with the systemd cgroup manager, runc
// included, so there is nothing to check here; see the TODO in the devices controller.

/// Checks the rules are enforced, not just present on the unit. The container's own default
/// rules allow mknod but no read access, so creating the node must work and opening it must
/// not.
fn test_deny_rule_is_enforced() -> TestResult {
    let cgroup_name = "systemd_devices_deny_rule";
    let deny_rule = test_result!(device_rule(
        false,
        Some(LinuxDeviceType::A),
        None,
        None,
        "rwm"
    ));
    let spec = test_result!(create_spec_with_args(
        cgroup_name,
        vec![deny_rule],
        vec!["runtimetest".to_string(), "device_cgroup".to_string()],
    ));
    let systemd_cgroup: &[&OsStr] = &[OsStr::new("--systemd-cgroup")];
    let options = CreateOptions::default().with_global_args(systemd_cgroup);

    test_inside_container(&spec, &options, &|_| Ok(()))
}

// NOTE: "*:minor" rules are left to the unit tests too. They cannot be seen from here: the
// default rules come after the spec's and systemd keeps the last entry for a path, so a
// "char-*" entry from the spec is always replaced by the default "char-* m".

/// The systemd cgroup manager needs a unified cgroup hierarchy, a running systemd to talk
/// to, and root to place units in system.slice.
fn systemd_cgroups_available() -> bool {
    nix::unistd::geteuid().is_root()
        && Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
        && Path::new("/run/systemd/system").is_dir()
}

fn can_run() -> bool {
    // DeviceAllow is youki specific enough (property names and defaults) that this is not
    // run against other runtimes.
    is_runtime_youki() && systemd_cgroups_available()
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_systemd_devices");
    let whitelist = ConditionalTest::new(
        "whitelist_rules",
        Box::new(can_run),
        Box::new(test_whitelist_rules),
    );
    let allow_all = ConditionalTest::new(
        "allow_all_is_auto",
        Box::new(can_run),
        Box::new(test_allow_all_is_auto),
    );
    let deny_rule = ConditionalTest::new(
        "deny_rule_is_enforced",
        Box::new(can_run),
        Box::new(test_deny_rule_is_enforced),
    );
    test_group.add(vec![
        Box::new(whitelist),
        Box::new(allow_all),
        Box::new(deny_rule),
    ]);
    test_group
}
