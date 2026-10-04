//! Tests for the systemd cgroup manager's device controller.

use std::ffi::OsStr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use oci_spec::runtime::{
    LinuxBuilder, LinuxDevice, LinuxDeviceBuilder, LinuxDeviceCgroup, LinuxDeviceCgroupBuilder,
    LinuxDeviceType, LinuxResourcesBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use super::{SCOPE_PREFIX, can_run, show_property, unit_name};
use crate::utils::test_utils::{CreateOptions, check_container_created};
use crate::utils::{is_runtime_runc, test_inside_container, test_outside_container_with_options};

fn create_spec(cgroup_name: &str, devices: Vec<LinuxDeviceCgroup>) -> Result<Spec> {
    create_spec_with_nodes(
        cgroup_name,
        devices,
        vec![],
        vec!["sleep".to_string(), "30".to_string()],
    )
}

/// `nodes` are created in the container by the runtime; runtimetest opens them and checks
/// each against the device cgroup rules in `devices`.
fn create_spec_with_nodes(
    cgroup_name: &str,
    devices: Vec<LinuxDeviceCgroup>,
    nodes: Vec<LinuxDevice>,
    args: Vec<String>,
) -> Result<Spec> {
    // systemd cgroupsPath notation: [slice]:[scope prefix]:[name]
    let cgroups_path = PathBuf::from(format!("system.slice:{SCOPE_PREFIX}:{cgroup_name}"));

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(args)
                .build()
                .context("failed to build process spec")?,
        )
        .linux(
            LinuxBuilder::default()
                .cgroups_path(cgroups_path)
                .devices(nodes)
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

/// A block device node for the runtime to create at `/dev/test-<major>-<minor>`.
fn block_node(major: i64, minor: i64) -> Result<LinuxDevice> {
    LinuxDeviceBuilder::default()
        .path(PathBuf::from(format!("/dev/test-{major}-{minor}")))
        .typ(LinuxDeviceType::B)
        .major(major)
        .minor(minor)
        .build()
        .context("failed to build device node")
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
    // Devices the runtime does not add by default, so the entries can only come from
    // these rules.
    let devices = vec![
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

/// A redundant deny must leave the allowed device accessible and other devices denied.
/// The runtimes may represent these rules differently in systemd's DeviceAllow list;
/// check access inside the container rather than requiring the same list.
fn test_redundant_deny_preserves_device_access() -> TestResult {
    let cgroup_name = "systemd_devices_redundant_deny";
    let devices = vec![
        test_result!(device_rule(
            false,
            Some(LinuxDeviceType::A),
            None,
            None,
            "rwm"
        )),
        test_result!(device_rule(
            true,
            Some(LinuxDeviceType::B),
            Some(8),
            Some(0),
            "rw"
        )),
        // Never allowed above, so denying it changes nothing.
        test_result!(device_rule(
            false,
            Some(LinuxDeviceType::B),
            Some(8),
            Some(1),
            "r"
        )),
    ];

    // 8:0 is allowed, 8:1 is explicitly denied, and 8:2 stays denied by default.
    let nodes = vec![
        test_result!(block_node(8, 0)),
        test_result!(block_node(8, 1)),
        test_result!(block_node(8, 2)),
    ];
    run_device_access_test(cgroup_name, devices, nodes)
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

/// A deny on top of allow-all has no DeviceAllow form, so the unit gets a deny-all list and
/// the eBPF filter carries the rules. Checks the container still runs and the denied access
/// is refused. Needs runc >= 1.5.2: older releases leave systemd's deny-all filter attached.
fn test_deny_rule_on_allow_all_is_enforced() -> TestResult {
    let cgroup_name = "systemd_devices_allow_all_deny";
    let devices = vec![
        test_result!(device_rule(
            true,
            Some(LinuxDeviceType::A),
            None,
            None,
            "rwm"
        )),
        // 8:0 is denied; 8:1, created next to it, shows the allow-all still holds.
        test_result!(device_rule(
            false,
            Some(LinuxDeviceType::B),
            Some(8),
            Some(0),
            "r"
        )),
    ];
    let nodes = vec![
        test_result!(block_node(8, 0)),
        test_result!(block_node(8, 1)),
    ];
    run_device_access_test(cgroup_name, devices, nodes)
}

fn run_device_access_test(
    cgroup_name: &str,
    devices: Vec<LinuxDeviceCgroup>,
    nodes: Vec<LinuxDevice>,
) -> TestResult {
    let spec = test_result!(create_spec_with_nodes(
        cgroup_name,
        devices,
        nodes,
        vec!["runtimetest".to_string(), "device_cgroup".to_string()],
    ));
    // runc warns on stderr about the temporary deny-all rule, and test_inside_container
    // reads anything on stderr as a failure, so its log goes to a file here.
    let runc_log = test_result!(tempfile::NamedTempFile::new().context("runc log file"));
    let systemd_cgroup: Vec<&OsStr> = if is_runtime_runc() {
        vec![
            OsStr::new("--systemd-cgroup"),
            OsStr::new("--log"),
            runc_log.path().as_os_str(),
        ]
    } else {
        vec![OsStr::new("--systemd-cgroup")]
    };
    let options = CreateOptions::default().with_global_args(&systemd_cgroup);

    test_inside_container(&spec, &options, &|_| Ok(()))
}

/// Checks the rules are enforced, not just present on the unit: under deny-all a node the
/// runtime created for the container must not be readable.
fn test_default_deny_is_enforced() -> TestResult {
    let cgroup_name = "systemd_devices_deny_rule";
    let deny_all = test_result!(device_rule(
        false,
        Some(LinuxDeviceType::A),
        None,
        None,
        "rwm"
    ));
    let nodes = vec![test_result!(block_node(8, 0))];
    let spec = test_result!(create_spec_with_nodes(
        cgroup_name,
        vec![deny_all],
        nodes,
        vec!["runtimetest".to_string(), "device_cgroup".to_string()],
    ));
    let systemd_cgroup: &[&OsStr] = &[OsStr::new("--systemd-cgroup")];
    let options = CreateOptions::default().with_global_args(systemd_cgroup);

    test_inside_container(&spec, &options, &|_| Ok(()))
}

// NOTE: "*:minor" rules are left to the unit tests too. They cannot be seen from here: the
// default rules come after the spec's and systemd keeps the last entry for a path, so a
// "char-*" entry from the spec is always replaced by the default "char-* m".

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
    let default_deny = ConditionalTest::new(
        "default_deny_is_enforced",
        Box::new(can_run),
        Box::new(test_default_deny_is_enforced),
    );
    let allow_all_deny = ConditionalTest::new(
        "deny_rule_on_allow_all_is_enforced",
        Box::new(can_run),
        Box::new(test_deny_rule_on_allow_all_is_enforced),
    );
    let redundant_deny = ConditionalTest::new(
        "redundant_deny_preserves_device_access",
        Box::new(can_run),
        Box::new(test_redundant_deny_preserves_device_access),
    );
    test_group.add(vec![
        Box::new(whitelist),
        Box::new(allow_all),
        Box::new(default_deny),
        Box::new(allow_all_deny),
        Box::new(redundant_deny),
    ]);
    test_group
}
