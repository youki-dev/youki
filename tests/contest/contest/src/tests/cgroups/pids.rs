use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use libcgroups::v2::controller_type::ControllerType;
use oci_spec::runtime::{LinuxBuilder, LinuxPidsBuilder, LinuxResourcesBuilder, Spec, SpecBuilder};
use test_framework::{ConditionalTest, TestGroup, TestResult, assert_result_eq, test_result};

use crate::utils::test_utils::{CGROUP_ROOT, check_container_created};
use crate::utils::{is_cgroup_v2_with_controller, test_outside_container};

const PIDS_MAX: &str = "pids.max";

// SPEC: the runtime spec does not state how the pids limit maps onto the
// cgroup v2 interface. youki follows runc here: a positive limit is written
// as-is, any negative limit becomes "max", and a limit of 0 is written as 1.
// A container created with that 1-process cap cannot fork its init process
// (#3644), so that case is not asserted here.

fn create_spec(cgroup_name: &str, pids: LinuxPidsBuilder) -> Result<Spec> {
    let pids = pids.build().context("failed to build pids spec")?;
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(PathBuf::from("/runtime-test").join(cgroup_name))
                .resources(
                    LinuxResourcesBuilder::default()
                        .pids(pids)
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

/// Tests that a pids limit is written to pids.max
fn test_pids_limit_set() -> TestResult {
    let limit = 64;
    let spec = test_result!(create_spec(
        "test_pids_limit_set",
        LinuxPidsBuilder::default().limit(limit)
    ));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cgroup_file(
            "test_pids_limit_set",
            PIDS_MAX,
            &limit.to_string()
        ));
        TestResult::Passed
    })
}

/// Tests that a negative pids limit is written as "max", which removes the
/// limit on the unified hierarchy
fn test_pids_negative_limit_is_max() -> TestResult {
    let spec = test_result!(create_spec(
        "test_pids_negative_limit_is_max",
        LinuxPidsBuilder::default().limit(-1)
    ));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cgroup_file(
            "test_pids_negative_limit_is_max",
            PIDS_MAX,
            "max"
        ));
        TestResult::Passed
    })
}

fn check_cgroup_file(cgroup_name: &str, cgroup_file: &str, expected: &str) -> Result<()> {
    let cgroup_path = PathBuf::from(CGROUP_ROOT)
        .join("runtime-test")
        .join(cgroup_name)
        .join(cgroup_file);

    let content = fs::read_to_string(&cgroup_path)
        .with_context(|| format!("failed to read {cgroup_path:?}"))?;
    assert_result_eq!(expected, content.trim(), "unexpected {cgroup_file}")
}

fn can_run() -> bool {
    is_cgroup_v2_with_controller(ControllerType::Pids)
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v2_pids");

    let pids_limit_set = ConditionalTest::new(
        "test_pids_limit_set",
        Box::new(can_run),
        Box::new(test_pids_limit_set),
    );

    let pids_negative_limit_is_max = ConditionalTest::new(
        "test_pids_negative_limit_is_max",
        Box::new(can_run),
        Box::new(test_pids_negative_limit_is_max),
    );

    test_group.add(vec![
        Box::new(pids_limit_set),
        Box::new(pids_negative_limit_is_max),
    ]);

    test_group
}
