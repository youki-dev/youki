use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use libcgroups::v2::controller_type::ControllerType;
use oci_spec::runtime::{
    LinuxBuilder, LinuxCpuBuilder, LinuxMemoryBuilder, LinuxResources, LinuxResourcesBuilder, Spec,
    SpecBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, assert_result_eq, test_result};

use crate::utils::test_utils::{CGROUP_ROOT, check_container_created};
use crate::utils::{
    cgroup_has_file, is_cgroup_v2, is_cgroup_v2_with_controller, test_outside_container,
};

const MEMORY_SWAP_MAX: &str = "memory.swap.max";

// SPEC: each key in linux.resources.unified names a file in the container's
// cgroup, and the runtime writes the value to that file, including keys that
// no other resource field covers, such as memory.high. The runtime must fail
// when a key refers to a controller that is not present. The spec does not say
// which value wins when a unified key and another resource field set the same
// file; youki follows runc and applies the unified map last, so the unified
// value wins.
//
// The tests use the values of the runc tests they port. The memory values are
// multiples of 64 KiB: the kernel keeps memory limits in whole pages, so a
// value that is not a multiple of the page size reads back rounded down.

fn create_spec(cgroup_name: &str, resources: LinuxResources) -> Result<Spec> {
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(PathBuf::from("/runtime-test").join(cgroup_name))
                .resources(resources)
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn unified_map(values: &[(&str, &str)]) -> HashMap<String, String> {
    values
        .iter()
        .map(|(cgroup_file, value)| (cgroup_file.to_string(), value.to_string()))
        .collect()
}

/// Tests that each value in the unified map is written to the cgroup file of
/// the same name, including memory.high, which no other resource field sets.
/// Port of runc's "runc run (cgroup v2 resources.unified only)".
fn test_unified_set() -> TestResult {
    const CGROUP_NAME: &str = "test_unified_set";
    let values = [
        ("memory.min", "131072"),
        ("memory.low", "524288"),
        ("memory.high", "20971520"),
        ("memory.max", "41943040"),
        ("pids.max", "99"),
        ("cpu.max", "10000 100000"),
        ("cpu.weight", "42"),
    ];
    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .unified(unified_map(&values))
            .build()
            .context("failed to build resource spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, resources));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        for (cgroup_file, expected) in values {
            test_result!(check_cgroup_file(CGROUP_NAME, cgroup_file, expected));
        }
        TestResult::Passed
    })
}

/// Tests that memory.swap.max from the unified map is written as-is, without
/// the swap - limit conversion that the memory.swap field goes through.
/// Port of runc's "runc run (cgroup v2 resources.unified swap)".
fn test_unified_swap_set() -> TestResult {
    const CGROUP_NAME: &str = "test_unified_swap_set";
    let values = [("memory.max", "20512768"), (MEMORY_SWAP_MAX, "20971520")];
    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .unified(unified_map(&values))
            .build()
            .context("failed to build resource spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, resources));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        for (cgroup_file, expected) in values {
            test_result!(check_cgroup_file(CGROUP_NAME, cgroup_file, expected));
        }
        TestResult::Passed
    })
}

/// Tests that a unified value wins over the value another resource field sets
/// for the same file. memory.max, cpu.max and cpu.weight are set both ways,
/// with values that differ, so a unified map applied before the other fields
/// fails here.
/// Port of runc's "runc run (cgroup v2 resources.unified override)".
fn test_unified_override() -> TestResult {
    const CGROUP_NAME: &str = "test_unified_override";
    let values = [
        ("memory.min", "131072"),
        ("memory.max", "41943040"),
        ("pids.max", "42"),
        ("cpu.max", "5000 50000"),
        ("cpu.weight", "42"),
    ];
    let memory = test_result!(
        LinuxMemoryBuilder::default()
            .limit(33554432)
            .build()
            .context("failed to build memory spec")
    );
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .shares(3333u64)
            .quota(40000)
            .period(100000u64)
            .build()
            .context("failed to build cpu spec")
    );
    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .memory(memory)
            .cpu(cpu)
            .unified(unified_map(&values))
            .build()
            .context("failed to build resource spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, resources));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        for (cgroup_file, expected) in values {
            test_result!(check_cgroup_file(CGROUP_NAME, cgroup_file, expected));
        }
        TestResult::Passed
    })
}

/// Tests that a unified key for a controller that is not present makes
/// container creation fail and leaves no container behind
fn test_unified_unavailable_controller() -> TestResult {
    const CGROUP_NAME: &str = "test_unified_unavailable_controller";
    let key = "nonexistent.max";
    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .unified(unified_map(&[(key, "1")]))
            .build()
            .context("failed to build resource spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, resources));

    test_outside_container(&spec, &|data| match data.create_result {
        Err(e) => TestResult::Failed(anyhow!(e)),
        Ok(status) if status.success() => TestResult::Failed(anyhow!(
            "unified key {key} was accepted, but its controller is not present"
        )),
        Ok(_) if data.state.is_some() => TestResult::Failed(anyhow!(
            "container state exists after the failed create: {:?}",
            data.state
        )),
        Ok(_) if data.state_err.is_empty() => {
            TestResult::Failed(anyhow!("state of the failed container returned no error"))
        }
        Ok(_) => TestResult::Passed,
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
    is_cgroup_v2_with_controller(ControllerType::Memory)
        && is_cgroup_v2_with_controller(ControllerType::Pids)
        && is_cgroup_v2_with_controller(ControllerType::Cpu)
}

fn can_run_swap() -> bool {
    is_cgroup_v2_with_controller(ControllerType::Memory) && cgroup_has_file(MEMORY_SWAP_MAX)
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v2_unified");

    let unified_set = ConditionalTest::new(
        "test_unified_set",
        Box::new(can_run),
        Box::new(test_unified_set),
    );

    let unified_swap_set = ConditionalTest::new(
        "test_unified_swap_set",
        Box::new(can_run_swap),
        Box::new(test_unified_swap_set),
    );

    let unified_override = ConditionalTest::new(
        "test_unified_override",
        Box::new(can_run),
        Box::new(test_unified_override),
    );

    let unified_unavailable_controller = ConditionalTest::new(
        "test_unified_unavailable_controller",
        Box::new(is_cgroup_v2),
        Box::new(test_unified_unavailable_controller),
    );

    test_group.add(vec![
        Box::new(unified_set),
        Box::new(unified_swap_set),
        Box::new(unified_override),
        Box::new(unified_unavailable_controller),
    ]);

    test_group
}
