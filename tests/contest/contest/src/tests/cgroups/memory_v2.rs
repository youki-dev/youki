use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use libcgroups::common::{self, CgroupSetup};
use libcgroups::v2::controller_type::ControllerType;
use oci_spec::runtime::{
    LinuxBuilder, LinuxMemoryBuilder, LinuxResourcesBuilder, Spec, SpecBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, assert_result_eq, test_result};

use crate::utils::test_outside_container;
use crate::utils::test_utils::{CGROUP_ROOT, check_container_created};

const MEMORY_MAX: &str = "memory.max";
const MEMORY_LOW: &str = "memory.low";
const MEMORY_SWAP_MAX: &str = "memory.swap.max";

// SPEC: the runtime spec does not state how the memory resource fields map onto
// the cgroup v2 interface. youki maps memory.limit to memory.max and
// memory.reservation to memory.low. memory.swap covers memory+swap in cgroup v1
// but is a separate value in cgroup v2, so when both are set youki writes
// swap - limit to memory.swap.max.

fn create_spec(cgroup_name: &str, memory: LinuxMemoryBuilder) -> Result<Spec> {
    let memory = memory.build().context("failed to build memory spec")?;
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(PathBuf::from("/runtime-test").join(cgroup_name))
                .resources(
                    LinuxResourcesBuilder::default()
                        .memory(memory)
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

/// Tests that a memory limit is written to memory.max
fn test_memory_limit_set() -> TestResult {
    let limit: i64 = 48 * 1024 * 1024;
    let spec = test_result!(create_spec(
        "test_memory_limit_set",
        LinuxMemoryBuilder::default().limit(limit)
    ));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_memory_max("test_memory_limit_set", limit));
        TestResult::Passed
    })
}

/// Tests that a memory reservation is written to memory.low. memory.high is a
/// throttling watermark with no counterpart in the runtime spec.
fn test_memory_reservation_set() -> TestResult {
    let reservation: i64 = 16 * 1024 * 1024;
    let spec = test_result!(create_spec(
        "test_memory_reservation_set",
        LinuxMemoryBuilder::default().reservation(reservation)
    ));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_memory_low("test_memory_reservation_set", reservation));
        TestResult::Passed
    })
}

/// Tests that with a limit and a swap value both set, memory.max holds the limit
/// and memory.swap.max holds swap - limit, the cgroup v1 to v2 conversion.
fn test_memory_swap_set() -> TestResult {
    let limit: i64 = 48 * 1024 * 1024;
    let swap: i64 = 64 * 1024 * 1024;
    let expected_swap_max = swap - limit;
    let spec = test_result!(create_spec(
        "test_memory_swap_set",
        LinuxMemoryBuilder::default().limit(limit).swap(swap)
    ));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_memory_max("test_memory_swap_set", limit));
        test_result!(check_memory_swap_max(
            "test_memory_swap_set",
            expected_swap_max
        ));
        TestResult::Passed
    })
}

fn check_memory_max(cgroup_name: &str, expected: i64) -> Result<()> {
    let data = read_cgroup_data(cgroup_name, MEMORY_MAX)?;
    let actual = data
        .parse::<i64>()
        .with_context(|| format!("failed to parse {data:?}"))?;
    assert_result_eq!(actual, expected, "unexpected memory.max")
}

fn check_memory_low(cgroup_name: &str, expected: i64) -> Result<()> {
    let data = read_cgroup_data(cgroup_name, MEMORY_LOW)?;
    let actual = data
        .parse::<i64>()
        .with_context(|| format!("failed to parse {data:?}"))?;
    assert_result_eq!(actual, expected, "unexpected memory.low")
}

fn check_memory_swap_max(cgroup_name: &str, expected: i64) -> Result<()> {
    let data = read_cgroup_data(cgroup_name, MEMORY_SWAP_MAX)?;
    let actual = data
        .parse::<i64>()
        .with_context(|| format!("failed to parse {data:?}"))?;
    assert_result_eq!(actual, expected, "unexpected memory.swap.max")
}

fn read_cgroup_data(cgroup_name: &str, cgroup_file: &str) -> Result<String> {
    let cgroup_path = PathBuf::from(CGROUP_ROOT)
        .join("runtime-test")
        .join(cgroup_name)
        .join(cgroup_file);

    let content = fs::read_to_string(&cgroup_path)
        .with_context(|| format!("failed to read {cgroup_path:?}"))?;
    Ok(content.trim().to_owned())
}

fn can_run() -> bool {
    let setup_result = common::get_cgroup_setup();
    if !matches!(setup_result, Ok(CgroupSetup::Unified)) {
        return false;
    }

    let controllers_result =
        libcgroups::v2::util::get_available_controllers(common::DEFAULT_CGROUP_ROOT);
    match controllers_result {
        Ok(controllers) => controllers.into_iter().any(|c| c == ControllerType::Memory),
        Err(_) => false,
    }
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v2_memory");

    let memory_limit_set = ConditionalTest::new(
        "test_memory_limit_set",
        Box::new(can_run),
        Box::new(test_memory_limit_set),
    );

    let memory_reservation_set = ConditionalTest::new(
        "test_memory_reservation_set",
        Box::new(can_run),
        Box::new(test_memory_reservation_set),
    );

    let memory_swap_set = ConditionalTest::new(
        "test_memory_swap_set",
        Box::new(can_run),
        Box::new(test_memory_swap_set),
    );

    test_group.add(vec![
        Box::new(memory_limit_set),
        Box::new(memory_reservation_set),
        Box::new(memory_swap_set),
    ]);

    test_group
}
