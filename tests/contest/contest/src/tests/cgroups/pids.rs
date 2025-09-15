use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use oci_spec::runtime::{LinuxBuilder, LinuxPidsBuilder, LinuxResourcesBuilder, Spec, SpecBuilder};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_outside_container;
use crate::utils::test_utils::{CGROUP_ROOT, check_container_created};

// SPEC: The runtime spec does not specify what the behavior should be if the limit is
// zero or negative. We assume that the number of pids should be unlimited in this case.

fn create_spec(cgroup_name: &str, limit: i64) -> Result<Spec> {
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(Path::new("/runtime-test").join(cgroup_name))
                .resources(
                    LinuxResourcesBuilder::default()
                        .pids(
                            LinuxPidsBuilder::default()
                                .limit(limit)
                                .build()
                                .context("failed to build pids spec")?,
                        )
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

// Tests if a specified limit was successfully set
fn test_positive_limit() -> TestResult {
    let cgroup_name = "test_positive_limit";
    let limit = 50;
    let spec = test_result!(create_spec(cgroup_name, limit));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_pid_limit_set(cgroup_name, limit));
        TestResult::Passed
    })
}

// Tests if a specified limit of zero sets the pid limit to unlimited
fn test_zero_limit() -> TestResult {
    let cgroup_name = "test_zero_limit";
    let limit = 0;
    let spec = test_result!(create_spec(cgroup_name, limit));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_pids_are_unlimited(cgroup_name));
        TestResult::Passed
    })
}

// Tests if a specified negative limit sets the pid limit to unlimited
fn test_negative_limit() -> TestResult {
    let cgroup_name = "test_negative_limit";
    let limit = -1;
    let spec = test_result!(create_spec(cgroup_name, limit));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_pids_are_unlimited(cgroup_name));
        TestResult::Passed
    })
}

fn check_pid_limit_set(cgroup_name: &str, expected: i64) -> Result<()> {
    let cgroup_path = PathBuf::from(CGROUP_ROOT)
        .join("pids/runtime-test")
        .join(cgroup_name)
        .join("pids.max");
    let content = fs::read_to_string(&cgroup_path)
        .with_context(|| format!("failed to read {cgroup_path:?}"))?;
    let trimmed = content.trim();

    if trimmed.is_empty() {
        bail!(
            "expected {:?} to contain a pid limit of {}, but it was empty",
            cgroup_path,
            expected
        );
    }

    if trimmed == "max" {
        bail!(
            "expected {:?} to contain a pid limit of {}, but no limit was set",
            cgroup_path,
            expected
        );
    }

    let actual: i64 = trimmed
        .parse()
        .with_context(|| format!("could not parse {trimmed:?}"))?;
    if expected != actual {
        bail!(
            "expected {:?} to contain a pid limit of {}, but the limit was {}",
            cgroup_path,
            expected,
            actual
        );
    }

    Ok(())
}

fn check_pids_are_unlimited(cgroup_name: &str) -> Result<()> {
    let cgroup_path = PathBuf::from(CGROUP_ROOT)
        .join("pids/runtime-test")
        .join(cgroup_name)
        .join("pids.max");
    let content = fs::read_to_string(&cgroup_path)
        .with_context(|| format!("failed to read {cgroup_path:?}"))?;
    let trimmed = content.trim();

    if trimmed.is_empty() {
        bail!(
            "expected {:?} to contain a pid limit of max, but it was empty",
            cgroup_path
        );
    }

    if trimmed != "max" {
        bail!(
            "expected {:?} to contain 'max' (unlimited), but the limit was {}",
            cgroup_path,
            trimmed
        );
    }

    Ok(())
}

fn can_run() -> bool {
    Path::new("/sys/fs/cgroup/pids").exists()
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v1_pids");
    let positive_limit = ConditionalTest::new(
        "positive_pid_limit",
        Box::new(can_run),
        Box::new(test_positive_limit),
    );
    let zero_limit = ConditionalTest::new(
        "zero_pid_limit",
        Box::new(can_run),
        Box::new(test_zero_limit),
    );
    let negative_limit = ConditionalTest::new(
        "negative_pid_limit",
        Box::new(can_run),
        Box::new(test_negative_limit),
    );

    test_group.add(vec![
        Box::new(positive_limit),
        Box::new(zero_limit),
        Box::new(negative_limit),
    ]);
    test_group
}
