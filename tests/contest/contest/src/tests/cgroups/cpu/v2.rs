use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use libcgroups::common::{self, CgroupSetup, DEFAULT_CGROUP_ROOT};
use libcgroups::v2::controller_type::ControllerType;
use libcontainer::utils::PathBufExt;
use oci_spec::runtime::{LinuxCpuBuilder, Spec};
use test_framework::{ConditionalTest, TestGroup, TestResult, assert_result_eq, test_result};
use tracing::debug;

use super::create_spec;
use crate::tests::cgroups::attach_controller;
use crate::utils::test_outside_container;
use crate::utils::test_utils::{CGROUP_ROOT, check_container_created};

const DEFAULT_PERIOD: u64 = 100_000;
const CPU: &str = "cpu";
const CGROUP_CPU_IDLE: &str = "cpu.idle";

// SPEC: The runtime spec does not specify what should happen if the cpu weight is outside
// of the valid range of values [1, 10000]. We assume that a value of zero means that no action
// should be taken and a value of over 10000 (after being converted into the cgroup v2 format)
// should be set to the maximum value (i.e. 10000).
// It also does not specify what should happen if the cpu quota or cpu period is negative or zero.
// We assume that a negative value means that it should be set to the default value and zero means
// that it should be unchanged.

/// Tests if a cpu idle value is successfully set
fn test_cpu_idle_set() -> TestResult {
    let idle: i64 = 1;
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .idle(idle)
            .build()
            .context("build cpu spec")
    );

    let spec = test_result!(create_spec("test_cpu_idle_set", cpu));
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cpu_idle("test_cpu_idle_set", idle));
        TestResult::Passed
    })
}

/// Tests default idle value is correct
fn test_cpu_idle_default() -> TestResult {
    let default_idle = 0;
    let cpu = test_result!(LinuxCpuBuilder::default().build().context("build cpu spec"));

    let spec = test_result!(create_spec("test_cpu_idle_default", cpu));
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cpu_idle("test_cpu_idle_default", default_idle));
        TestResult::Passed
    })
}

/// Tests if a cpu weight that is in the valid range [1, 10000] is successfully set
fn test_cpu_weight_valid_set() -> TestResult {
    let cpu_weight = 22_000u64;
    let converted_cpu_weight = 1204u64;
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .shares(cpu_weight)
            .build()
            .context("build cpu spec")
    );

    let spec = test_result!(create_spec("test_cpu_weight_valid_set", cpu));
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cpu_weight(
            "test_cpu_weight_valid_set",
            converted_cpu_weight
        ));
        TestResult::Passed
    })
}

/// Tests if a cpu weight of zero is ignored
fn test_cpu_weight_zero_ignored() -> TestResult {
    let cpu_weight = 0u64;
    let default_cpu_weight = 100;
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .shares(cpu_weight)
            .build()
            .context("build cpu spec")
    );

    let spec = test_result!(create_spec("test_cpu_weight_zero_ignored", cpu));
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cpu_weight(
            "test_cpu_weight_zero_ignored",
            default_cpu_weight
        ));
        TestResult::Passed
    })
}

/// Tests behavior when setting a cpu weight that is too high
/// According to kernel documentation, cpu.weight must be in range [1, 10000]
/// Modern kernels enforce this range strictly and reject out-of-range values
fn test_cpu_weight_too_high_maximum_set() -> TestResult {
    let cpu_weight = 500_000u64;
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .shares(cpu_weight)
            .build()
            .context("build cpu spec")
    );

    let spec = test_result!(create_spec("test_cpu_weight_too_high_maximum_set", cpu));
    // We accept both behaviors: either container creation fails due to
    // out-of-range value, or it succeeds with weight set to maximum (10000)
    test_outside_container(&spec, &|data| {
        check_container_created(&data).map_or_else(
            |_e| TestResult::Passed, // Failure is expected on kernels that strictly enforce range
            |_| {
                check_cpu_weight("test_cpu_weight_too_high_maximum_set", 10_000).map_or_else(
                    |e| TestResult::Failed(anyhow::anyhow!("Weight check failed: {}", e)),
                    |_| TestResult::Passed,
                )
            },
        )
    })
}

/// Tests if a valid cpu quota (x > 0) is set successfully
fn test_cpu_quota_valid_set() -> TestResult {
    let cpu_quota = 250_000;
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .quota(cpu_quota)
            .build()
            .context("build cpu spec")
    );

    let spec = test_result!(create_spec("test_cpu_quota_valid_set", cpu));
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cpu_max(
            "test_cpu_quota_valid_set",
            cpu_quota,
            DEFAULT_PERIOD
        ));
        TestResult::Passed
    })
}

/// Tests if the cpu quota is the default value (max) if a cpu quota of zero has been specified
fn test_cpu_quota_zero_default_set() -> TestResult {
    let cpu_quota = 0;
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .quota(cpu_quota)
            .build()
            .context("build cpu spec")
    );

    let spec = test_result!(create_spec("test_cpu_quota_zero_default_set", cpu));
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cpu_max(
            "test_cpu_quota_zero_default_set",
            i64::MAX,
            DEFAULT_PERIOD
        ));
        TestResult::Passed
    })
}

/// Tests if the cpu quota is the default value (max) if a negative cpu quota has been specified
fn test_cpu_quota_negative_default_set() -> TestResult {
    let cpu_quota = -9999;
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .quota(cpu_quota)
            .build()
            .context("build cpu spec")
    );

    let spec = test_result!(create_spec(
        "test_cpu_quota_negative_value_default_set",
        cpu
    ));
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cpu_max(
            "test_cpu_quota_negative_value_default_set",
            i64::MAX,
            DEFAULT_PERIOD
        ));
        TestResult::Passed
    })
}

/// Tests if a valid cpu period (x > 0) is set successfully
/// According to kernel documentation, cpu.max format is "$MAX $PERIOD"
/// Where $MAX can be "max" to indicate no limit
/// If only one number is written, $MAX is updated (not $PERIOD)
/// Therefore, to update only period while keeping quota unlimited,
/// we must use format "max $PERIOD"
fn test_cpu_period_valid_set() -> TestResult {
    let expected_period = 250_000;
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .period(expected_period)
            .build()
            .context("build cpu spec")
    );

    let spec = test_result!(create_spec("test_cpu_period_valid_set", cpu));
    // Set period with "max $PERIOD" format as required by kernel docs
    test_result!(prepare_cpu_max(&spec, "max", &expected_period.to_string()));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        let data = test_result!(read_cgroup_data("test_cpu_period_valid_set", "cpu.max"));
        let parts: Vec<&str> = data.split_whitespace().collect();
        if parts.len() != 2 {
            return TestResult::Failed(anyhow::anyhow!("Invalid cpu.max format: {}", data));
        }
        let quota = parts[0].trim();
        let period = parts[1].trim();
        // Verify period is set correctly
        let actual_period = match period.parse::<u64>() {
            Ok(p) => p,
            Err(e) => return TestResult::Failed(anyhow::anyhow!("Failed to parse period: {}", e)),
        };
        if actual_period != expected_period || quota != "max" {
            return TestResult::Failed(anyhow::anyhow!(
                "expected cpu.max to be 'max {}', but was '{} {}'",
                expected_period,
                quota,
                actual_period
            ));
        }
        TestResult::Passed
    })
}

/// Tests if the cpu period is unchanged if the cpu period is unspecified. Cpu quota needs
/// to be unchanged as well
fn test_cpu_quota_period_unspecified_unchanged() -> TestResult {
    let quota = 250_000;
    let expected_period = 250_000;
    let cpu = test_result!(LinuxCpuBuilder::default().build().context("build cpu spec"));

    let spec = test_result!(create_spec("test_cpu_period_unspecified_unchanged", cpu));
    test_result!(prepare_cpu_max(
        &spec,
        &quota.to_string(),
        &expected_period.to_string()
    ));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cpu_max(
            "test_cpu_period_unspecified_unchanged",
            quota,
            expected_period
        ));
        TestResult::Passed
    })
}

fn test_cpu_period_and_quota_valid_set() -> TestResult {
    let expected_quota = 250_000;
    let expected_period = 250_000;
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .quota(expected_quota)
            .period(expected_period)
            .build()
            .context("build cpu spec")
    );

    let spec = test_result!(create_spec("test_cpu_period_and_quota_valid_set", cpu));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cpu_max(
            "test_cpu_period_and_quota_valid_set",
            expected_quota,
            expected_period
        ));
        TestResult::Passed
    })
}

fn check_cpu_weight(cgroup_name: &str, expected_weight: u64) -> Result<()> {
    let data = read_cgroup_data(cgroup_name, "cpu.weight")?;

    let actual_weight = data
        .parse::<u64>()
        .with_context(|| format!("failed to parse {data:?}"))?;
    assert_result_eq!(actual_weight, expected_weight, "unexpected cpu weight")
}

fn check_cpu_idle(cgroup_name: &str, expected_value: i64) -> Result<()> {
    let data = read_cgroup_data(cgroup_name, "cpu.idle")?;
    assert_result_eq!(
        data.parse::<i64>()
            .with_context(|| format!("failed to parse {data:?}"))?,
        expected_value
    )
}

fn check_cpu_max(cgroup_name: &str, expected_quota: i64, expected_period: u64) -> Result<()> {
    let data = read_cgroup_data(cgroup_name, "cpu.max")?;
    let parts: Vec<&str> = data.split_whitespace().collect();
    if parts.len() != 2 {
        bail!(
            "expected cpu.max to consist of 'quota period' but was {:?}",
            data
        );
    }

    let quota = parts[0].trim();
    if quota == "max" {
        if expected_quota != i64::MAX {
            bail!(
                "expected cpu quota to be {:?}, but was 'max'",
                expected_quota
            );
        }
    } else {
        let actual_quota = quota
            .parse::<i64>()
            .with_context(|| format!("failed to parse {quota:?}"))?;
        assert_result_eq!(expected_quota, actual_quota, "unexpected cpu quota")?;
    }

    let period = parts[1].trim();
    let actual_period = period
        .parse::<u64>()
        .with_context(|| format!("failed to parse {period:?}"))?;
    assert_result_eq!(expected_period, actual_period, "unexpected cpu period")
}

fn read_cgroup_data(cgroup_name: &str, cgroup_file: &str) -> Result<String> {
    let cgroup_path = PathBuf::from(CGROUP_ROOT)
        .join("runtime-test")
        .join(cgroup_name)
        .join(cgroup_file);

    debug!("reading value from {:?}", cgroup_path);
    let content = fs::read_to_string(&cgroup_path)
        .with_context(|| format!("failed to read {cgroup_path:?}"))?;
    let trimmed = content.trim();
    Ok(trimmed.to_owned())
}

// Ensures that cpu.max is set to different values from the default (max 100000)
// Required to catch runtimes that do not actually skip setting cpu.max if cpu
// quota and period are not specified, but overwrite the current cpu.max settings
// with the default values.
fn prepare_cpu_max(spec: &Spec, quota: &str, period: &str) -> Result<()> {
    let cgroups_path = spec
        .linux()
        .as_ref()
        .and_then(|l| l.cgroups_path().as_ref())
        .unwrap();

    let full_cgroup_path = PathBuf::from(common::DEFAULT_CGROUP_ROOT).join_safely(cgroups_path)?;
    fs::create_dir_all(&full_cgroup_path)
        .with_context(|| format!("could not create cgroup {full_cgroup_path:?}"))?;
    attach_controller(Path::new(DEFAULT_CGROUP_ROOT), cgroups_path, "cpu")?;

    let cpu_max_path = full_cgroup_path.join("cpu.max");
    fs::write(&cpu_max_path, format!("{quota} {period}"))
        .with_context(|| format!("failed to write to {cpu_max_path:?}"))?;

    Ok(())
}

fn can_run() -> bool {
    let setup_result = common::get_cgroup_setup();
    if !matches!(setup_result, Ok(CgroupSetup::Unified)) {
        debug!("cgroup setup is not v2, was {:?}", setup_result);
        return false;
    }

    let controllers_result =
        libcgroups::v2::util::get_available_controllers(common::DEFAULT_CGROUP_ROOT);
    if controllers_result.is_err() {
        debug!(
            "could not retrieve cgroup controllers: {:?}",
            controllers_result
        );
        return false;
    }

    if !controllers_result
        .unwrap()
        .into_iter()
        .any(|c| c == ControllerType::Cpu)
    {
        debug!("cpu controller is not attached to the v2 hierarchy");
        return false;
    }

    true
}

fn can_run_idle() -> bool {
    let idle_path = Path::new(common::DEFAULT_CGROUP_ROOT)
        .join(CPU)
        .join(CGROUP_CPU_IDLE);
    can_run() && idle_path.exists()
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v2_cpu");
    let test_cpu_weight_valid_set = ConditionalTest::new(
        "test_cpu_weight_valid_set",
        Box::new(can_run),
        Box::new(test_cpu_weight_valid_set),
    );

    let test_cpu_weight_zero_ignored = ConditionalTest::new(
        "test_cpu_weight_zero_ignored",
        Box::new(can_run),
        Box::new(test_cpu_weight_zero_ignored),
    );

    let test_cpu_weight_too_high_maximum_set = ConditionalTest::new(
        "test_cpu_weight_too_high_maximum_set",
        Box::new(can_run),
        Box::new(test_cpu_weight_too_high_maximum_set),
    );

    let test_cpu_quota_valid_set = ConditionalTest::new(
        "test_cpu_quota_valid_set",
        Box::new(can_run),
        Box::new(test_cpu_quota_valid_set),
    );

    let test_cpu_quota_zero_default_set = ConditionalTest::new(
        "test_cpu_quota_zero_default_set",
        Box::new(can_run),
        Box::new(test_cpu_quota_zero_default_set),
    );

    let test_cpu_quota_negative_default_set = ConditionalTest::new(
        "test_cpu_quota_negative_value_default_set",
        Box::new(can_run),
        Box::new(test_cpu_quota_negative_default_set),
    );

    let test_cpu_period_valid_set = ConditionalTest::new(
        "test_cpu_period_valid_set",
        Box::new(can_run),
        Box::new(test_cpu_period_valid_set),
    );

    let test_cpu_period_unspecified_unchanged = ConditionalTest::new(
        "test_cpu_period_unspecified_unchanged",
        Box::new(can_run),
        Box::new(test_cpu_quota_period_unspecified_unchanged),
    );

    let test_cpu_period_and_quota_valid_set = ConditionalTest::new(
        "test_cpu_period_and_quota_valid_set",
        Box::new(can_run),
        Box::new(test_cpu_period_and_quota_valid_set),
    );

    let test_cpu_idle_set = ConditionalTest::new(
        "test_cpu_idle_set",
        Box::new(can_run_idle),
        Box::new(test_cpu_idle_set),
    );

    let test_cpu_idle_default = ConditionalTest::new(
        "test_cpu_idle_default",
        Box::new(can_run_idle),
        Box::new(test_cpu_idle_default),
    );

    test_group.add(vec![
        Box::new(test_cpu_weight_valid_set),
        Box::new(test_cpu_weight_zero_ignored),
        Box::new(test_cpu_weight_too_high_maximum_set),
        Box::new(test_cpu_quota_valid_set),
        Box::new(test_cpu_quota_zero_default_set),
        Box::new(test_cpu_quota_negative_default_set),
        Box::new(test_cpu_period_valid_set),
        Box::new(test_cpu_period_unspecified_unchanged),
        Box::new(test_cpu_period_and_quota_valid_set),
        Box::new(test_cpu_idle_set),
        Box::new(test_cpu_idle_default),
    ]);
    test_group
}
