mod blkio;
mod common;
mod cpu;
mod cpuset;
mod pids_limit;

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use libcgroups::v2::controller_type::ControllerType;
use test_framework::{ConditionalTest, TestGroup};

pub(super) use crate::utils::is_cgroup_v2;
use crate::utils::{is_cgroup_v2_with_controller, is_runtime_youki, update_container};

pub(super) fn check_cgroup_value(base: &Path, file: &str, expected: &str) -> anyhow::Result<()> {
    let path = base.join(file);
    let got =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let got = got.trim();

    if got != expected {
        anyhow::bail!("{}: expected {}, got {}", path.display(), expected, got);
    }
    Ok(())
}

/// Runs `update` and waits for it to complete successfully.
/// Intended for happy-path tests only. Use `update_container` directly
/// when testing expected failure cases.
pub(super) fn update_container_and_wait<P: AsRef<Path>>(
    id: &str,
    dir: P,
    args: &[&str],
) -> Result<()> {
    let status = update_container(id, dir, args)?
        .wait()
        .context("failed to wait for container update")?;

    if !status.success() {
        return Err(anyhow!("container update failed with status: {status}"));
    }

    Ok(())
}

// can_run checks if the test environment supports cgroup v2.
fn can_run() -> bool {
    is_cgroup_v2()
}
// can_run_update checks if the test environment supports cgroup v2
// and the runtime supports the update command with all CLI flags.
// youki only supports --pids-limit and --resources (JSON) via update CLI.
// https://github.com/youki-dev/youki/blob/b55b14491ebddf66a29d109d0270b450e020fa32/crates/youki/src/commands/update.rs#L26
// but --pids-limit is temporarily skipped because its behavior is incorrect.
// See https://github.com/youki-dev/youki/issues/3594.
// TODO: remove is_runtime_runc() condition when youki supports full update CLI & support test for cgroup_v1
fn can_run_update() -> bool {
    !is_runtime_youki() && is_cgroup_v2()
}

fn cpu_count() -> usize {
    fs::read_to_string("/proc/cpuinfo")
        .map(|content| {
            content
                .lines()
                .filter(|line| line.starts_with("processor"))
                .count()
        })
        .unwrap_or(0)
}

fn can_run_cpuset() -> bool {
    is_cgroup_v2_with_controller(ControllerType::CpuSet)
}

fn can_run_cpuset_update() -> bool {
    can_run_cpuset() && cpu_count() >= 2
}

fn can_run_cpuset_range_update() -> bool {
    can_run_cpuset() && cpu_count() > 8
}

fn can_run_blkio_update() -> bool {
    is_cgroup_v2_with_controller(ControllerType::Io)
}

pub fn get_update_test() -> TestGroup {
    let mut test_group = TestGroup::new("update");

    let update_cgroup_v2_common_limits_test = ConditionalTest::new(
        "update_cgroup_v2_common_limits_test",
        Box::new(can_run_update),
        Box::new(common::update_common_limits_test),
    );

    let update_cpu_limits_test = ConditionalTest::new(
        "update_cpu_limits_test",
        Box::new(can_run_update),
        Box::new(cpu::update_cpu_limits_test),
    );

    let update_pids_limit_test = ConditionalTest::new(
        "update_pids_limit_test",
        Box::new(can_run_update),
        Box::new(pids_limit::update_pids_limit_test),
    );

    let update_blkio_weight_test = ConditionalTest::new(
        "update_blkio_weight_test",
        Box::new(can_run_blkio_update),
        Box::new(blkio::update_blkio_weight_test),
    );

    let cpu_burst_test = ConditionalTest::new(
        "cpu_burst_test",
        Box::new(can_run_update),
        Box::new(cpu::cpu_burst_test),
    );

    let set_cpu_period_without_quota_test = ConditionalTest::new(
        "set_cpu_period_without_quota_test",
        Box::new(can_run),
        Box::new(cpu::set_cpu_period_without_quota_test),
    );

    let set_cpu_period_without_quota_invalid_test = ConditionalTest::new(
        "set_cpu_period_without_quota_invalid_test",
        Box::new(can_run),
        Box::new(cpu::set_cpu_period_without_quota_invalid_test),
    );

    let set_cpu_quota_without_period_test = ConditionalTest::new(
        "set_cpu_quota_without_period_test",
        Box::new(can_run),
        Box::new(cpu::set_cpu_quota_without_period_test),
    );

    let update_cpu_period_without_previous_limits_test = ConditionalTest::new(
        "update_cpu_period_without_previous_limits_test",
        Box::new(can_run_update),
        Box::new(cpu::update_cpu_period_without_previous_limits_test),
    );

    let update_cpu_quota_without_previous_limits_test = ConditionalTest::new(
        "update_cpu_quota_without_previous_limits_test",
        Box::new(can_run_update),
        Box::new(cpu::update_cpu_quota_without_previous_limits_test),
    );

    let update_cgroup_cpu_idle_test = ConditionalTest::new(
        "update_cgroup_cpu_idle_test",
        Box::new(can_run_update),
        Box::new(cpu::update_cgroup_cpu_idle_test),
    );

    let update_cgroup_v2_resources_via_unified_map_test = ConditionalTest::new(
        "update_cgroup_v2_resources_via_unified_map_test",
        Box::new(can_run),
        Box::new(cpuset::update_cgroup_v2_resources_via_unified_map_test),
    );

    let update_cpuset_parameters_via_resources_cpu_test = ConditionalTest::new(
        "update_cpuset_parameters_via_resources_cpu_test",
        Box::new(can_run_cpuset_update),
        Box::new(cpuset::update_cpuset_parameters_via_resources_cpu_test),
    );

    let update_cpuset_parameters_via_v2_unified_map_test = ConditionalTest::new(
        "update_cpuset_parameters_via_v2_unified_map_test",
        Box::new(can_run_cpuset_update),
        Box::new(cpuset::update_cpuset_parameters_via_v2_unified_map_test),
    );

    let update_cpuset_cpus_range_via_v2_unified_map_test = ConditionalTest::new(
        "update_cpuset_cpus_range_via_v2_unified_map_test",
        Box::new(can_run_cpuset_range_update),
        Box::new(cpuset::update_cpuset_cpus_range_via_v2_unified_map_test),
    );

    test_group.add(vec![
        Box::new(update_cgroup_v2_common_limits_test),
        Box::new(update_cpu_limits_test),
        Box::new(update_pids_limit_test),
        Box::new(update_blkio_weight_test),
        Box::new(cpu_burst_test),
        Box::new(set_cpu_period_without_quota_test),
        Box::new(set_cpu_period_without_quota_invalid_test),
        Box::new(set_cpu_quota_without_period_test),
        Box::new(update_cpu_period_without_previous_limits_test),
        Box::new(update_cpu_quota_without_previous_limits_test),
        Box::new(update_cgroup_cpu_idle_test),
        Box::new(update_cgroup_v2_resources_via_unified_map_test),
        Box::new(update_cpuset_parameters_via_resources_cpu_test),
        Box::new(update_cpuset_parameters_via_v2_unified_map_test),
        Box::new(update_cpuset_cpus_range_via_v2_unified_map_test),
    ]);
    test_group
}
