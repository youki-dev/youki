use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{
    LinuxCpuBuilder, LinuxResources, LinuxResourcesBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{TestResult, test_result};

use super::{check_cgroup_value, update_container_and_wait};
use crate::utils::test_utils::check_container_created;
use crate::utils::{
    start_container, test_outside_container, update_container, update_container_with_stdin,
};

fn create_spec(cgroup_name: &str, resources: Option<LinuxResources>) -> Result<Spec> {
    let mut spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "1000".to_string()])
                .build()?,
        )
        .build()
        .context("failed to build spec")?;

    if let Some(linux) = spec.linux_mut() {
        linux.set_cgroups_path(Some(Path::new("/runtime-test").join(cgroup_name)));
        linux.set_resources(resources);
    }

    Ok(spec)
}

// crates/libcgroups/src/v2/cpu.rs
fn convert_shares_to_cgroup2(shares: u64) -> u64 {
    if shares == 0 {
        return 0;
    }

    const MIN_SHARES: u64 = 2;
    const MAX_SHARES: u64 = 262_144;
    const MAX_CPU_WEIGHT: u64 = 10_000;

    if shares <= MIN_SHARES {
        return 1;
    }

    if shares >= MAX_SHARES {
        return MAX_CPU_WEIGHT;
    }

    let log_shares = (shares as f64).log2();
    let exponent = (log_shares * log_shares + 125.0 * log_shares) / 612.0 - 7.0 / 34.0;
    let weight = (10f64.powf(exponent)).ceil() as u64;

    weight.clamp(1, MAX_CPU_WEIGHT)
}

// "update cgroup cpu limits"
pub(crate) fn update_cpu_limits_test() -> TestResult {
    const CGROUP_NAME: &str = "cpu_limits";
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .period(1000000_u64)
            .quota(500000)
            .shares(100_u64)
            .build()
            .context("failed to build cpu resources")
    );

    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .cpu(cpu)
            .build()
            .context("failed to build resources spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, Some(resources)));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();

        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }
        let cgroup_path = Path::new("/sys/fs/cgroup/runtime-test").join(CGROUP_NAME);

        test_result!(check_cgroup_value(
            &cgroup_path,
            "cpu.max",
            "500000 1000000"
        ));
        test_result!(check_cgroup_value(
            &cgroup_path,
            "cpu.weight",
            &convert_shares_to_cgroup2(100).to_string()
        ));

        // Update cpu period.
        test_result!(update_container_and_wait(
            id,
            dir,
            &["--cpu-period", "900000"],
        ));
        test_result!(check_cgroup_value(&cgroup_path, "cpu.max", "500000 900000"));

        // Update cpu quota.
        test_result!(update_container_and_wait(
            id,
            dir,
            &["--cpu-quota", "600000"],
        ));
        test_result!(check_cgroup_value(&cgroup_path, "cpu.max", "600000 900000"));

        // Remove cpu quota.
        test_result!(update_container_and_wait(id, dir, &["--cpu-quota", "-1"],));
        test_result!(check_cgroup_value(&cgroup_path, "cpu.max", "max 900000"));

        // Update cpu-shares.
        test_result!(update_container_and_wait(id, dir, &["--cpu-share", "200"],));
        test_result!(check_cgroup_value(
            &cgroup_path,
            "cpu.weight",
            &convert_shares_to_cgroup2(200).to_string()
        ));

        // Revert to the test initial value via json on stdin
        let json = serde_json::json!({"cpu": {"shares": 100,"quota": 500000,"period": 1000000,}})
            .to_string();
        let update_result = update_container_with_stdin(id, dir, &["-r", "-"], &json)
            .unwrap()
            .wait()
            .unwrap();
        if !update_result.success() {
            return TestResult::Failed(anyhow!("update cpu_limit_test via stdin failed"));
        }
        test_result!(check_cgroup_value(
            &cgroup_path,
            "cpu.max",
            "500000 1000000"
        ));

        // Redo all the changes at once.
        test_result!(update_container_and_wait(
            id,
            dir,
            &[
                "--cpu-period",
                "900000",
                "--cpu-quota",
                "600000",
                "--cpu-share",
                "200"
            ],
        ));
        test_result!(check_cgroup_value(&cgroup_path, "cpu.max", "600000 900000"));
        test_result!(check_cgroup_value(
            &cgroup_path,
            "cpu.weight",
            &convert_shares_to_cgroup2(200).to_string()
        ));

        // Reset to initial test values via json file.
        let json_path = dir.join("update_cpu_limits.json");
        fs::write(&json_path, &json).unwrap();
        test_result!(update_container_and_wait(
            id,
            dir,
            &["-r", json_path.to_str().unwrap()]
        ));
        test_result!(check_cgroup_value(
            &cgroup_path,
            "cpu.max",
            "500000 1000000"
        ));
        test_result!(check_cgroup_value(
            &cgroup_path,
            "cpu.weight",
            &convert_shares_to_cgroup2(100).to_string()
        ));

        TestResult::Passed
    })
}

// "cpu burst"
pub(crate) fn cpu_burst_test() -> TestResult {
    const CGROUP_NAME: &str = "cpu_burst";
    let spec = test_result!(create_spec(CGROUP_NAME, None));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();

        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }
        let cgroup_path = Path::new("/sys/fs/cgroup/runtime-test").join(CGROUP_NAME);

        test_result!(check_cgroup_value(&cgroup_path, "cpu.max.burst", "0"));

        test_result!(update_container_and_wait(
            id,
            dir,
            &["--cpu-period", "900000", "--cpu-burst", "500000"],
        ));
        test_result!(check_cgroup_value(&cgroup_path, "cpu.max.burst", "500000"));

        // Ensure a memory-only update does not reset cpu.max.burst.
        test_result!(update_container_and_wait(id, dir, &["--memory", "100M"]));
        test_result!(check_cgroup_value(&cgroup_path, "cpu.max.burst", "500000"));

        test_result!(update_container_and_wait(
            id,
            dir,
            &["--cpu-period", "900000", "--cpu-burst", "0"],
        ));
        test_result!(check_cgroup_value(&cgroup_path, "cpu.max.burst", "0"));

        TestResult::Passed
    })
}

// "set cpu period with no quota"
pub(crate) fn set_cpu_period_without_quota_test() -> TestResult {
    const CGROUP_NAME: &str = "cpu_period_no_quota";
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .period(1000000_u64)
            .build()
            .context("failed to build cpu resources")
    );

    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .cpu(cpu)
            .build()
            .context("failed to build resources spec")
    );

    let spec = test_result!(create_spec(CGROUP_NAME, Some(resources)));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();

        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let cgroup_path = Path::new("/sys/fs/cgroup/runtime-test").join(CGROUP_NAME);

        test_result!(check_cgroup_value(&cgroup_path, "cpu.max", "max 1000000"));

        TestResult::Passed
    })
}

// "set cpu period with no quota (invalid period)"
pub(crate) fn set_cpu_period_without_quota_invalid_test() -> TestResult {
    const CGROUP_NAME: &str = "cpu_period_invalid";
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .period(100_u64)
            .build()
            .context("failed to build cpu resources")
    );

    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .cpu(cpu)
            .build()
            .context("failed to build resources spec")
    );

    let spec = test_result!(create_spec(CGROUP_NAME, Some(resources)));

    test_outside_container(&spec, &|data| {
        if check_container_created(&data).is_ok() {
            return TestResult::Failed(anyhow!(
                "expected container creation to fail with invalid cpu period"
            ));
        }
        TestResult::Passed
    })
}

// "set cpu quota with no period"
pub(crate) fn set_cpu_quota_without_period_test() -> TestResult {
    const CGROUP_NAME: &str = "cpu_quota_no_period";
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .quota(5000)
            .build()
            .context("failed to build cpu resources")
    );

    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .cpu(cpu)
            .build()
            .context("failed to build resources spec")
    );

    let spec = test_result!(create_spec(CGROUP_NAME, Some(resources)));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();

        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let cgroup_path = Path::new("/sys/fs/cgroup/runtime-test").join(CGROUP_NAME);

        // cpu period defaults to 100000 (100ms) when not specified
        test_result!(check_cgroup_value(&cgroup_path, "cpu.max", "5000 100000"));

        TestResult::Passed
    })
}

// "update cpu period with no previous period/quota set"
pub(crate) fn update_cpu_period_without_previous_limits_test() -> TestResult {
    const CGROUP_NAME: &str = "update_cpu_period_without_previous_limits";
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .build()
            .context("failed to build empty cpu resources")
    );

    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .cpu(cpu)
            .build()
            .context("failed to build resources spec")
    );

    let spec = test_result!(create_spec(CGROUP_NAME, Some(resources)));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let cgroup_path = Path::new("/sys/fs/cgroup/runtime-test").join(CGROUP_NAME);

        test_result!(update_container_and_wait(
            id,
            dir,
            &["--cpu-period", "50000"]
        ));
        test_result!(check_cgroup_value(&cgroup_path, "cpu.max", "max 50000"));

        TestResult::Passed
    })
}

// "update cpu quota with no previous period/quota set"
pub(crate) fn update_cpu_quota_without_previous_limits_test() -> TestResult {
    const CGROUP_NAME: &str = "update_cpu_quota_without_previous_limits";
    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .build()
            .context("failed to build empty cpu resources")
    );

    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .cpu(cpu)
            .build()
            .context("failed to build resources spec")
    );

    let spec = test_result!(create_spec(CGROUP_NAME, Some(resources)));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let cgroup_path = Path::new("/sys/fs/cgroup/runtime-test").join(CGROUP_NAME);

        test_result!(update_container_and_wait(
            id,
            dir,
            &["--cpu-quota", "30000"]
        ));
        test_result!(check_cgroup_value(&cgroup_path, "cpu.max", "30000 100000"));

        TestResult::Passed
    })
}

// "update cgroup cpu.idle"
pub(crate) fn update_cgroup_cpu_idle_test() -> TestResult {
    const CGROUP_NAME: &str = "update_cgroup_cpu_idle";

    let spec = test_result!(create_spec(CGROUP_NAME, None));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let cgroup_path = Path::new("/sys/fs/cgroup/runtime-test").join(CGROUP_NAME);

        test_result!(check_cgroup_value(&cgroup_path, "cpu.idle", "0"));

        for val in ["1", "0", "1"] {
            let json =
                serde_json::json!({"cpu": {"idle": val.parse::<i64>().unwrap()}}).to_string();

            let update_result = update_container_with_stdin(id, dir, &["-r", "-"], &json)
                .unwrap()
                .wait()
                .unwrap();
            if !update_result.success() {
                return TestResult::Failed(anyhow!("update --cpu-idle {val} via stdin failed"));
            }
            test_result!(check_cgroup_value(&cgroup_path, "cpu.idle", val));
        }

        for val in ["1", "0", "1"] {
            test_result!(update_container_and_wait(id, dir, &["--cpu-idle", val]));
            test_result!(check_cgroup_value(&cgroup_path, "cpu.idle", val));
        }

        for val in ["-1", "2", "3"] {
            let update_result = update_container(id, dir, &["--cpu-idle", val])
                .unwrap()
                .wait()
                .unwrap();

            if update_result.success() {
                return TestResult::Failed(anyhow!(
                    "expected --cpu-idle {val} to fail, but it succeeded"
                ));
            }
            test_result!(check_cgroup_value(&cgroup_path, "cpu.idle", "1"));
        }

        test_result!(update_container_and_wait(
            id,
            dir,
            &["--cpu-period", "10000"]
        ));
        test_result!(check_cgroup_value(&cgroup_path, "cpu.idle", "1"));

        TestResult::Passed
    })

    // Not ported: runc's "update cpu period in a pod cgroup with pod limit set"
    // requires cgroup v1.
    //
    // Not ported: runc's "update cgroup cpu.idle via systemd v252+"
    // requires the systemd cgroup driver (systemd_v252); contest tests
    // currently target the cgroupfs driver only.
}
