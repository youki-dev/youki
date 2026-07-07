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
