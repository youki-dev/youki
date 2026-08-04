use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{
    LinuxCpuBuilder, LinuxResources, LinuxResourcesBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{TestResult, test_result};

use super::check_cgroup_value;
use crate::utils::test_utils::check_container_created;
use crate::utils::{start_container, test_outside_container, update_container_with_stdin};

const CPUSET_MEMS_EFFECTIVE: &str = "/sys/fs/cgroup/cpuset.mems.effective";

fn has_multiple_numa_nodes() -> bool {
    fs::read_to_string(CPUSET_MEMS_EFFECTIVE)
        .is_ok_and(|effective_mems| effective_mems.trim() != "0")
}

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

// "update cpuset parameters via resources.CPU"
pub(crate) fn update_cpuset_parameters_via_resources_cpu_test() -> TestResult {
    const CGROUP_NAME: &str = "update_cpuset_parameters_via_resources_cpu";

    let cpu = test_result!(
        LinuxCpuBuilder::default()
            .cpus("0")
            .mems("0")
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

        // check the initial values were properly set
        test_result!(check_cgroup_value(&cgroup_path, "cpuset.cpus", "0"));
        test_result!(check_cgroup_value(&cgroup_path, "cpuset.mems", "0"));

        // set CPU.Cpus to 1 in JSON format
        let json = serde_json::json!({"cpu": {"cpus": "1"}}).to_string();
        update_container_with_stdin(id, dir, &["-r", "-"], &json)
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "cpuset.cpus", "1"));

        // if NUMA is not enabled, skip this step
        if !has_multiple_numa_nodes() {
            return TestResult::Passed;
        }

        // set CPU.Mems to 1 in JSON format
        let json = serde_json::json!({"cpu": {"mems": "1"}}).to_string();
        update_container_with_stdin(id, dir, &["-r", "-"], &json)
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "cpuset.mems", "1"));

        TestResult::Passed
    })
}

// "update cpuset parameters via v2 unified map"
pub(crate) fn update_cpuset_parameters_via_v2_unified_map_test() -> TestResult {
    const CGROUP_NAME: &str = "update_cpuset_parameters_via_v2_unified_map";

    let unified = HashMap::from([
        ("cpuset.cpus".to_string(), "0".to_string()),
        ("cpuset.mems".to_string(), "0".to_string()),
    ]);
    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .unified(unified)
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

        // check the initial values were properly set
        test_result!(check_cgroup_value(&cgroup_path, "cpuset.cpus", "0"));
        test_result!(check_cgroup_value(&cgroup_path, "cpuset.mems", "0"));

        // set cpuset.cpus via v2 unified map to 1 in JSON format
        let json = serde_json::json!({"unified": {"cpuset.cpus": "1"}}).to_string();
        update_container_with_stdin(id, dir, &["-r", "-"], &json)
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "cpuset.cpus", "1"));

        // if NUMA is not enabled, skip this step
        if !has_multiple_numa_nodes() {
            return TestResult::Passed;
        }

        // set cpuset.mems via v2 unified map to 1 in JSON format
        let json = serde_json::json!({"unified": {"cpuset.mems": "1"}}).to_string();
        update_container_with_stdin(id, dir, &["-r", "-"], &json)
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "cpuset.mems", "1"));

        TestResult::Passed
    })
}

// "update cpuset cpus range via v2 unified map"
pub(crate) fn update_cpuset_cpus_range_via_v2_unified_map_test() -> TestResult {
    const CGROUP_NAME: &str = "update_cpuset_cpus_range_via_v2_unified_map";

    let unified = HashMap::from([("cpuset.cpus".to_string(), "0-5".to_string())]);
    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .unified(unified)
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

        test_result!(check_cgroup_value(&cgroup_path, "cpuset.cpus", "0-5"));

        // set cpuset.cpus via v2 unified map to 5-8 in JSON format
        let json = serde_json::json!({"unified": {"cpuset.cpus": "5-8"}}).to_string();
        update_container_with_stdin(id, dir, &["-r", "-"], &json)
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "cpuset.cpus", "5-8"));

        TestResult::Passed
    })
}
