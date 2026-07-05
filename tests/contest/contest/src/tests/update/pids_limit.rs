use std::path::Path;

use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{
    LinuxPidsBuilder, LinuxResourcesBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{TestResult, test_result};

use super::check_cgroup_value;
use crate::utils::test_utils::check_container_created;
use crate::utils::{start_container, test_outside_container, update_container};

fn create_spec(cgroup_name: &str) -> Result<Spec> {
    let pids = LinuxPidsBuilder::default()
        .limit(20)
        .build()
        .context("failed to build pids spec")?;

    let resources = LinuxResourcesBuilder::default()
        .pids(pids)
        .build()
        .context("failed to build resources spec")?;

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
        linux.set_resources(Some(resources));
    }

    Ok(spec)
}

pub(crate) fn update_pids_limit_test() -> TestResult {
    const CGROUP_NAME: &str = "update_pids_limit";
    let spec = test_result!(create_spec(CGROUP_NAME));

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
        test_result!(check_cgroup_value(&cgroup_path, "pids.max", "20"));

        // update pids.limit to a specific value
        update_container(id, dir, &["--pids-limit", "12345"])
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "pids.max", "12345"));

        // update pids.limit to -1, pids.max will become `max`
        update_container(id, dir, &["--pids-limit", "-1"])
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "pids.max", "max"));

        // update pids.limit to 0, pids.max will become 1
        // runc maps 0 to 1, because pids.max=0 would prevent any task from being created in the cgroup, making the container unusable
        // this test follows runc's behavior
        update_container(id, dir, &["--pids-limit", "0"])
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "pids.max", "1"));

        TestResult::Passed
    })
}
