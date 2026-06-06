use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{
    LinuxMemoryBuilder, LinuxPidsBuilder, LinuxResourcesBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{TestResult, test_result};

use super::check_cgroup_value;
use crate::utils::test_utils::check_container_created;
use crate::utils::{
    start_container, test_outside_container, update_container, update_container_with_stdin,
};

const CGROUP_NAME: &str = "update_common_limits";

fn create_spec() -> Result<Spec> {
    let memory = LinuxMemoryBuilder::default()
        .limit(33554432)
        .reservation(25165824)
        .build()
        .context("failed to build memory spec")?;

    let pids = LinuxPidsBuilder::default()
        .limit(20)
        .build()
        .context("failed to build pids spec")?;

    let resources = LinuxResourcesBuilder::default()
        .memory(memory)
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
        linux.set_cgroups_path(Some(Path::new("/runtime-test").join(CGROUP_NAME)));
        linux.set_resources(Some(resources));
    }

    Ok(spec)
}

pub(crate) fn update_common_limits_test() -> TestResult {
    let spec = test_result!(create_spec());

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();

        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let cgroup_path = Path::new("/sys/fs/cgroup/runtime-test").join(CGROUP_NAME);
        let have_swap = cgroup_path.join("memory.swap.max").exists();

        // check that initial values were properly set
        test_result!(check_cgroup_value(&cgroup_path, "memory.max", "33554432"));
        test_result!(check_cgroup_value(&cgroup_path, "memory.low", "25165824"));
        test_result!(check_cgroup_value(&cgroup_path, "pids.max", "20"));

        // update cpuset (only on multi-core systems)
        let content = fs::read_to_string("/proc/cpuinfo").expect("read /proc/cpuinfo failed");
        let cpu_count = content
            .lines()
            .filter(|l| l.starts_with("processor"))
            .count();
        if cpu_count > 1 {
            update_container(id, dir, &["--cpuset-cpus", "1"])
                .unwrap()
                .wait()
                .unwrap();
            test_result!(check_cgroup_value(&cgroup_path, "cpuset.cpus", "1"));
        }

        // update memory limit
        update_container(id, dir, &["--memory", "67108864"])
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "memory.max", "67108864"));

        update_container(id, dir, &["--memory", "50M"])
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "memory.max", "52428800"));

        // update memory soft limit
        update_container(id, dir, &["--memory-reservation", "33554432"])
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "memory.low", "33554432"));

        // run swap memory tests if swap is available
        if have_swap {
            // remove memory swap limit
            update_container(id, dir, &["--memory-swap", "-1"])
                .unwrap()
                .wait()
                .unwrap();
            test_result!(check_cgroup_value(&cgroup_path, "memory.swap.max", "max"));

            // update memory swap
            // --memory-swap sets total of swap & memory
            // for cgroupv2, memory and swap can only be set together
            update_container(
                id,
                dir,
                &["--memory", "52428800", "--memory-swap", "96468992"],
            )
            .unwrap()
            .wait()
            .unwrap();
            // for cgroup v2, memory.swap.max is swap only (does not include mem)
            test_result!(check_cgroup_value(
                &cgroup_path,
                "memory.swap.max",
                &(96468992 - 52428800).to_string()
            ));
        }

        // try to remove memory limit
        update_container(id, dir, &["--memory", "-1"])
            .unwrap()
            .wait()
            .unwrap();
        // check memory & swap limit is gone
        test_result!(check_cgroup_value(&cgroup_path, "memory.max", "max"));
        if have_swap {
            test_result!(check_cgroup_value(&cgroup_path, "memory.swap.max", "max"));
        }

        // update pids limit
        update_container(id, dir, &["--pids-limit", "10"])
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "pids.max", "10"));

        // remove pids limit
        update_container(id, dir, &["--pids-limit", "-1"])
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "pids.max", "max"));

        // Test bulk updates via JSON (stdin and file)
        let json = serde_json::json!({
            "memory":{"limit": 33554432, "reservation": 25165824},
            "cpu": {"shares": 100, "quota": 500000, "period": 1000000, "cpus": "0"},
            "pids": {"limit": 20}
        })
        .to_string();

        // via stdin
        update_container_with_stdin(id, dir, &["-r", "-"], &json)
            .unwrap()
            .wait()
            .unwrap();
        test_result!(check_cgroup_value(&cgroup_path, "cpuset.cpus", "0"));
        test_result!(check_cgroup_value(&cgroup_path, "memory.max", "33554432"));
        test_result!(check_cgroup_value(&cgroup_path, "memory.low", "25165824"));
        test_result!(check_cgroup_value(&cgroup_path, "pids.max", "20"));

        // redo all the changes at once
        update_container(
            id,
            dir,
            &[
                "--cpu-period",
                "900000",
                "--cpu-quota",
                "600000",
                "--cpu-share",
                "200",
                "--memory",
                "67108864",
                "--memory-reservation",
                "33554432",
                "--pids-limit",
                "10",
            ],
        )
        .unwrap()
        .wait()
        .unwrap();

        test_result!(check_cgroup_value(&cgroup_path, "memory.max", "67108864"));
        test_result!(check_cgroup_value(&cgroup_path, "memory.low", "33554432"));
        test_result!(check_cgroup_value(&cgroup_path, "pids.max", "10"));

        // via file
        let json_path = dir.join("update_resources.json");
        fs::write(&json_path, &json).unwrap();

        update_container(id, dir, &["-r", json_path.to_str().unwrap()])
            .unwrap()
            .wait()
            .unwrap();

        test_result!(check_cgroup_value(&cgroup_path, "cpuset.cpus", "0"));
        test_result!(check_cgroup_value(&cgroup_path, "memory.max", "33554432"));
        test_result!(check_cgroup_value(&cgroup_path, "memory.low", "25165824"));
        test_result!(check_cgroup_value(&cgroup_path, "pids.max", "20"));

        // Regression test for https://github.com/opencontainers/runc/pull/592
        if have_swap {
            update_container(id, dir, &["--memory", "30M", "--memory-swap", "50M"])
                .unwrap()
                .wait()
                .unwrap();

            test_result!(check_cgroup_value(
                &cgroup_path,
                "memory.max",
                &(30 * 1024 * 1024).to_string()
            ));
            test_result!(check_cgroup_value(
                &cgroup_path,
                "memory.swap.max",
                &(20 * 1024 * 1024).to_string()
            ));

            update_container(id, dir, &["--memory", "60M", "--memory-swap", "80M"])
                .unwrap()
                .wait()
                .unwrap();

            test_result!(check_cgroup_value(
                &cgroup_path,
                "memory.max",
                &(60 * 1024 * 1024).to_string()
            ));
            test_result!(check_cgroup_value(
                &cgroup_path,
                "memory.swap.max",
                &(20 * 1024 * 1024).to_string()
            ));
        }

        TestResult::Passed
    })
}
