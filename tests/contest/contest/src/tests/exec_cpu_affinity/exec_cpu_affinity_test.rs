use std::fs;

use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{ExecCPUAffinityBuilder, ProcessBuilder, Spec, SpecBuilder};
use regex::Regex;
use serde_json::{Value, json};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::{exec_container, is_runtime_runc, start_container, test_outside_container};

fn create_spec(initial: Option<&str>, fin: Option<&str>) -> Result<Spec> {
    let mut builder = ExecCPUAffinityBuilder::default();
    if let Some(i) = initial {
        builder = builder.initial(i.to_string());
    }
    if let Some(f) = fin {
        builder = builder.cpu_affinity_final(f.to_string());
    }

    let cpu_affinity = builder.build()?;

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "10000".to_string()])
                .exec_cpu_affinity(cpu_affinity)
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn test_cpu_affinity_only_initial_set_from_process_json() -> TestResult {
    let spec = test_result!(create_spec(None, None));
    test_outside_container(&spec, &|data| {
        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let process_affinity_initial = "0,1";
        let process_json = create_process(Some(process_affinity_initial), None);

        let process_path = dir.join("process.json");
        if let Err(e) = fs::write(
            &process_path,
            serde_json::to_vec_pretty(&process_json).unwrap(),
        ) {
            return TestResult::Failed(anyhow!("failed to write process.json: {}", e));
        }

        let (_stdout, stderr) = match exec_container(id, dir, &["/bin/true"], Some(&process_path)) {
            Ok(output) => output,
            Err(e) => return TestResult::Failed(e),
        };

        let mask = affinity_mask_from_str(process_affinity_initial);
        let pattern = format!(r".*affinity: 0x{:x}", mask);
        let re = Regex::new(&pattern).unwrap();
        if !re.is_match(&stderr) {
            return TestResult::Failed(anyhow!(
                "missing expected affinity log in stderr: {}",
                stderr
            ));
        }

        TestResult::Passed
    })
}

fn test_cpu_affinity_initial_and_final_set_from_process_json() -> TestResult {
    let spec = test_result!(create_spec(None, None));
    test_outside_container(&spec, &|data| {
        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let process_affinity_initial = "0";
        let process_affinity_final = "1";
        let process_json =
            create_process(Some(process_affinity_initial), Some(process_affinity_final));

        let process_path = dir.join("process.json");
        if let Err(e) = fs::write(
            &process_path,
            serde_json::to_vec_pretty(&process_json).unwrap(),
        ) {
            return TestResult::Failed(anyhow!("failed to write process.json: {}", e));
        }

        let (stdout, stderr) = match exec_container(
            id,
            dir,
            &["grep", "Cpus_allowed_list", "/proc/self/status"],
            Some(&process_path),
        ) {
            Ok(output) => output,
            Err(e) => return TestResult::Failed(e),
        };

        if !stdout.contains(process_affinity_final) {
            return TestResult::Failed(anyhow!("unexpected Cpus_allowed_list: {}", stdout));
        }

        let mask = affinity_mask_from_str(process_affinity_initial);
        let pattern = format!(r".*affinity: 0x{:x}", mask);
        let re = Regex::new(&pattern).unwrap();
        if !re.is_match(&stderr) {
            return TestResult::Failed(anyhow!(
                "missing expected affinity log in stderr: {}",
                stderr
            ));
        }

        TestResult::Passed
    })
}

fn test_cpu_affinity_from_config_json() -> TestResult {
    let affinity_initial = "0";
    let affinity_final = "1";

    let spec = test_result!(create_spec(Some(affinity_initial), Some(affinity_final)));
    test_outside_container(&spec, &|data| {
        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, stderr) = exec_container(
            id,
            dir,
            &["grep", "Cpus_allowed_list", "/proc/self/status"],
            None,
        )
        .expect("exec failed");

        if !stdout.contains(affinity_final) {
            return TestResult::Failed(anyhow!("unexpected Cpus_allowed_list: {}", stdout));
        }

        let mask = affinity_mask_from_str(affinity_initial);
        let pattern = format!(r".*affinity: 0x{:x}", mask);
        let re = Regex::new(&pattern).unwrap();
        if !re.is_match(&stderr) {
            return TestResult::Failed(anyhow!(
                "missing expected affinity log in stderr: {}",
                stderr
            ));
        }

        TestResult::Passed
    })
}

// In runc, `exec_cpu_affinity` is introduced in version 1.3.0.
// Since the current CI uses an older version of runc, `exec_cpu_affinity` is not available and the test will be skipped.
// youki/.github/workflows/integration_tests_validation.yaml:95
// https://github.com/opencontainers/runc/releases/tag/v1.3.0-rc.1
pub fn get_exec_cpu_affinity_test() -> TestGroup {
    let mut exec_cpu_affinity_test_group = TestGroup::new("exec_cpu_affinity");

    let test_cpu_affinity_only_initial_set_from_process_json = ConditionalTest::new(
        "test_cpu_affinity_only_initial_set_from_process_json",
        Box::new(|| !is_runtime_runc()),
        Box::new(test_cpu_affinity_only_initial_set_from_process_json),
    );
    let test_cpu_affinity_initial_and_final_set_from_process_json = ConditionalTest::new(
        "test_cpu_affinity_initial_and_final_set_from_process_json",
        Box::new(|| !is_runtime_runc()),
        Box::new(test_cpu_affinity_initial_and_final_set_from_process_json),
    );
    let test_cpu_affinity_from_config_json = ConditionalTest::new(
        "test_cpu_affinity_from_config_json",
        Box::new(|| !is_runtime_runc()),
        Box::new(test_cpu_affinity_from_config_json),
    );
    exec_cpu_affinity_test_group.add(vec![
        Box::new(test_cpu_affinity_only_initial_set_from_process_json),
        Box::new(test_cpu_affinity_initial_and_final_set_from_process_json),
        Box::new(test_cpu_affinity_from_config_json),
    ]);

    exec_cpu_affinity_test_group
}

pub fn create_process(
    cpu_affinity_initial: Option<&str>,
    cpu_affinity_final: Option<&str>,
) -> Value {
    let mut exec_cpu_affinity = serde_json::Map::new();

    if let Some(init) = cpu_affinity_initial {
        exec_cpu_affinity.insert("initial".to_string(), json!(init));
    }
    if let Some(fin) = cpu_affinity_final {
        exec_cpu_affinity.insert("final".to_string(), json!(fin));
    }

    let exec_cpu_affinity_value = Value::Object(exec_cpu_affinity);

    json!({
        "terminal": false,
        "cwd": "/",
        "args": [
            "/bin/grep",
            "-F",
            "Cpus_allowed_list:",
            "/proc/self/status"
        ],
        "env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM=xterm"
        ],
        "user": {
            "uid": 0,
            "gid": 0
        },
        "execCPUAffinity": exec_cpu_affinity_value
    })
}

fn affinity_mask_from_str(cpuset_str: &str) -> u64 {
    let mut mask = 0u64;

    for part in cpuset_str.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: usize = start.parse().unwrap();
            let end: usize = end.parse().unwrap();
            for i in start..=end {
                mask |= 1 << i;
            }
        } else {
            let cpu: usize = part.parse().unwrap();
            mask |= 1 << cpu;
        }
    }

    mask
}
