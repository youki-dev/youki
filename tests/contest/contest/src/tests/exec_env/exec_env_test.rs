use std::ffi::OsStr;
use std::fs;

use anyhow::{Context, anyhow};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use serde_json::json;
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_utils::check_container_created;
use crate::utils::{exec_container, start_container, test_outside_container};

fn create_spec_with_env(env: Vec<String>) -> anyhow::Result<Spec> {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "1000".to_string()])
                .env(env)
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

/// Exec inherits spec env vars when no --env is passed.
fn test_exec_inherits_spec_env() -> TestResult {
    let spec = test_result!(create_spec_with_env(vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        "SPEC_VAR=from_spec".to_string(),
    ]));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) = match exec_container(id, dir, &["/bin/printenv", "SPEC_VAR"], None, &[]) {
            Ok(output) => output,
            Err(e) => return TestResult::Failed(e),
        };

        if stdout.trim() != "from_spec" {
            return TestResult::Failed(anyhow!(
                "expected SPEC_VAR=from_spec, got: {}",
                stdout.trim()
            ));
        }

        TestResult::Passed
    })
}

/// --env on CLI overrides the same variable from the spec.
fn test_cli_env_overrides_spec() -> TestResult {
    let spec = test_result!(create_spec_with_env(vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        "MY_VAR=from_spec".to_string(),
    ]));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) = match exec_container(
            id,
            dir,
            &["/bin/printenv", "MY_VAR"],
            None,
            &[("MY_VAR", "from_cli")],
        ) {
            Ok(output) => output,
            Err(e) => return TestResult::Failed(e),
        };

        if stdout.trim() != "from_cli" {
            return TestResult::Failed(anyhow!(
                "expected MY_VAR=from_cli (override), got: {}",
                stdout.trim()
            ));
        }

        TestResult::Passed
    })
}

/// --env on CLI adds new variables alongside spec env.
fn test_cli_env_adds_new_var() -> TestResult {
    let spec = test_result!(create_spec_with_env(vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        "EXISTING=yes".to_string(),
    ]));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        // Exec with a new env var, print all env
        let (stdout, _) =
            match exec_container(id, dir, &["/bin/env"], None, &[("NEW_VAR", "hello")]) {
                Ok(output) => output,
                Err(e) => return TestResult::Failed(e),
            };

        if !stdout.contains("NEW_VAR=hello") {
            return TestResult::Failed(anyhow!(
                "expected NEW_VAR=hello in env output, got: {}",
                stdout
            ));
        }
        if !stdout.contains("EXISTING=yes") {
            return TestResult::Failed(anyhow!(
                "expected EXISTING=yes (inherited) in env output, got: {}",
                stdout
            ));
        }

        TestResult::Passed
    })
}

/// Env vars from process.json are used when --process is specified.
fn test_env_from_process_json() -> TestResult {
    let spec = test_result!(create_spec_with_env(vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    ]));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let process_json = json!({
            "terminal": false,
            "cwd": "/",
            "args": ["/bin/printenv", "PROC_VAR"],
            "env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "PROC_VAR=from_process_json"
            ],
            "user": {
                "uid": 0,
                "gid": 0
            }
        });

        let process_path = dir.join("process.json");
        if let Err(e) = fs::write(
            &process_path,
            serde_json::to_vec_pretty(&process_json).unwrap(),
        ) {
            return TestResult::Failed(anyhow!("failed to write process.json: {}", e));
        }

        let (stdout, _) = match exec_container(id, dir, &[OsStr::new("")], Some(&process_path), &[])
        {
            Ok(output) => output,
            Err(e) => return TestResult::Failed(e),
        };

        if stdout.trim() != "from_process_json" {
            return TestResult::Failed(anyhow!(
                "expected PROC_VAR=from_process_json, got: {}",
                stdout.trim()
            ));
        }

        TestResult::Passed
    })
}

pub fn get_exec_env_test() -> TestGroup {
    let mut test_group = TestGroup::new("exec_env");

    let inherit = Test::new(
        "test_exec_inherits_spec_env",
        Box::new(test_exec_inherits_spec_env),
    );
    let override_test = Test::new(
        "test_cli_env_overrides_spec",
        Box::new(test_cli_env_overrides_spec),
    );
    let add_new = Test::new(
        "test_cli_env_adds_new_var",
        Box::new(test_cli_env_adds_new_var),
    );
    let process_json = Test::new(
        "test_env_from_process_json",
        Box::new(test_env_from_process_json),
    );

    test_group.add(vec![
        Box::new(inherit),
        Box::new(override_test),
        Box::new(add_new),
        Box::new(process_json),
    ]);

    test_group
}
