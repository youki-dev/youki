use anyhow::{Result, anyhow};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::{
    exec_container, exec_container_with_env, start_container, test_outside_container,
};

/// Create a spec with environment variables set in the process
fn create_spec_with_env(env_vars: Vec<String>) -> Result<Spec> {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "10000".to_string()])
                .env(env_vars)
                .build()?,
        )
        .build()
        .map_err(|e| anyhow!("failed to create spec: {}", e))
}

/// Test that exec inherits environment variables from config.json
fn test_exec_inherits_env_from_config() -> TestResult {
    // Create a spec with environment variables
    let spec_env = vec![
        "PATH=/usr/bin:/bin".to_string(),
        "HOME=/root".to_string(),
        "CUSTOM_VAR=from_config".to_string(),
        "ANOTHER_VAR=also_from_config".to_string(),
    ];

    let spec = match create_spec_with_env(spec_env) {
        Ok(s) => s,
        Err(e) => return TestResult::Failed(e),
    };

    test_outside_container(&spec, &|data| {
        let id = &data.id;
        let dir = &data.bundle;

        // Start the container
        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        // Exec into the container and print environment variables
        // Use /bin/sh -c 'env' to get all environment variables
        let (stdout, _stderr) = match exec_container(id, dir, &["/bin/sh", "-c", "env"], None) {
            Ok(output) => output,
            Err(e) => return TestResult::Failed(e),
        };

        // Verify that the environment variables from config.json are present
        if !stdout.contains("CUSTOM_VAR=from_config") {
            return TestResult::Failed(anyhow!(
                "CUSTOM_VAR not inherited from config.json. stdout: {}",
                stdout
            ));
        }

        if !stdout.contains("ANOTHER_VAR=also_from_config") {
            return TestResult::Failed(anyhow!(
                "ANOTHER_VAR not inherited from config.json. stdout: {}",
                stdout
            ));
        }

        if !stdout.contains("HOME=/root") {
            return TestResult::Failed(anyhow!(
                "HOME not inherited from config.json. stdout: {}",
                stdout
            ));
        }

        TestResult::Passed
    })
}

/// Test that exec env vars override config.json env vars
fn test_exec_env_overrides_config() -> TestResult {
    // Create a spec with environment variables
    let spec_env = vec![
        "PATH=/usr/bin:/bin".to_string(),
        "OVERRIDE_VAR=from_config".to_string(),
        "KEEP_VAR=from_config".to_string(),
    ];

    let spec = match create_spec_with_env(spec_env) {
        Ok(s) => s,
        Err(e) => return TestResult::Failed(e),
    };

    test_outside_container(&spec, &|data| {
        let id = &data.id;
        let dir = &data.bundle;

        // Start the container
        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        // Exec with env vars that should override config.json
        let exec_env = [("OVERRIDE_VAR", "from_exec"), ("NEW_VAR", "only_from_exec")];

        let (stdout, _stderr) =
            match exec_container_with_env(id, dir, &["/bin/sh", "-c", "env"], None, &exec_env) {
                Ok(output) => output,
                Err(e) => return TestResult::Failed(e),
            };

        // Verify that OVERRIDE_VAR was overridden by exec
        if !stdout.contains("OVERRIDE_VAR=from_exec") {
            return TestResult::Failed(anyhow!(
                "OVERRIDE_VAR was not overridden by exec. stdout: {}",
                stdout
            ));
        }

        // Verify that KEEP_VAR is still from config
        if !stdout.contains("KEEP_VAR=from_config") {
            return TestResult::Failed(anyhow!(
                "KEEP_VAR should be inherited from config.json. stdout: {}",
                stdout
            ));
        }

        // Verify that NEW_VAR was added by exec
        if !stdout.contains("NEW_VAR=only_from_exec") {
            return TestResult::Failed(anyhow!(
                "NEW_VAR should be added by exec. stdout: {}",
                stdout
            ));
        }

        TestResult::Passed
    })
}

/// Returns the test group for exec environment variable inheritance tests
pub fn get_exec_env_inheritance_test() -> TestGroup {
    let mut test_group = TestGroup::new("exec_env_inheritance");

    let test_inherit = Test::new(
        "exec_inherits_env_from_config",
        Box::new(test_exec_inherits_env_from_config),
    );
    test_group.add(vec![Box::new(test_inherit)]);

    let test_override = Test::new(
        "exec_env_overrides_config",
        Box::new(test_exec_env_overrides_config),
    );
    test_group.add(vec![Box::new(test_override)]);

    test_group
}
