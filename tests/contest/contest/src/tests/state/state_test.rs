use std::process::{Command, Output};

use anyhow::anyhow;
use test_framework::{Test, TestGroup, TestResult};

use crate::tests::lifecycle::ContainerLifecycle;
use crate::utils::{State, get_runtime_path};

fn run_state(container: &ContainerLifecycle, id: Option<&str>) -> std::io::Result<Output> {
    let mut command = Command::new(get_runtime_path());
    command
        .arg("--root")
        .arg(container.get_project_path().join("runtime"))
        .arg("state");

    if let Some(id) = id {
        command.arg(id);
    }

    command.output()
}

fn state_without_id() -> TestResult {
    let container = ContainerLifecycle::new();

    match run_state(&container, None) {
        Ok(output) if !output.status.success() => TestResult::Passed,
        Ok(_) => TestResult::Failed(anyhow!(
            "state without a container ID unexpectedly succeeded"
        )),
        Err(err) => TestResult::Failed(anyhow!("failed to execute state command: {err}")),
    }
}

fn state_nonexistent_container() -> TestResult {
    let container = ContainerLifecycle::new();

    match run_state(&container, Some(container.get_id())) {
        Ok(output) if !output.status.success() => TestResult::Passed,
        Ok(_) => TestResult::Failed(anyhow!(
            "state for a non-existent container unexpectedly succeeded"
        )),
        Err(err) => TestResult::Failed(anyhow!("failed to execute state command: {err}")),
    }
}

fn state_created_container() -> TestResult {
    let container = ContainerLifecycle::new();

    if let TestResult::Failed(err) = container.create() {
        return TestResult::Failed(err.context("failed to create container"));
    }

    let result = match run_state(&container, Some(container.get_id())) {
        Ok(output) if output.status.success() => {
            match serde_json::from_slice::<State>(&output.stdout) {
                Ok(state) if state.id == container.get_id() && state.status == "created" => {
                    TestResult::Passed
                }
                Ok(state) => TestResult::Failed(anyhow!(
                    "unexpected container state: id={}, status={}",
                    state.id,
                    state.status
                )),
                Err(err) => TestResult::Failed(anyhow!(
                    "failed to parse state output as OCI state JSON: {err}"
                )),
            }
        }
        Ok(output) => TestResult::Failed(anyhow!(
            "state for a created container failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )),
        Err(err) => TestResult::Failed(anyhow!("failed to execute state command: {err}")),
    };

    let cleanup = container.delete();
    match result {
        TestResult::Passed => cleanup,
        _ => result,
    }
}

pub fn get_state_test() -> TestGroup {
    let mut test_group = TestGroup::new("state");
    test_group.add(vec![
        Box::new(Test::new("state_without_id", Box::new(state_without_id))),
        Box::new(Test::new(
            "state_nonexistent_container",
            Box::new(state_nonexistent_container),
        )),
        Box::new(Test::new(
            "state_created_container",
            Box::new(state_created_container),
        )),
    ]);
    test_group
}
