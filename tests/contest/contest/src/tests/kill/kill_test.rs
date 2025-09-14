use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::tests::lifecycle::ContainerLifecycle;

fn create_spec(args: &[&str]) -> Result<Spec> {
    let args_vec: Vec<String> = args.iter().map(|&a| a.into()).collect();
    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(args_vec)
                .build()
                .context("failed to build process spec")?,
        )
        .build()
        .context("failed to build spec")?;
    Ok(spec)
}

fn failed_and_delete(text: String, container: ContainerLifecycle) -> TestResult {
    let delete_result = container.delete();
    match delete_result {
        TestResult::Passed => TestResult::Failed(anyhow!(text)),
        TestResult::Failed(err) => TestResult::Failed(anyhow!(
            "{}; also container deletion failed: {:?}",
            text,
            err
        )),
        _ => TestResult::Failed(anyhow!("{}; unexpected delete result", text)),
    }
}

fn merge_test_results(kill_result: TestResult, delete_result: TestResult) -> TestResult {
    match (kill_result, delete_result) {
        (TestResult::Failed(err), _) => TestResult::Failed(err),
        (TestResult::Passed, TestResult::Failed(err)) => {
            TestResult::Failed(anyhow!("Delete failed: {:?}", err))
        }
        (TestResult::Passed, TestResult::Passed) => TestResult::Passed,
        _ => TestResult::Failed(anyhow!("Unexpected result")),
    }
}

// Killing a container with an empty ID should fail.
fn kill_with_empty_id_test() -> TestResult {
    let mut container = ContainerLifecycle::new();

    // kill with empty id
    container.set_id("");
    match container.kill() {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!(
            "Expected killing container with empty id to fail, but was successful"
        )),
        _ => TestResult::Failed(anyhow!(
            "Unexpected killing container with empty id test result"
        )),
    }
}

// Killing a non-existent container should fail.
fn kill_non_existed_container() -> TestResult {
    let container = ContainerLifecycle::new();

    // kill for non existed container
    match container.kill() {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!(
            "Expected killing non existed container to fail, but was successful"
        )),
        _ => TestResult::Failed(anyhow!(
            "Unexpected killing non existed container test result"
        )),
    }
}

// Create a container, then kill and delete it successfully.
fn kill_created_container_test() -> TestResult {
    let container = ContainerLifecycle::new();

    // kill created container
    match container.create() {
        TestResult::Passed => {}
        _ => return failed_and_delete("Failed to create container".to_string(), container),
    }
    let kill_result = container.kill();
    let delete_result = container.delete();
    merge_test_results(kill_result, delete_result)
}

// After a container stops naturally, killing it should fail, then deletion should succeed.
fn kill_stopped_container_test() -> TestResult {
    let container = ContainerLifecycle::new();
    let spec = create_spec(&["true"]).unwrap();

    // kill stopped container
    match container.create_with_spec(spec) {
        TestResult::Passed => {}
        _ => return failed_and_delete("Failed to create container".to_string(), container),
    }
    match container.start() {
        TestResult::Passed => {}
        _ => return failed_and_delete("Failed to start container".to_string(), container),
    }
    container.wait_for_state("stopped", Duration::from_secs(1));
    let kill_result = match container.kill() {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!("Expected failure but got success")),
        _ => TestResult::Failed(anyhow!("Unexpected test result")),
    };
    let delete_result = container.delete();
    merge_test_results(kill_result, delete_result)
}

// Kill a running container should succeed, then delete should succeed.
fn kill_start_container_test() -> TestResult {
    let container = ContainerLifecycle::new();
    let spec = create_spec(&["sleep", "30"]).unwrap();

    // kill start container
    match container.create_with_spec(spec) {
        TestResult::Passed => {}
        _ => return failed_and_delete("Failed to recreate container".to_string(), container),
    }

    match container.start() {
        TestResult::Passed => {}
        _ => return failed_and_delete(("Failed to start container").to_string(), container),
    }
    container.wait_for_state("running", Duration::from_secs(1));
    let kill_result = container.kill();
    let delete_result = container.delete();
    merge_test_results(kill_result, delete_result)
}

pub fn get_kill_test() -> TestGroup {
    let mut test_group = TestGroup::new("kill_container");

    let kill_with_empty_id_test =
        Test::new("kill_with_empty_id_test", Box::new(kill_with_empty_id_test));
    let kill_non_existed_container = Test::new(
        "kill_non_existed_container",
        Box::new(kill_non_existed_container),
    );
    let kill_created_container_test = Test::new(
        "kill_created_container_test",
        Box::new(kill_created_container_test),
    );
    let kill_stopped_container_test = Test::new(
        "kill_stopped_container_test",
        Box::new(kill_stopped_container_test),
    );
    let kill_start_container_test = Test::new(
        "kill_start_container_test",
        Box::new(kill_start_container_test),
    );
    test_group.add(vec![
        Box::new(kill_with_empty_id_test),
        Box::new(kill_non_existed_container),
        Box::new(kill_created_container_test),
        Box::new(kill_stopped_container_test),
        Box::new(kill_start_container_test),
    ]);
    test_group
}
