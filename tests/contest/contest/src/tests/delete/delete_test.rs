use std::time::Duration;

use anyhow::anyhow;
use test_framework::{Test, TestGroup, TestResult};

use crate::tests::lifecycle::ContainerLifecycle;

// Default timeout for state transitions
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(75);

/// Test deleting a non-existent container
fn delete_non_existed_container() -> TestResult {
    let container = ContainerLifecycle::new();

    match container.delete() {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!(
            "Expected deleting a non-existent container to fail, but it succeeded"
        )),
        _ => TestResult::Failed(anyhow!("Unexpected test result")),
    }
}

/// Test deleting a container in "created" state
fn delete_created_container_test() -> TestResult {
    let container = ContainerLifecycle::new();

    // Create the container
    match container.create() {
        TestResult::Passed => {}
        _ => return TestResult::Failed(anyhow!("Failed to create container")),
    }

    // Wait for the container to be in created state
    match container.wait_for_state("created", DEFAULT_TIMEOUT) {
        TestResult::Passed => {}
        result => return result,
    }

    // Delete the container in "created" state
    match container.delete() {
        TestResult::Passed => TestResult::Passed,
        TestResult::Failed(err) => TestResult::Failed(anyhow!(
            "Failed to delete container in 'created' state: {}",
            err
        )),
        _ => TestResult::Failed(anyhow!("Unexpected test result")),
    }
}

/// Test deleting a container in "running" state
fn delete_running_container_test() -> TestResult {
    let container = ContainerLifecycle::new();

    // Create the container
    match container.create() {
        TestResult::Passed => {}
        _ => return TestResult::Failed(anyhow!("Failed to create container")),
    }

    // Start the container
    match container.start() {
        TestResult::Passed => {}
        _ => {
            // Clean up and return error
            let _ = container.kill();
            let _ = container.wait_for_state("stopped", DEFAULT_TIMEOUT);
            let _ = container.delete();
            return TestResult::Failed(anyhow!("Failed to start container"));
        }
    }

    // Wait for running state
    match container.wait_for_state("running", DEFAULT_TIMEOUT) {
        TestResult::Passed => {}
        result => {
            // Clean up and return error
            let _ = container.kill();
            let _ = container.wait_for_state("stopped", DEFAULT_TIMEOUT);
            let _ = container.delete();
            return result;
        }
    }

    // Try to delete the running container (should fail per OCI spec)
    let delete_result = match container.delete() {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!(
            "Expected deleting a running container to fail, but it succeeded"
        )),
        _ => TestResult::Failed(anyhow!("Unexpected test result")),
    };

    // Clean up
    let _ = container.kill();
    let _ = container.wait_for_state("stopped", DEFAULT_TIMEOUT);
    let cleanup_result = container.delete();

    // Return test result
    match delete_result {
        TestResult::Passed => cleanup_result,
        _ => delete_result,
    }
}

/// Test deleting a container in "stopped" state
fn delete_stopped_container_test() -> TestResult {
    let container = ContainerLifecycle::new();

    // Create the container
    match container.create() {
        TestResult::Passed => {}
        _ => return TestResult::Failed(anyhow!("Failed to create container")),
    }

    // Start the container
    match container.start() {
        TestResult::Passed => {}
        _ => {
            // Clean up and return error
            let _ = container.kill();
            let _ = container.wait_for_state("stopped", DEFAULT_TIMEOUT);
            let _ = container.delete();
            return TestResult::Failed(anyhow!("Failed to start container"));
        }
    }

    // Stop the container
    match container.kill() {
        TestResult::Passed => {}
        _ => {
            // Clean up and return error
            let _ = container.delete();
            return TestResult::Failed(anyhow!("Failed to kill container"));
        }
    }

    // Wait for stopped state
    match container.wait_for_state("stopped", DEFAULT_TIMEOUT) {
        TestResult::Passed => {}
        result => return result,
    }

    // Delete the stopped container
    match container.delete() {
        TestResult::Passed => TestResult::Passed,
        TestResult::Failed(err) => TestResult::Failed(anyhow!(
            "Expected deleting a stopped container to succeed, but it failed: {}",
            err
        )),
        _ => TestResult::Failed(anyhow!("Unexpected test result")),
    }
}

/// Create and return the delete_container test group
pub fn get_delete_test() -> TestGroup {
    let mut test_group = TestGroup::new("delete");

    let delete_non_existed_container = Test::new(
        "delete_non_existed_container",
        Box::new(delete_non_existed_container),
    );
    let delete_created_container_test = Test::new(
        "delete_created_container_test",
        Box::new(delete_created_container_test),
    );
    let delete_running_container_test = Test::new(
        "delete_running_container_test",
        Box::new(delete_running_container_test),
    );
    let delete_stopped_container_test = Test::new(
        "delete_stopped_container_test",
        Box::new(delete_stopped_container_test),
    );

    test_group.add(vec![
        Box::new(delete_non_existed_container),
        Box::new(delete_created_container_test),
        Box::new(delete_running_container_test),
        Box::new(delete_stopped_container_test),
    ]);

    test_group
}
