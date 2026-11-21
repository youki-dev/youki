use std::time::Duration;

use anyhow::{Result, anyhow};
use oci_spec::runtime::{
    LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, ProcessBuilder,
    Spec, SpecBuilder, get_default_namespaces,
};
use test_framework::{Test, TestGroup, TestResult};

use crate::tests::lifecycle::ContainerLifecycle;

// Default timeout for state transitions
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(75);

fn create_userns_spec() -> Result<Spec> {
    let mut namespaces = get_default_namespaces();
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()?,
    );

    let uid_mapping = LinuxIdMappingBuilder::default()
        .host_id(100000_u32)
        .container_id(0_u32)
        .size(65534_u32)
        .build()?;
    let gid_mapping = LinuxIdMappingBuilder::default()
        .host_id(200000_u32)
        .container_id(0_u32)
        .size(65534_u32)
        .build()?;

    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "10".to_string()])
                .build()?,
        )
        .linux(
            LinuxBuilder::default()
                .namespaces(namespaces)
                .uid_mappings(vec![uid_mapping])
                .gid_mappings(vec![gid_mapping])
                .build()?,
        )
        .build()?;

    Ok(spec)
}

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

/// Test force-deleting a running container with a new user namespace.
///
/// A new user namespace forces the systemd cgroup manager, and the state has to
/// record that. Otherwise `delete --force` rebuilds a cgroupfs manager, fails to
/// remove the cgroup and leaves the container running with its state behind.
fn delete_force_running_userns_container_test() -> TestResult {
    let spec = match create_userns_spec() {
        Ok(spec) => spec,
        Err(err) => return TestResult::Failed(err),
    };
    let container = ContainerLifecycle::new();

    match container.create_with_spec(spec) {
        TestResult::Passed => {}
        _ => return TestResult::Failed(anyhow!("Failed to create container")),
    }

    match container.start() {
        TestResult::Passed => {}
        _ => {
            let _ = container.delete_force();
            return TestResult::Failed(anyhow!("Failed to start container"));
        }
    }

    match container.wait_for_state("running", DEFAULT_TIMEOUT) {
        TestResult::Passed => {}
        result => {
            let _ = container.delete_force();
            return result;
        }
    }

    match container.delete_force() {
        TestResult::Passed => {}
        TestResult::Failed(err) => {
            let _ = container.kill();
            let _ = container.delete();
            return TestResult::Failed(anyhow!(
                "Failed to force-delete running container with a user namespace: {}",
                err
            ));
        }
        _ => return TestResult::Failed(anyhow!("Unexpected test result")),
    }

    let container_dir = container
        .get_project_path()
        .join("runtime")
        .join(container.get_id());
    if container_dir.exists() {
        return TestResult::Failed(anyhow!(
            "Container directory still exists after delete --force"
        ));
    }

    TestResult::Passed
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
    let delete_force_running_userns_container_test = Test::new(
        "delete_force_running_userns_container_test",
        Box::new(delete_force_running_userns_container_test),
    );

    test_group.add(vec![
        Box::new(delete_non_existed_container),
        Box::new(delete_created_container_test),
        Box::new(delete_running_container_test),
        Box::new(delete_stopped_container_test),
        Box::new(delete_force_running_userns_container_test),
    ]);

    test_group
}
