use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::tests::lifecycle::ContainerLifecycle;

fn create_spec(args: &[&str]) -> Result<Spec> {
    let args_vec: Vec<String> = args.iter().map(|&a| a.to_string()).collect();
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

fn kill_with_empty_id_test() -> TestResult {
    let mut container = ContainerLifecycle::new();

    // kill with empty id
    container.set_id("");
    let result = match container.kill() {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!(
            "Expected killing container with empty id to fail, but was successful"
        )),
        _ => TestResult::Failed(anyhow!(
            "Unexpected killing container with empty id test result"
        )),
    };
    container.delete();
    result
}

fn kill_non_existed_container() -> TestResult {
    let mut container = ContainerLifecycle::new();

    // kill for non existed container
    container.set_id("non-existent-container-id");
    let result = match container.kill() {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!(
            "Expected killing non existed container to fail, but was successful"
        )),
        _ => TestResult::Failed(anyhow!(
            "Unexpected killing non existed container test result"
        )),
    };
    container.delete();
    result
}
fn kill_created_container_test() -> TestResult {
    let container = ContainerLifecycle::new();

    // kill created container
    match container.create() {
        TestResult::Passed => {}
        _ => return TestResult::Failed(anyhow!("Failed to create container")),
    }
    let result = container.kill();
    container.delete();
    result
}

fn kill_stopped_container_test() -> TestResult {
    let container = ContainerLifecycle::new();
    let spec = create_spec(&["true"]).unwrap();

    // kill stopped container
    match container.create_with_spec(spec) {
        TestResult::Passed => {}
        _ => return TestResult::Failed(anyhow!("Failed to create container")),
    }
    match container.start() {
        TestResult::Passed => {}
        _ => return TestResult::Failed(anyhow!("Failed to start container")),
    }
    container.waiting_for_status(Duration::from_secs(10), Duration::from_secs(1), "stopped");
    let result = match container.kill() {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!("Expected failure but got success")),
        _ => TestResult::Failed(anyhow!("Unexpected test result")),
    };
    container.delete();
    result
}

fn kill_start_container_test() -> TestResult {
    let container = ContainerLifecycle::new();
    let spec = create_spec(&["sleep", "30"]).unwrap();

    // kill start container
    match container.create_with_spec(spec) {
        TestResult::Passed => {}
        _ => return TestResult::Failed(anyhow!("Failed to recreate container")),
    }

    match container.start() {
        TestResult::Passed => {}
        TestResult::Failed(err) => {
            return TestResult::Failed(anyhow!("Failed to start container: {:?}", err));
        }
        _ => unreachable!(),
    }
    container.waiting_for_status(Duration::from_secs(10), Duration::from_secs(1), "running");
    let result = container.kill();
    container.delete();
    result
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
