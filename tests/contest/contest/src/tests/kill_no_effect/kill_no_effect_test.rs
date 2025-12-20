use crate::{tests::lifecycle::ContainerLifecycle, utils::get_state};
use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use std::time::Duration;
use test_framework::{Test, TestGroup, TestResult};

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

//This test MUST ensure that attempting to send a signal to a container that is neither created nor running has no effect on the container and generates an error.
fn kill_no_effect_test() -> TestResult {
    let container = ContainerLifecycle::new();
    let spec = create_spec(&["sleep", "1"]).unwrap();

    match container.create_with_spec(spec) {
        TestResult::Passed => {}
        _ => return failed_and_delete("Failed to recreate container".to_string(), container),
    }

    match container.start() {
        TestResult::Passed => {}
        _ => return failed_and_delete(("Failed to start container").to_string(), container),
    }

    container.wait_for_state("stopped", Duration::from_secs(5));

    // get state before kill
    let (before_stdout, before_stderr) =
        match get_state(container.get_id(), container.get_project_path()) {
            Ok(v) => v,
            _ => return failed_and_delete(("Failed to start container").to_string(), container),
        };
    if before_stderr.contains("Error") || before_stderr.contains("error") {
        return failed_and_delete(("Failed to get container state").to_string(), container);
    }

    //kill the stopped container
    match container.kill() {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => {
            return failed_and_delete(
                "Should not be able to kill a stopped container".to_string(),
                container,
            );
        }
        _ => return failed_and_delete("Unexpected test result".to_string(), container),
    };

    // get state after kill
    let (after_stdout, after_stderr) =
        match get_state(container.get_id(), container.get_project_path()) {
            Ok(v) => v,
            _ => return failed_and_delete(("Failed to start container").to_string(), container),
        };
    if after_stderr.contains("Error") || after_stderr.contains("error") {
        return failed_and_delete(("Failed to get container state").to_string(), container);
    }

    // state before and after kill should be the same
    if before_stdout != after_stdout {
        return TestResult::Failed(anyhow!("container state changed after kill signal"));
    }

    //delete container after test
    match container.delete() {
        TestResult::Passed => {}
        _ => return failed_and_delete("Failed to delete container".to_string(), container),
    }

    TestResult::Passed
}

pub fn get_kill_no_effect_test() -> TestGroup {
    let mut test_group = TestGroup::new("kill_container_no_effect");
    let kill_no_effect_test = Test::new("kill_no_effect_test", Box::new(kill_no_effect_test));
    test_group.add(vec![Box::new(kill_no_effect_test)]);
    test_group
}
