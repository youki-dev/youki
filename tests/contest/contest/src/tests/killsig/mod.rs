use std::fs;
use std::time::Duration;

use anyhow::{Context, anyhow};
use oci_spec::runtime::{ProcessBuilder, RootBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::tests::lifecycle::{ContainerLifecycle, get_result_from_output};
use crate::utils::kill_container_with_signal;

const SIGNALS: [&str; 3] = ["TERM", "USR1", "USR2"];
const STATE_TIMEOUT: Duration = Duration::from_secs(5);

fn create_spec(signal: &str) -> anyhow::Result<Spec> {
    let command = format!("trap 'touch /{signal}' {signal}; sleep 10 & wait $!");

    SpecBuilder::default()
        .root(
            RootBuilder::default()
                .readonly(false)
                .build()
                .context("failed to build root spec")?,
        )
        .process(
            ProcessBuilder::default()
                .args(vec!["sh".to_string(), "-c".to_string(), command])
                .build()
                .context("failed to build process spec")?,
        )
        .build()
        .context("failed to build spec")
}

fn check_signal(signal: &str) -> TestResult {
    let container = ContainerLifecycle::new();
    let signal_file = container
        .get_project_path()
        .join("bundle")
        .join("rootfs")
        .join(signal);
    let spec = test_result!(create_spec(signal));

    if let TestResult::Failed(err) = container.create_with_spec(spec) {
        return TestResult::Failed(err.context("failed to create container"));
    }

    if let TestResult::Failed(err) = container.start() {
        let _ = container.delete();
        return TestResult::Failed(err.context("failed to start container"));
    }

    if let TestResult::Failed(err) = container.wait_for_state("running", STATE_TIMEOUT) {
        let _ = container.kill();
        let _ = container.delete();
        return TestResult::Failed(err);
    }

    let kill_result = match kill_container_with_signal(
        container.get_id(),
        container.get_project_path(),
        signal,
    ) {
        Ok(child) => get_result_from_output(child.wait_with_output()).into(),
        Err(err) => TestResult::Failed(err),
    };

    if let TestResult::Failed(err) = kill_result {
        let _ = container.delete();
        return TestResult::Failed(err.context(format!("failed to send {signal}")));
    }

    let stopped_result = container.wait_for_state("stopped", STATE_TIMEOUT);

    if let TestResult::Failed(err) = stopped_result {
        let _ = container.delete();
        return TestResult::Failed(err);
    }

    let signal_file_result = fs::metadata(&signal_file);
    let delete_result = container.delete();

    if let TestResult::Failed(err) = delete_result {
        return TestResult::Failed(err.context("failed to delete container"));
    }

    match signal_file_result {
        Ok(_) => TestResult::Passed,
        Err(err) => TestResult::Failed(anyhow!(
            "expected signal handler to create {}, but stat failed: {}",
            signal_file.display(),
            err
        )),
    }
}

pub fn get_killsig_test() -> TestGroup {
    let mut test_group = TestGroup::new("killsig");

    for signal in SIGNALS {
        test_group.add(vec![Box::new(Test::new(
            signal,
            Box::new(move || check_signal(signal)),
        ))]);
    }

    test_group
}
