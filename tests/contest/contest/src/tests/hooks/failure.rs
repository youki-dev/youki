//! Hook failures and the lifecycle the OCI runtime spec requires of them.
//!
//! Step 9: if a poststart hook fails, the runtime generates an error, stops the
//! container, and continues at step 12 (destroy), so `delete` can run the
//! poststop hooks (youki-dev/youki issue 3774). Steps 4 and 5: if a
//! createRuntime or createContainer hook fails, the container is destroyed and
//! the poststop hooks are invoked (issue 3758).

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::anyhow;
use oci_spec::runtime::{Hook, HookBuilder, HooksBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{ConditionalTest, Test, TestGroup, TestResult};

use super::invoke::{delete_hook_output_file, get_hook_output_path, write_log_hook};
use crate::utils::{
    CreateOptions, LifecycleStatus, WaitTarget, create_container, delete_container, generate_uuid,
    is_runtime_runc, prepare_bundle, set_config, start_container, wait_for_state,
};

const STATE_WAIT_TIMEOUT_SECS: u64 = 5;
const STATE_POLL_INTERVAL_MILLIS: u64 = 100;

/// A hook that records its invocation and then fails with exit code 7.
fn failing_log_hook(content: &str, host_output_file_path: &str) -> Hook {
    HookBuilder::default()
        .path("/bin/sh")
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo '{content}' >> {host_output_file_path}; exit 7"),
        ])
        .build()
        .expect("could not build hook")
}

fn wait_for_target(id: &str, bundle_path: &Path, target: WaitTarget) -> anyhow::Result<()> {
    wait_for_state(
        id,
        bundle_path,
        target,
        Duration::from_secs(STATE_WAIT_TIMEOUT_SECS),
        Duration::from_millis(STATE_POLL_INTERVAL_MILLIS),
    )
}

fn poststart_failure_spec(host_output_file: &str) -> Spec {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "60".to_string()])
                .build()
                .unwrap(),
        )
        .hooks(
            HooksBuilder::default()
                .poststart(vec![failing_log_hook(
                    "post-start-failed",
                    host_output_file,
                )])
                .poststop(vec![write_log_hook("post-stop called", host_output_file)])
                .build()
                .expect("could not build hooks"),
        )
        .build()
        .unwrap()
}

fn create_runtime_failure_spec(host_output_file: &str) -> Spec {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["true".to_string()])
                .build()
                .unwrap(),
        )
        .hooks(
            HooksBuilder::default()
                .create_runtime(vec![failing_log_hook(
                    "create-runtime-failed",
                    host_output_file,
                )])
                .poststop(vec![write_log_hook("post-stop called", host_output_file)])
                .build()
                .expect("could not build hooks"),
        )
        .build()
        .unwrap()
}

fn poststart_failure_test() -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();
    let host_output_file = get_hook_output_path(&bundle);
    let host_output_file_str = host_output_file.to_str().unwrap();
    set_config(&bundle, &poststart_failure_spec(host_output_file_str)).unwrap();

    create_container(&id, &bundle, &CreateOptions::default())
        .unwrap()
        .wait()
        .unwrap();
    if let Err(e) = wait_for_target(
        &id,
        bundle.path(),
        WaitTarget::Status(LifecycleStatus::Created),
    ) {
        return TestResult::Failed(anyhow!("container did not reach created: {e}"));
    }

    let start = start_container(&id, &bundle).unwrap().wait().unwrap();
    if start.success() {
        let _ = delete_container(&id, &bundle).and_then(|mut c| Ok(c.wait()?));
        return TestResult::Failed(anyhow!(
            "start must fail when a poststart hook fails, but it exited successfully"
        ));
    }

    // Step 9: the container is stopped, not left running.
    if let Err(e) = wait_for_target(
        &id,
        bundle.path(),
        WaitTarget::Status(LifecycleStatus::Stopped),
    ) {
        let _ = delete_container(&id, &bundle).and_then(|mut c| Ok(c.wait()?));
        return TestResult::Failed(anyhow!(
            "container must be stopped after a poststart hook failure: {e}"
        ));
    }

    // Step 12 and 13: delete destroys it and runs the poststop hooks.
    delete_container(&id, &bundle).unwrap().wait().unwrap();
    if let Err(e) = wait_for_target(&id, bundle.path(), WaitTarget::Deleted) {
        return TestResult::Failed(anyhow!("container was not deleted: {e}"));
    }
    let log = fs::read_to_string(&host_output_file).expect("cannot read output file");
    delete_hook_output_file(&host_output_file).unwrap();
    let expected = "post-start-failed\npost-stop called\n";
    if log != expected {
        return TestResult::Failed(anyhow!(
            "unexpected hook log after a poststart failure.\ngot:\n{log}\nexpected:\n{expected}"
        ));
    }
    TestResult::Passed
}

fn create_runtime_failure_test() -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();
    let host_output_file = get_hook_output_path(&bundle);
    let host_output_file_str = host_output_file.to_str().unwrap();
    set_config(&bundle, &create_runtime_failure_spec(host_output_file_str)).unwrap();

    let create = create_container(&id, &bundle, &CreateOptions::default())
        .unwrap()
        .wait()
        .unwrap();
    if create.success() {
        let _ = delete_container(&id, &bundle).and_then(|mut c| Ok(c.wait()?));
        return TestResult::Failed(anyhow!(
            "create must fail when a createRuntime hook fails, but it exited successfully"
        ));
    }

    // Steps 4, 12 and 13: the failed create destroyed the container and ran the poststop hooks.
    let log = fs::read_to_string(&host_output_file).expect("cannot read output file");
    delete_hook_output_file(&host_output_file).unwrap();
    let expected = "create-runtime-failed\npost-stop called\n";
    if log != expected {
        return TestResult::Failed(anyhow!(
            "unexpected hook log after a createRuntime failure.\ngot:\n{log}\nexpected:\n{expected}"
        ));
    }
    if let Err(e) = wait_for_target(&id, bundle.path(), WaitTarget::Deleted) {
        return TestResult::Failed(anyhow!(
            "container must not exist after a failed create: {e}"
        ));
    }
    TestResult::Passed
}

pub fn get_hook_failure_tests() -> TestGroup {
    let mut tg = TestGroup::new("hooks_failure");
    // runc runs the poststart hooks during `create` rather than `start`
    // (opencontainers/runc#4347), so under runc the container never reaches
    // `created` here; the case is youki-only, as `poststart_fail` is.
    tg.add(vec![Box::new(ConditionalTest::new(
        "poststart_failure_stops_container",
        Box::new(|| !is_runtime_runc()),
        Box::new(poststart_failure_test),
    ))]);
    tg.add(vec![Box::new(Test::new(
        "create_runtime_failure_runs_poststop",
        Box::new(create_runtime_failure_test),
    ))]);
    tg
}
