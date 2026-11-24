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
use crate::utils::test_utils::{delete_container_force, run_container_detached};
use crate::utils::{
    CreateOptions, LifecycleStatus, WaitTarget, create_container, delete_container, generate_uuid,
    is_runtime_runc, prepare_bundle, set_config, start_container, wait_for_state,
};

const STATE_WAIT_TIMEOUT_SECS: u64 = 5;
const STATE_POLL_INTERVAL_MILLIS: u64 = 100;

/// A hook that records its invocation and the `status` of the OCI state it
/// receives on stdin, as `<content> status=<status>`.
fn status_log_hook(content: &str, host_output_file_path: &str) -> Hook {
    HookBuilder::default()
        .path("/bin/sh")
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                r#"status=$(sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([a-z]*\)".*/\1/p'); echo "{content} status=$status" >> {host_output_file_path}"#
            ),
        ])
        .build()
        .expect("could not build hook")
}

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

/// A hook that records its invocation, then outlives its 2 s timeout.
/// The runtime kills it and reports the hook as failed.
/// The 2 s leave a slow host time to write the log line first.
fn timing_out_log_hook(content: &str, host_output_file_path: &str) -> Hook {
    HookBuilder::default()
        .path("/bin/sh")
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo '{content}' >> {host_output_file_path}; exec /bin/sleep 30"),
        ])
        .timeout(2)
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

/// The two ways a hook can fail: a non-zero exit, or outliving its timeout.
#[derive(Clone, Copy)]
enum HookFailure {
    Exit,
    Timeout,
}

impl HookFailure {
    /// The failing hook, and the line it writes to the hook log.
    /// The line is `<stage>-failed` or `<stage>-timed-out`.
    fn hook(self, stage: &str, host_output_file: &str) -> (Hook, String) {
        match self {
            HookFailure::Exit => {
                let content = format!("{stage}-failed");
                (failing_log_hook(&content, host_output_file), content)
            }
            HookFailure::Timeout => {
                let content = format!("{stage}-timed-out");
                (timing_out_log_hook(&content, host_output_file), content)
            }
        }
    }
}

/// The create-time hook stages that run before `create` returns.
#[derive(Clone, Copy)]
enum CreateStage {
    CreateRuntime,
    CreateContainer,
}

/// A container whose poststart hook fails, and the line that hook logs.
fn poststart_failure_spec(host_output_file: &str, failure: HookFailure) -> (Spec, String) {
    let (hook, logged) = failure.hook("post-start", host_output_file);
    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "60".to_string()])
                .build()
                .unwrap(),
        )
        .hooks(
            HooksBuilder::default()
                .poststart(vec![hook])
                .poststop(vec![write_log_hook("post-stop called", host_output_file)])
                .build()
                .expect("could not build hooks"),
        )
        .build()
        .unwrap();
    (spec, logged)
}

/// A container whose createRuntime or createContainer hook fails.
/// Also returns the line that hook logs.
fn create_failure_spec(
    host_output_file: &str,
    stage: CreateStage,
    failure: HookFailure,
) -> (Spec, String) {
    let mut hooks = HooksBuilder::default();
    let logged = match stage {
        CreateStage::CreateRuntime => {
            let (hook, logged) = failure.hook("create-runtime", host_output_file);
            hooks = hooks.create_runtime(vec![hook]);
            logged
        }
        CreateStage::CreateContainer => {
            let (hook, logged) = failure.hook("create-container", host_output_file);
            hooks = hooks.create_container(vec![hook]);
            logged
        }
    };
    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["true".to_string()])
                .build()
                .unwrap(),
        )
        .hooks(
            hooks
                .poststop(vec![status_log_hook("post-stop", host_output_file)])
                .build()
                .expect("could not build hooks"),
        )
        .build()
        .unwrap();
    (spec, logged)
}

fn poststart_failure_test(failure: HookFailure) -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();
    let host_output_file = get_hook_output_path(&bundle);
    let host_output_file_str = host_output_file.to_str().unwrap();
    let (spec, logged) = poststart_failure_spec(host_output_file_str, failure);
    set_config(&bundle, &spec).unwrap();

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
        let _ = delete_container_force(&id, &bundle).and_then(|mut c| Ok(c.wait()?));
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
        let _ = delete_container_force(&id, &bundle).and_then(|mut c| Ok(c.wait()?));
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
    let expected = format!("{logged}\npost-stop called\n");
    if log != expected {
        return TestResult::Failed(anyhow!(
            "unexpected hook log after a poststart failure.\ngot:\n{log}\nexpected:\n{expected}"
        ));
    }
    TestResult::Passed
}

/// `youki run` creates and starts in one command.
/// After a poststart hook failure it must destroy the container itself.
/// It must also run the poststop hooks.
fn run_poststart_failure_test(failure: HookFailure) -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();
    let host_output_file = get_hook_output_path(&bundle);
    let host_output_file_str = host_output_file.to_str().unwrap();
    let (spec, logged) = poststart_failure_spec(host_output_file_str, failure);
    set_config(&bundle, &spec).unwrap();

    let run = run_container_detached(&id, &bundle)
        .unwrap()
        .wait()
        .unwrap();
    if run.success() {
        let _ = delete_container_force(&id, &bundle).and_then(|mut c| Ok(c.wait()?));
        return TestResult::Failed(anyhow!(
            "run must fail when a poststart hook fails, but it exited successfully"
        ));
    }

    // Steps 9, 12 and 13, all inside `run`: no container is left to delete.
    if let Err(e) = wait_for_target(&id, bundle.path(), WaitTarget::Deleted) {
        let _ = delete_container_force(&id, &bundle).and_then(|mut c| Ok(c.wait()?));
        return TestResult::Failed(anyhow!("container must not exist after a failed run: {e}"));
    }
    let log = fs::read_to_string(&host_output_file).expect("cannot read output file");
    delete_hook_output_file(&host_output_file).unwrap();
    let expected = format!("{logged}\npost-stop called\n");
    if log != expected {
        return TestResult::Failed(anyhow!(
            "unexpected hook log after a failed run.\ngot:\n{log}\nexpected:\n{expected}"
        ));
    }
    TestResult::Passed
}

fn create_failure_test(stage: CreateStage, failure: HookFailure) -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();
    let host_output_file = get_hook_output_path(&bundle);
    let host_output_file_str = host_output_file.to_str().unwrap();
    let (spec, logged) = create_failure_spec(host_output_file_str, stage, failure);
    set_config(&bundle, &spec).unwrap();

    let create = create_container(&id, &bundle, &CreateOptions::default())
        .unwrap()
        .wait()
        .unwrap();
    if create.success() {
        let _ = delete_container_force(&id, &bundle).and_then(|mut c| Ok(c.wait()?));
        return TestResult::Failed(anyhow!(
            "create must fail when its hook fails ({logged}), but it exited successfully"
        ));
    }

    // Step 4 or 5, then 12 and 13: the failed create destroyed the container.
    // It also ran the poststop hooks.
    let log = fs::read_to_string(&host_output_file).expect("cannot read output file");
    delete_hook_output_file(&host_output_file).unwrap();
    let expected = format!("{logged}\npost-stop status=stopped\n");
    if log != expected {
        return TestResult::Failed(anyhow!(
            "unexpected hook log after a failed create.\ngot:\n{log}\nexpected:\n{expected}"
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
    tg.add(vec![
        Box::new(ConditionalTest::new(
            "poststart_failure_stops_container",
            Box::new(|| !is_runtime_runc()),
            Box::new(|| poststart_failure_test(HookFailure::Exit)),
        )),
        Box::new(ConditionalTest::new(
            "poststart_timeout_stops_container",
            Box::new(|| !is_runtime_runc()),
            Box::new(|| poststart_failure_test(HookFailure::Timeout)),
        )),
        Box::new(ConditionalTest::new(
            "run_poststart_failure_deletes_container",
            Box::new(|| !is_runtime_runc()),
            Box::new(|| run_poststart_failure_test(HookFailure::Exit)),
        )),
        Box::new(ConditionalTest::new(
            "run_poststart_timeout_deletes_container",
            Box::new(|| !is_runtime_runc()),
            Box::new(|| run_poststart_failure_test(HookFailure::Timeout)),
        )),
    ]);
    tg.add(vec![
        Box::new(Test::new(
            "create_runtime_failure_runs_poststop",
            Box::new(|| create_failure_test(CreateStage::CreateRuntime, HookFailure::Exit)),
        )),
        Box::new(Test::new(
            "create_runtime_timeout_runs_poststop",
            Box::new(|| create_failure_test(CreateStage::CreateRuntime, HookFailure::Timeout)),
        )),
        Box::new(Test::new(
            "create_container_failure_runs_poststop",
            Box::new(|| create_failure_test(CreateStage::CreateContainer, HookFailure::Exit)),
        )),
        Box::new(Test::new(
            "create_container_timeout_runs_poststop",
            Box::new(|| create_failure_test(CreateStage::CreateContainer, HookFailure::Timeout)),
        )),
    ]);
    tg
}
