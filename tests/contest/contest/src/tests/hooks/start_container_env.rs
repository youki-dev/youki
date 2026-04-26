use std::time::Duration;

use anyhow::anyhow;
use oci_spec::runtime::{HookBuilder, HooksBuilder, ProcessBuilder, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::{
    CreateOptions, LifecycleStatus, WaitTarget, create_container, delete_container, generate_uuid,
    kill_container, prepare_bundle, set_config, start_container, wait_for_state,
};

const STATE_WAIT_TIMEOUT_SECS: u64 = 5;
const STATE_POLL_INTERVAL_MILLIS: u64 = 100;

fn wait_for_target(id: &str, bundle_path: &std::path::Path, target: WaitTarget) {
    wait_for_state(
        id,
        bundle_path,
        target,
        Duration::from_secs(STATE_WAIT_TIMEOUT_SECS),
        Duration::from_millis(STATE_POLL_INTERVAL_MILLIS),
    )
    .unwrap();
}

fn run_hook_env_test(
    shell_condition: &str,
    process_env: Vec<String>,
    hook_env: Option<Vec<String>>,
) -> TestResult {
    let id = generate_uuid();
    let id_str = id.to_string();
    let bundle = prepare_bundle().unwrap();

    let shell_cmd = format!("if {shell_condition}; then exit 0; else exit 1; fi");
    let hook_args = vec!["sh".to_string(), "-c".to_string(), shell_cmd];
    let hook = if let Some(env) = hook_env {
        HookBuilder::default()
            .path("/bin/sh")
            .args(hook_args)
            .env(env)
    } else {
        HookBuilder::default().path("/bin/sh").args(hook_args)
    };

    let mut process = ProcessBuilder::default()
        .args(vec!["sleep".to_string(), "60".to_string()])
        .build()
        .unwrap();
    let mut env = process.env().clone().unwrap();
    for e in process_env {
        env.push(e);
    }
    process.set_env(Some(env));

    let spec = SpecBuilder::default()
        .process(process)
        .hooks(
            HooksBuilder::default()
                .start_container(vec![
                    hook.build().expect("could not build startContainer hook"),
                ])
                .build()
                .expect("could not build hooks"),
        )
        .build()
        .unwrap();
    set_config(&bundle, &spec).unwrap();

    create_container(&id_str, &bundle, &CreateOptions::default())
        .unwrap()
        .wait()
        .unwrap();
    wait_for_target(
        &id_str,
        bundle.path(),
        WaitTarget::Status(LifecycleStatus::Created),
    );
    start_container(&id_str, &bundle)
        .and_then(|mut child| child.wait().map_err(Into::into))
        .unwrap();
    let test_passed = wait_for_state(
        &id_str,
        bundle.path(),
        WaitTarget::Status(LifecycleStatus::Running),
        Duration::from_secs(STATE_WAIT_TIMEOUT_SECS),
        Duration::from_millis(STATE_POLL_INTERVAL_MILLIS),
    )
    .is_ok();

    let _ = kill_container(&id_str, &bundle).and_then(|mut c| c.wait().map_err(Into::into));
    let _ = delete_container(&id_str, &bundle).and_then(|mut c| c.wait().map_err(Into::into));
    let _ = wait_for_state(
        &id_str,
        bundle.path(),
        WaitTarget::Deleted,
        Duration::from_secs(STATE_WAIT_TIMEOUT_SECS),
        Duration::from_millis(STATE_POLL_INTERVAL_MILLIS),
    );

    if test_passed {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "startContainer hook env check failed — container did not reach Running state \
             (hook likely exited non-zero)"
        ))
    }
}

fn get_test_inherit_env() -> Test {
    Test::new(
        "start_container_env_inherit",
        Box::new(|| {
            run_hook_env_test(
                r#"test "$ONE" = "two" && test "$FOO" = "bar""#,
                vec!["ONE=two".to_string(), "FOO=bar".to_string()],
                None,
            )
        }),
    )
}

fn get_test_explicit_env() -> Test {
    Test::new(
        "start_container_env_explicit",
        Box::new(|| {
            run_hook_env_test(
                r#"test "$HOOK_VAR" = "hook_value" && test -z "$PROC_VAR""#,
                vec!["PROC_VAR=should_not_appear".to_string()],
                Some(vec!["HOOK_VAR=hook_value".to_string()]),
            )
        }),
    )
}

pub fn get_start_container_env_tests() -> TestGroup {
    let mut tg = TestGroup::new("start_container_hook_env_inherit");
    tg.add(vec![
        Box::new(get_test_inherit_env()),
        Box::new(get_test_explicit_env()),
    ]);
    tg
}
