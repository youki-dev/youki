use std::fs;
use std::time::Duration;

use anyhow::anyhow;
use oci_spec::runtime::{
    HookBuilder, HooksBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult};

use crate::tests::hooks::{delete_hook_output_file, get_hook_output_path, write_log_hook};
use crate::utils::test_utils::CreateOptions;
use crate::utils::{
    LifecycleStatus, WaitTarget, create_container, delete_container, generate_uuid, prepare_bundle,
    set_config, start_container, wait_for_state,
};

fn get_spec(host_output_file: &str) -> Spec {
    SpecBuilder::default()
        .root(
            RootBuilder::default()
                .path("rootfs")
                .readonly(false)
                .build()
                .expect("failed to create root"),
        )
        .process(
            ProcessBuilder::default()
                .args(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "true".to_string(),
                ])
                .cwd("/")
                .build()
                .unwrap(),
        )
        .hooks(
            HooksBuilder::default()
                .poststop(vec![
                    write_log_hook("hook_1 called", host_output_file),
                    HookBuilder::default()
                        .path("/bin/sh")
                        .args(vec![
                            "sh".to_string(),
                            "-c".to_string(),
                            format!("echo 'hook_2 called' >> {host_output_file}; exit 1"),
                        ])
                        .build()
                        .expect("could not build hook"),
                    write_log_hook("hook_3 called", host_output_file),
                ])
                .build()
                .expect("could not build hooks"),
        )
        .build()
        .unwrap()
}

/// Tests that failed poststop hooks do not prevent later hooks or container deletion.

fn get_test(test_name: &'static str) -> Test {
    Test::new(
        test_name,
        Box::new(move || {
            let id = generate_uuid().to_string();
            let bundle = prepare_bundle().unwrap();

            let host_output_file = get_hook_output_path(&bundle);

            let spec = get_spec(host_output_file.to_str().unwrap());
            set_config(&bundle, &spec).unwrap();

            create_container(&id, &bundle, &CreateOptions::default())
                .unwrap()
                .wait()
                .unwrap();

            start_container(&id, &bundle).unwrap().wait().unwrap();

            if let Err(e) = wait_for_state(
                &id,
                &bundle,
                WaitTarget::Status(LifecycleStatus::Stopped),
                Duration::from_secs(5),
                Duration::from_millis(100),
            ) {
                return TestResult::Failed(e);
            }

            let delete_result = delete_container(&id, &bundle).map(|mut cmd| cmd.wait());
            let delete_succeeded = matches!(delete_result, Ok(Ok(status)) if status.success());

            let result = if !delete_succeeded {
                TestResult::Failed(anyhow!(
                    "delete operation should succeed when a poststop hook fails"
                ))
            } else if !host_output_file.exists() {
                TestResult::Failed(anyhow!("no poststop hooks ran (output file doesn't exist)"))
            } else {
                let content =
                    fs::read_to_string(&host_output_file).expect("failed to read output file");

                let lines: Vec<&str> = content.lines().collect();
                let expected = vec!["hook_1 called", "hook_2 called", "hook_3 called"];
                if lines != expected {
                    TestResult::Failed(anyhow!("expected hooks output {expected:?}, got {lines:?}"))
                } else {
                    TestResult::Passed
                }
            };

            delete_hook_output_file(&host_output_file).unwrap();
            result
        }),
    )
}

pub fn get_poststop_fail_tests() -> TestGroup {
    let mut tg = TestGroup::new("poststop_fail");
    tg.add(vec![Box::new(get_test("poststop_fail"))]);
    tg
}
