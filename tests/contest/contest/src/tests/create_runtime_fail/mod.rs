use std::fs;
use std::path::PathBuf;

use anyhow::anyhow;
use oci_spec::runtime::{
    HookBuilder, HooksBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{create_container, delete_container, generate_uuid, prepare_bundle, set_config};

const HOOK_OUTPUT_FILE: &str = "output";

fn get_output_file_path(bundle: &tempfile::TempDir) -> PathBuf {
    bundle
        .as_ref()
        .join("bundle")
        .join("rootfs")
        .join(HOOK_OUTPUT_FILE)
}

fn delete_output_file(path: &PathBuf) {
    if path.exists() {
        fs::remove_file(path).expect("failed to remove output file");
    }
}

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
                .build()
                .unwrap(),
        )
        .hooks(
            HooksBuilder::default()
                .create_runtime(vec![
                    HookBuilder::default()
                        .path("/bin/sh")
                        .args(vec![
                            "sh".to_string(),
                            "-c".to_string(),
                            format!("echo 'hook_1 called' >> {host_output_file}"),
                        ])
                        .build()
                        .expect("could not build hook"),
                    HookBuilder::default()
                        .path("/bin/sh")
                        .args(vec![
                            "sh".to_string(),
                            "-c".to_string(),
                            format!("echo 'hook_2 called' >> {host_output_file}; exit 1"),
                        ])
                        .build()
                        .expect("could not build hook"),
                    HookBuilder::default()
                        .path("/bin/sh")
                        .args(vec![
                            "sh".to_string(),
                            "-c".to_string(),
                            format!("echo 'hook_3 called' >> {host_output_file}"),
                        ])
                        .build()
                        .expect("could not build hook"),
                ])
                .build()
                .expect("could not build hooks"),
        )
        .build()
        .unwrap()
}

/// Tests that when a createRuntime hook fails, the runtime generates an error,
/// stops the container, and subsequent hooks are not executed.
///
/// According to the OCI spec: "If any createRuntime hook fails, the runtime MUST
/// generate an error, stop the container, and continue the lifecycle at step 12."
/// This test creates 3 hooks where hook_2 fails, then verifies that hook_1 and
/// hook_2 ran but hook_3 did not.
fn get_test(test_name: &'static str) -> Test {
    Test::new(
        test_name,
        Box::new(move || {
            let id = generate_uuid().to_string();
            let bundle = prepare_bundle().unwrap();

            let host_output_file = get_output_file_path(&bundle);

            let spec = get_spec(host_output_file.to_str().unwrap());
            set_config(&bundle, &spec).unwrap();

            let create_result =
                create_container(&id, &bundle, &CreateOptions::default()).map(|mut cmd| cmd.wait());

            let create_failed = match create_result {
                Err(_) => true,
                Ok(Ok(status)) if !status.success() => true,
                _ => false,
            };

            if !create_failed {
                let _ = delete_container(&id, &bundle);
                delete_output_file(&host_output_file);
                return TestResult::Failed(anyhow!(
                    "container creation should fail when a createRuntime hook fails"
                ));
            }

            let result = if !host_output_file.exists() {
                TestResult::Failed(anyhow!(
                    "No createRuntime hooks ran (output file doesn't exist)"
                ))
            } else {
                let content =
                    fs::read_to_string(&host_output_file).expect("failed to read output file");

                if !content.contains("hook_1 called") {
                    TestResult::Failed(anyhow!(
                        "first createRuntime hook should run before the failing hook"
                    ))
                } else if !content.contains("hook_2 called") {
                    TestResult::Failed(anyhow!(
                        "the failing createRuntime hook should have attempted to run"
                    ))
                } else if content.contains("hook_3 called") {
                    TestResult::Failed(anyhow!(
                        "hook after the failed hook was executed, but it shouldn't have"
                    ))
                } else {
                    TestResult::Passed
                }
            };

            let _ = delete_container(&id, &bundle);
            delete_output_file(&host_output_file);
            result
        }),
    )
}

pub fn get_create_runtime_fail_tests() -> TestGroup {
    let mut tg = TestGroup::new("create_runtime_fail");
    tg.add(vec![Box::new(get_test("create_runtime_fail"))]);
    tg
}
