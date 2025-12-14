use std::fs;
use std::path::PathBuf;

use anyhow::anyhow;
use oci_spec::runtime::{
    HookBuilder, HooksBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{
    create_container, delete_container, generate_uuid, is_runtime_runc, prepare_bundle, set_config,
    start_container,
};

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
                .cwd("/")
                .build()
                .unwrap(),
        )
        .hooks(
            HooksBuilder::default()
                .poststart(vec![
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

/// Tests that when a poststart hook fails, subsequent hooks are not executed.
///
/// Validates that the runtime stops executing remaining poststart hooks after one fails,
/// and returns an error (exit code 1). This test creates 3 hooks where `hook_2` fails,
/// then verifies that `hook_1` and `hook_2` ran but `hook_3` did not.
fn get_test(test_name: &'static str) -> ConditionalTest {
    ConditionalTest::new(
        test_name,
        Box::new(|| !is_runtime_runc()),
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

            if create_failed {
                let _ = delete_container(&id, &bundle);
                delete_output_file(&host_output_file);
                return TestResult::Failed(anyhow!("runtime failed at create"));
            }

            if let Ok(mut cmd) = start_container(&id, &bundle) {
                let code = cmd.wait().unwrap().code().unwrap();
                if code != 1 {
                    let _ = delete_container(&id, &bundle);
                    delete_output_file(&host_output_file);
                    return TestResult::Failed(anyhow!(
                        "start should exit with code 1, got {code}"
                    ));
                }
            }

            let result = if host_output_file.exists() {
                let content =
                    fs::read_to_string(&host_output_file).expect("failed to read output file");

                if !content.contains("hook_1 called") {
                    TestResult::Failed(anyhow!("first successful poststart hook did not run"))
                } else if !content.contains("hook_2 called") {
                    TestResult::Failed(anyhow!("the failing poststart hook did not run"))
                } else if content.contains("hook_3 called") {
                    TestResult::Failed(anyhow!(
                        "the hook after the failed hook was executed, but it shouldn't have"
                    ))
                } else {
                    TestResult::Passed
                }
            } else {
                TestResult::Failed(anyhow!(
                    "no poststart hooks ran (output file doesn't exist)"
                ))
            };

            let _ = delete_container(&id, &bundle);
            delete_output_file(&host_output_file);
            result
        }),
    )
}

pub fn get_poststart_fail_tests() -> TestGroup {
    let mut tg = TestGroup::new("poststart_fail");
    tg.add(vec![Box::new(get_test("poststart_fail"))]);
    tg
}
