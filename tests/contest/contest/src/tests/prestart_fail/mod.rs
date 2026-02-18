use std::fs;
use std::path::PathBuf;

use anyhow::anyhow;
use oci_spec::runtime::{
    HookBuilder, HooksBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{create_container, delete_container, generate_uuid, prepare_bundle, set_config};

const OUTPUT_FILE: &str = "output";

fn get_output_file_path(bundle: &tempfile::TempDir) -> PathBuf {
    bundle
        .as_ref()
        .join("bundle")
        .join("rootfs")
        .join(OUTPUT_FILE)
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
                    format!("echo 'process called' >> {OUTPUT_FILE}"),
                ])
                .cwd("/")
                .build()
                .unwrap(),
        )
        .hooks(
            HooksBuilder::default()
                .prestart(vec![
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

/// Tests that when a prestart hook fails, the runtime generates an error, stops the container, and
/// subsequent hooks are not executed.
///
/// According to the OCI spec: "If any prestart hook fails, the runtime MUST generate an error,
/// stop the container, and continue the lifecycle at step 12." This test creates 3 hooks where
/// hook_2 fails, then verifies that hook_1 and hook_2 ran in order, hook_3 did not run, and the
/// container process was never started.
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
                    "container creation should fail when a prestart hook fails"
                ));
            }

            let result = if !host_output_file.exists() {
                TestResult::Failed(anyhow!("No prestart hooks ran (output file doesn't exist)"))
            } else {
                let content =
                    fs::read_to_string(&host_output_file).expect("failed to read output file");
                let lines: Vec<&str> = content.lines().collect();

                if lines.contains(&"process called") {
                    TestResult::Failed(anyhow!(
                        "container process must not run when a prestart hook fails"
                    ))
                } else {
                    let expected = vec!["hook_1 called", "hook_2 called"];
                    if lines != expected {
                        TestResult::Failed(anyhow!(
                            "expected hooks to run in order {:?}, but got {:?}",
                            expected,
                            lines
                        ))
                    } else {
                        TestResult::Passed
                    }
                }
            };

            let _ = delete_container(&id, &bundle);
            delete_output_file(&host_output_file);
            result
        }),
    )
}

pub fn get_prestart_fail_tests() -> TestGroup {
    let mut tg = TestGroup::new("prestart_fail");
    tg.add(vec![Box::new(get_test("prestart_fail"))]);
    tg
}
