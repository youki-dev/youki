use std::fs;
use std::path::PathBuf;

use anyhow::anyhow;
use oci_spec::runtime::{
    HookBuilder, HooksBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{
    create_container, delete_container, generate_uuid, prepare_bundle, set_config, start_container,
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
                .poststop(vec![
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

/// Tests the current behavior when a poststop hook fails.
///
/// TODO: This test currently validates youki's existing behavior, which differs from the OCI spec.
/// According to the spec: "If any poststop hook fails, the runtime MUST log a warning, but the
/// remaining hooks and lifecycle continue as if the hook had succeeded."
///
/// Current youki behavior (non-spec compliant):
/// - When a poststop hook fails, subsequent hooks are NOT executed
/// - The delete operation fails
///
/// Expected spec-compliant behavior:
/// - All hooks should execute even if one fails
/// - The delete operation should succeed (only log a warning)
///
/// This test should be updated once either youki is fixed to follow the spec or the spec itself is
/// updated: https://github.com/opencontainers/runtime-spec/issues/1309
fn get_test(test_name: &'static str) -> Test {
    Test::new(
        test_name,
        Box::new(move || {
            let id = generate_uuid().to_string();
            let bundle = prepare_bundle().unwrap();

            let host_output_file = get_output_file_path(&bundle);

            let spec = get_spec(host_output_file.to_str().unwrap());
            set_config(&bundle, &spec).unwrap();

            create_container(&id, &bundle, &CreateOptions::default())
                .unwrap()
                .wait()
                .unwrap();

            start_container(&id, &bundle).unwrap().wait().unwrap();

            let delete_result = delete_container(&id, &bundle).map(|mut cmd| cmd.wait());

            let delete_failed = match delete_result {
                Err(_) => true,
                Ok(Ok(status)) if !status.success() => true,
                _ => false,
            };

            if !delete_failed {
                delete_output_file(&host_output_file);
                return TestResult::Failed(anyhow!(
                    "delete operation should fail when poststop hook fails (current non-spec behavior)"
                ));
            }

            let result = if !host_output_file.exists() {
                TestResult::Failed(anyhow!("no poststop hooks ran (output file doesn't exist)"))
            } else {
                let content =
                    fs::read_to_string(&host_output_file).expect("failed to read output file");

                let lines: Vec<&str> = content.lines().collect();
                let expected = vec!["hook_1 called", "hook_2 called"];
                if lines != expected {
                    TestResult::Failed(anyhow!("expected hooks output {expected:?}, got {lines:?}"))
                } else {
                    TestResult::Passed
                }
            };

            delete_output_file(&host_output_file);
            result
        }),
    )
}

pub fn get_poststop_fail_tests() -> TestGroup {
    let mut tg = TestGroup::new("poststop_fail");
    tg.add(vec![Box::new(get_test("poststop_fail"))]);
    tg
}
