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

fn build_log_hook(host_output_file: &str) -> oci_spec::runtime::Hook {
    HookBuilder::default()
        .path("/bin/sh")
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo 'create-runtime called' >> {host_output_file}"),
        ])
        .build()
        .expect("could not build hook")
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
                .create_runtime(vec![build_log_hook(host_output_file)])
                .build()
                .expect("could not build hooks"),
        )
        .build()
        .unwrap()
}

/// Tests that the createRuntime hook executes during the create operation.
/// According to the OCI spec, createRuntime hooks MUST be invoked by the runtime
/// after the container runtime environment has been created but before pivot_root
/// has been executed. The createRuntime hooks are called in the runtime namespace.
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

            let result = if !host_output_file.exists() {
                TestResult::Failed(anyhow!(
                    "createRuntime hook did not create output file during create operation"
                ))
            } else {
                let content = fs::read_to_string(&host_output_file)
                    .expect("failed to read output file after create");

                if content.contains("create-runtime called") {
                    TestResult::Passed
                } else {
                    TestResult::Failed(anyhow!(
                        "the runtime MUST run the createRuntime hooks during create. Got: '{content}'"
                    ))
                }
            };

            let _ = delete_container(&id, &bundle);
            delete_output_file(&host_output_file);
            result
        }),
    )
}

pub fn get_create_runtime_tests() -> TestGroup {
    let mut tg = TestGroup::new("create_runtime");
    tg.add(vec![Box::new(get_test("create_runtime"))]);
    tg
}
