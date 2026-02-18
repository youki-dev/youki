use std::fs;

use anyhow::anyhow;
use oci_spec::runtime::{HooksBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{
    build_hook, create_container, delete_container, delete_hook_output_file, generate_uuid,
    get_hook_output_file_path, is_runtime_runc, prepare_bundle, set_config, start_container,
    wait_for_file_content,
};

const CONTAINER_OUTPUT_FILE: &str = "output";

fn write_process_command() -> Vec<String> {
    vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!("echo 'process called' >> {}", CONTAINER_OUTPUT_FILE),
    ]
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
                .args(write_process_command())
                .build()
                .unwrap(),
        )
        .hooks(
            HooksBuilder::default()
                .poststart(vec![build_hook("post-start called", host_output_file)])
                .build()
                .expect("could not build hooks"),
        )
        .build()
        .unwrap()
}

/// Tests that the poststart hook executes in the correct order.
/// The poststart hook should execute after the container process has started.
/// This is validated by having both the process and hook write to the same file in sequence.
fn get_test(test_name: &'static str) -> Test {
    Test::new(
        test_name,
        Box::new(move || {
            let id = generate_uuid();
            let id_str = id.to_string();
            let bundle = prepare_bundle().unwrap();

            let host_output_file = get_hook_output_file_path(&bundle);
            let host_output_file_str = host_output_file.to_str().unwrap();

            let spec = get_spec(host_output_file_str);
            set_config(&bundle, &spec).unwrap();

            create_container(&id_str, &bundle, &CreateOptions::default())
                .unwrap()
                .wait()
                .unwrap();

            if !is_runtime_runc() && host_output_file.exists() {
                // runc behaviour is incorrect in this case
                // https://github.com/opencontainers/runc/issues/4347
                let content = fs::read_to_string(&host_output_file)
                    .expect("failed to read output file after create");
                if !content.is_empty() {
                    let _ = delete_container(&id_str, &bundle);
                    delete_hook_output_file(&host_output_file);
                    let has_poststart = content.contains("post-start called");
                    let has_process = content.contains("process called");
                    return match (has_poststart, has_process) {
                        (true, _) => TestResult::Failed(anyhow!(
                            "The post-start hooks MUST NOT be called before the `start` operation"
                        )),
                        (false, true) => TestResult::Failed(anyhow!(
                            "The user-specified program (from process) MUST NOT be run before the `start` operation"
                        )),
                        (false, false) => TestResult::Failed(anyhow!(
                            "file {} should not exist after create, but has content: '{content}'",
                            host_output_file.display(),
                        )),
                    };
                }
            }

            start_container(&id_str, &bundle).unwrap().wait().unwrap();

            let wait_result = wait_for_file_content(
                &host_output_file,
                "process called",
                std::time::Duration::from_secs(5),
                std::time::Duration::from_millis(100),
            );

            let result = if let Err(e) = wait_result {
                TestResult::Failed(anyhow!("Container process execution failed: {e}"))
            } else if !host_output_file.exists() {
                TestResult::Failed(anyhow!(
                    "Expected output file {} does not exist. Neither the container process nor poststart hook created it",
                    host_output_file.display()
                ))
            } else {
                let contents =
                    fs::read_to_string(&host_output_file).expect("failed to read output file");
                match contents.as_str() {
                    // Order of the execution between the process logic and post-start hook logic
                    // is not guaranteed, so both outcomes are acceptable
                    "process called\npost-start called\n" => TestResult::Passed,
                    "post-start called\nprocess called\n" => TestResult::Passed,
                    "process called\n" => {
                        TestResult::Failed(anyhow!("The runtime MUST run the post-start hook"))
                    }
                    "post-start called\n" => TestResult::Failed(anyhow!(
                        "The runtime MUST run the user-specified program, as specified by `process`"
                    )),
                    _ => TestResult::Failed(anyhow!("unsupported output: {contents}")),
                }
            };

            let _ = delete_container(&id_str, &bundle);
            delete_hook_output_file(&host_output_file);
            result
        }),
    )
}

pub fn get_poststart_tests() -> TestGroup {
    let mut tg = TestGroup::new("poststart");
    tg.add(vec![Box::new(get_test("poststart"))]);
    tg
}
