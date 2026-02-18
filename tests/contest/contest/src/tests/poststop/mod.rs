use std::fs;

use anyhow::anyhow;
use oci_spec::runtime::{HooksBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::{
    CreateOptions, build_hook, create_container, delete_container, delete_hook_output_file,
    generate_uuid, get_hook_output_file_path, prepare_bundle, set_config, start_container,
    wait_for_file_content,
};

const POSTSTOP_OUTPUT_FILE: &str = "output";

fn write_process_command() -> Vec<String> {
    vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!("echo 'process called' >> {POSTSTOP_OUTPUT_FILE}"),
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
                .poststop(vec![build_hook("post-stop called", host_output_file)])
                .build()
                .expect("could not build hooks"),
        )
        .build()
        .unwrap()
}

/// Tests that the poststop hook executes in the correct order.
/// The poststop hooks should execute after the container process has ended.
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

            start_container(&id_str, &bundle).unwrap().wait().unwrap();

            let wait_result = wait_for_file_content(
                &host_output_file,
                "process called",
                std::time::Duration::from_secs(5),
                std::time::Duration::from_millis(100),
            );

            let result = if let Err(e) = wait_result {
                TestResult::Failed(anyhow!("Container process execution failed: {e}"))
            } else {
                let contents =
                    fs::read_to_string(&host_output_file).expect("failed to read output file");
                match contents.as_str() {
                    "process called\n" => TestResult::Passed,
                    "post-stop called\n"
                    | "post-stop called\nprocess called\n"
                    | "process called\npost-stop called\n" => TestResult::Failed(anyhow!(
                        "The post-stop hooks MUST be called after the container is deleted"
                    )),
                    _ => TestResult::Failed(anyhow!("Unsupported output information: {contents}")),
                }
            };

            delete_container(&id_str, &bundle).unwrap().wait().unwrap();

            if let TestResult::Failed(_) = result {
                delete_hook_output_file(&host_output_file);
                return result;
            }

            let wait_result = wait_for_file_content(
                &host_output_file,
                "post-stop called",
                std::time::Duration::from_secs(5),
                std::time::Duration::from_millis(100),
            );
            let result = if let Err(e) = wait_result {
                TestResult::Failed(anyhow!("post-stop hook execution failed: {e}"))
            } else {
                let contents =
                    fs::read_to_string(&host_output_file).expect("failed to read output file");
                match contents.as_str() {
                    "process called\npost-stop called\n" => TestResult::Passed,
                    "post-stop called" => TestResult::Failed(anyhow!(
                        "The runtime MUST run the user-specified program, as specified by `process`"
                    )),
                    "process called\n" => TestResult::Failed(anyhow!(
                        "The poststop hooks MUST be invoked by the runtime."
                    )),
                    "post-stop called\nprocess called\n" => TestResult::Failed(anyhow!(
                        "The post-stop should called after the user-specified program command is executed"
                    )),
                    _ => TestResult::Failed(anyhow!("Unsupported output information: {contents}")),
                }
            };

            delete_hook_output_file(&host_output_file);
            result
        }),
    )
}

pub fn get_poststop_tests() -> TestGroup {
    let mut tg = TestGroup::new("poststop");
    tg.add(vec![Box::new(get_test("poststop"))]);
    tg
}
