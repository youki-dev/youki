use std::fs;

use anyhow::anyhow;
use oci_spec::runtime::{HooksBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{
    build_hook, create_container, delete_container, delete_hook_output_file, generate_uuid,
    get_hook_output_file_path, prepare_bundle, set_config,
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
                .build()
                .unwrap(),
        )
        .hooks(
            HooksBuilder::default()
                .prestart(vec![build_hook("pre-start called", host_output_file)])
                .build()
                .expect("could not build hooks"),
        )
        .build()
        .unwrap()
}

/// Tests that the prestart hook executes during the create operation.
/// According to the OCI spec, prestart hooks MUST be invoked by the runtime
/// after the container has been created but before the user-specified program
/// is executed (which happens during start).
fn get_test(test_name: &'static str) -> Test {
    Test::new(
        test_name,
        Box::new(move || {
            let id = generate_uuid().to_string();
            let bundle = prepare_bundle().unwrap();

            let host_output_file = get_hook_output_file_path(&bundle);

            let spec = get_spec(host_output_file.to_str().unwrap());
            set_config(&bundle, &spec).unwrap();

            create_container(&id, &bundle, &CreateOptions::default())
                .unwrap()
                .wait()
                .unwrap();

            let result = if !host_output_file.exists() {
                TestResult::Failed(anyhow!(
                    "prestart hook did not create output file during create operation"
                ))
            } else {
                let content = fs::read_to_string(&host_output_file)
                    .expect("failed to read output file after create");

                if content.contains("pre-start called") {
                    TestResult::Passed
                } else {
                    TestResult::Failed(anyhow!(
                        "the runtime MUST run the pre-start hooks during create. Got: '{content}'"
                    ))
                }
            };

            let _ = delete_container(&id, &bundle);
            delete_hook_output_file(&host_output_file);
            result
        }),
    )
}

pub fn get_prestart_tests() -> TestGroup {
    let mut tg = TestGroup::new("prestart");
    tg.add(vec![Box::new(get_test("prestart"))]);
    tg
}
