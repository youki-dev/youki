use std::fs;
use std::fs::OpenOptions;
use std::io::Write;

use anyhow::{Context, Ok, Result, anyhow};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use serde_json::Value;
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec() -> Result<Spec> {
    let process = ProcessBuilder::default()
        .args(vec!["sleep".to_string(), "1m".to_string()])
        .build()
        .expect("error in creating process config");

    let spec = SpecBuilder::default()
        .process(process)
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn process_capabilities_fail_test() -> TestResult {
    let spec = test_result!(create_spec());
    let result = test_inside_container(&spec, &CreateOptions::default(), &|bundle| {
        let spec_path = bundle.join("../config.json");
        let spec_str = fs::read_to_string(spec_path.clone()).unwrap();

        let mut spec_json: Value = serde_json::from_str(&spec_str)?;

        // Before container creation, replace the spec's capability with an invalid one.
        let capability_paths = vec![
            "/process/capabilities/bounding",
            "/process/capabilities/effective",
        ];
        for path in &capability_paths {
            if let Some(array) = spec_json.pointer_mut(path)
                && let Some(arr) = array.as_array_mut()
            {
                for cap in arr.iter_mut() {
                    *cap = Value::String("TEST_CAP".to_string());
                }
            }
        }

        let updated_spec_str = serde_json::to_string_pretty(&spec_json)?;

        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(spec_path)?;
        file.write_all(updated_spec_str.as_bytes())?;

        Ok(())
    });

    // Check the test result: Fail if the container was created successfully (because it should fail)
    match result {
        TestResult::Failed(e) => {
            let err_str = format!("{:?}", e);

            // youki: error from rust deserialization when loading config.json with invalid capability
            let is_invalid_variant_error = err_str.contains("no variant for TEST_CAP");

            // runc: warning when TEST_CAP is unknown or unsupported and ignored
            let is_runc_cap_warning =
                err_str.contains("ignoring unknown or unavailable capabilities: [TEST_CAP]");

            if is_invalid_variant_error || is_runc_cap_warning {
                TestResult::Passed
            } else {
                TestResult::Failed(anyhow!("unexpected error: {e:?}"))
            }
        }
        TestResult::Skipped => TestResult::Failed(anyhow!("test was skipped unexpectedly.")),
        TestResult::Passed => {
            TestResult::Failed(anyhow!("container creation succeeded unexpectedly."))
        }
    }
}

pub fn get_process_capabilities_fail_test() -> TestGroup {
    let mut process_capabilities_fail_test_group = TestGroup::new("process_capabilities_fail");
    let test = Test::new(
        "process_capabilities_fail_test",
        Box::new(process_capabilities_fail_test),
    );
    process_capabilities_fail_test_group.add(vec![Box::new(test)]);

    process_capabilities_fail_test_group
}
