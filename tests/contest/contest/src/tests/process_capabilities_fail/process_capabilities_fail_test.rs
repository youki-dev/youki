use std::collections::HashSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;

use anyhow::{anyhow, Context, Ok, Result};
use oci_spec::runtime::{Capability, LinuxCapabilitiesBuilder, ProcessBuilder, Spec, SpecBuilder};
use serde_json::Value;
use test_framework::{test_result, Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec() -> Result<Spec> {
    // When an invalid linux capability is specified, the spec cannot be created, so a valid linux capability is used.
    let linux_capability = LinuxCapabilitiesBuilder::default()
        .bounding(HashSet::from([Capability::Syslog])) // Adding the syslog capability here
        .build()?;

    let process = ProcessBuilder::default()
        .args(vec!["sleep".to_string(), "1m".to_string()])
        .capabilities(linux_capability)
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
        if let Some(bounding) = spec_json.pointer_mut("/process/capabilities/bounding") {
            if let Some(bounding_array) = bounding.as_array_mut() {
                for capability in bounding_array.iter_mut() {
                    if capability == "CAP_SYSLOG" {
                        *capability = Value::String("TEST_CAP".to_string()); // Invalid capability
                    }
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
        TestResult::Failed(_e) => TestResult::Passed,
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
