use std::{collections::HashSet, fs, fs::OpenOptions, io::Write};

use anyhow::{anyhow, Context, Ok, Result};
use oci_spec::runtime::{Capability, LinuxCapabilitiesBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{test_result, Test, TestGroup, TestResult};

use serde_json::Value;

use crate::utils::{test_inside_container, test_utils::CreateOptions};

fn create_spec() -> Result<Spec> {
    let linux_capability = LinuxCapabilitiesBuilder::default()
        .bounding(HashSet::from([Capability::Syslog]))
        .build()?;

    let process = ProcessBuilder::default()
        .args(vec![
            "runtimetest".to_string(),
            "process_capabilities_fail".to_string(),
        ])
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

        if let Some(bounding) = spec_json.pointer_mut("/process/capabilities/bounding") {
            if let Some(bounding_array) = bounding.as_array_mut() {
                for capanility in bounding_array.iter_mut() {
                    if capanility == "CAP_SYSLOG" {
                        *capanility = Value::String("TEST_CAP".to_string());
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
