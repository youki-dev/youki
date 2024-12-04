use anyhow::{Context, Error, Ok, Result};
use oci_spec::runtime::{Capability, LinuxCapabilitiesBuilder, ProcessBuilder, Spec, SpecBuilder};
use std::collections::HashSet;
use std::str::FromStr;
use test_framework::{Test, TestGroup, TestResult};

fn create_spec() -> Result<Spec> {
    let capability = Capability::from_str("CAP_TEST").context("invalid capability")?;

    let linux_capability = LinuxCapabilitiesBuilder::default()
        .bounding(HashSet::from([capability]))
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
    match create_spec() {
        Result::Ok(_) => TestResult::Failed(Error::msg("create_spec succeeded unexpectedly.")),
        Err(e) => {
            if e.to_string() == "invalid capability" {
                TestResult::Passed
            } else {
                TestResult::Failed(Error::msg(format!("unexpected error: {}", e)))
            }
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
