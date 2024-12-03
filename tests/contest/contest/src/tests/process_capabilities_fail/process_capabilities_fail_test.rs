use anyhow::{anyhow, Context, Ok, Result};
use oci_spec::runtime::{Capability, LinuxCapabilitiesBuilder, ProcessBuilder, Spec, SpecBuilder};
use std::collections::HashSet;
use std::str::FromStr;
use test_framework::{test_result, Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec() -> Result<Spec> {
    let cap_test = Capability::from_str("CAP_TEST").context("invalid capability: CAP_TEST")?;

    let linux_capability = LinuxCapabilitiesBuilder::default()
        .bounding(HashSet::from([cap_test]))
        // .bounding(HashSet::from([Capability::from_str("CAP_TEST")]))
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

    let result = test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()));

    match result {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!("test unexpectedly passed.")),
        _ => TestResult::Failed(anyhow!("test result was unexpected.")),
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
