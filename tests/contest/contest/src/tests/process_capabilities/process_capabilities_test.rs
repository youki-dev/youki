use anyhow::{Context, Ok, Result};
use libcontainer::capabilities::CapabilityExt;
use oci_spec::runtime::{
    Capabilities, Capability, LinuxCapabilitiesBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

// Grant every capability supported by the running host
fn all_capabilities() -> Capabilities {
    caps::all().into_iter().map(Capability::from_cap).collect()
}

fn create_spec() -> Result<Spec> {
    let caps = all_capabilities();
    let capabilities = LinuxCapabilitiesBuilder::default()
        .bounding(caps.clone())
        .effective(caps.clone())
        .inheritable(caps.clone())
        .permitted(caps.clone())
        .ambient(caps.clone())
        .build()
        .expect("error in creating capabilities");

    let process = ProcessBuilder::default()
        .args(vec![
            "runtimetest".to_string(),
            "process_capabilities".to_string(),
        ])
        .capabilities(capabilities)
        .build()
        .expect("error in creating process config");

    SpecBuilder::default()
        .process(process)
        .build()
        .context("failed to build spec")
}

fn process_capabilities_test() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_process_capabilities_test() -> TestGroup {
    let mut tg = TestGroup::new("process_capabilities");
    let test = Test::new(
        "process_capabilities_test",
        Box::new(process_capabilities_test),
    );
    tg.add(vec![Box::new(test)]);
    tg
}
