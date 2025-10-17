use std::collections::HashMap;

use anyhow::{Context, Ok, Result};
use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespace, LinuxNamespaceType, LinuxTimeOffset, ProcessBuilder, Spec,
    SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec() -> Result<Spec> {
    let mut default_namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces();
    default_namespaces.push(
        LinuxNamespace::default()
            .set_typ(LinuxNamespaceType::Time)
            .to_owned(),
    );

    let boottime: HashMap<_, _> = [(
        "boottime".to_owned(),
        LinuxTimeOffset::default()
            .set_secs(Some(9999999))
            .to_owned(),
    )]
    .into_iter()
    .collect();

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(
                    ["runtimetest", "hello_world"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?,
        )
        .linux(
            LinuxBuilder::default()
                .time_offsets(boottime)
                .namespaces(default_namespaces)
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn time_ns_test() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_time_ns_test() -> TestGroup {
    let mut test_group = TestGroup::new("time_ns");
    let test1 = Test::new("set boottime to 9999999", Box::new(time_ns_test));
    test_group.add(vec![Box::new(test1)]);

    test_group
}
