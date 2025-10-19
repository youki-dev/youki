use std::collections::HashMap;

use anyhow::{Context, Ok, Result};
use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespace, LinuxNamespaceType, LinuxTimeOffset, ProcessBuilder, Spec,
    SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec_for_set_times() -> Result<Spec> {
    let mut default_namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces();
    default_namespaces.push(
        LinuxNamespace::default()
            .set_typ(LinuxNamespaceType::Time)
            .to_owned(),
    );

    let time_offsets = create_time_offset(1337, 3141519, 7881, 2718281);

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(
                    ["runtimetest", "time_offsets"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?,
        )
        .linux(
            LinuxBuilder::default()
                .time_offsets(time_offsets)
                .namespaces(default_namespaces)
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn create_spec_with_no_time_ns_but_time_offsets() -> Result<Spec> {
    let mut default_namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces();
    default_namespaces.retain(|ns| ns.typ() != LinuxNamespaceType::Time);

    let time_offsets = create_time_offset(1337, 3141519, 7881, 2718281);

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
                .time_offsets(time_offsets)
                .namespaces(default_namespaces)
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn create_spec_for_timens_no_offsets() -> Result<Spec> {
    let mut default_namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces();
    default_namespaces.push(
        LinuxNamespace::default()
            .set_typ(LinuxNamespaceType::Time)
            .to_owned(),
    );

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(
                    ["runtimetest", "time_offsets"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?,
        )
        .linux(
            LinuxBuilder::default()
                .namespaces(default_namespaces)
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn create_time_offset(
    boottime_secs: i64,
    boottime_nanosecs: u32,
    monotonic_secs: i64,
    monotonic_nanosecs: u32,
) -> HashMap<String, LinuxTimeOffset> {
    let time_offsets = [
        (
            "boottime".to_owned(),
            LinuxTimeOffset::default()
                .set_secs(Some(boottime_secs))
                .set_nanosecs(Some(boottime_nanosecs))
                .to_owned(),
        ),
        (
            "monotonic".to_owned(),
            LinuxTimeOffset::default()
                .set_secs(Some(monotonic_secs))
                .set_nanosecs(Some(monotonic_nanosecs))
                .to_owned(),
        ),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>();
    time_offsets
}

fn set_times_test() -> TestResult {
    let spec = test_result!(create_spec_for_set_times());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn with_no_time_ns_but_time_offsets_test() -> TestResult {
    let spec = test_result!(create_spec_with_no_time_ns_but_time_offsets());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn timens_no_offsets_test() -> TestResult {
    let spec = test_result!(create_spec_for_timens_no_offsets());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_time_ns_test() -> TestGroup {
    let mut test_group = TestGroup::new("time_ns");
    let test1 = Test::new("simple timens", Box::new(set_times_test));
    let test2 = Test::new(
        "timens offsets with no timens",
        Box::new(with_no_time_ns_but_time_offsets_test),
    );
    let test3 = Test::new("timens with no offsets", Box::new(timens_no_offsets_test));
    test_group.add(vec![Box::new(test1), Box::new(test2), Box::new(test3)]);

    test_group
}
