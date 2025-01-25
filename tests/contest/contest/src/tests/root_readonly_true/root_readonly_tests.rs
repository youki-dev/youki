use anyhow::{Context, Ok, Result};
use oci_spec::runtime::{ProcessBuilder, RootBuilder, Spec, SpecBuilder};
use test_framework::{test_result, Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec(readonly: bool) -> Result<Spec> {
    let spec = SpecBuilder::default()
        .root(RootBuilder::default().readonly(readonly).build().unwrap())
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "root_readonly".to_string()])
                .build()
                .expect("error in creating config"),
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn root_readonly_true_test() -> TestResult {
    let spec_true = test_result!(create_spec(true));
    test_inside_container(spec_true, &CreateOptions::default(), &|_| Ok(()))
}

fn root_readonly_false_test() -> TestResult {
    let spec_false = test_result!(create_spec(false));
    test_inside_container(spec_false, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_root_readonly_test() -> TestGroup {
    let mut root_readonly_test_group = TestGroup::new("root_readonly");

    let test_true = Test::new("root_readonly_true_test", Box::new(root_readonly_true_test));
    let test_false = Test::new(
        "root_readonly_false_test",
        Box::new(root_readonly_false_test),
    );
    root_readonly_test_group.add(vec![Box::new(test_true), Box::new(test_false)]);

    root_readonly_test_group
}
