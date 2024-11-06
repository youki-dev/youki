use anyhow::{Context, Ok, Result};
use oci_spec::runtime::{RootBuilder, Spec, SpecBuilder};
use test_framework::{test_result, Test, TestGroup, TestResult};

use crate::utils::test_inside_container;

fn create_spec() -> Result<Spec> {
    let spec = SpecBuilder::default()
        .root(RootBuilder::default().readonly(true).build().unwrap())
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn root_readonly_test() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(spec, &|_| Ok(()))
}

pub fn get_root_readonly_test() -> TestGroup {
    let mut root_readonly_test_group = TestGroup::new("root_readonly");

    let test = Test::new("root_readonly_test", Box::new(root_readonly_test));
    root_readonly_test_group.add(vec![Box::new(test)]);

    root_readonly_test_group
}
