use anyhow::{Context, Result};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use test_framework::{test_result, Test, TestGroup, TestResult};

use crate::utils::test_utils::{test_inside_container, CreateOptions};

fn create_spec() -> Result<Spec> {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "no_pivot".to_string()])
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn no_pivot_test() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(
        spec,
        &CreateOptions::default().with_no_pivot_root(),
        &|_| Ok(()),
    )
}

pub fn get_no_pivot_test() -> TestGroup {
    let mut test_group = TestGroup::new("no_pivot");
    let no_pivot_test = Test::new("no_pivot_test", Box::new(no_pivot_test));
    test_group.add(vec![Box::new(no_pivot_test)]);

    test_group
}
