use anyhow::{Context, Result};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use test_framework::{test_result, Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

////////// ANCHOR: get_example_spec
fn create_spec() -> Result<Spec> {
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
        .build()
        .context("failed to create spec")
}
////////// ANCHOR_END: get_example_spec

////////// ANCHOR: example_test
fn example_test() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()))
}
////////// ANCHOR_END: example_test

////////// ANCHOR: get_example_test
pub fn get_example_test() -> TestGroup {
    let mut test_group = TestGroup::new("example");
    let test1 = Test::new("hello world", Box::new(example_test));
    test_group.add(vec![Box::new(test1)]);

    test_group
}
////////// ANCHOR_END: get_example_test
