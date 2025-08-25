mod ignore_paused_test;
mod preserve_fds_test;

use anyhow::{Context, Result};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup};

fn create_spec() -> Result<Spec> {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(
                    ["sleep", "1000"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

pub fn get_exec_test() -> TestGroup {
    let mut test_group = TestGroup::new("exec");

    let preserve_fds_test = Test::new(
        "preserve_fds_test",
        Box::new(preserve_fds_test::preserve_fds_test),
    );

    let ignore_paused_test = Test::new(
        "ignore_paused_test",
        Box::new(ignore_paused_test::ignore_paused_test),
    );

    test_group.add(vec![
        Box::new(preserve_fds_test),
        Box::new(ignore_paused_test),
    ]);

    test_group
}
