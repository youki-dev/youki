mod common;

use anyhow::Context;
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup};

fn create_spec(process: Option<ProcessBuilder>) -> anyhow::Result<Spec> {
    let p = process.unwrap_or_default().args(
        ["sleep", "1000"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>(),
    );
    SpecBuilder::default()
        .process(p.build()?)
        .build()
        .context("failed to create spec")
}

pub fn get_update_test() -> TestGroup {
    let mut test_group = TestGroup::new("update");

    let update_cgroup_v1_v2_common_limits_test = Test::new(
        "update_cgroup_v1_v2_common_limits_test",
        Box::new(common::update_common_limits_test),
    );

    test_group.add(vec![
        Box::new(update_cgroup_v1_v2_common_limits_test),
    ]);
    test_group
}
