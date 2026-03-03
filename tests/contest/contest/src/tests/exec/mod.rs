mod mount_test;

use anyhow::{Context, Result};
use oci_spec::runtime::{ProcessBuilder, RootBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup};

fn create_spec(process: Option<ProcessBuilder>) -> Result<Spec> {
    let p = process.unwrap_or_default().args(
        ["sleep", "1000"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>(),
    );
    SpecBuilder::default()
        .root(RootBuilder::default().readonly(true).build().unwrap())
        .process(p.build()?)
        .build()
        .context("failed to create spec")
}

pub fn get_exec_test() -> TestGroup {
    let mut test_group = TestGroup::new("exec");
    let mount_test = Test::new("mount_test", Box::new(mount_test::get_mount_test));

    test_group.add(vec![Box::new(mount_test)]);

    test_group
}
