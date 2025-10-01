mod cap_test;
mod cgroup_test;
mod ignore_paused_test;
mod preserve_fds_test;

use anyhow::{Context, Result};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup};

fn create_spec(process: Option<ProcessBuilder>) -> Result<Spec> {
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
    let cgroup_test = Test::new("cgroup_test", Box::new(cgroup_test::cgroup_test));
    let no_capabilities_test = Test::new(
        "no_capabilities_test",
        Box::new(cap_test::get_test_no_capabilities),
    );
    let new_privileges_test = Test::new(
        "new_privileges_test",
        Box::new(cap_test::get_test_new_privileges),
    );
    let some_capabilities_test = Test::new(
        "some_capabilities_test",
        Box::new(cap_test::get_test_some_capabilities),
    );
    let capabilities_by_flag_test_case1 = Test::new(
        "capabilities_by_flag_test_case1",
        Box::new(cap_test::get_test_capabilities_by_flag_case1),
    );
    let capabilities_by_flag_test_case2 = Test::new(
        "capabilities_by_flag_test_case2",
        Box::new(cap_test::get_test_capabilities_by_flag_case2),
    );

    test_group.add(vec![
        Box::new(preserve_fds_test),
        Box::new(ignore_paused_test),
        Box::new(cgroup_test),
        Box::new(no_capabilities_test),
        Box::new(new_privileges_test),
        Box::new(some_capabilities_test),
        Box::new(capabilities_by_flag_test_case1),
        Box::new(capabilities_by_flag_test_case2),
    ]);

    test_group
}
