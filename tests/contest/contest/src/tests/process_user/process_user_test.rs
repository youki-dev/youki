use anyhow::{Context, Ok, Result};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder, UserBuilder};
use test_framework::{test_result, Test, TestGroup, TestResult};

use crate::utils::test_inside_container;

fn create_spec() -> Result<Spec> {
    let user = UserBuilder::default()
        .uid(10u32)
        .gid(10u32)
        .additional_gids(vec![5u32])
        .umask(0o02u32)
        .build()?;

    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "process_user".to_string()])
                .user(user)
                .build()
                .expect("error in creating process config"),
        )
        .build()
        .context("failed to build spec")?;
    Ok(spec)
}
fn process_user_test() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(spec, &|_| Ok(()))
}

pub fn get_process_user_test() -> TestGroup {
    let mut process_user_test_group = TestGroup::new("process_user");

    let test = Test::new("process_user_test", Box::new(process_user_test));
    process_user_test_group.add(vec![Box::new(test)]);

    process_user_test_group
}
