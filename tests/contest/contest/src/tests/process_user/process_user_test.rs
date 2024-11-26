use anyhow::{Context, Ok, Result};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder, UserBuilder};
use rand::Rng;
use test_framework::{test_result, Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

// Generates a Vec<u32> with a random number of elements (between 5 and 15),
// where each element is a random u32 value between 0 and 65535.
fn generate_unique_random_vec() -> Vec<u32> {
    let mut rng = rand::thread_rng();
    let vec_size = rng.gen_range(5..=10);
    let mut ret = Vec::new();
    while ret.len() < vec_size {
        let rand = rng.gen_range(100..=200);
        if !ret.contains(&rand) {
            ret.push(rand);
        }
    }
    ret
}

fn create_spec() -> Result<Spec> {
    let umask = 0o002;
    let user = UserBuilder::default()
        .uid(10u32)
        .gid(10u32)
        .additional_gids(generate_unique_random_vec())
        .umask(umask as u32)
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
    test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_process_user_test() -> TestGroup {
    let mut process_user_test_group = TestGroup::new("process_user");

    let test = Test::new("process_user_test", Box::new(process_user_test));
    process_user_test_group.add(vec![Box::new(test)]);

    process_user_test_group
}
