use anyhow::{Context, Ok, Result};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder, UserBuilder};
use rand::Rng;
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{is_runtime_runc, test_inside_container};

// Generates a Vec<u32> with a random number of elements (between 5 and 15),
// where each element is a random u32 value between 0 and 65535.
fn generate_unique_random_vec() -> Vec<u32> {
    let mut rng = rand::rng();
    let vec_size = rng.random_range(5..=10);
    let mut ret = Vec::new();
    while ret.len() < vec_size {
        let rand = rng.random_range(100..=200);
        if !ret.contains(&rand) {
            ret.push(rand);
        }
    }
    ret
}

fn create_spec(gids: Vec<u32>) -> Result<Spec> {
    let umask = 0o002;
    let user = UserBuilder::default()
        .uid(10u32)
        .gid(10u32)
        .additional_gids(gids)
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

fn process_user_test_unique_gids() -> TestResult {
    let gids = generate_unique_random_vec();
    let spec = test_result!(create_spec(gids));
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn process_user_test_duplicate_gids() -> TestResult {
    let mut gids = generate_unique_random_vec();
    let duplicate = gids[0];
    gids.push(duplicate);
    let spec = test_result!(create_spec(gids));
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_process_user_test() -> TestGroup {
    let mut process_user_test_group = TestGroup::new("process_user");

    let test1 = ConditionalTest::new(
        "process_user_unique_gids_test",
        Box::new(|| true),
        Box::new(process_user_test_unique_gids),
    );
    // In runc 1.1, duplicates are removed, but in 1.3, duplicates are handled as-is.
    // The current CI for Youki uses runc 1.1, so this will be skipped.
    let test2 = ConditionalTest::new(
        "process_user_duplicate_gids_test",
        Box::new(|| !is_runtime_runc()),
        Box::new(process_user_test_duplicate_gids),
    );
    process_user_test_group.add(vec![Box::new(test1), Box::new(test2)]);

    process_user_test_group
}
