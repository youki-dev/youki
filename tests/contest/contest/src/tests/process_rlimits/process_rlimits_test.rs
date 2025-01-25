use anyhow::{Context, Ok, Result};
use oci_spec::runtime::{
    PosixRlimit, PosixRlimitBuilder, PosixRlimitType, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{test_result, Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

const GIGABYTES: u64 = 1024 * 1024 * 1024;

fn create_rlimit(
    rlimit_type: PosixRlimitType,
    hard_val: u64,
    soft_val: u64,
) -> Result<PosixRlimit> {
    let rlimit = PosixRlimitBuilder::default()
        .typ(rlimit_type)
        .hard(hard_val)
        .soft(soft_val)
        .build()?;
    Ok(rlimit)
}

#[allow(clippy::identity_op)]
fn create_spec() -> Result<Spec> {
    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec![
                    "runtimetest".to_string(),
                    "process_rlimits".to_string(),
                ])
                .rlimits(vec![
                    create_rlimit(PosixRlimitType::RlimitAs, 2 * GIGABYTES, 1 * GIGABYTES).unwrap(),
                    create_rlimit(PosixRlimitType::RlimitCore, 4 * GIGABYTES, 3 * GIGABYTES)
                        .unwrap(),
                    create_rlimit(PosixRlimitType::RlimitData, 6 * GIGABYTES, 5 * GIGABYTES)
                        .unwrap(),
                    create_rlimit(PosixRlimitType::RlimitFsize, 8 * GIGABYTES, 7 * GIGABYTES)
                        .unwrap(),
                    create_rlimit(PosixRlimitType::RlimitStack, 10 * GIGABYTES, 9 * GIGABYTES)
                        .unwrap(),
                    create_rlimit(PosixRlimitType::RlimitCpu, 120, 60).unwrap(),
                    create_rlimit(PosixRlimitType::RlimitNofile, 4000, 3000).unwrap(),
                ])
                .build()
                .expect("error in creating process config"),
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn process_rlimits_test() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_process_rlimits_test() -> TestGroup {
    let mut process_rlimits_test_group = TestGroup::new("process_rlimits");

    let test = Test::new("process_rlimits_test", Box::new(process_rlimits_test));
    process_rlimits_test_group.add(vec![Box::new(test)]);

    process_rlimits_test_group
}
