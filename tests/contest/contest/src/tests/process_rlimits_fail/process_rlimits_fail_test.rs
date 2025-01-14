use anyhow::{anyhow, Context, Result};
use oci_spec::runtime::{PosixRlimitBuilder, PosixRlimitType, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{test_result, Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec() -> Result<Spec> {
    let invalid_rlimit = PosixRlimitBuilder::default()
        .typ(PosixRlimitType::RlimitNofile)
        .hard(u64::MAX)
        .soft(u64::MAX)
        .build()?;

    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec![
                    "runtimetest".to_string(),
                    "process_rlimits".to_string(),
                ])
                .rlimits(vec![invalid_rlimit])
                .build()
                .context("failed to create process config")?,
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn process_rlimits_fail_test() -> TestResult {
    let spec = test_result!(create_spec());
    match test_inside_container(spec, &CreateOptions::default(), &|_| Ok(())) {
        TestResult::Passed => TestResult::Failed(anyhow!(
            "expected test with invalid rlimit value to fail, but it passed instead"
        )),
        _ => TestResult::Passed,
    }
}

pub fn get_process_rlimits_fail_test() -> TestGroup {
    let mut test_group = TestGroup::new("process_rlimits_fail");
    let test = Test::new(
        "process_rlimits_fail_test",
        Box::new(process_rlimits_fail_test),
    );
    test_group.add(vec![Box::new(test)]);
    test_group
}
