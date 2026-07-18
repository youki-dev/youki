use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{PosixRlimitBuilder, PosixRlimitType, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

/// Creates a spec with an invalid rlimit value.
///
/// According to the OCI Runtime Spec, "The runtime MUST generate an error for any values
/// which cannot be mapped to a relevant kernel interface."
///
/// While the original Go test in runtime-tools validates this by using an invalid rlimit type
/// (RLIMIT_TEST), this implementation takes a different approach due to Rust's type safety:
/// - Uses a valid rlimit type (RLIMIT_NOFILE)
/// - Sets its value to u64::MAX, which exceeds the system's maximum allowed value
///   defined in /proc/sys/fs/nr_open
/// - This causes the kernel to reject the value with EPERM
///
/// See `man 2 setrlimit` for more details:
/// > EPERM The caller tried to increase the hard RLIMIT_NOFILE limit above
/// > the maximum defined by /proc/sys/fs/nr_open
/// > See also: https://docs.kernel.org/admin-guide/sysctl/fs.html#nr-open
fn create_spec() -> Result<Spec> {
    let invalid_rlimit = PosixRlimitBuilder::default()
        .typ(PosixRlimitType::RlimitNofile)
        .hard(u64::MAX) // Exceeds /proc/sys/fs/nr_open limit
        .soft(u64::MAX) // Exceeds /proc/sys/fs/nr_open limit
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
    match test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(())) {
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
