//! Experimental io_uring restrictions (`dev.youki.io_uring` annotation).
//!
//! Needs a kernel with task-level io_uring BPF filters (Linux 7.0+), and only
//! youki implements the annotation, so both tests are skipped otherwise.

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow};
use libcontainer::io_uring;
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::is_runtime_youki;
use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

/// The policy `runtimetest io_uring` checks: NOP, READ and SOCKET allowed,
/// sockets limited to AF_INET, provided-buffer selection denied.
const POLICY: &str = r#"{
    "defaultAction": "deny",
    "ops": ["IORING_OP_NOP", "IORING_OP_READ", "IORING_OP_SOCKET"],
    "socketFamilies": ["AF_INET"],
    "deniedSqeFlags": ["IOSQE_BUFFER_SELECT"]
}"#;

fn can_run() -> bool {
    is_runtime_youki() && io_uring::supported()
}

fn create_spec(policy: &str, runtimetest: &str) -> Result<Spec> {
    SpecBuilder::default()
        .annotations(HashMap::from([(
            io_uring::ANNOTATION.to_string(),
            policy.to_string(),
        )]))
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), runtimetest.to_string()])
                .build()
                .context("failed to create process config")?,
        )
        .build()
        .context("failed to build spec")
}

fn io_uring_policy_test() -> TestResult {
    let spec = test_result!(create_spec(POLICY, "io_uring"));
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

/// An unknown opcode name must stop the container from being created. The
/// container runs a check that always passes, so the test can only pass if
/// the runtime refuses the policy.
fn io_uring_invalid_policy_test() -> TestResult {
    let policy = r#"{"defaultAction": "deny", "ops": ["read"]}"#;
    let spec = test_result!(create_spec(policy, "hello_world"));
    match test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(())) {
        TestResult::Passed => TestResult::Failed(anyhow!(
            "expected a container with an invalid io_uring policy to fail, but it ran"
        )),
        _ => TestResult::Passed,
    }
}

pub fn get_io_uring_tests() -> TestGroup {
    let mut test_group = TestGroup::new("io_uring");
    let policy = ConditionalTest::new(
        "io_uring_policy",
        Box::new(can_run),
        Box::new(io_uring_policy_test),
    );
    let invalid = ConditionalTest::new(
        "io_uring_invalid_policy",
        Box::new(can_run),
        Box::new(io_uring_invalid_policy_test),
    );
    test_group.add(vec![Box::new(policy), Box::new(invalid)]);
    test_group
}
