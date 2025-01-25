use anyhow::{Context, Result};
use oci_spec::runtime::{
    LinuxSchedulerPolicy, ProcessBuilder, SchedulerBuilder, Spec, SpecBuilder,
};
use test_framework::{test_result, ConditionalTest, TestGroup, TestResult};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{is_runtime_runc, test_inside_container};

fn create_spec(policy: LinuxSchedulerPolicy, execute_test: &str) -> Result<Spec> {
    let sc = SchedulerBuilder::default()
        .policy(policy)
        .nice(1i32)
        .build()
        .unwrap();
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(
                    ["runtimetest", execute_test]
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
                .scheduler(sc)
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn scheduler_policy_other_test() -> TestResult {
    let spec = test_result!(create_spec(
        LinuxSchedulerPolicy::SchedOther,
        "scheduler_policy_other"
    ));
    test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()))
}

fn scheduler_policy_batch_test() -> TestResult {
    let spec = test_result!(create_spec(
        LinuxSchedulerPolicy::SchedBatch,
        "scheduler_policy_batch"
    ));
    test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_scheduler_test() -> TestGroup {
    let mut scheduler_policy_group = TestGroup::new("set_scheduler_policy");
    let policy_fifo_test = ConditionalTest::new(
        "policy_other",
        Box::new(|| !is_runtime_runc()),
        Box::new(scheduler_policy_other_test),
    );
    let policy_rr_test = ConditionalTest::new(
        "policy_batch",
        Box::new(|| !is_runtime_runc()),
        Box::new(scheduler_policy_batch_test),
    );

    scheduler_policy_group.add(vec![Box::new(policy_fifo_test), Box::new(policy_rr_test)]);
    scheduler_policy_group
}
