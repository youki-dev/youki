use anyhow::{Context, Result};
use oci_spec::runtime::{
    IOPriorityClass, LinuxIOPriorityBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{test_result, ConditionalTest, TestGroup, TestResult};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{is_runtime_runc, test_inside_container};

fn create_spec(
    io_priority_class: IOPriorityClass,
    execute_test: &str,
    priority: i64,
) -> Result<Spec> {
    let io_p = LinuxIOPriorityBuilder::default()
        .class(io_priority_class)
        .priority(priority)
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
                .io_priority(io_p)
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn io_priority_class_rt_test() -> TestResult {
    let spec = test_result!(create_spec(
        IOPriorityClass::IoprioClassRt,
        "io_priority_class_rt",
        1,
    ));
    test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()))
}

fn io_priority_class_be_test() -> TestResult {
    let spec = test_result!(create_spec(
        IOPriorityClass::IoprioClassBe,
        "io_priority_class_be",
        2,
    ));
    test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()))
}

fn io_priority_class_idle_test() -> TestResult {
    let spec = test_result!(create_spec(
        IOPriorityClass::IoprioClassIdle,
        "io_priority_class_idle",
        3,
    ));
    test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_io_priority_test() -> TestGroup {
    let mut io_priority_group = TestGroup::new("set_io_priority");
    let io_priority_class_rt = ConditionalTest::new(
        "io_priority_class_rt",
        Box::new(|| !is_runtime_runc()),
        Box::new(io_priority_class_rt_test),
    );
    let io_priority_class_be = ConditionalTest::new(
        "io_priority_class_be",
        Box::new(|| !is_runtime_runc()),
        Box::new(io_priority_class_be_test),
    );
    let io_priority_class_idle = ConditionalTest::new(
        "io_priority_class_idle",
        Box::new(|| !is_runtime_runc()),
        Box::new(io_priority_class_idle_test),
    );

    io_priority_group.add(vec![
        Box::new(io_priority_class_rt),
        Box::new(io_priority_class_be),
        Box::new(io_priority_class_idle),
    ]);
    io_priority_group
}
