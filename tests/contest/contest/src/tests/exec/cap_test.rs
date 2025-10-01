use std::collections::HashSet;

use anyhow::anyhow;
use oci_spec::runtime::{LinuxCapabilitiesBuilder, ProcessBuilder};
use test_framework::{TestResult, test_result};

use crate::utils::test_utils::{
    check_container_created, exec_container, start_container, test_outside_container,
};

pub(crate) fn get_test_no_capabilities() -> TestResult {
    let no_caps = LinuxCapabilitiesBuilder::default()
        .bounding(HashSet::new())
        .effective(HashSet::new())
        .inheritable(HashSet::new())
        .permitted(HashSet::new())
        .ambient(HashSet::new());
    let spec = test_result!(super::create_spec(Some(
        ProcessBuilder::default()
            .no_new_privileges(true)
            .capabilities(no_caps.build().expect("build no caps failed"))
    )));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) =
            exec_container(id, dir, &["cat", "/proc/self/status"], None).expect("exec failed");

        if !stdout.contains("CapInh:\t0000000000000000") {
            return TestResult::Failed(anyhow!("unexpected output: {}", stdout));
        }
        if !stdout.contains("CapAmb:\t0000000000000000") {
            return TestResult::Failed(anyhow!("unexpected output: {}", stdout));
        }
        if !stdout.contains("NoNewPrivs:\t1") {
            return TestResult::Failed(anyhow!("unexpected output: {}", stdout));
        }

        TestResult::Passed
    })
}

pub(crate) fn get_test_new_privileges() -> TestResult {
    let no_caps = LinuxCapabilitiesBuilder::default()
        .bounding(HashSet::new())
        .effective(HashSet::new())
        .inheritable(HashSet::new())
        .permitted(HashSet::new())
        .ambient(HashSet::new());
    let spec = test_result!(super::create_spec(Some(
        ProcessBuilder::default()
            .no_new_privileges(false)
            .capabilities(no_caps.build().expect("build no caps failed"))
    )));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) =
            exec_container(id, dir, &["cat", "/proc/self/status"], None).expect("exec failed");

        if !stdout.contains("CapInh:\t0000000000000000") {
            return TestResult::Failed(anyhow!("unexpected output: {}", stdout));
        }
        if !stdout.contains("CapAmb:\t0000000000000000") {
            return TestResult::Failed(anyhow!("unexpected output: {}", stdout));
        }
        if !stdout.contains("NoNewPrivs:\t0") {
            return TestResult::Failed(anyhow!("unexpected output: {}", stdout));
        }

        TestResult::Passed
    })
}
