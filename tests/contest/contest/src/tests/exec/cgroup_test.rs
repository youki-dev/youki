use anyhow::anyhow;
use test_framework::{test_result, TestResult};

use crate::utils::test_utils::{
    check_container_created, exec_container, start_container, test_outside_container,
};

pub(crate) fn cgroup_test() -> TestResult {
    let spec = test_result!(super::create_spec());

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        // check we can't join parent cgroup
        exec_container(
            id,
            dir,
            &["--cgroup", "..", "cat", "/proc/self/cgroup"],
            None,
        )
        .expect_err("exec success");

        // check we can't join non-existing subcgroup
        exec_container(
            id,
            dir,
            &["--cgroup", "notexistspath", "cat", "/proc/self/cgroup"],
            None,
        )
        .expect_err("exec success");

        // check we can't join non-existing subcgroup (for a particular controller)
        exec_container(
            id,
            dir,
            &["--cgroup", "cpu:notexistspath", "cat", "/proc/self/cgroup"],
            None,
        )
        .expect_err("exec success");

        // check we can't specify non-existent controller
        exec_container(id, dir, &["--cgroup", "waaaaat:/", "true"], None)
            .expect_err("exec success");

        // check we can join top-level cgroup (implicit)
        exec_container(id, dir, &["cat", "/proc/self/cgroup"], None).expect("exec failed");
        exec_container(id, dir, &["grep", "^0::/$", "/proc/self/cgroup"], None)
            .expect("exec failed");

        // check we can join top-level cgroup (explicit)
        exec_container(
            id,
            dir,
            &["--cgroup", "/", "cat", "/proc/self/cgroup"],
            None,
        )
        .expect("exec failed");

        TestResult::Passed
    })
}
