use std::path::Path;

use anyhow::anyhow;
use test_framework::{TestResult, test_result};

use crate::utils::test_utils::{
    check_container_created, exec_container, start_container, test_outside_container,
};

pub(crate) fn cgroup_test() -> TestResult {
    let mut spec = test_result!(super::create_spec(None));

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
        exec_container(id, dir, &["--cgroup=/", "cat", "/proc/self/cgroup"], None)
            .expect("exec failed");

        TestResult::Passed
    });

    if let Some(mounts) = spec.mounts_mut() {
        for mount in mounts {
            if mount.destination() == Path::new("/sys/fs/cgroup")
                && let Some(options) = mount.options_mut()
            {
                options.retain(|opt| opt != "ro");
            }
        }
    }

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        // move init to a subcgroup, and check it was moved
        exec_container(
            id,
            dir,
            &["sh", "-euc", "mkdir /sys/fs/cgroup/foobar && echo 1 > /sys/fs/cgroup/foobar/cgroup.procs && grep -w foobar /proc/1/cgroup"],
            None,
        )
        .expect("exec failed");

        // the init process is now in "/foo", but an exec process can still join "/" because we haven't enabled any domain controller yet
        exec_container(id, dir, &["grep", "^0::/$", "/proc/self/cgroup"], None)
            .expect("exec failed");

        // turn on a domain controller (memory)
        exec_container(id, dir,
            &["sh", "-euc", "echo $$ > /sys/fs/cgroup/foobar/cgroup.procs; echo +memory > /sys/fs/cgroup/cgroup.subtree_control"], None)
            .expect("exec failed");

        // // an exec process can no longer join "/" after turning on a domain controller. Check that cgroup v2 fallback to init cgroup works
        // exec_container(
        //     id,
        //     dir,
        //     &[
        //         "sh",
        //         "-euc",
        //         "cat /proc/self/cgroup && grep '^0::/foobar$' /proc/self/cgroup",
        //     ],
        //     None,
        // )
        // .expect("exec failed");

        TestResult::Passed
    })
}
