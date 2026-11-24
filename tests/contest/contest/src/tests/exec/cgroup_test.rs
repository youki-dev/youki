use std::path::Path;

use anyhow::anyhow;
use test_framework::{TestResult, test_result};

use crate::utils::test_utils::{
    check_container_created, exec_container, start_container, test_outside_container,
};
use crate::utils::{is_runtime_runc, is_runtime_youki};

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
            &[],
        )
        .expect_err("exec success");

        // check we can't join non-existing subcgroup
        exec_container(
            id,
            dir,
            &["--cgroup", "notexistspath", "cat", "/proc/self/cgroup"],
            None,
            &[],
        )
        .expect_err("exec success");

        // check we can't join non-existing subcgroup (for a particular controller)
        exec_container(
            id,
            dir,
            &["--cgroup", "cpu:notexistspath", "cat", "/proc/self/cgroup"],
            None,
            &[],
        )
        .expect_err("exec success");

        // check we can't specify non-existent controller
        exec_container(id, dir, &["--cgroup", "waaaaat:/", "true"], None, &[])
            .expect_err("exec success");

        // check we can join top-level cgroup (implicit)
        exec_container(id, dir, &["cat", "/proc/self/cgroup"], None, &[]).expect("exec failed");
        exec_container(id, dir, &["grep", "^0::/$", "/proc/self/cgroup"], None, &[])
            .expect("exec failed");

        // check we can join top-level cgroup (explicit)
        exec_container(
            id,
            dir,
            &["--cgroup=/", "cat", "/proc/self/cgroup"],
            None,
            &[],
        )
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

        exec_container(id, dir, &["grep", "^0::/$", "/proc/self/cgroup"], None, &[])
            .expect("exec failed");

        // move init to a sub-cgroup, and check it was moved
        exec_container(
            id,
            dir,
            &["sh", "-euc", "mkdir /sys/fs/cgroup/foobar && echo 1 > /sys/fs/cgroup/foobar/cgroup.procs && grep -w foobar /proc/1/cgroup"],
            None,
            &[],
        )
        .expect("exec failed");

        // youki adopts the "proactive inference" approach rather than runc's "retrying" approach,
        // so the exec process joins the "/foobar" sub-cgroup the init process was moved to.
        // runc leaves the exec process in "/" here instead.
        // ref (runc's behavior test): https://github.com/opencontainers/runc/blob/main/tests/integration/cgroups.bats#L99-L103
        // ref (approach details): https://github.com/youki-dev/youki/pull/3347#issuecomment-4557652166
        // ref (discussion): https://github.com/youki-dev/youki/pull/3347#issuecomment-5224550358
        if is_runtime_youki() {
            exec_container(
                id,
                dir,
                &["grep", "^0::/foobar$", "/proc/self/cgroup"],
                None,
                &[],
            )
            .expect("exec failed");
        } else if is_runtime_runc() {
            exec_container(id, dir, &["grep", "^0::/$", "/proc/self/cgroup"], None, &[])
                .expect("exec failed");
        }

        // turn on a domain controller (memory)
        exec_container(
            id,
            dir,
            &["sh", "-euc", "echo $$ > /sys/fs/cgroup/foobar/cgroup.procs; echo +memory > /sys/fs/cgroup/cgroup.subtree_control"],
            None,
            &[],
        )
        .expect("exec failed");

        // After a domain controller is enabled, joining "/" fails with EBUSY,
        // so both runtimes fall back to the init process's "/foobar" sub-cgroup.
        exec_container(
            id,
            dir,
            &["grep", "^0::/foobar$", "/proc/self/cgroup"],
            None,
            &[],
        )
        .expect("exec failed");

        // a nested sub-cgroup is inferred as a whole.
        exec_container(
            id,
            dir,
            &["sh", "-euc", "mkdir -p /sys/fs/cgroup/foobar/nested && echo 1 > /sys/fs/cgroup/foobar/nested/cgroup.procs && grep -w nested /proc/1/cgroup"],
            None,
            &[],
        )
        .expect("exec failed");

        // After a domain controller is enabled, both runtimes fall back to
        // the init process's nested sub-cgroup, as with "/foobar" above.
        exec_container(
            id,
            dir,
            &["grep", "^0::/foobar/nested$", "/proc/self/cgroup"],
            None,
            &[],
        )
        .expect("exec failed");

        TestResult::Passed
    });

    // Without any sub-cgroup, the exec process joins "/" without inference.
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        exec_container(id, dir, &["grep", "^0::/$", "/proc/self/cgroup"], None, &[])
            .expect("exec failed");

        TestResult::Passed
    })
}
