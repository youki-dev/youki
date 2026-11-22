use anyhow::{Context, Result};
use oci_spec::runtime::{LinuxBuilder, ProcessBuilder, Spec, SpecBuilder, get_default_mounts};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{is_cgroup_v2, test_inside_container};

const MOUNT_LABEL: &str = "system_u:object_r:container_file_t:s0";

fn create_spec() -> Result<Spec> {
    let mut mounts = get_default_mounts();
    for m in mounts
        .iter_mut()
        .filter(|m| m.typ().as_deref() == Some("mqueue"))
    {
        let mut options = m.options().clone().unwrap_or_default();
        options.push("ro".to_string());
        m.set_options(Some(options));
    }

    SpecBuilder::default()
        .mounts(mounts)
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "mount_label".to_string()])
                .build()
                .context("failed to build process")?,
        )
        .linux(
            LinuxBuilder::default()
                .mount_label(MOUNT_LABEL)
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")
}

fn mqueue_ro_mount_label_test() -> TestResult {
    let spec = test_result!(create_spec());
    // runtimetest checks /dev/mqueue's label and that it is read-only.
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

// The default spec has a cgroup mount and a cgroup namespace. runtimetest checks that
// /sys/fs/cgroup is the container's own cgroup, which `context=` on cgroup2 breaks.
fn cgroup_mount_label_test() -> TestResult {
    let spec = test_result!(
        SpecBuilder::default()
            .process(test_result!(
                ProcessBuilder::default()
                    .args(vec![
                        "runtimetest".to_string(),
                        "cgroup_mount_label".to_string(),
                    ])
                    .build()
                    .context("failed to build process")
            ))
            .linux(test_result!(
                LinuxBuilder::default()
                    .mount_label(MOUNT_LABEL)
                    .build()
                    .context("failed to build linux spec")
            ))
            .build()
            .context("failed to build spec")
    );
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

// SELinux is enabled and its policy knows the label (container-selinux).
fn can_run() -> bool {
    std::fs::write("/sys/fs/selinux/context", MOUNT_LABEL).is_ok()
}

pub fn get_mount_label_test() -> TestGroup {
    let mut tg = TestGroup::new("mount_label");
    tg.add(vec![
        Box::new(ConditionalTest::new(
            "mqueue_ro_mount_label_test",
            Box::new(can_run),
            Box::new(mqueue_ro_mount_label_test),
        )),
        // runtimetest reads cgroup.procs at the top of the mount, which only cgroup v2 has.
        Box::new(ConditionalTest::new(
            "cgroup_mount_label_test",
            Box::new(|| can_run() && is_cgroup_v2()),
            Box::new(cgroup_mount_label_test),
        )),
    ]);
    tg
}

test_framework::register_test_group!(get_mount_label_test);
