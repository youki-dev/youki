use anyhow::{Context, Result};
use oci_spec::runtime::{LinuxBuilder, Spec, SpecBuilder, get_default_mounts};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_outside_container;
use crate::utils::test_utils::check_container_created;

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
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        TestResult::Passed
    })
}

// SELinux is enabled and its policy knows the label (container-selinux).
fn can_run() -> bool {
    std::fs::write("/sys/fs/selinux/context", MOUNT_LABEL).is_ok()
}

pub fn get_mount_label_test() -> TestGroup {
    let mut tg = TestGroup::new("mount_label");
    tg.add(vec![Box::new(ConditionalTest::new(
        "mqueue_ro_mount_label_test",
        Box::new(can_run),
        Box::new(mqueue_ro_mount_label_test),
    ))]);
    tg
}
