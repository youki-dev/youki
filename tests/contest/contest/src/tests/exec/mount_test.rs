use anyhow::anyhow;
use oci_spec::runtime::ProcessBuilder;
use test_framework::{TestResult, test_result};

use crate::utils::test_utils::{
    check_container_created, exec_container, start_container, test_outside_container,
};

// https://github.com/youki-dev/youki/issues/3431
// In the issue above, we found that `exec` into a container could add duplicate mounts
// due to `maskedPaths` and `readonlyPaths`. This is a regression test to ensure those mounts are not re-applied on `exec`.
pub(crate) fn get_mount_test() -> TestResult {
    let spec = test_result!(super::create_spec(Some(ProcessBuilder::default())));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) =
            exec_container(id, dir, &["cat", "/proc/self/mountinfo"], None).expect("exec failed");

        let rootfs_lines: Vec<&str> = stdout
            .lines()
            .filter(|l| l.split_whitespace().nth(4) == Some("/"))
            .collect();

        // rootfs readonly test
        let rootfs_is_ro = rootfs_lines.iter().any(|l| {
            l.split_whitespace()
                .nth(5) // mount options
                .is_some_and(|opts| opts.split(',').any(|o| o == "ro"))
        });

        // maskedPaths test
        // /proc/acpi is default maskedPath
        let count_proc_acpi = stdout
            .lines()
            .filter(|l| l.split_whitespace().nth(4) == Some("/proc/acpi"))
            .count();

        // readonlyPaths test
        // /proc/bus is default maskedPath
        let count_proc_bus = stdout
            .lines()
            .filter(|l| l.split_whitespace().nth(4) == Some("/proc/bus"))
            .count();

        if !rootfs_is_ro {
            return TestResult::Failed(anyhow!(
                "expected root (/) to be mounted read-only; root mountinfo lines:{}",
                rootfs_lines.join("\n")
            ));
        }

        if count_proc_acpi != 1 {
            return TestResult::Failed(anyhow!(
                "expected exactly 1 mountinfo entry for /proc/acpi, got {}",
                count_proc_acpi
            ));
        }
        if count_proc_bus != 1 {
            return TestResult::Failed(anyhow!(
                "expected exactly 1 mountinfo entry for /proc/bus: {}",
                count_proc_bus
            ));
        }

        TestResult::Passed
    })
}
