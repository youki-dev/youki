mod common;

use std::fs;
use std::path::Path;

use anyhow::Context;
use nix::sys::statfs::{CGROUP2_SUPER_MAGIC, statfs};
use test_framework::{ConditionalTest, TestGroup};

use crate::utils::is_runtime_youki;

pub(super) fn is_cgroup_v2() -> bool {
    statfs("/sys/fs/cgroup")
        .map(|stat| stat.filesystem_type() == CGROUP2_SUPER_MAGIC)
        .unwrap_or(false)
}

pub(super) fn check_cgroup_value(base: &Path, file: &str, expected: &str) -> anyhow::Result<()> {
    let path = base.join(file);
    let got =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let got = got.trim();

    if got != expected {
        anyhow::bail!("{}: expected {}, got {}", path.display(), expected, got);
    }
    Ok(())
}

// youki update only supports --pids-limit and --resources (JSON) via CLI.
// other flags (--memory, --cpuset-cpus, etc.) are not implemented yet.
// https://github.com/youki-dev/youki/blob/b55b14491ebddf66a29d109d0270b450e020fa32/crates/youki/src/commands/update.rs#L26
// TODO: remove is_runtime_runc() condition when youki supports full update CLI & support test for cgroup_v1
fn can_run() -> bool {
    !is_runtime_youki() && is_cgroup_v2()
}

pub fn get_update_test() -> TestGroup {
    let mut test_group = TestGroup::new("update");

    let update_cgroup_v2_common_limits_test = ConditionalTest::new(
        "update_cgroup_v2_common_limits_test",
        Box::new(can_run),
        Box::new(common::update_common_limits_test),
    );

    test_group.add(vec![Box::new(update_cgroup_v2_common_limits_test)]);
    test_group
}
