use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result};
use oci_spec::runtime::{MountBuilder, ProcessBuilder, Spec, SpecBuilder, get_default_mounts};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

const TMPFS: &str = "/tmpfs";
/// Carries the expected tmpfs mode to runtimetest, since it only has access to the spec
/// and cannot know the mode of the destination directory before the tmpfs is mounted.
const EXPECTED_MODE_ANNOTATION: &str = "org.youki.contest.tmpfs";

fn create_spec(options: &[&str], expected_mode: u32) -> Result<Spec> {
    let mut mounts = get_default_mounts();
    mounts.push(
        MountBuilder::default()
            .destination(TMPFS)
            .typ("tmpfs")
            .source("tmpfs")
            .options(options.iter().map(|o| o.to_string()).collect::<Vec<_>>())
            .build()
            .context("failed to build tmpfs mount")?,
    );

    SpecBuilder::default()
        .mounts(mounts)
        .annotations(HashMap::from([(
            EXPECTED_MODE_ANNOTATION.to_string(),
            format!("{expected_mode:o}"),
        )]))
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "tmpfs".to_string()])
                .build()
                .context("failed to build process")?,
        )
        .build()
        .context("failed to build spec")
}

fn check_tmpfs_mode(
    options: &[&str],
    existing_dir_mode: Option<u32>,
    expected_mode: u32,
) -> TestResult {
    let spec = test_result!(create_spec(options, expected_mode));
    test_inside_container(&spec, &CreateOptions::default(), &|rootfs| {
        let Some(mode) = existing_dir_mode else {
            return Ok(());
        };
        let dir = rootfs.join(TMPFS.trim_start_matches('/'));
        fs::create_dir(&dir).with_context(|| format!("failed to create {dir:?}"))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(mode))
            .with_context(|| format!("failed to chmod {dir:?} to {mode:o}"))
    })
}

// Without an explicit mode option, all permission bits of an existing directory are inherited,
// including setuid, setgid, and sticky bits (like runc's "runc run with tmpfs" test).
fn mode_inherit_all_bits_test() -> TestResult {
    check_tmpfs_mode(&["noexec", "nosuid", "nodev"], Some(0o7777), 0o7777)
}

// The following cases are those of runc's "runc run with tmpfs perms" test.

// Without an explicit mode option, an existing directory's mode is inherited.
fn mode_inherit_test() -> TestResult {
    check_tmpfs_mode(&[], Some(0o710), 0o710)
}

// An explicit mode option takes precedence over the existing directory's mode.
fn mode_option_overrides_existing_test() -> TestResult {
    check_tmpfs_mode(&["mode=0410"], Some(0o710), 0o410)
}

// When the destination does not already exist, the explicit mode option is used.
fn mode_option_on_new_dir_test() -> TestResult {
    check_tmpfs_mode(&["mode=0444"], None, 0o444)
}

pub fn get_tmpfs_test() -> TestGroup {
    let mut tg = TestGroup::new("tmpfs");
    tg.add(vec![
        Box::new(Test::new(
            "mode_inherit_all_bits_test",
            Box::new(mode_inherit_all_bits_test),
        )),
        Box::new(Test::new("mode_inherit_test", Box::new(mode_inherit_test))),
        Box::new(Test::new(
            "mode_option_overrides_existing_test",
            Box::new(mode_option_overrides_existing_test),
        )),
        Box::new(Test::new(
            "mode_option_on_new_dir_test",
            Box::new(mode_option_on_new_dir_test),
        )),
    ]);
    tg
}
