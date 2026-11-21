use std::path::Path;

use anyhow::{Context, Result, ensure};
use oci_spec::runtime::{MountBuilder, ProcessBuilder, Spec, SpecBuilder, get_default_mounts};
use procfs::process::Process;
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_utils::{ContainerData, check_container_created, test_outside_container};

const MOUNT_POINT: &str = "/sync-test";

fn create_spec(options: &[&str]) -> Result<Spec> {
    let mut mounts = get_default_mounts();
    mounts.push(
        MountBuilder::default()
            .destination(MOUNT_POINT)
            .typ("tmpfs")
            .source("tmpfs")
            .options(
                options
                    .iter()
                    .map(|option| option.to_string())
                    .collect::<Vec<_>>(),
            )
            .build()?,
    );
    Ok(SpecBuilder::default()
        .mounts(mounts)
        .process(
            ProcessBuilder::default()
                .args(vec!["true".to_owned()])
                .build()?,
        )
        .build()?)
}

fn check_mount_flags(data: &ContainerData, expected_flags: &[&str]) -> Result<()> {
    check_container_created(data)?;
    let pid = data
        .state
        .as_ref()
        .and_then(|state| state.pid)
        .context("missing container PID")?;
    let mount = Process::new(pid)?
        .mountinfo()?
        .into_iter()
        .find(|mount| mount.mount_point == Path::new(MOUNT_POINT) && mount.fs_type == "tmpfs")
        .context("missing tmpfs mount in container mountinfo")?;

    for flag in ["sync", "dirsync"] {
        let expected = expected_flags.contains(&flag);
        ensure!(
            mount.super_options.contains_key(flag) == expected,
            "expected {MOUNT_POINT} superblock option {flag} present: {expected}"
        );
    }
    Ok(())
}

pub fn get_mount_sync_flags_test() -> TestGroup {
    let cases: [(&str, &[&str], &[&str]); 7] = [
        ("default_async", &[], &[]),
        ("sync", &["sync"], &["sync"]),
        ("dirsync", &["dirsync"], &["dirsync"]),
        (
            "sync_and_dirsync",
            &["sync", "dirsync"],
            &["sync", "dirsync"],
        ),
        ("async_clears_sync", &["sync", "async"], &[]),
        ("sync_after_async", &["async", "sync"], &["sync"]),
        (
            "async_preserves_dirsync",
            &["sync", "dirsync", "async"],
            &["dirsync"],
        ),
    ];
    let mut group = TestGroup::new("mount_sync_flags");
    for (name, options, expected_flags) in cases {
        group.add(vec![Box::new(Test::new(
            name,
            Box::new(move || {
                let spec = test_result!(create_spec(options));
                test_outside_container(&spec, &|data| {
                    test_result!(check_mount_flags(&data, expected_flags));
                    TestResult::Passed
                })
            }),
        ))]);
    }
    group
}
