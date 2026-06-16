use std::path::Path;

use anyhow::{Context, Ok, Result};
use nix::mount::MsFlags;
use oci_spec::runtime::{ProcessBuilder, RootBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec(readonly: bool) -> Result<Spec> {
    let spec = SpecBuilder::default()
        .root(RootBuilder::default().readonly(readonly).build().unwrap())
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "root_readonly".to_string()])
                .build()
                .expect("error in creating config"),
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn root_readonly_true_test() -> TestResult {
    let spec_true = test_result!(create_spec(true));
    test_inside_container(&spec_true, &CreateOptions::default(), &|_| Ok(()))
}

fn root_readonly_true_in_userns_test() -> TestResult {
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let mut spec = Spec::rootless(uid, gid);
    spec.set_root(RootBuilder::default().readonly(true).build().ok())
        .set_process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "root_readonly".to_string()])
                .build()
                .ok(),
        );
    test_inside_container(&spec, &CreateOptions::default(), &|rootfs: &Path| {
        // Bind-mount the rootfs onto itself with MS_NODEV | MS_NOSUID, simulating a
        // filesystem that has those flags locked (the typical case in user namespaces).
        // Without the fix for #3517, the subsequent readonly remount would fail with
        // EPERM because the kernel rejects dropping these flags in a user namespace.
        nix::mount::mount(
            Some(rootfs),
            rootfs,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;
        nix::mount::mount(
            Some(rootfs),
            rootfs,
            None::<&str>,
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
            None::<&str>,
        )?;
        Ok(())
    })
}

fn root_readonly_false_test() -> TestResult {
    let spec_false = test_result!(create_spec(false));
    test_inside_container(&spec_false, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_root_readonly_test() -> TestGroup {
    let mut root_readonly_test_group = TestGroup::new("root_readonly");

    let test_true = Test::new("root_readonly_true_test", Box::new(root_readonly_true_test));
    let test_true_in_userns = Test::new(
        "root_readonly_true_in_userns_test",
        Box::new(root_readonly_true_in_userns_test),
    );
    let test_false = Test::new(
        "root_readonly_false_test",
        Box::new(root_readonly_false_test),
    );
    root_readonly_test_group.add(vec![
        Box::new(test_true),
        Box::new(test_true_in_userns),
        Box::new(test_false),
    ]);

    root_readonly_test_group
}
