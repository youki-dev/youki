use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use anyhow::{Context, Ok, Result, anyhow};
use oci_spec::runtime::{MountBuilder, ProcessBuilder, Spec, SpecBuilder, get_default_mounts};
use tempfile::TempDir;
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec() -> Result<Spec> {
    let process = ProcessBuilder::default()
        .args(vec!["sleep".to_string(), "3000".to_string()])
        .build()
        .expect("error in creating process config");

    let spec = SpecBuilder::default()
        .process(process)
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn check_create_error(result: TestResult, expected_messages: &[&str]) -> TestResult {
    match result {
        TestResult::Failed(e) => {
            let err_str = format!("{:?}", e);
            if expected_messages.iter().any(|m| err_str.contains(m)) {
                TestResult::Passed
            } else {
                TestResult::Failed(anyhow!(
                    "unexpected error (expected substring not found): {err_str}"
                ))
            }
        }
        TestResult::Skipped(_) => TestResult::Failed(anyhow!("test was skipped unexpectedly.")),
        TestResult::Passed => {
            TestResult::Failed(anyhow!("container creation succeeded unexpectedly."))
        }
    }
}

fn prohibit_symlink_test(path: String) -> TestResult {
    let spec = test_result!(create_spec());
    let result = test_inside_container(&spec, &CreateOptions::default(), &|bundle| {
        let symlink_path = bundle.join(path.clone());
        fs::create_dir_all(&symlink_path)?;

        let link = bundle.join(path.clone());

        // delete existing directory or file
        if link.exists() {
            let md = fs::symlink_metadata(&link)?;
            if md.file_type().is_dir() {
                fs::remove_dir_all(&link)?;
            } else {
                fs::remove_file(&link)?;
            }
        }

        // create symbolic link
        symlink(&symlink_path, &link)?;
        Ok(())
    });

    check_create_error(result, &["must be mounted on ordinary directory"])
}

// Bind mount a host directory on /data, where /data in the rootfs is a symlink to `target`.
// The mount must be checked against the path the symlink resolves to, not /data.
fn prohibit_symlink_bind_test(target: &str, expected_messages: &[&str]) -> TestResult {
    let source = test_result!(TempDir::new().context("failed to create bind source"));

    let mut mounts = get_default_mounts();
    mounts.push(test_result!(
        MountBuilder::default()
            .destination(PathBuf::from("/data"))
            .typ("bind")
            .source(source.path())
            .options(vec!["bind".to_string()])
            .build()
            .context("failed to build bind mount")
    ));

    let process = test_result!(
        ProcessBuilder::default()
            .args(vec!["true".to_string()])
            .build()
            .context("failed to build process")
    );
    let spec = test_result!(
        SpecBuilder::default()
            .process(process)
            .mounts(mounts)
            .build()
            .context("failed to build spec")
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|rootfs| {
        symlink(target, rootfs.join("data"))?;
        Ok(())
    });

    check_create_error(result, expected_messages)
}

fn prohibit_symlink_proc_test() -> TestResult {
    prohibit_symlink_test("proc".to_string())
}

fn prohibit_symlink_sys_test() -> TestResult {
    prohibit_symlink_test("sys".to_string())
}

fn prohibit_symlink_bind_to_proc_test() -> TestResult {
    prohibit_symlink_bind_test(
        "proc",
        &[
            // youki
            "cannot be mounted because it is not type proc",
            // runc
            "cannot be mounted because it is not of type proc",
        ],
    )
}

fn prohibit_symlink_bind_under_proc_test() -> TestResult {
    prohibit_symlink_bind_test(
        "proc/sys",
        &[
            // youki
            "is not a valid mount under /proc",
            // runc
            "cannot be mounted because it is inside /proc",
        ],
    )
}

fn prohibit_symlink_bind_to_rootfs_test() -> TestResult {
    prohibit_symlink_bind_test("/", &["is on the top of rootfs"])
}

pub fn get_prohibit_symlink_test() -> TestGroup {
    let mut prohibit_symlink_test_group = TestGroup::new("prohibit_symlink");

    let prohibit_symlink_proc_test = Test::new(
        "prohibit_symlink_proc_test",
        Box::new(prohibit_symlink_proc_test),
    );
    let prohibit_symlink_sys_test = Test::new(
        "prohibit_symlink_sys_test",
        Box::new(prohibit_symlink_sys_test),
    );
    let prohibit_symlink_bind_to_proc_test = Test::new(
        "prohibit_symlink_bind_to_proc_test",
        Box::new(prohibit_symlink_bind_to_proc_test),
    );
    let prohibit_symlink_bind_under_proc_test = Test::new(
        "prohibit_symlink_bind_under_proc_test",
        Box::new(prohibit_symlink_bind_under_proc_test),
    );
    let prohibit_symlink_bind_to_rootfs_test = Test::new(
        "prohibit_symlink_bind_to_rootfs_test",
        Box::new(prohibit_symlink_bind_to_rootfs_test),
    );
    prohibit_symlink_test_group.add(vec![
        Box::new(prohibit_symlink_proc_test),
        Box::new(prohibit_symlink_sys_test),
        Box::new(prohibit_symlink_bind_to_proc_test),
        Box::new(prohibit_symlink_bind_under_proc_test),
        Box::new(prohibit_symlink_bind_to_rootfs_test),
    ]);

    prohibit_symlink_test_group
}
