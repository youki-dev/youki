use std::fs;
use std::os::unix::fs::symlink;

use anyhow::{Context, Ok, Result, anyhow};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
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

    match result {
        TestResult::Failed(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("must be mounted on ordinary directory") {
                TestResult::Passed
            } else {
                TestResult::Failed(anyhow!(
                    "unexpected error (expected substring not found): {err_str}"
                ))
            }
        }
        TestResult::Skipped => TestResult::Failed(anyhow!("test was skipped unexpectedly.")),
        TestResult::Passed => {
            TestResult::Failed(anyhow!("container creation succeeded unexpectedly."))
        }
    }
}

fn prohibit_symlink_proc_test() -> TestResult {
    prohibit_symlink_test("proc".to_string())
}

fn prohibit_symlink_sys_test() -> TestResult {
    prohibit_symlink_test("sys".to_string())
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
    prohibit_symlink_test_group.add(vec![
        Box::new(prohibit_symlink_proc_test),
        Box::new(prohibit_symlink_sys_test),
    ]);

    prohibit_symlink_test_group
}
