use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Ok, Result};
use oci_spec::runtime::{MountBuilder, ProcessBuilder, Spec, SpecBuilder, get_default_mounts};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec(options: &[&str]) -> Result<Spec> {
    let mut mounts = get_default_mounts();
    mounts.push(
        MountBuilder::default()
            .destination("/dir1")
            .typ("tmpfs")
            .source("tmpfs")
            .options(options.iter().map(|o| o.to_string()).collect::<Vec<_>>())
            .build()
            .context("failed to build tmpfs mount")?,
    );

    SpecBuilder::default()
        .mounts(mounts)
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "tmpcopyup".to_string()])
                .build()
                .context("failed to build process")?,
        )
        .build()
        .context("failed to build spec")
}

// The tmpfs on /dir1 must start with /dir1/dir2 of the image, with its mode
// (like runc's "runc run [tmpcopyup]" test).
fn setup_rootfs(rootfs: &Path) -> Result<()> {
    let dir = rootfs.join("dir1/dir2");
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777))?;
    Ok(())
}

fn tmpcopyup_test() -> TestResult {
    let spec = test_result!(create_spec(&["tmpcopyup"]));
    test_inside_container(&spec, &CreateOptions::default(), &setup_rootfs)
}

fn tmpcopyup_ro_test() -> TestResult {
    let spec = test_result!(create_spec(&["tmpcopyup", "ro"]));
    test_inside_container(&spec, &CreateOptions::default(), &setup_rootfs)
}

pub fn get_tmpcopyup_test() -> TestGroup {
    let mut tg = TestGroup::new("tmpcopyup");
    tg.add(vec![
        Box::new(Test::new("tmpcopyup_test", Box::new(tmpcopyup_test))),
        Box::new(Test::new("tmpcopyup_ro_test", Box::new(tmpcopyup_ro_test))),
    ]);
    tg
}
