use std::fs::{create_dir, remove_dir_all};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Ok, Result, anyhow};
use nix::mount::{MsFlags, mount, umount};
use oci_spec::runtime::{Mount, ProcessBuilder, Spec, SpecBuilder, get_default_mounts};
use tempfile::TempDir;
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

const MOUNT_DEST: &str = "/mnt/mount_propagation";
const SUB_DIR_NAME: &str = "sub";

fn create_spec(source: &Path, propagation: &str) -> Result<Spec> {
    let mut mounts = get_default_mounts();

    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(PathBuf::from_str(MOUNT_DEST).unwrap())
        .set_typ(None)
        .set_source(Some(source.to_path_buf()))
        .set_options(Some(vec!["rbind".to_string(), propagation.to_string()]));
    mounts.push(mount_spec);

    let process = ProcessBuilder::default()
        .args(vec![
            "runtimetest".to_string(),
            "mount_propagation".to_string(),
        ])
        .build()
        .context("failed to build process")?;

    let spec = SpecBuilder::default()
        .mounts(mounts)
        .process(process)
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

// Make mount_dir shared and add a submount so propagation changes are
// observable, including the difference between recursive and non-recursive options.
fn setup_mount(mount_dir: &Path, sub_mount_dir: &Path) -> Result<()> {
    create_dir(mount_dir)?;
    mount::<Path, Path, str, str>(Some(mount_dir), mount_dir, None, MsFlags::MS_BIND, None)?;

    mount::<Path, Path, str, str>(None, mount_dir, None, MsFlags::MS_SHARED, None)?;
    create_dir(sub_mount_dir)?;
    mount::<Path, Path, str, str>(None, sub_mount_dir, Some("tmpfs"), MsFlags::empty(), None)?;
    Ok(())
}

fn clean_mount(mount_dir: &Path, sub_mount_dir: &Path) -> Result<()> {
    umount(sub_mount_dir)?;
    umount(mount_dir)?;
    remove_dir_all(mount_dir)?;
    Ok(())
}

fn check_propagation(propagation: &str) -> TestResult {
    let base_dir = TempDir::new().unwrap();
    let dir_path = base_dir.path().join("mount_dir");
    let sub_path = dir_path.join(SUB_DIR_NAME);

    let spec = test_result!(create_spec(&dir_path, propagation));

    let result = test_inside_container(&spec, &CreateOptions::default(), &|_rootfs| {
        setup_mount(&dir_path, &sub_path).map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        Ok(())
    });

    if let Err(e) = clean_mount(&dir_path, &sub_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_dir={}): {e:?}",
            dir_path.display(),
            sub_path.display(),
        );
    }

    result
}

fn shared_test() -> TestResult {
    check_propagation("shared")
}

fn rshared_test() -> TestResult {
    check_propagation("rshared")
}

fn rslave_test() -> TestResult {
    check_propagation("rslave")
}

fn private_test() -> TestResult {
    check_propagation("private")
}

fn rprivate_test() -> TestResult {
    check_propagation("rprivate")
}

fn unbindable_test() -> TestResult {
    check_propagation("unbindable")
}

fn runbindable_test() -> TestResult {
    check_propagation("runbindable")
}

pub fn get_mount_propagation_test() -> TestGroup {
    let mut test_group = TestGroup::new("mount_propagation");

    let shared_test = Test::new("mount_propagation_shared_test", Box::new(shared_test));
    let rshared_test = Test::new("mount_propagation_rshared_test", Box::new(rshared_test));
    let rslave_test = Test::new("mount_propagation_rslave_test", Box::new(rslave_test));
    let private_test = Test::new("mount_propagation_private_test", Box::new(private_test));
    let rprivate_test = Test::new("mount_propagation_rprivate_test", Box::new(rprivate_test));
    let unbindable_test = Test::new(
        "mount_propagation_unbindable_test",
        Box::new(unbindable_test),
    );
    let runbindable_test = Test::new(
        "mount_propagation_runbindable_test",
        Box::new(runbindable_test),
    );

    test_group.add(vec![
        Box::new(shared_test),
        Box::new(rshared_test),
        Box::new(rslave_test),
        Box::new(private_test),
        Box::new(rprivate_test),
        Box::new(unbindable_test),
        Box::new(runbindable_test),
    ]);

    test_group
}
