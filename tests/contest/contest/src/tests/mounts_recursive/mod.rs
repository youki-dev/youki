use std::collections::hash_set::HashSet;
use std::fs;
use std::fs::File;
use std::os::unix::fs::symlink;
use std::os::unix::prelude::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::anyhow;
use nix::mount::{MsFlags, mount, umount};
use nix::sys::stat::{Mode, SFlag, makedev, mknod};
use nix::unistd::{Uid, chown};
use oci_spec::runtime::{
    Capability, LinuxBuilder, LinuxCapabilitiesBuilder, Mount, ProcessBuilder, Spec, SpecBuilder,
    get_default_mounts,
};
use tempfile::TempDir;
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn get_spec(added_mounts: Vec<Mount>, process_args: Vec<String>) -> Spec {
    let mut mounts = get_default_mounts();
    for mount in added_mounts {
        mounts.push(mount);
    }

    let caps = vec![
        Capability::Chown,
        Capability::DacOverride,
        Capability::Fsetid,
        Capability::Fowner,
        Capability::Mknod,
        Capability::NetRaw,
        Capability::Setgid,
        Capability::Setuid,
        Capability::Setfcap,
        Capability::Setpcap,
        Capability::NetBindService,
        Capability::SysChroot,
        Capability::Kill,
        Capability::AuditWrite,
    ];
    let mut cap_bounding = HashSet::new();
    let mut cap_effective = HashSet::new();
    let mut cap_permitted = HashSet::new();

    for cap in caps {
        cap_bounding.insert(cap);
        cap_effective.insert(cap);
        cap_permitted.insert(cap);
    }

    SpecBuilder::default()
        .mounts(mounts)
        .linux(
            // Need to reset the read-only paths
            LinuxBuilder::default()
                .readonly_paths(vec![])
                .build()
                .expect("error in building linux config"),
        )
        .process(
            ProcessBuilder::default()
                .args(process_args)
                .capabilities(
                    LinuxCapabilitiesBuilder::default()
                        .bounding(cap_bounding)
                        .effective(cap_effective)
                        .permitted(cap_permitted)
                        .build()
                        .unwrap(),
                )
                .rlimits(vec![])
                .no_new_privileges(false)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

fn setup_mount(mount_dir: &Path, sub_mount_dir: &Path) -> anyhow::Result<()> {
    fs::create_dir(mount_dir)?;
    mount::<Path, Path, str, str>(None, mount_dir, Some("tmpfs"), MsFlags::empty(), None)?;
    fs::create_dir(sub_mount_dir)?;
    mount::<Path, Path, str, str>(None, sub_mount_dir, Some("tmpfs"), MsFlags::empty(), None)?;
    Ok(())
}

fn setup_remount(mount_dir: &Path, sub_mount_dir: &Path, flag: MsFlags) -> anyhow::Result<()> {
    mount::<Path, Path, str, str>(None, mount_dir, None, MsFlags::MS_REMOUNT | flag, None)?;
    mount::<Path, Path, str, str>(None, sub_mount_dir, None, MsFlags::MS_REMOUNT | flag, None)?;
    Ok(())
}

fn clean_mount(mount_dir: &Path, sub_mount_dir: &Path) -> anyhow::Result<()> {
    umount(sub_mount_dir)?;
    umount(mount_dir)?;
    fs::remove_dir_all(mount_dir)?;
    Ok(())
}

// Mount Recursive test
// Host:
//   - <tmp>/<test>_dir is a mount point (tmpfs)
//   - <tmp>/<test>_dir/<test>_subdir is a submount (tmpfs)
//
// rbind:
//   - Bind-mount <tmp>/<test>_dir into the container at /mnt (rbind)
//
// In the container, we should observe:
//   - mount at /mnt
//   - submount at /mnt/<test>_subdir
//
// Key check: the mount options/attributes must be applied to SUBMOUNTS.

// rro_test
// rro makes both /mnt and /mnt/rro_subdir read-only (including submounts).
fn check_recursive_readonly() -> TestResult {
    let rro_test_base_dir = TempDir::new().unwrap();
    let rro_dir_path = rro_test_base_dir.path().join("rro_dir");
    let rro_subdir_path = rro_dir_path.join("rro_subdir");
    let mount_dest_path = PathBuf::from_str("/mnt").unwrap();

    let mount_options = vec!["rbind".to_string(), "rro".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rro_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rro_dir_path, &rro_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        std::fs::write(rro_subdir_path.join("bar"), b"bar\n").unwrap();
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rro_dir_path, &rro_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rro_dir_path.display(),
            rro_subdir_path.display(),
        );
    };

    result
}

// rnosuid_test
fn check_recursive_nosuid() -> TestResult {
    let rnosuid_test_base_dir = TempDir::new().unwrap();
    let rnosuid_dir_path = rnosuid_test_base_dir.path().join("rnosuid_dir");
    let rnosuid_subdir_path = rnosuid_dir_path.join("rnosuid_subdir");
    let mount_dest_path = PathBuf::from_str("/mnt").unwrap();
    let executable_file_name = "whoami";

    let mount_options = vec!["rbind".to_string(), "rnosuid".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path.clone())
        .set_typ(None)
        .set_source(Some(rnosuid_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "{}; {}",
                mount_dest_path.join(executable_file_name).to_str().unwrap(),
                mount_dest_path
                    .join("rnosuid_subdir/whoami")
                    .to_str()
                    .unwrap()
            ),
        ],
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|bundle_path| {
        setup_mount(&rnosuid_dir_path, &rnosuid_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;

        let executable_file_path = bundle_path.join("bin").join(executable_file_name);
        let in_container_executable_file_path = rnosuid_dir_path.join(executable_file_name);
        let in_container_executable_subdir_file_path =
            rnosuid_subdir_path.join(executable_file_name);

        fs::copy(&executable_file_path, &in_container_executable_file_path)?;
        fs::copy(
            &executable_file_path,
            &in_container_executable_subdir_file_path,
        )?;

        let in_container_executable_file = fs::File::open(&in_container_executable_file_path)?;
        let in_container_executable_subdir_file =
            fs::File::open(&in_container_executable_subdir_file_path)?;

        let mut in_container_executable_file_perm =
            in_container_executable_file.metadata()?.permissions();
        let mut in_container_executable_subdir_file_perm = in_container_executable_subdir_file
            .metadata()?
            .permissions();

        // Change file user to nonexistent uid and set suid.
        // if rnosuid is applied, whoami command is executed as root.
        // but if not adapted, whoami command is executed as uid 1200 and make an error.
        chown(
            &in_container_executable_file_path,
            Some(Uid::from_raw(1200)),
            None,
        )
        .unwrap();
        chown(
            &in_container_executable_subdir_file_path,
            Some(Uid::from_raw(1200)),
            None,
        )
        .unwrap();
        in_container_executable_file_perm
            .set_mode(in_container_executable_file_perm.mode() | Mode::S_ISUID.bits());
        in_container_executable_subdir_file_perm
            .set_mode(in_container_executable_subdir_file_perm.mode() | Mode::S_ISUID.bits());

        in_container_executable_file.set_permissions(in_container_executable_file_perm.clone())?;
        in_container_executable_subdir_file
            .set_permissions(in_container_executable_subdir_file_perm.clone())?;

        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rnosuid_dir_path, &rnosuid_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rnosuid_dir_path.display(),
            rnosuid_subdir_path.display(),
        );
    };

    result
}

// rsuid_test
// Mounting with 'rsuid' honors SUID bits on this mount (i.e., SUID can take effect).
// Note: The bits remain set in the inode (e.g., ls -l still shows 's').
fn check_recursive_rsuid() -> TestResult {
    let rsuid_base_dir_path = TempDir::new().unwrap();
    let rsuid_dir_path = rsuid_base_dir_path.path().join("rsuid_dir");
    let rsuid_subdir_path = rsuid_dir_path.join("rsuid_subdir");

    let mount_dest_path = PathBuf::from_str("/mnt").unwrap();
    let executable_file_name = "whoami";

    let mount_options = vec!["rbind".to_string(), "rsuid".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path.clone())
        .set_typ(None)
        .set_source(Some(rsuid_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "{}; {}",
                mount_dest_path.join(executable_file_name).to_str().unwrap(),
                mount_dest_path
                    .join("rsuid_subdir/whoami")
                    .to_str()
                    .unwrap()
            ),
        ],
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|bundle_path| {
        setup_mount(&rsuid_dir_path, &rsuid_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;

        let executable_file_path = bundle_path.join("bin").join(executable_file_name);
        let in_container_executable_file_path = rsuid_dir_path.join(executable_file_name);
        let in_container_executable_subdir_file_path = rsuid_subdir_path.join(executable_file_name);
        fs::copy(&executable_file_path, &in_container_executable_file_path)?;
        fs::copy(
            &executable_file_path,
            &in_container_executable_subdir_file_path,
        )?;

        let in_container_executable_file = fs::File::open(&in_container_executable_file_path)?;
        let in_container_executable_subdir_file =
            fs::File::open(&in_container_executable_subdir_file_path)?;
        let mut in_container_executable_file_perm =
            in_container_executable_file.metadata()?.permissions();
        let mut in_container_executable_subdir_file_perm = in_container_executable_subdir_file
            .metadata()?
            .permissions();

        // Change file user to nonexistent uid and set suid.
        // if rsuid is applied, whoami command is executed as 1200 and make an error.
        chown(
            &in_container_executable_file_path,
            Some(Uid::from_raw(1200)),
            None,
        )
        .unwrap();
        chown(
            &in_container_executable_subdir_file_path,
            Some(Uid::from_raw(1200)),
            None,
        )
        .unwrap();
        in_container_executable_file_perm
            .set_mode(in_container_executable_file_perm.mode() | Mode::S_ISUID.bits());
        in_container_executable_subdir_file_perm
            .set_mode(in_container_executable_subdir_file_perm.mode() | Mode::S_ISUID.bits());

        in_container_executable_file.set_permissions(in_container_executable_file_perm.clone())?;
        in_container_executable_subdir_file
            .set_permissions(in_container_executable_subdir_file_perm.clone())?;
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rsuid_dir_path, &rsuid_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rsuid_dir_path.display(),
            rsuid_subdir_path.display(),
        );
    };

    match result {
        TestResult::Failed(e) => {
            let msg = e.to_string();
            // This error message may vary depending on the environment.
            if msg.contains("whoami: unknown uid 1200") {
                TestResult::Passed
            } else {
                TestResult::Failed(anyhow!(
                    "whoami failed, but not with expected message. error: {}",
                    msg
                ))
            }
        }
        // TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!(
            "Expected execute a non-existent user to fail, but it succeeded"
        )),
        _ => TestResult::Failed(anyhow!("Unexpected test result")),
    }
}

// rnoexec_test
fn check_recursive_noexec() -> TestResult {
    let rnoexec_test_base_dir = TempDir::new().unwrap();
    let rnoexec_dir_path = rnoexec_test_base_dir.path().join("rnoexec_dir");
    let rnoexec_subdir_path = rnoexec_dir_path.join("rnoexec_subdir");
    let mount_dest_path = PathBuf::from_str("/mnt").unwrap();

    let mount_options = vec!["rbind".to_string(), "rnoexec".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rnoexec_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|bundle_path| {
        setup_mount(&rnoexec_dir_path, &rnoexec_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;

        let executable_file_name = "echo";
        let executable_file_path = bundle_path.join("bin").join(executable_file_name);
        let in_container_executable_file_path = rnoexec_dir_path.join(executable_file_name);
        let in_container_executable_subdir_file_path =
            rnoexec_subdir_path.join(executable_file_name);

        fs::copy(&executable_file_path, in_container_executable_file_path)?;
        fs::copy(
            &executable_file_path,
            in_container_executable_subdir_file_path,
        )?;

        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rnoexec_dir_path, &rnoexec_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rnoexec_dir_path.display(),
            rnoexec_subdir_path.display(),
        );
    };

    result
}

// rexec_test
fn check_recursive_rexec() -> TestResult {
    let rnoexec_test_base_dir = TempDir::new().unwrap();
    let rnoexec_dir_path = rnoexec_test_base_dir.path().join("rexec_dir");
    let rnoexec_subdir_path = rnoexec_dir_path.join("rexec_subdir");
    let mount_dest_path = PathBuf::from_str("/mnt").unwrap();

    let mount_options = vec!["rbind".to_string(), "rexec".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rnoexec_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|bundle_path| {
        setup_mount(&rnoexec_dir_path, &rnoexec_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;

        let executable_file_name = "echo";
        let executable_file_path = bundle_path.join("bin").join(executable_file_name);
        let in_container_executable_file_path = rnoexec_dir_path.join(executable_file_name);
        let in_container_executable_subdir_file_path =
            rnoexec_subdir_path.join(executable_file_name);

        fs::copy(&executable_file_path, in_container_executable_file_path)?;
        fs::copy(
            &executable_file_path,
            in_container_executable_subdir_file_path,
        )?;

        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rnoexec_dir_path, &rnoexec_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rnoexec_dir_path.display(),
            rnoexec_subdir_path.display(),
        );
    };

    result
}

// rdiratime_test
// rdiratime If set in attr_clr, removes the restriction that prevented updating access time for directories.
fn check_recursive_rdiratime() -> TestResult {
    let rdiratime_base_dir = TempDir::new().unwrap();
    let rdiratime_dir = rdiratime_base_dir.path().join("rdiratime");
    let rdiratime_subdir = rdiratime_dir.join("rdiratime_subdir");
    let mount_dest_path = PathBuf::from_str("/rdiratime").unwrap();

    let mount_options = vec!["rbind".to_string(), "rdiratime".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rdiratime_dir.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rdiratime_dir, &rdiratime_subdir)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rdiratime_dir, &rdiratime_subdir) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rdiratime_dir.display(),
            rdiratime_subdir.display(),
        );
    };

    result
}

// rnodiratime_test
// If set in attr_set, prevents updating access time for directories on this mount
fn check_recursive_rnodiratime() -> TestResult {
    let rdiratime_base_dir = TempDir::new().unwrap();
    let rnodiratime_dir = rdiratime_base_dir.path().join("rnodiratime_dir");
    let rnodiratime_subdir = rnodiratime_dir.join("rnodiratime_subdir");
    let mount_dest_path = PathBuf::from_str("/rnodiratime_dir").unwrap();

    let mount_options = vec!["rbind".to_string(), "rnodiratime".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rnodiratime_dir.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rnodiratime_dir, &rnodiratime_subdir)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rnodiratime_dir, &rnodiratime_subdir) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rnodiratime_dir.display(),
            rnodiratime_subdir.display(),
        );
    };

    result
}

// rdev_test
fn check_recursive_rdev() -> TestResult {
    let rdev_base_dir = TempDir::new().unwrap();
    let rdev_dir_path = rdev_base_dir.path().join("rdev");
    let rdev_subdir_path = rdev_dir_path.join("rdev_subdir");
    let mount_dest_path = PathBuf::from_str("/rdev").unwrap();

    let mount_options = vec!["rbind".to_string(), "rdev".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rdev_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rdev_dir_path, &rdev_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        let dev = makedev(1, 3);
        mknod(
            &rdev_subdir_path.join("null"),
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o666),
            dev,
        )
        .expect("create null device");
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rdev_dir_path, &rdev_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rdev_dir_path.display(),
            rdev_subdir_path.display(),
        );
    };

    result
}

// rnodev_test
// rnodev disables device-node interpretation recursively; opening /rnodev/rnodev_subdir/null should fail.
fn check_recursive_rnodev() -> TestResult {
    let rnodev_base_dir = TempDir::new().unwrap();
    let rnodev_dir_path = rnodev_base_dir.path().join("rnodev");
    let rnodev_subdir_path = rnodev_dir_path.join("rnodev_subdir");
    let mount_dest_path = PathBuf::from_str("/rnodev").unwrap();

    let mount_options = vec!["rbind".to_string(), "rnodev".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rnodev_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rnodev_dir_path, &rnodev_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        let dev = makedev(1, 3);
        mknod(
            &rnodev_subdir_path.join("null"),
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o666),
            dev,
        )
        .expect("create null device");
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rnodev_dir_path, &rnodev_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rnodev_dir_path.display(),
            rnodev_subdir_path.display(),
        );
    };

    result
}

// rrw_test
fn check_recursive_readwrite() -> TestResult {
    let rrw_test_base_dir = TempDir::new().unwrap();
    let rrw_dir_path = rrw_test_base_dir.path().join("rrw_dir");
    let rrw_subdir_path = rrw_dir_path.join("rrw_subdir");
    let mount_dest_path = PathBuf::from_str("/rrw").unwrap();

    let mount_options = vec!["rbind".to_string(), "rrw".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rrw_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rrw_dir_path, &rrw_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        std::fs::write(rrw_subdir_path.join("bar"), b"bar\n").unwrap();
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rrw_dir_path, &rrw_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rrw_dir_path.display(),
            rrw_subdir_path.display(),
        );
    };

    result
}

// rrelatime_test
fn check_recursive_rrelatime() -> TestResult {
    let rrelatime_base_dir = TempDir::new().unwrap();
    let rrelatime_dir_path = rrelatime_base_dir.path().join("rrelatime_dir");
    let rrelatime_subdir_path = rrelatime_dir_path.join("rrelatime_subdir");
    let mount_dest_path = PathBuf::from_str("/rrelatime_dir").unwrap();

    let mount_options = vec!["rbind".to_string(), "rrelatime".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rrelatime_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rrelatime_dir_path, &rrelatime_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        setup_remount(
            &rrelatime_dir_path,
            &rrelatime_subdir_path,
            MsFlags::MS_STRICTATIME,
        )
        .map_err(|e| anyhow!("setup_remount failed: {e:?}"))?;
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rrelatime_dir_path, &rrelatime_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rrelatime_dir_path.display(),
            rrelatime_subdir_path.display(),
        );
    };
    result
}

// rnorelatime_test
fn check_recursive_rnorelatime() -> TestResult {
    let rnorelatime_base_dir = TempDir::new().unwrap();
    let rnorelatime_dir_path = rnorelatime_base_dir.path().join("rnorelatime_dir");
    let rnorelatime_subdir_path = rnorelatime_dir_path.join("rnorelatime_subdir");
    let mount_dest_path = PathBuf::from_str("/rnorelatime_dir").unwrap();

    let mount_options = vec!["rbind".to_string(), "rnorelatime".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rnorelatime_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    // The container implementation treats `norelatime` as clearing the `relatime` flag.
    // In this test, the mount is configured with `strictatime`, so once `relatime` is cleared, the mount ends up using `strictatime`.
    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rnorelatime_dir_path, &rnorelatime_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        setup_remount(
            &rnorelatime_dir_path,
            &rnorelatime_subdir_path,
            MsFlags::MS_STRICTATIME,
        )
        .map_err(|e| anyhow!("setup_remount failed: {e:?}"))?;
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rnorelatime_dir_path, &rnorelatime_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rnorelatime_dir_path.display(),
            rnorelatime_subdir_path.display(),
        );
    };
    result
}

// rnoatime_test
fn check_recursive_rnoatime() -> TestResult {
    let rnoatime_base_dir = TempDir::new().unwrap();
    let rnoatime_dir_path = rnoatime_base_dir.path().join("rnoatime_dir");
    let rnoatime_subdir_path = rnoatime_dir_path.join("rnoatime_subdir");
    let mount_dest_path = PathBuf::from_str("/rnoatime_dir").unwrap();

    let mount_options = vec!["rbind".to_string(), "rnoatime".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rnoatime_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rnoatime_dir_path, &rnoatime_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rnoatime_dir_path, &rnoatime_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rnoatime_dir_path.display(),
            rnoatime_subdir_path.display(),
        );
    };
    result
}

// rstrictatime_test
fn check_recursive_rstrictatime() -> TestResult {
    let rstrictatime_base_dir = TempDir::new().unwrap();
    let rstrictatime_dir_path = rstrictatime_base_dir.path().join("rstrictatime_dir");
    let rstrictatime_subdir_path = rstrictatime_dir_path.join("rstrictatime_subdir");
    let mount_dest_path = PathBuf::from_str("/rstrictatime").unwrap();

    let mount_options = vec!["rbind".to_string(), "rstrictatime".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rstrictatime_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );
    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rstrictatime_dir_path, &rstrictatime_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rstrictatime_dir_path, &rstrictatime_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rstrictatime_dir_path.display(),
            rstrictatime_subdir_path.display(),
        );
    };
    result
}

// rnosymfollow_test
fn check_recursive_rnosymfollow() -> TestResult {
    let rnosymfollow_base_path = TempDir::new().unwrap();
    let rnosymfollow_dir_path = rnosymfollow_base_path.path().join("rnosymfollow_dir");
    let rnosymfollow_subdir_path = rnosymfollow_dir_path.join("rnosymfollow_subdir");
    let mount_dest_path = PathBuf::from_str("/mnt").unwrap();

    let mount_options = vec!["rbind".to_string(), "rnosymfollow".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rnosymfollow_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );
    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rnosymfollow_dir_path, &rnosymfollow_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        let original_file_path =
            format!("{}/{}", rnosymfollow_subdir_path.to_str().unwrap(), "file");
        let _ = File::create(&original_file_path)?;
        let link_file_path = format!("{}/{}", rnosymfollow_subdir_path.to_str().unwrap(), "link");

        symlink(original_file_path, link_file_path)?;
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rnosymfollow_dir_path, &rnosymfollow_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rnosymfollow_dir_path.display(),
            rnosymfollow_subdir_path.display(),
        );
    };
    result
}

// rsymfollow_test
fn check_recursive_rsymfollow() -> TestResult {
    let rsymfollow_base_path = TempDir::new().unwrap();
    let rsymfollow_dir_path = rsymfollow_base_path.path().join("rsymfollow_dir");
    let rsymfollow_subdir_path = rsymfollow_dir_path.join("rsymfollow_subdir");
    let mount_dest_path = PathBuf::from_str("/mnt").unwrap();

    let mount_options = vec!["rbind".to_string(), "rsymfollow".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rsymfollow_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );
    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rsymfollow_dir_path, &rsymfollow_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        let original_file_path = format!("{}/{}", rsymfollow_subdir_path.to_str().unwrap(), "file");
        let _ = File::create(&original_file_path)?;
        let link_file_path = format!("{}/{}", rsymfollow_subdir_path.to_str().unwrap(), "link");

        symlink(original_file_path, link_file_path)?;
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rsymfollow_dir_path, &rsymfollow_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rsymfollow_dir_path.display(),
            rsymfollow_subdir_path.display(),
        );
    };
    result
}

// rbind_ro_test
// If we specify `rbind` and `ro`, the top-level mount becomes read-only, but the setting is not applied recursively to submounts.
// ref: https://github.com/opencontainers/runc/blob/main/tests/integration/mounts_recursive.bats#L34
fn check_rbind_ro_is_readonly_but_not_recursively() -> TestResult {
    let rbind_ro_base_path = TempDir::new().unwrap();
    let rbind_ro_dir_path = rbind_ro_base_path.path().join("rbind_ro_dir");
    let rbind_ro_subdir_path = rbind_ro_dir_path.join("rbind_ro_subdir");
    let mount_dest_path = PathBuf::from_str("/mnt").unwrap();

    let mount_options = vec!["rbind".to_string(), "ro".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rbind_ro_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec![
            "runtimetest".to_string(),
            "mounts_recursive_rbind_ro".to_string(),
        ],
    );
    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| {
        setup_mount(&rbind_ro_dir_path, &rbind_ro_subdir_path)
            .map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        std::fs::write(rbind_ro_dir_path.join("bar"), b"bar\n").unwrap();
        std::fs::write(rbind_ro_subdir_path.join("bar"), b"bar\n").unwrap();
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&rbind_ro_dir_path, &rbind_ro_subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            rbind_ro_dir_path.display(),
            rbind_ro_subdir_path.display(),
        );
    };
    result
}

// this mount test how to work?
// 1. Create mount_options based on the mount properties of the test
// 2. Create OCI Spec content, container one process is runtimetest,(runtimetest is cargo model, file path `tests/runtimetest/`)
// 3. inside container to check if the actual mount matches the spec, (spec https://man7.org/linux/man-pages/man2/mount_setattr.2.html),
//    eg. tests/runtimetest/src/tests.rs
pub fn get_mounts_recursive_test() -> TestGroup {
    let rro_test = Test::new("rro_test", Box::new(check_recursive_readonly));
    let rnosuid_test = Test::new("rnosuid_test", Box::new(check_recursive_nosuid));
    let rsuid_test = Test::new("rsuid_test", Box::new(check_recursive_rsuid));
    let rnoexec_test = Test::new("rnoexec_test", Box::new(check_recursive_noexec));
    let rnodiratime_test = Test::new("rnodiratime_test", Box::new(check_recursive_rnodiratime));
    let rdiratime_test = Test::new("rdiratime_test", Box::new(check_recursive_rdiratime));
    let rdev_test = Test::new("rdev_test", Box::new(check_recursive_rdev));
    let rnodev_test = Test::new("rnodev_test", Box::new(check_recursive_rnodev));
    let rrw_test = Test::new("rrw_test", Box::new(check_recursive_readwrite));
    let rexec_test = Test::new("rexec_test", Box::new(check_recursive_rexec));
    let rrelatime_test = Test::new("rrelatime_test", Box::new(check_recursive_rrelatime));
    let rnorelatime_test = Test::new("rnorelatime_test", Box::new(check_recursive_rnorelatime));
    let rnoatime_test = Test::new("rnoatime_test", Box::new(check_recursive_rnoatime));
    let rstrictatime_test = Test::new("rstrictatime_test", Box::new(check_recursive_rstrictatime));
    let rnosymfollow_test = Test::new("rnosymfollow_test", Box::new(check_recursive_rnosymfollow));
    let rsymfollow_test = Test::new("rsymfollow_test", Box::new(check_recursive_rsymfollow));
    let rbind_ro_test = Test::new(
        "rbind_ro_test",
        Box::new(check_rbind_ro_is_readonly_but_not_recursively),
    );

    let mut tg = TestGroup::new("mounts_recursive");
    tg.add(vec![
        Box::new(rro_test),
        Box::new(rnosuid_test),
        Box::new(rsuid_test),
        Box::new(rnoexec_test),
        Box::new(rdiratime_test),
        Box::new(rnodiratime_test),
        Box::new(rdev_test),
        Box::new(rnodev_test),
        Box::new(rrw_test),
        Box::new(rexec_test),
        Box::new(rrelatime_test),
        Box::new(rnorelatime_test),
        Box::new(rnoatime_test),
        Box::new(rstrictatime_test),
        Box::new(rnosymfollow_test),
        Box::new(rsymfollow_test),
        Box::new(rbind_ro_test),
    ]);

    tg
}
