use std::collections::hash_set::HashSet;
use std::fs;
use std::fs::{File, copy, create_dir, write};
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

const MOUNT_DEST: &str = "/mnt";

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
    create_dir(mount_dir)?;
    mount::<Path, Path, str, str>(None, mount_dir, Some("tmpfs"), MsFlags::empty(), None)?;
    create_dir(sub_mount_dir)?;
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

// Helper for mounts_recursive tests.
// - `mount_options`: OCI mount options (e.g. ["rbind", "rro"]).
// - `process_args`: If `None`, uses the default ["runtimetest", "mounts_recursive"].
// - `setup_extra`: Hook to perform additional host-side setup before starting the container.
//   It takes three parameters:
//   - `bundle_path`: Bundle root (e.g. used to copy files from bundle/bin).
//   - `dir_path`: Host directory that will be mounted at /mnt.
//   - `subdir_path`: Host subdirectory that will be mounted at /mnt/mount_subdir.
fn check_recursive<F>(
    mount_options: Vec<String>,
    process_args: Option<Vec<String>>,
    setup_extra: F,
) -> TestResult
where
    F: Fn(&Path, &Path, &Path) -> anyhow::Result<()>,
{
    let test_base_dir = TempDir::new().unwrap();
    let dir_path = test_base_dir.path().join("mount_dir");
    let subdir_path = dir_path.join("mount_subdir");
    let mount_dest_path = PathBuf::from_str(MOUNT_DEST).unwrap();

    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(dir_path.clone()))
        .set_options(Some(mount_options));

    let process_args = process_args
        .unwrap_or_else(|| vec!["runtimetest".to_string(), "mounts_recursive".to_string()]);

    let spec = get_spec(vec![mount_spec], process_args);

    let result = test_inside_container(&spec, &CreateOptions::default(), &|bundle_path| {
        setup_mount(&dir_path, &subdir_path).map_err(|e| anyhow!("setup_mount failed: {e:?}"))?;
        setup_extra(bundle_path, &dir_path, &subdir_path)
            .map_err(|e| anyhow!("setup_extra failed: {e:?}"))?;
        Ok(())
    });

    // Even if clean_mount fails, we do not treat the test as failed.
    if let Err(e) = clean_mount(&dir_path, &subdir_path) {
        eprintln!(
            "clean_mount failed (mount_dir={}, sub_mount_dir={}): {e:?}",
            dir_path.display(),
            subdir_path.display(),
        );
    };

    result
}

// Mount Recursive test
// Host:
//   - <tmp>/mount_dir is a mount point (tmpfs)
//   - <tmp>/mount_dir/mount_subdir is a submount (tmpfs)
//
// rbind:
//   - Bind-mount <tmp>/mount_dir into the container at /mnt (rbind)
//
// In the container, we should observe:
//   - mount at /mnt
//   - submount at /mnt/mount_subdir
//
// Key check: the mount options/attributes must be applied to SUBMOUNTS.

// rro_test
// rro makes both /mnt and /mnt/mount_subdir read-only (including submounts).
fn check_recursive_readonly() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rro".to_string()];
    check_recursive(
        mount_options,
        None,
        |_bundle_path: &Path, _dir_path: &Path, subdir: &Path| {
            write(subdir.join("bar"), b"bar\n").map_err(|e| anyhow!("write bar failed: {e:?}"))?;
            Ok(())
        },
    )
}

// rnosuid_test
fn check_recursive_nosuid() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rnosuid".to_string()];
    let mount_dest_path = PathBuf::from_str(MOUNT_DEST).unwrap();
    let executable_file_name = "whoami";
    check_recursive(
        mount_options,
        Some(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "{}; {}",
                mount_dest_path.join(executable_file_name).to_str().unwrap(),
                mount_dest_path
                    .join("mount_subdir/whoami")
                    .to_str()
                    .unwrap()
            ),
        ]),
        |bundle_path: &Path, dir_path: &Path, subdir_path: &Path| {
            let executable_file_path = bundle_path.join("bin").join(executable_file_name);
            let in_container_executable_file_path = dir_path.join(executable_file_name);
            let in_container_executable_subdir_file_path = subdir_path.join(executable_file_name);

            copy(&executable_file_path, &in_container_executable_file_path)?;
            copy(
                &executable_file_path,
                &in_container_executable_subdir_file_path,
            )?;

            let in_container_executable_file = File::open(&in_container_executable_file_path)?;
            let in_container_executable_subdir_file =
                File::open(&in_container_executable_subdir_file_path)?;

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

            in_container_executable_file
                .set_permissions(in_container_executable_file_perm.clone())?;
            in_container_executable_subdir_file
                .set_permissions(in_container_executable_subdir_file_perm.clone())?;
            Ok(())
        },
    )
}

// rsuid_test
// Mounting with 'rsuid' honors SUID bits on this mount (i.e., SUID can take effect).
// Note: The bits remain set in the inode (e.g., ls -l still shows 's').
fn check_recursive_rsuid() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rsuid".to_string()];
    let mount_dest_path = PathBuf::from_str(MOUNT_DEST).unwrap();
    let executable_file_name = "whoami";
    let result = check_recursive(
        mount_options,
        Some(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "{}; {}",
                mount_dest_path.join(executable_file_name).to_str().unwrap(),
                mount_dest_path
                    .join("mount_subdir/whoami")
                    .to_str()
                    .unwrap()
            ),
        ]),
        |bundle_path: &Path, dir_path: &Path, subdir_path: &Path| {
            let executable_file_path = bundle_path.join("bin").join(executable_file_name);
            let in_container_executable_file_path = dir_path.join(executable_file_name);
            let in_container_executable_subdir_file_path = subdir_path.join(executable_file_name);
            copy(&executable_file_path, &in_container_executable_file_path)?;
            copy(
                &executable_file_path,
                &in_container_executable_subdir_file_path,
            )?;

            let in_container_executable_file = File::open(&in_container_executable_file_path)?;
            let in_container_executable_subdir_file =
                File::open(&in_container_executable_subdir_file_path)?;
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

            in_container_executable_file
                .set_permissions(in_container_executable_file_perm.clone())?;
            in_container_executable_subdir_file
                .set_permissions(in_container_executable_subdir_file_perm.clone())?;
            Ok(())
        },
    );

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
    let mount_options = vec!["rbind".to_string(), "rnoexec".to_string()];
    check_recursive(
        mount_options,
        None,
        |bundle_path: &Path, dir_path: &Path, subdir_path: &Path| {
            let executable_file_name = "echo";
            let executable_file_path = bundle_path.join("bin").join(executable_file_name);
            let in_container_executable_file_path = dir_path.join(executable_file_name);
            let in_container_executable_subdir_file_path = subdir_path.join(executable_file_name);

            copy(&executable_file_path, in_container_executable_file_path)?;
            copy(
                &executable_file_path,
                in_container_executable_subdir_file_path,
            )?;

            Ok(())
        },
    )
}

// rexec_test
fn check_recursive_rexec() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rexec".to_string()];
    check_recursive(
        mount_options,
        None,
        |bundle_path: &Path, dir_path: &Path, subdir_path: &Path| {
            let executable_file_name = "echo";
            let executable_file_path = bundle_path.join("bin").join(executable_file_name);
            let in_container_executable_file_path = dir_path.join(executable_file_name);
            let in_container_executable_subdir_file_path = subdir_path.join(executable_file_name);

            copy(&executable_file_path, in_container_executable_file_path)?;
            copy(
                &executable_file_path,
                in_container_executable_subdir_file_path,
            )?;

            Ok(())
        },
    )
}

// rdiratime_test
// rdiratime If set in attr_clr, removes the restriction that prevented updating access time for directories.
fn check_recursive_rdiratime() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rdiratime".to_string()];
    check_recursive(
        mount_options,
        None,
        |_bundle_path: &Path, _dir_path: &Path, _subdir_path: &Path| Ok(()),
    )
}

// rnodiratime_test
// If set in attr_set, prevents updating access time for directories on this mount
fn check_recursive_rnodiratime() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rnodiratime".to_string()];
    check_recursive(
        mount_options,
        None,
        |_bundle_path: &Path, _dir_path: &Path, _subdir_path: &Path| Ok(()),
    )
}

// rdev_test
fn check_recursive_rdev() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rdev".to_string()];
    check_recursive(
        mount_options,
        None,
        |_bundle_path: &Path, _dir_path: &Path, subdir_path: &Path| {
            let dev = makedev(1, 3);
            mknod(
                &subdir_path.join("null"),
                SFlag::S_IFCHR,
                Mode::from_bits_truncate(0o666),
                dev,
            )
            .expect("create null device");
            Ok(())
        },
    )
}

// rnodev_test
fn check_recursive_rnodev() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rnodev".to_string()];
    check_recursive(
        mount_options,
        None,
        |_bundle_path: &Path, _dir_path: &Path, subdir_path: &Path| {
            let dev = makedev(1, 3);
            mknod(
                &subdir_path.join("null"),
                SFlag::S_IFCHR,
                Mode::from_bits_truncate(0o666),
                dev,
            )
            .expect("create null device");
            Ok(())
        },
    )
}

// rrw_test
fn check_recursive_readwrite() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rrw".to_string()];
    check_recursive(
        mount_options,
        None,
        |_bundle_path: &Path, _dir_path: &Path, subdir_path: &Path| {
            write(subdir_path.join("bar"), b"bar\n").unwrap();
            Ok(())
        },
    )
}

// rrelatime_test
fn check_recursive_rrelatime() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rrelatime".to_string()];
    check_recursive(
        mount_options,
        None,
        |_bundle_path: &Path, dir_path: &Path, subdir_path: &Path| {
            setup_remount(dir_path, subdir_path, MsFlags::MS_STRICTATIME)
                .map_err(|e| anyhow!("setup_remount failed: {e:?}"))?;
            Ok(())
        },
    )
}

// rnorelatime_test
fn check_recursive_rnorelatime() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rnorelatime".to_string()];
    check_recursive(
        mount_options,
        None,
        |_bundle_path: &Path, dir_path: &Path, subdir_path: &Path| {
            // The container implementation treats `norelatime` as clearing the `relatime` flag.
            // In this test, the mount is configured with `strictatime`, so once `relatime` is cleared, the mount ends up using `strictatime`.
            setup_remount(dir_path, subdir_path, MsFlags::MS_STRICTATIME)
                .map_err(|e| anyhow!("setup_remount failed: {e:?}"))?;
            Ok(())
        },
    )
}

// rnoatime_test
fn check_recursive_rnoatime() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rnoatime".to_string()];
    check_recursive(
        mount_options,
        None,
        |_bundle_path: &Path, _dir_path: &Path, _subdir_path: &Path| Ok(()),
    )
}

// rstrictatime_test
fn check_recursive_rstrictatime() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rstrictatime".to_string()];
    check_recursive(
        mount_options,
        None,
        |_bundle_path: &Path, _dir_path: &Path, _subdir_path: &Path| Ok(()),
    )
}

// rnosymfollow_test
fn check_recursive_rnosymfollow() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rnosymfollow".to_string()];
    check_recursive(
        mount_options,
        None,
        |_bundle_path: &Path, _dir_path: &Path, subdir_path: &Path| {
            let original_file_path = format!("{}/{}", subdir_path.to_str().unwrap(), "file");
            let _ = File::create(&original_file_path)?;
            let link_file_path = format!("{}/{}", subdir_path.to_str().unwrap(), "link");

            symlink(original_file_path, link_file_path)?;
            Ok(())
        },
    )
}

// rsymfollow_test
fn check_recursive_rsymfollow() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "rsymfollow".to_string()];
    check_recursive(
        mount_options,
        None,
        |_bundle_path: &Path, _dir_path: &Path, subdir_path: &Path| {
            let original_file_path = format!("{}/{}", subdir_path.to_str().unwrap(), "file");
            let _ = File::create(&original_file_path)?;
            let link_file_path = format!("{}/{}", subdir_path.to_str().unwrap(), "link");
            symlink(original_file_path, link_file_path)?;
            Ok(())
        },
    )
}

// rbind_ro_test
// If we specify `rbind` and `ro`, the top-level mount becomes read-only, but the setting is not applied recursively to submounts.
// ref: https://github.com/opencontainers/runc/blob/main/tests/integration/mounts_recursive.bats#L34
fn check_rbind_ro_is_readonly_but_not_recursively() -> TestResult {
    let mount_options = vec!["rbind".to_string(), "ro".to_string()];
    check_recursive(
        mount_options,
        Some(vec![
            "runtimetest".to_string(),
            "mounts_recursive_rbind_ro".to_string(),
        ]),
        |_bundle_path: &Path, dir_path: &Path, subdir_path: &Path| {
            write(dir_path.join("bar"), b"bar\n").unwrap();
            write(subdir_path.join("bar"), b"bar\n").unwrap();
            Ok(())
        },
    )
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
