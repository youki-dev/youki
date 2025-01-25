use std::collections::hash_set::HashSet;
use std::fs;
use std::fs::File;
use std::os::unix::fs::symlink;
use std::os::unix::prelude::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::Context;
use nix::libc;
use nix::mount::{mount, umount, MsFlags};
use nix::sys::stat::Mode;
use nix::unistd::{chown, Uid};
use oci_spec::runtime::{
    get_default_mounts, Capability, LinuxBuilder, LinuxCapabilitiesBuilder, Mount, ProcessBuilder,
    Spec, SpecBuilder,
};
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

fn setup_mount(mount_dir: &Path, sub_mount_dir: &Path) {
    fs::create_dir(mount_dir).unwrap();
    mount::<Path, Path, str, str>(None, mount_dir, Some("tmpfs"), MsFlags::empty(), None).unwrap();
    fs::create_dir(sub_mount_dir).unwrap();
    mount::<Path, Path, str, str>(None, sub_mount_dir, Some("tmpfs"), MsFlags::empty(), None)
        .unwrap();
}

fn clean_mount(mount_dir: &Path, sub_mount_dir: &Path) {
    umount(sub_mount_dir).unwrap();
    umount(mount_dir).unwrap();
    fs::remove_dir_all(mount_dir).unwrap();
}

fn check_recursive_readonly() -> TestResult {
    let rro_test_base_dir = PathBuf::from_str("/tmp").unwrap();
    let rro_dir_path = rro_test_base_dir.join("rro_dir");
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

    let result = test_inside_container(spec, &CreateOptions::default(), &|_| {
        setup_mount(&rro_dir_path, &rro_subdir_path);
        Ok(())
    });

    clean_mount(&rro_dir_path, &rro_subdir_path);

    result
}

fn check_recursive_nosuid() -> TestResult {
    let rnosuid_test_base_dir = PathBuf::from_str("/tmp").unwrap();
    let rnosuid_dir_path = rnosuid_test_base_dir.join("rnosuid_dir");
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

    let result = test_inside_container(spec, &CreateOptions::default(), &|bundle_path| {
        setup_mount(&rnosuid_dir_path, &rnosuid_subdir_path);

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

    clean_mount(&rnosuid_dir_path, &rnosuid_subdir_path);

    result
}

fn check_recursive_rsuid() -> TestResult {
    let rsuid_dir_path = PathBuf::from_str("/tmp/rsuid_dir").unwrap();
    let mount_dest_path = PathBuf::from_str("/mnt/rsuid_dir").unwrap();
    fs::create_dir_all(rsuid_dir_path.clone()).unwrap();
    scopeguard::defer!(fs::remove_dir_all(rsuid_dir_path.clone()).unwrap());

    let mount_options = vec!["rbind".to_string(), "rsuid".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rsuid_dir_path.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );
    test_inside_container(spec, &CreateOptions::default(), &|_| {
        let original_file_path = rsuid_dir_path.join("file");
        let file = File::create(original_file_path)?;
        let mut permission = file.metadata()?.permissions();
        // chmod +s /tmp/rsuid_dir/file && chmod +g /tmp/rsuid_dir/file
        permission.set_mode(permission.mode() | libc::S_ISUID | libc::S_ISGID);
        file.set_permissions(permission)
            .with_context(|| "failed to set permission")?;

        Ok(())
    })
}

fn check_recursive_noexec() -> TestResult {
    let rnoexec_test_base_dir = PathBuf::from_str("/tmp").unwrap();
    let rnoexec_dir_path = rnoexec_test_base_dir.join("rnoexec_dir");
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

    let result = test_inside_container(spec, &CreateOptions::default(), &|bundle_path| {
        setup_mount(&rnoexec_dir_path, &rnoexec_subdir_path);

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

    clean_mount(&rnoexec_dir_path, &rnoexec_subdir_path);

    result
}

fn check_recursive_rexec() -> TestResult {
    let rnoexec_test_base_dir = PathBuf::from_str("/tmp").unwrap();
    let rnoexec_dir_path = rnoexec_test_base_dir.join("rexec_dir");
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

    let result = test_inside_container(spec, &CreateOptions::default(), &|bundle_path| {
        setup_mount(&rnoexec_dir_path, &rnoexec_subdir_path);

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

    clean_mount(&rnoexec_dir_path, &rnoexec_subdir_path);

    result
}

/// rdiratime If set in attr_clr, removes the restriction that prevented updating access time for directories.
fn check_recursive_rdiratime() -> TestResult {
    let rdiratime_base_dir = PathBuf::from_str("/tmp/rdiratime").unwrap();
    let mount_dest_path = PathBuf::from_str("/rdiratime").unwrap();
    fs::create_dir(rdiratime_base_dir.clone()).unwrap();

    let mount_options = vec!["rbind".to_string(), "rdiratime".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rdiratime_base_dir.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    let result = test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()));

    fs::remove_dir(rdiratime_base_dir).unwrap();
    result
}

/// If set in attr_set, prevents updating access time for directories on this mount
fn check_recursive_rnodiratime() -> TestResult {
    let rnodiratime_base_dir = PathBuf::from_str("/tmp/rnodiratime").unwrap();
    let mount_dest_path = PathBuf::from_str("/rnodiratime").unwrap();
    fs::create_dir(rnodiratime_base_dir.clone()).unwrap();

    let mount_options = vec!["rbind".to_string(), "rnodiratime".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rnodiratime_base_dir.clone()))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    let result = test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()));
    fs::remove_dir(rnodiratime_base_dir).unwrap();
    result
}

fn check_recursive_rdev() -> TestResult {
    let rdev_base_dir = PathBuf::from_str("/dev").unwrap();
    let mount_dest_path = PathBuf::from_str("/rdev").unwrap();

    let mount_options = vec!["rbind".to_string(), "rdev".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rdev_base_dir))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()))
}

fn check_recursive_rnodev() -> TestResult {
    let rnodev_base_dir = PathBuf::from_str("/dev").unwrap();
    let mount_dest_path = PathBuf::from_str("/rnodev").unwrap();

    let mount_options = vec!["rbind".to_string(), "rnodev".to_string()];
    let mut mount_spec = Mount::default();
    mount_spec
        .set_destination(mount_dest_path)
        .set_typ(None)
        .set_source(Some(rnodev_base_dir))
        .set_options(Some(mount_options));
    let spec = get_spec(
        vec![mount_spec],
        vec!["runtimetest".to_string(), "mounts_recursive".to_string()],
    );

    test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()))
}

fn check_recursive_readwrite() -> TestResult {
    let rrw_test_base_dir = PathBuf::from_str("/tmp").unwrap();
    let rrw_dir_path = rrw_test_base_dir.join("rrw_dir");
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

    let result = test_inside_container(spec, &CreateOptions::default(), &|_| {
        setup_mount(&rrw_dir_path, &rrw_subdir_path);
        Ok(())
    });

    clean_mount(&rrw_dir_path, &rrw_subdir_path);

    result
}

fn check_recursive_rrelatime() -> TestResult {
    let rrelatime_base_dir = PathBuf::from_str("/tmp").unwrap();
    let rrelatime_dir_path = rrelatime_base_dir.join("rrelatime_dir");
    let rrelatime_suddir_path = rrelatime_dir_path.join("rrelatime_subdir");
    let mount_dest_path = PathBuf::from_str("/rrelatime").unwrap();
    fs::create_dir_all(rrelatime_suddir_path).unwrap();

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
    let result = test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()));

    fs::remove_dir_all(rrelatime_dir_path).unwrap();
    result
}

fn check_recursive_rnorelatime() -> TestResult {
    let rnorelatime_base_dir = PathBuf::from_str("/tmp").unwrap();
    let rnorelatime_dir_path = rnorelatime_base_dir.join("rnorelatime_dir");
    let mount_dest_path = PathBuf::from_str("/rnorelatime").unwrap();
    fs::create_dir(rnorelatime_dir_path.clone()).unwrap();

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

    let result = test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()));

    fs::remove_dir_all(rnorelatime_dir_path).unwrap();
    result
}

fn check_recursive_rnoatime() -> TestResult {
    let rnoatime_base_dir = PathBuf::from_str("/tmp").unwrap();
    let rnoatime_dir_path = rnoatime_base_dir.join("rnoatime_dir");
    let mount_dest_path = PathBuf::from_str("/rnoatime").unwrap();
    fs::create_dir(rnoatime_dir_path.clone()).unwrap();

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

    let result = test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()));

    fs::remove_dir_all(rnoatime_dir_path).unwrap();
    result
}

fn check_recursive_rstrictatime() -> TestResult {
    let rstrictatime_base_dir = PathBuf::from_str("/tmp").unwrap();
    let rstrictatime_dir_path = rstrictatime_base_dir.join("rstrictatime_dir");
    let mount_dest_path = PathBuf::from_str("/rstrictatime").unwrap();
    fs::create_dir(rstrictatime_dir_path.clone()).unwrap();

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
    let result = test_inside_container(spec, &CreateOptions::default(), &|_| Ok(()));

    fs::remove_dir_all(rstrictatime_dir_path).unwrap();
    result
}

fn check_recursive_rnosymfollow() -> TestResult {
    let rnosymfollow_dir_path = PathBuf::from_str("/tmp/rnosymfollow").unwrap();
    let mount_dest_path = PathBuf::from_str("/mnt/rnosymfollow").unwrap();
    fs::create_dir_all(rnosymfollow_dir_path.clone()).unwrap();

    let mount_options = vec![
        "rbind".to_string(),
        "rnosymfollow".to_string(),
        "rsuid".to_string(),
    ];
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
    let result = test_inside_container(spec, &CreateOptions::default(), &|_| {
        let original_file_path = format!("{}/{}", rnosymfollow_dir_path.to_str().unwrap(), "file");
        let file = File::create(&original_file_path)?;
        let link_file_path = format!("{}/{}", rnosymfollow_dir_path.to_str().unwrap(), "link");
        println!("original file: {original_file_path:?},link file: {link_file_path:?}");
        let mut permission = file.metadata()?.permissions();
        permission.set_mode(permission.mode() | libc::S_ISUID | libc::S_ISGID);
        file.set_permissions(permission)
            .with_context(|| "failed to set permission")?;

        symlink(original_file_path, link_file_path)?;
        println!("symlink success");
        Ok(())
    });

    fs::remove_dir_all(rnosymfollow_dir_path).unwrap();
    result
}

fn check_recursive_rsymfollow() -> TestResult {
    let rsymfollow_dir_path = PathBuf::from_str("/tmp/rsymfollow").unwrap();
    let mount_dest_path = PathBuf::from_str("/mnt/rsymfollow").unwrap();
    fs::create_dir_all(rsymfollow_dir_path.clone()).unwrap();

    let mount_options = vec![
        "rbind".to_string(),
        "rsymfollow".to_string(),
        "rsuid".to_string(),
    ];
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
    let result = test_inside_container(spec, &CreateOptions::default(), &|_| {
        let original_file_path = format!("{}/{}", rsymfollow_dir_path.to_str().unwrap(), "file");
        let file = File::create(&original_file_path)?;
        let link_file_path = format!("{}/{}", rsymfollow_dir_path.to_str().unwrap(), "link");
        let mut permission = file.metadata()?.permissions();
        permission.set_mode(permission.mode() | libc::S_ISUID | libc::S_ISGID);
        file.set_permissions(permission)
            .with_context(|| "failed to set permission")?;

        symlink(original_file_path, link_file_path)?;
        println!("symlink success");
        Ok(())
    });

    fs::remove_dir_all(rsymfollow_dir_path).unwrap();
    result
}

/// this mount test how to work?
/// 1. Create mount_options based on the mount properties of the test
/// 2. Create OCI.Spec content, container one process is runtimetest,(runtimetest is cargo model, file path `tests/runtimetest/`)
/// 3. inside container to check if the actual mount matches the spec, (spec https://man7.org/linux/man-pages/man2/mount_setattr.2.html),
///    eg. tests/runtimetest/src/tests.rs
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
    ]);

    tg
}
