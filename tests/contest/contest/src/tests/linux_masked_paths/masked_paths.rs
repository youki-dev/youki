use std::path::PathBuf;

use anyhow::{anyhow, bail};
use nix::sys::stat::SFlag;
use oci_spec::runtime::{LinuxBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_inside_container;

fn get_spec(masked_paths: Vec<String>) -> Spec {
    SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .masked_paths(masked_paths)
                .build()
                .expect("could not build"),
        )
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "masked_paths".to_string()])
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

fn check_masked_paths() -> TestResult {
    let masked_dir = "masked-dir";
    let masked_subdir = "masked-subdir";
    let masked_file = "masked-file";

    let masked_dir_top = PathBuf::from(masked_dir);
    let masked_file_top = PathBuf::from(masked_file);

    let masked_dir_sub = masked_dir_top.join(masked_subdir);
    let masked_file_sub = masked_dir_top.join(masked_file);
    let masked_file_sub_sub = masked_dir_sub.join(masked_file);

    let root = PathBuf::from("/");

    let masked_paths = vec![
        root.join(&masked_dir_top).to_string_lossy().to_string(),
        root.join(&masked_file_top).to_string_lossy().to_string(),
        root.join(&masked_dir_sub).to_string_lossy().to_string(),
        root.join(&masked_file_sub).to_string_lossy().to_string(),
        root.join(&masked_file_sub_sub)
            .to_string_lossy()
            .to_string(),
    ];

    let spec = get_spec(masked_paths);

    test_inside_container(spec, &|bundle_path| {
        use std::{fs, io};
        let test_dir = bundle_path.join(&masked_dir_sub);

        match fs::create_dir_all(&test_dir) {
            io::Result::Ok(_) => { /*This is expected*/ }
            io::Result::Err(e) => {
                bail!(e)
            }
        }

        match fs::File::create(test_dir.join("tmp")) {
            io::Result::Ok(_) => { /*This is expected*/ }
            io::Result::Err(e) => {
                bail!(e)
            }
        }

        let test_sub_sub_file = bundle_path.join(&masked_file_sub_sub);
        match fs::File::create(test_sub_sub_file) {
            io::Result::Ok(_) => { /*This is expected*/ }
            io::Result::Err(e) => {
                bail!(e)
            }
        }

        let test_sub_file = bundle_path.join(&masked_file_sub);
        match fs::File::create(test_sub_file) {
            io::Result::Ok(_) => { /*This is expected*/ }
            io::Result::Err(e) => {
                bail!(e)
            }
        }

        let test_file = bundle_path.join(masked_file);
        match fs::File::create(test_file) {
            io::Result::Ok(_) => { /*This is expected*/ }
            io::Result::Err(e) => {
                bail!(e)
            }
        }

        Ok(())
    })
}

fn check_masked_rel_paths() -> TestResult {
    // Deliberately set a relative path to be masked,
    // and expect an error
    let masked_rel_path = "masked_rel_path";
    let masked_paths = vec![masked_rel_path.to_string()];
    let spec = get_spec(masked_paths);

    test_inside_container(spec, &|bundle_path| {
        use std::{fs, io};
        let test_file = bundle_path.join(masked_rel_path);
        match fs::metadata(&test_file) {
            io::Result::Ok(md) => {
                bail!(
                    "reading path {:?} should have given error, found {:?} instead",
                    test_file,
                    md
                )
            }
            io::Result::Err(e) => {
                let err = e.kind();
                if let io::ErrorKind::NotFound = err {
                    Ok(())
                } else {
                    bail!("expected not found error, got {:?}", err);
                }
            }
        }
    })
}

fn check_masked_symlinks() -> TestResult {
    // Deliberately create a masked symlink that points an invalid file,
    // and expect an error.
    let root = PathBuf::from("/");
    let masked_symlink = "masked_symlink";
    let masked_paths = vec![root.join(masked_symlink).to_string_lossy().to_string()];
    let spec = get_spec(masked_paths);

    let res = test_inside_container(spec, &|bundle_path| {
        use std::{fs, io};
        let test_file = bundle_path.join(masked_symlink);
        // ln -s .. /masked-symlink ; readlink -f /masked-symlink; ls -L /masked-symlink
        match std::os::unix::fs::symlink("../masked_symlink", &test_file) {
            io::Result::Ok(_) => { /* This is expected */ }
            io::Result::Err(e) => {
                bail!("error in creating symlink, to {:?} {:?}", test_file, e);
            }
        }

        let r_path = match fs::read_link(&test_file) {
            io::Result::Ok(p) => p,
            io::Result::Err(e) => {
                bail!("error in reading symlink at {:?} : {:?}", test_file, e);
            }
        };

        match fs::metadata(r_path) {
            io::Result::Ok(md) => {
                bail!(
                    "reading path {:?} should have given error, found {:?} instead",
                    test_file,
                    md
                )
            }
            io::Result::Err(e) => {
                let err = e.kind();
                if let io::ErrorKind::NotFound = err {
                    Ok(())
                } else {
                    bail!("expected not found error, got {:?}", err);
                }
            }
        }
    });

    if let TestResult::Passed = res {
        TestResult::Failed(anyhow!(
            "expected error in container creation with invalid symlink, found no error"
        ))
    } else {
        TestResult::Passed
    }
}

fn test_node(mode: u32) -> TestResult {
    let root = PathBuf::from("/");
    let masked_device = "masked_device";
    let masked_paths = vec![root.join(masked_device).to_string_lossy().to_string()];
    let spec = get_spec(masked_paths);

    test_inside_container(spec, &|bundle_path| {
        use std::os::unix::fs::OpenOptionsExt;
        use std::{fs, io};
        let test_file = bundle_path.join(masked_device);

        let mut opts = fs::OpenOptions::new();
        opts.mode(mode);
        opts.create(true);
        if let io::Result::Err(e) = fs::OpenOptions::new()
            .mode(mode)
            .create(true)
            .write(true)
            .open(&test_file)
        {
            bail!(
                "could not create file {:?} with mode {:?} : {:?}",
                test_file,
                mode ^ 0o666,
                e
            );
        }

        match fs::metadata(&test_file) {
            io::Result::Ok(_) => Ok(()),
            io::Result::Err(e) => {
                let err = e.kind();
                if let io::ErrorKind::NotFound = err {
                    bail!("error in creating device node, {:?}", e)
                } else {
                    Ok(())
                }
            }
        }
    })
}

fn check_masked_device_nodes() -> TestResult {
    let modes = [
        SFlag::S_IFBLK.bits() | 0o666,
        SFlag::S_IFCHR.bits() | 0o666,
        SFlag::S_IFIFO.bits() | 0o666,
    ];
    for mode in modes {
        let res = test_node(mode);
        if let TestResult::Failed(_) = res {
            return res;
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
    TestResult::Passed
}

pub fn get_linux_masked_paths_tests() -> TestGroup {
    let mut tg = TestGroup::new("masked_paths");
    let masked_paths_test = Test::new("masked_paths", Box::new(check_masked_paths));
    let masked_rel_paths_test = Test::new("masked_rel_paths", Box::new(check_masked_rel_paths));
    let masked_symlinks_test = Test::new("masked_symlinks", Box::new(check_masked_symlinks));
    let masked_device_nodes_test =
        Test::new("masked_device_nodes", Box::new(check_masked_device_nodes));
    tg.add(vec![
        Box::new(masked_paths_test),
        Box::new(masked_rel_paths_test),
        Box::new(masked_symlinks_test),
        Box::new(masked_device_nodes_test),
    ]);
    tg
}
