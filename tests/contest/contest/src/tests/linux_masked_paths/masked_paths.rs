use std::path::PathBuf;

use anyhow::{anyhow, bail};
use nix::sys::stat::SFlag;
use oci_spec::runtime::{LinuxBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn get_spec(masked_paths: Vec<PathBuf>) -> Spec {
    let paths: Vec<String> = masked_paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .masked_paths(paths)
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
    const MASKED_DIR: &str = "masked-dir";
    const MASKED_SUBDIR: &str = "masked-subdir";
    const MASKED_FILE: &str = "masked-file";

    let masked_dir_top = PathBuf::from(MASKED_DIR);
    let masked_file_top = PathBuf::from(MASKED_FILE);

    let masked_dir_sub = masked_dir_top.join(MASKED_SUBDIR);
    let masked_file_sub = masked_dir_top.join(MASKED_FILE);
    let masked_file_sub_sub = masked_dir_sub.join(MASKED_FILE);

    let root = PathBuf::from("/");

    let masked_paths = vec![
        root.join(&masked_dir_top),
        root.join(&masked_file_top),
        root.join(&masked_dir_sub),
        root.join(&masked_file_sub),
        root.join(&masked_file_sub_sub),
    ];

    let spec = get_spec(masked_paths);

    test_inside_container(&spec, &CreateOptions::default(), &|bundle_path| {
        use std::fs;
        let test_dir = bundle_path.join(&masked_dir_sub);
        fs::create_dir_all(&test_dir)?;

        fs::File::create(test_dir.join("tmp"))?;

        // runtimetest cannot check the readability of empty files, so
        // write something.
        let test_sub_sub_file = bundle_path.join(&masked_file_sub_sub);
        fs::File::create(&test_sub_sub_file)?;
        fs::write(&test_sub_sub_file, b"secrets")?;

        let test_sub_file = bundle_path.join(&masked_file_sub);
        fs::File::create(&test_sub_file)?;
        fs::write(&test_sub_file, b"secrets")?;

        let test_file = bundle_path.join(MASKED_FILE);
        fs::File::create(&test_file)?;
        fs::write(&test_file, b"secrets")?;

        Ok(())
    })
}

fn check_masked_rel_paths() -> TestResult {
    // Deliberately set a relative path to be masked,
    // and expect an error
    let masked_rel_path = PathBuf::from("../masked_rel_path");
    let masked_paths = vec![masked_rel_path];
    let spec = get_spec(masked_paths);

    let res = test_inside_container(&spec, &CreateOptions::default(), &|_bundle_path| Ok(()));
    // If the container creation succeeds, we expect an error since the masked paths does not support relative paths.
    if let TestResult::Passed = res {
        TestResult::Failed(anyhow!(
            "expected error in container creation with invalid symlink, found no error"
        ))
    } else {
        TestResult::Passed
    }
}

fn check_masked_symlinks() -> TestResult {
    // Deliberately create a masked symlink that points an invalid file,
    // and expect an error.
    const MASKED_SYMLINK: &str = "masked_symlink";

    let root = PathBuf::from("/");
    let masked_paths = vec![root.join(MASKED_SYMLINK)];
    let spec = get_spec(masked_paths);

    let res = test_inside_container(&spec, &CreateOptions::default(), &|bundle_path| {
        use std::{fs, io};
        let test_file = bundle_path.join(MASKED_SYMLINK);
        // ln -s ../masked-symlink ; readlink -f /masked-symlink; ls -L /masked-symlink
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

        // It ensures that the symlink points not to exist.
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

    // If the container creation succeeds, we expect an error since the masked paths does not support symlinks.
    if let TestResult::Passed = res {
        TestResult::Failed(anyhow!(
            "expected error in container creation with invalid symlink, found no error"
        ))
    } else {
        TestResult::Passed
    }
}

fn test_mode(mode: u32) -> TestResult {
    const MASKED_DEVICE: &str = "masked_device";

    let root = PathBuf::from("/");
    let masked_paths = vec![root.join(MASKED_DEVICE)];
    let spec = get_spec(masked_paths);

    test_inside_container(&spec, &CreateOptions::default(), &|bundle_path| {
        use std::os::unix::fs::OpenOptionsExt;
        use std::{fs, io};
        let test_file = bundle_path.join(MASKED_DEVICE);

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
    [
        SFlag::S_IFBLK.bits() | 0o666,
        SFlag::S_IFCHR.bits() | 0o666,
        SFlag::S_IFIFO.bits() | 0o666,
    ]
    .iter()
    .map(|mode| test_mode(*mode))
    .find(|res| matches!(res, TestResult::Failed(_)))
    .unwrap_or(TestResult::Passed)
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
