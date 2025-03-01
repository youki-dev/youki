use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use oci_spec::runtime::{Process, Spec};
use once_cell::sync::OnceCell;
use rand::Rng;
use tar::Archive;
use tempfile::TempDir;
use uuid::Uuid;

static RUNTIME_PATH: OnceCell<PathBuf> = OnceCell::new();
static RUNTIMETEST_PATH: OnceCell<PathBuf> = OnceCell::new();

pub fn set_runtime_path(path: &Path) {
    RUNTIME_PATH.set(path.to_owned()).unwrap();
}

pub fn get_runtime_path() -> &'static PathBuf {
    RUNTIME_PATH.get().expect("Runtime path is not set")
}

pub fn set_runtimetest_path(path: &Path) {
    RUNTIMETEST_PATH.set(path.to_owned()).unwrap();
}

pub fn get_runtimetest_path() -> &'static PathBuf {
    RUNTIMETEST_PATH.get().expect("Runtimetest path is not set")
}

#[allow(dead_code)]
pub fn get_project_path() -> PathBuf {
    let current_dir_path_result = env::current_dir();
    match current_dir_path_result {
        Ok(path_buf) => path_buf,
        Err(e) => panic!("directory is not found, {e}"),
    }
}

/// This will generate the UUID needed when creating the container.
pub fn generate_uuid() -> Uuid {
    let mut rng = rand::rng();
    const CHARSET: &[u8] = b"0123456789abcdefABCDEF";

    let rand_string: String = (0..32)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    match Uuid::parse_str(&rand_string) {
        Ok(uuid) => uuid,
        Err(e) => panic!("can not parse uuid, {e}"),
    }
}

/// Creates a bundle directory in a temp directory
pub fn prepare_bundle() -> Result<TempDir> {
    let temp_dir = tempfile::tempdir()?;
    let tar_file_name = "bundle.tar.gz";
    let tar_source = std::env::current_dir()?.join(tar_file_name);
    let tar_target = temp_dir.as_ref().join(tar_file_name);
    std::fs::copy(&tar_source, &tar_target)
        .with_context(|| format!("could not copy {tar_source:?} to {tar_target:?}"))?;

    let tar_gz = File::open(&tar_source)?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive.unpack(&temp_dir).with_context(|| {
        format!(
            "failed to unpack {:?} to {:?}",
            tar_source,
            temp_dir.as_ref()
        )
    })?;

    let mut spec = Spec::default();
    let mut process = Process::default();
    process.set_args(Some(vec!["sleep".into(), "10".into()]));
    spec.set_process(Some(process));
    set_config(&temp_dir, &spec).unwrap();

    Ok(temp_dir)
}

/// Sets the config.json file as per given spec
pub fn set_config<P: AsRef<Path>>(project_path: P, config: &Spec) -> Result<()> {
    let path = project_path.as_ref().join("bundle").join("config.json");
    config.save(path)?;
    Ok(())
}

pub fn is_runtime_runc() -> bool {
    match std::env::var("RUNTIME_KIND") {
        Err(_) => false,
        Ok(s) => s == "runc",
    }
}
