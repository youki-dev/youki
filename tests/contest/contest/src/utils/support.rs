use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::{env, fs};

use anyhow::{Context, Result, anyhow};
use flate2::read::GzDecoder;
use oci_spec::runtime::{Hook, HookBuilder, Process, Spec};
use rand::RngExt;
use tar::Archive;
use tempfile::TempDir;
use uuid::Uuid;

static RUNTIME_PATH: OnceLock<PathBuf> = OnceLock::new();
static RUNTIMETEST_PATH: OnceLock<PathBuf> = OnceLock::new();

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

pub fn wait_for_file_content(
    file_path: &PathBuf,
    expected_content: &str,
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
) -> anyhow::Result<()> {
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        if file_path.exists()
            && let Ok(contents) = fs::read_to_string(file_path)
            && contents.contains(expected_content)
        {
            return Ok(());
        }
        std::thread::sleep(poll_interval);
    }

    let actual_content = fs::read_to_string(file_path)
        .unwrap_or_else(|_| "(file does not exist or cannot be read)".to_string());

    Err(anyhow!(
        "Timed out waiting for file {} to contain '{expected_content}', but got: '{actual_content}'",
        file_path.display(),
    ))
}

const HOOK_OUTPUT_FILE: &str = "output";

pub fn get_hook_output_file_path(bundle: &TempDir) -> PathBuf {
    bundle
        .as_ref()
        .join("bundle")
        .join("rootfs")
        .join(HOOK_OUTPUT_FILE)
}

pub fn delete_hook_output_file(path: &PathBuf) {
    if path.exists() {
        fs::remove_file(path).expect("failed to remove output file");
    }
}

pub fn build_hook(message: &str, host_output_file: &str) -> Hook {
    HookBuilder::default()
        .path("/bin/sh")
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo '{message}' >> {host_output_file}"),
        ])
        .build()
        .expect("could not build hook")
}
