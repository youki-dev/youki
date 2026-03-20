use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::anyhow;
use test_framework::TestResult;

use super::get_result_from_output;
use crate::utils::get_runtime_path;
use crate::utils::test_utils::State;

fn get_container_pid(project_path: &Path, id: &str) -> Result<i32, TestResult> {
    let res_state = match Command::new(get_runtime_path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("--root")
        .arg(project_path.join("runtime"))
        .arg("state")
        .arg(id)
        .spawn()
        .expect("failed to execute state command")
        .wait_with_output()
    {
        Ok(o) => o,
        Err(e) => {
            return Err(TestResult::Failed(anyhow!(
                "error getting container state {}",
                e
            )));
        }
    };
    let stdout = match String::from_utf8(res_state.stdout) {
        Ok(s) => s,
        Err(e) => {
            return Err(TestResult::Failed(anyhow!(
                "failed to parse container stdout {}",
                e
            )));
        }
    };
    let state: State = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(e) => {
            return Err(TestResult::Failed(anyhow!(
                "error in parsing state of container: stdout : {}, parse error : {}",
                stdout,
                e
            )));
        }
    };

    Ok(state.pid.unwrap_or(-1))
}

fn setup_network_namespace(project_path: &Path, id: &str) -> Result<(), TestResult> {
    let pid = get_container_pid(project_path, id)?;

    if let Err(e) = Command::new("nsenter")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("-t")
        .arg(format!("{pid}"))
        .arg("-a")
        .args(vec!["/bin/ip", "link", "set", "up", "dev", "lo"])
        .spawn()
        .expect("failed to exec ip")
        .wait_with_output()
    {
        return Err(TestResult::Failed(anyhow!(
            "error setting up network namespace {}",
            e
        )));
    }

    Ok(())
}

fn checkpoint(
    project_path: &Path,
    id: &str,
    image_path: Option<&Path>,
    args: Vec<&str>,
    work_path: Option<&str>,
) -> Result<(), TestResult> {
    setup_network_namespace(project_path, id)?;

    let (_default_dir, default_path) = if image_path.is_none() {
        let (dir, path) = create_checkpoint_image_dir()?;
        (Some(dir), Some(path))
    } else {
        (None, None)
    };
    let image_path = image_path
        .or(default_path.as_deref())
        .expect("image_path should be set");

    let additional_args = match work_path {
        Some(wp) => vec!["--work-path", wp],
        _ => Vec::new(),
    };

    let runtime_path = get_runtime_path();

    let mut cmd = Command::new(runtime_path);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("--root")
        .arg(project_path.join("runtime"))
        .arg(match runtime_path {
            _ if runtime_path.ends_with("youki") => "checkpointt",
            _ => "checkpoint",
        })
        .arg("--image-path")
        .arg(image_path);
    let checkpoint = cmd
        .args(additional_args)
        .args(args)
        .arg(id)
        .spawn()
        .expect("failed to execute checkpoint command")
        .wait_with_output();

    if let Err(e) = get_result_from_output(checkpoint) {
        return Err(TestResult::Failed(anyhow::anyhow!(
            "failed to execute checkpoint command: {e}"
        )));
    }

    if !image_path.join("inventory.img").exists() {
        return Err(TestResult::Failed(anyhow::anyhow!(
            "resulting checkpoint does not seem to be complete. {:?}/inventory.img is missing",
            image_path,
        )));
    }

    if !image_path.join("descriptors.json").exists() {
        return Err(TestResult::Failed(anyhow::anyhow!(
            "resulting checkpoint does not seem to be complete. {:?}/descriptors.json is missing",
            image_path,
        )));
    }

    let dump_log = match work_path {
        Some(wp) => Path::new(wp).join("dump.log"),
        _ => image_path.join("dump.log"),
    };

    if !dump_log.exists() {
        return Err(TestResult::Failed(anyhow::anyhow!(
            "resulting checkpoint log file {:?} not found.",
            &dump_log,
        )));
    }

    Ok(())
}

fn create_checkpoint_image_dir() -> Result<(tempfile::TempDir, std::path::PathBuf), TestResult> {
    let temp_dir = tempfile::tempdir().map_err(|e| {
        TestResult::Failed(anyhow::anyhow!(
            "failed creating temporary directory {:?}",
            e
        ))
    })?;
    let image_path = temp_dir.path().join("checkpoint");
    std::fs::create_dir(&image_path).map_err(|e| {
        TestResult::Failed(anyhow::anyhow!(
            "failed creating checkpoint directory ({:?}): {}",
            &image_path,
            e
        ))
    })?;
    Ok((temp_dir, image_path))
}

pub fn checkpoint_leave_running_work_path_tmp(project_path: &Path, id: &str) -> TestResult {
    match checkpoint(
        project_path,
        id,
        None,
        vec!["--leave-running"],
        Some("/tmp/"),
    ) {
        Ok(()) => TestResult::Passed,
        Err(e) => e,
    }
}

pub fn checkpoint_leave_running(project_path: &Path, id: &str) -> TestResult {
    match checkpoint(project_path, id, None, vec!["--leave-running"], None) {
        Ok(()) => TestResult::Passed,
        Err(e) => e,
    }
}

pub fn checkpoint_manage_cgroups_mode_ignore(project_path: &Path, id: &str) -> TestResult {
    let (_temp_dir, image_path) = match create_checkpoint_image_dir() {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let Err(e) = checkpoint(
        project_path,
        id,
        Some(image_path.as_path()),
        vec!["--leave-running", "--manage-cgroups-mode", "ignore"],
        None,
    ) {
        return e;
    }

    let cgroup_img = image_path.join("cgroup.img");
    let content = match std::fs::read(&cgroup_img) {
        Ok(c) => c,
        Err(e) => {
            return TestResult::Failed(anyhow::anyhow!(
                "failed to read cgroup.img at {:?}: {}",
                cgroup_img,
                e
            ));
        }
    };

    if content
        .windows(b"cgroup.subtree_control".len())
        .any(|w| w == b"cgroup.subtree_control")
    {
        return TestResult::Failed(anyhow::anyhow!(
            "cgroup.img should not contain cgroup properties with --manage-cgroups-mode ignore, \
             but found 'cgroup.subtree_control'",
        ));
    }

    TestResult::Passed
}

pub fn checkpoint_manage_cgroups_mode_soft(project_path: &Path, id: &str) -> TestResult {
    let (_temp_dir, image_path) = match create_checkpoint_image_dir() {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let Err(e) = checkpoint(
        project_path,
        id,
        Some(image_path.as_path()),
        vec!["--leave-running", "--manage-cgroups-mode", "soft"],
        None,
    ) {
        return e;
    }

    let cgroup_img = image_path.join("cgroup.img");
    let content = match std::fs::read(&cgroup_img) {
        Ok(c) => c,
        Err(e) => {
            return TestResult::Failed(anyhow::anyhow!(
                "failed to read cgroup.img at {:?}: {}",
                cgroup_img,
                e
            ));
        }
    };

    if !content
        .windows(b"cgroup.subtree_control".len())
        .any(|w| w == b"cgroup.subtree_control")
    {
        return TestResult::Failed(anyhow::anyhow!(
            "cgroup.img should contain cgroup properties with --manage-cgroups-mode soft, \
             but 'cgroup.subtree_control' not found",
        ));
    }

    TestResult::Passed
}
