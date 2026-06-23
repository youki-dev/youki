use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Result, anyhow};
use oci_spec::runtime::{MountBuilder, Spec};
use test_framework::TestResult;

use super::{create, get_result_from_output, start};
use crate::utils::{
    State, delete_container, generate_uuid, get_runtime_path, kill_container, prepare_bundle,
    set_config, wait_container_running,
};

// Simple function to figure out the PID of the first container process
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

// CRIU requires a minimal network setup in the network namespace
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

fn is_process_running(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    Path::new(&format!("/proc/{pid}")).exists()
}

fn checkpoint(
    project_path: &Path,
    id: &str,
    image_path: &Path,
    args: Vec<&str>,
    work_path: Option<&str>,
) -> TestResult {
    let pid_before = match get_container_pid(project_path, id) {
        Ok(p) => p,
        Err(e) => return e,
    };

    if let Err(e) = setup_network_namespace(project_path, id) {
        return e;
    }

    let leave_running = args.contains(&"--leave-running");

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
        .arg("checkpoint")
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
        return TestResult::Failed(anyhow::anyhow!("failed to execute checkpoint command: {e}"));
    }

    // Check for complete checkpoint
    if !image_path.join("inventory.img").exists() {
        return TestResult::Failed(anyhow::anyhow!(
            "resulting checkpoint does not seem to be complete. {:?}/inventory.img is missing",
            image_path,
        ));
    }

    if !image_path.join("descriptors.json").exists() {
        return TestResult::Failed(anyhow::anyhow!(
            "resulting checkpoint does not seem to be complete. {:?}/descriptors.json is missing",
            image_path,
        ));
    }

    let dump_log = match work_path {
        Some(wp) => Path::new(wp).join("dump.log"),
        _ => image_path.join("dump.log"),
    };

    if !dump_log.exists() {
        return TestResult::Failed(anyhow::anyhow!(
            "resulting checkpoint log file {:?} not found.",
            &dump_log,
        ));
    }

    // Verify process state based on --leave-running flag
    if leave_running {
        if !is_process_running(pid_before) {
            return TestResult::Failed(anyhow::anyhow!(
                "process (pid {}) should still be running after checkpoint with --leave-running, \
                 but it is gone",
                pid_before,
            ));
        }
    } else {
        if is_process_running(pid_before) {
            return TestResult::Failed(anyhow::anyhow!(
                "process (pid {}) should have stopped after checkpoint without --leave-running, \
                 but it is still running",
                pid_before,
            ));
        }

        // Without --leave-running the runtime must fully remove the container
        // from its state (matching runc's behavior), so `state <id>` must fail.
        let state_output = Command::new(get_runtime_path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("--root")
            .arg(project_path.join("runtime"))
            .arg("state")
            .arg(id)
            .spawn()
            .expect("failed to execute state command")
            .wait_with_output()
            .expect("failed to wait for state command");

        if state_output.status.success() {
            return TestResult::Failed(anyhow::anyhow!(
                "container {} should have been removed from runtime state after checkpoint \
                 without --leave-running, but `state` command still succeeded",
                id,
            ));
        }
    }

    TestResult::Passed
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
    let (_temp_dir, image_path) = match create_checkpoint_image_dir() {
        Ok(v) => v,
        Err(e) => return e,
    };

    checkpoint(
        project_path,
        id,
        &image_path,
        vec!["--leave-running"],
        Some("/tmp/"),
    )
}

pub fn checkpoint_leave_running(project_path: &Path, id: &str) -> TestResult {
    let (_temp_dir, image_path) = match create_checkpoint_image_dir() {
        Ok(v) => v,
        Err(e) => return e,
    };

    checkpoint(project_path, id, &image_path, vec!["--leave-running"], None)
}

pub fn checkpoint_manage_cgroups_mode_ignore(project_path: &Path, id: &str) -> TestResult {
    let (_temp_dir, image_path) = match create_checkpoint_image_dir() {
        Ok(v) => v,
        Err(e) => return e,
    };

    let result = checkpoint(
        project_path,
        id,
        &image_path,
        vec!["--leave-running", "--manage-cgroups-mode", "ignore"],
        None,
    );
    if let TestResult::Failed(_) = &result {
        return result;
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

    let result = checkpoint(
        project_path,
        id,
        &image_path,
        vec!["--leave-running", "--manage-cgroups-mode", "soft"],
        None,
    );
    if let TestResult::Failed(_) = &result {
        return result;
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

// Builds a spec whose init holds an "invisible file" (open-but-unlinked with a
// surviving hard link), which CRIU can only dump with `--link-remap`.
// See https://criu.org/Invisible_files.
fn link_remap_spec() -> Result<Spec, TestResult> {
    let mut spec = Spec::default();

    let mut process = spec.process().clone().unwrap_or_default();
    process.set_args(Some(vec![
        "sh".to_string(),
        "-c".to_string(),
        "echo -n link-remap-marker > /work/data; ln /work/data /work/keep; \
         exec 3< /work/data; unlink /work/data; while true; do sleep 1; done"
            .to_string(),
    ]));
    spec.set_process(Some(process));

    let tmpfs = MountBuilder::default()
        .typ("tmpfs".to_string())
        .source("tmpfs")
        .destination(std::path::PathBuf::from("/work"))
        .options(vec!["rw".to_string(), "nosuid".to_string()])
        .build()
        .map_err(|e| TestResult::Failed(anyhow!("failed to build tmpfs mount: {e}")))?;
    let mut mounts = spec.mounts().clone().unwrap_or_default();
    mounts.push(tmpfs);
    spec.set_mounts(Some(mounts));

    Ok(spec)
}

pub fn checkpoint_link_remap() -> TestResult {
    let bundle = match prepare_bundle() {
        Ok(b) => b,
        Err(e) => return TestResult::Failed(anyhow!("failed to prepare bundle: {e}")),
    };
    let id = generate_uuid().to_string();

    let spec = match link_remap_spec() {
        Ok(s) => s,
        Err(e) => return e,
    };
    if let Err(e) = set_config(&bundle, &spec) {
        return TestResult::Failed(anyhow!("failed to write config.json: {e}"));
    }

    let bundle_path = bundle.path();

    let cleanup = || {
        if let Ok(mut child) = kill_container(&id, bundle_path) {
            let _ = child.wait();
        }
        if let Ok(mut child) = delete_container(&id, bundle_path) {
            let _ = child.wait();
        }
    };

    if let Err(e) = create::create(bundle_path, &id) {
        cleanup();
        return TestResult::Failed(anyhow!("create container failed: {e}"));
    }

    if let Err(e) = start::start(bundle_path, &id) {
        cleanup();
        return TestResult::Failed(anyhow!("start container failed: {e}"));
    }

    if let Err(e) = wait_container_running(&id, bundle_path) {
        cleanup();
        return TestResult::Failed(anyhow!("container did not reach running state: {e}"));
    }

    let (_image_temp_dir, image_path) = match create_checkpoint_image_dir() {
        Ok(v) => v,
        Err(e) => {
            cleanup();
            return e;
        }
    };

    let result = checkpoint(bundle_path, &id, &image_path, vec!["--link-remap"], None);
    if let TestResult::Failed(_) = &result {
        cleanup();
        return result;
    }

    // youki cannot restore, so instead verify CRIU recorded the link-remap into
    // the image: dumping the open-but-unlinked file with --link-remap creates
    // remap-fpath.img (a remap entry with the `linked` flag set).
    let remap_img = image_path.join("remap-fpath.img");
    let result = if remap_img.exists() {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "expected remap-fpath.img to be created in the checkpoint image with --link-remap, \
             but it is missing at {remap_img:?}"
        ))
    };

    cleanup();
    result
}

/// Check that a namespace was treated as external by CRIU.
/// Fails if `<img_prefix>-*.img` is absent or lacks `ext_key`.
/// CRIU img files embed protobuf strings as raw UTF-8, so a byte search suffices.
fn check_external_ns(
    checkpoint_dir: &Path,
    img_prefix: &str,
    ext_key: &[u8],
) -> Result<(), TestResult> {
    let ns_img = std::fs::read_dir(checkpoint_dir)
        .map_err(|e| TestResult::Failed(anyhow::anyhow!("failed to read dir: {}", e)))?
        .flatten()
        .find(|e| e.file_name().to_string_lossy().starts_with(img_prefix))
        .map(|e| e.path());

    let img = ns_img.ok_or_else(|| {
        TestResult::Failed(anyhow::anyhow!(
            "{}-*.img not found in {:?}: namespace image is missing",
            img_prefix,
            checkpoint_dir,
        ))
    })?;

    let bytes = std::fs::read(&img)
        .map_err(|e| TestResult::Failed(anyhow::anyhow!("failed to read {:?}: {}", img, e)))?;
    if !bytes.windows(ext_key.len()).any(|w| w == ext_key) {
        return Err(TestResult::Failed(anyhow::anyhow!(
            "{:?} does not contain ext_key={}: namespace was not treated as external",
            img,
            String::from_utf8_lossy(ext_key),
        )));
    }

    Ok(())
}

/// Check that the network namespace was treated as external by CRIU.
pub fn check_external_netns(checkpoint_dir: &Path) -> Result<(), TestResult> {
    check_external_ns(checkpoint_dir, "netns", b"extRootNetNS")
}

/// Check that the PID namespace was treated as external by CRIU.
pub fn check_external_pidns(checkpoint_dir: &Path) -> Result<(), TestResult> {
    check_external_ns(checkpoint_dir, "pidns", b"extRootPidNS")
}

/// Checkpoint a container started with external network and PID namespaces.
/// Verifies that CRIU recorded both namespaces as external.
pub fn checkpoint_with_external_namespaces(project_path: &Path, id: &str) -> TestResult {
    let (_temp_dir, image_path) = match create_checkpoint_image_dir() {
        Ok(v) => v,
        Err(e) => return e,
    };

    let result = checkpoint(project_path, id, &image_path, vec!["--leave-running"], None);
    if !matches!(result, TestResult::Passed) {
        return result;
    }

    if let Err(e) = check_external_netns(&image_path) {
        return e;
    }

    if let Err(e) = check_external_pidns(&image_path) {
        return e;
    }

    TestResult::Passed
}
