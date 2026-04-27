//! Contains utility functions for testing
//! Similar to https://github.com/opencontainers/runtime-tools/blob/master/validation/util/test.go
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use nix::mount::{MntFlags, umount2};
use oci_spec::runtime::{LinuxNamespaceType, Spec};
use serde::{Deserialize, Serialize};
use test_framework::{TestResult, test_result};
use thiserror::Error;

use super::{generate_uuid, get_runtime_path, get_runtimetest_path, prepare_bundle, set_config};

const SLEEP_TIME: Duration = Duration::from_millis(150);
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Error, Debug)]
pub enum ContainerStateError {
    #[error("Failed to parse lifecycle status")]
    ParseLifecycleStatus(#[source] serde_json::Error),
    #[error("Container does not exist")]
    ContainerNotFound,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub oci_version: String,
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    pub bundle: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<u32>,
    pub use_systemd: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum LifecycleStatus {
    Creating,
    Created,
    Running,
    Stopped,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WaitTarget {
    Status(LifecycleStatus),
    // the state after the container is deleted
    // this state isn't in the runtime spec, but is useful for tests that wait for deletion
    Deleted,
}

#[derive(Debug)]
pub struct ContainerData {
    pub id: String,
    pub state: Option<State>,
    pub state_err: String,
    pub create_result: std::io::Result<ExitStatus>,
    pub bundle: PathBuf,
}

#[derive(Debug, Default)]
pub struct CreateOptions<'a> {
    extra_args: &'a [&'a OsStr],
    no_pivot: bool,
}

impl<'a> CreateOptions<'a> {
    pub fn with_extra_args(mut self, extra_args: &'a [&'a OsStr]) -> Self {
        self.extra_args = extra_args;
        self
    }

    pub fn with_no_pivot_root(mut self) -> Self {
        self.no_pivot = true;
        self
    }
}

fn create_container_command<P: AsRef<Path>>(id: &str, dir: P, options: &CreateOptions) -> Command {
    let mut command = Command::new(get_runtime_path());
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("--root")
        .arg(dir.as_ref().join("runtime"))
        .arg("create")
        .arg(id)
        .arg("--bundle")
        .arg(dir.as_ref().join("bundle"))
        .args(options.extra_args);
    if options.no_pivot {
        command.arg("--no-pivot");
    }
    command
}

/// Starts the runtime with given directory as root directory
pub fn create_container<P: AsRef<Path>>(
    id: &str,
    dir: P,
    options: &CreateOptions,
) -> Result<Child> {
    let res = create_container_command(id, dir, options)
        .spawn()
        .context("could not create container")?;
    Ok(res)
}

/// Sends a kill command to the given container process
pub fn kill_container<P: AsRef<Path>>(id: &str, dir: P) -> Result<Child> {
    let res = runtime_command(dir)
        .arg("kill")
        .arg(id)
        .arg("9")
        .spawn()
        .context("could not kill container")?;
    Ok(res)
}

pub fn delete_container<P: AsRef<Path>>(id: &str, dir: P) -> Result<Child> {
    let res = runtime_command(dir)
        .arg("delete")
        .arg(id)
        .spawn()
        .context("could not delete container")?;
    Ok(res)
}

pub fn get_state<P: AsRef<Path>>(id: &str, dir: P) -> Result<(String, String)> {
    sleep(SLEEP_TIME);
    let output = runtime_command(dir)
        .arg("state")
        .arg(id)
        .spawn()
        .context("could not get container state")?
        .wait_with_output()
        .context("failed while waiting for state command")?;
    let stderr = String::from_utf8(output.stderr).context("failed to parse std error stream")?;
    let stdout = String::from_utf8(output.stdout).context("failed to parse std output stream")?;
    Ok((stdout, stderr))
}

/// Get the container status as a LifecycleStatus
pub fn get_container_status<P: AsRef<Path>>(
    id: &str,
    dir: P,
) -> Result<LifecycleStatus, ContainerStateError> {
    let (stdout, stderr) = get_state(id, &dir).map_err(|e| {
        if e.to_string().contains("does not exist") {
            ContainerStateError::ContainerNotFound
        } else {
            ContainerStateError::Other(e)
        }
    })?;

    if stderr.contains("does not exist") {
        return Err(ContainerStateError::ContainerNotFound);
    }

    if stderr.contains("Error") || stderr.contains("error") {
        return Err(ContainerStateError::Other(anyhow!(
            "Error :\nstdout : {}\nstderr : {}",
            stdout,
            stderr
        )));
    }

    let value = serde_json::from_str::<serde_json::Value>(&stdout).map_err(|err| {
        ContainerStateError::Other(anyhow!(
            "Failed to parse state output as JSON: {} - {}",
            stdout,
            err
        ))
    })?;

    let status = value.get("status").ok_or_else(|| {
        ContainerStateError::Other(anyhow!(
            "Failed to extract status from state output: {}",
            stdout
        ))
    })?;

    serde_json::from_value::<LifecycleStatus>(status.clone())
        .map_err(ContainerStateError::ParseLifecycleStatus)
}

/// Check if a container matches the expected wait target
///
/// Returns `true` if the container state matches the expected target, `false` otherwise.
/// When `WaitTarget::Deleted` is specified, returns `true` if the container does not exist.
pub fn is_in_state<P: AsRef<Path>>(
    id: &str,
    dir: P,
    expected_target: WaitTarget,
) -> Result<bool, ContainerStateError> {
    match (get_container_status(id, &dir), expected_target) {
        (Ok(status), WaitTarget::Status(expected_status)) => Ok(status == expected_status),
        (Ok(_), WaitTarget::Deleted) => Ok(false),
        (Err(ContainerStateError::ContainerNotFound), WaitTarget::Deleted) => Ok(true),
        (Err(ContainerStateError::ContainerNotFound), WaitTarget::Status(_)) => Ok(false),
        (Err(e), _) => Err(e),
    }
}

/// Wait for a container to reach a specific wait target with timeout
pub fn wait_for_state<P: AsRef<Path>>(
    id: &str,
    dir: P,
    expected_target: WaitTarget,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<()> {
    let start = std::time::Instant::now();
    let deadline = start + timeout;

    while std::time::Instant::now() < deadline {
        match is_in_state(id, &dir, expected_target) {
            Ok(true) => return Ok(()),
            Ok(false) | Err(ContainerStateError::ParseLifecycleStatus(_)) => {
                std::thread::sleep(poll_interval)
            }
            Err(e) => {
                return Err(anyhow::Error::from(e).context(format!(
                    "Failed to wait for container {} to reach {:?} target",
                    id, expected_target
                )));
            }
        }
    }

    bail!(
        "Timed out waiting for container {} to reach {:?} target",
        id,
        expected_target
    )
}

pub fn start_container<P: AsRef<Path>>(id: &str, dir: P) -> Result<Child> {
    let res = runtime_command(dir)
        .arg("start")
        .arg(id)
        .spawn()
        .context("could not start container")?;
    Ok(res)
}

pub fn pause_container<P: AsRef<Path>>(id: &str, dir: P) -> Result<Child> {
    let res = runtime_command(dir)
        .arg("pause")
        .arg(id)
        .spawn()
        .context("could not pause container")?;
    Ok(res)
}

pub fn resume_container<P: AsRef<Path>>(id: &str, dir: P) -> Result<Child> {
    let res = runtime_command(dir)
        .arg("resume")
        .arg(id)
        .spawn()
        .context("could not resume container")?;
    Ok(res)
}

fn runtime_command<P: AsRef<Path>>(dir: P) -> Command {
    let mut command = Command::new(get_runtime_path());
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("--root")
        .arg(dir.as_ref().join("runtime"));
    command
}

pub fn test_outside_container(
    spec: &Spec,
    execute_test: &dyn Fn(ContainerData) -> TestResult,
) -> TestResult {
    let id = generate_uuid();
    let id_str = id.to_string();
    let bundle = prepare_bundle().unwrap();
    set_config(&bundle, spec).unwrap();
    let options = CreateOptions::default();
    let create_result = create_container(&id_str, &bundle, &options).unwrap().wait();
    let (out, err) = get_state(&id_str, &bundle).unwrap();
    let state: Option<State> = serde_json::from_str(&out).ok();
    let data = ContainerData {
        id: id.to_string(),
        state,
        state_err: err,
        create_result,
        bundle: bundle.path().to_path_buf(),
    };
    let test_result = execute_test(data);
    // this is to unmount the mounted rootfs. The issue here is that for ns_itype test
    // we do not create mount namespace, which results in mounting the actual root on bundle
    // thus the deletion in tempdir on drop fails and the tempdir remains. So, we check if there
    // is no mount namespace in the spec's namespaces, and if there is no mount namespace,
    // we manually unmount the rootfs so tmpdir deletion can succeed and cleanup is done.
    let ns = spec.linux().as_ref().and_then(|l| l.namespaces().clone());
    if let Some(ns) = ns
        && !ns.iter().any(|n| n.typ() == LinuxNamespaceType::Mount)
    {
        umount2(&bundle.path().join("bundle/rootfs"), MntFlags::MNT_DETACH).unwrap();
    }

    kill_container(&id_str, &bundle).unwrap().wait().unwrap();
    delete_container(&id_str, &bundle).unwrap().wait().unwrap();
    test_result
}

// mostly needs a name that better expresses what this actually does
pub fn test_inside_container(
    spec: &Spec,
    options: &CreateOptions,
    setup_for_test: &dyn Fn(&Path) -> Result<()>,
) -> TestResult {
    let id = generate_uuid();
    let id_str = id.to_string();
    let bundle = prepare_bundle().unwrap();

    set_config(&bundle, spec).unwrap();

    // This will do the required setup for the test
    test_result!(setup_for_test(
        &bundle.as_ref().join("bundle").join("rootfs")
    ));

    // as we have to run runtimetest inside the container, and is expects
    // the config.json to be at path /config.json we save it there
    let path = bundle
        .as_ref()
        .join("bundle")
        .join("rootfs")
        .join("config.json");
    spec.save(path).unwrap();

    let runtimetest_path = get_runtimetest_path();
    // The config will directly use runtime as the command to be run, so we have to
    // save the runtimetest binary at its /bin
    std::fs::copy(
        runtimetest_path,
        bundle
            .as_ref()
            .join("bundle")
            .join("rootfs")
            .join("bin")
            .join("runtimetest"),
    )
    .unwrap();
    let create_process = create_container(&id_str, &bundle, options).unwrap();
    // here we do not wait for the process by calling wait() as in the test_outside_container
    // function because we need the output of the runtimetest. If we call wait, it will return
    // and we won't have an easy way of getting the stdio of the runtimetest.
    // Thus to make sure the container is created, we just wait for sometime, and
    // assume that the create command was successful. If it wasn't we can catch that error
    // in the start_container, as we can not start a non-created container anyways
    std::thread::sleep(std::time::Duration::from_millis(1000));
    match start_container(&id_str, &bundle)
        .unwrap()
        .wait_with_output()
    {
        Ok(c) => c,
        Err(e) => {
            // given that start has failed, we can be pretty sure that create has either failed
            // or completed already, so we wait on it so it does not become a zombie process
            let _ = create_process.wait_with_output();
            return TestResult::Failed(anyhow!("container start failed : {:?}", e));
        }
    };

    let create_output = create_process
        .wait_with_output()
        .context("getting output after starting the container failed")
        .unwrap();

    let stdout = String::from_utf8_lossy(&create_output.stdout);
    if !stdout.is_empty() {
        println!(
            "{:?}",
            anyhow!("container stdout was not empty, found : {}", stdout)
        )
    }
    let stderr = String::from_utf8_lossy(&create_output.stderr);
    if !stderr.is_empty() {
        return TestResult::Failed(anyhow!(
            "container stderr was not empty, found : {}",
            stderr
        ));
    }

    let (out, err) = get_state(&id_str, &bundle).unwrap();
    if !err.is_empty() {
        return TestResult::Failed(anyhow!(
            "error in getting state after starting the container : {}",
            err
        ));
    }

    let state: State = match serde_json::from_str(&out) {
        Ok(v) => v,
        Err(e) => {
            return TestResult::Failed(anyhow!(
                "error in parsing state of container after start in test_inside_container : stdout : {}, parse error : {}",
                out,
                e
            ));
        }
    };
    if state.status != "stopped" {
        return TestResult::Failed(anyhow!(
            "error : unexpected container status in test_inside_runtime : expected stopped, got {}, container state : {:?}",
            state.status,
            state
        ));
    }
    kill_container(&id_str, &bundle).unwrap().wait().unwrap();
    delete_container(&id_str, &bundle).unwrap().wait().unwrap();
    TestResult::Passed
}

pub fn check_container_created(data: &ContainerData) -> Result<()> {
    match &data.create_result {
        Ok(exit_status) => {
            if !exit_status.success() {
                bail!(
                    "container creation was not successful. Exit code was {:?}",
                    exit_status.code()
                )
            }

            if !data.state_err.is_empty() {
                bail!(
                    "container state could not be retrieved successfully. Error was {}",
                    data.state_err
                );
            }

            if data.state.is_none() {
                bail!("container state could not be retrieved");
            }

            let container_state = data.state.as_ref().unwrap();
            if container_state.id != data.id {
                bail!(
                    "container state contains container id {}, but expected was {}",
                    container_state.id,
                    data.id
                );
            }

            if container_state.status != "created" {
                bail!(
                    "expected container to be in state created, but was in state {}",
                    container_state.status
                );
            }

            Ok(())
        }
        Err(e) => Err(anyhow!("{}", e)),
    }
}

/// Run a container with `run -d`.
/// Uses `Stdio::null()` to avoid the detached child process inheriting
/// pipe write-ends and blocking `wait()`.
pub fn run_container<P: AsRef<Path>>(id: &str, dir: P) -> Result<Child> {
    let res = Command::new(get_runtime_path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .arg("--root")
        .arg(dir.as_ref().join("runtime"))
        .arg("run")
        .arg("-d")
        .arg("--bundle")
        .arg(dir.as_ref().join("bundle"))
        .arg(id)
        .spawn()
        .context("could not run container")?;
    Ok(res)
}

/// Wait until a container reaches `Running` state (10 s timeout).
pub fn wait_container_running<P: AsRef<Path>>(id: &str, dir: P) -> Result<()> {
    wait_for_state(
        id,
        dir,
        WaitTarget::Status(LifecycleStatus::Running),
        Duration::from_secs(10),
        Duration::from_millis(100),
    )
}

/// Checkpoint a running container into `image_dir`.
/// `global_args` are passed before `--root` (e.g. `&["--debug"]`).
pub fn checkpoint_container(
    bundle_path: &Path,
    id: &str,
    image_dir: &Path,
    work_dir: Option<&Path>,
    checkpoint_args: &[&str],
    global_args: &[&str],
) -> Result<()> {
    let output = try_checkpoint_container(
        bundle_path,
        id,
        image_dir,
        work_dir,
        checkpoint_args,
        global_args,
    )?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "checkpoint failed ({}): stdout={stdout}, stderr={stderr}",
            output.status,
        );
    }

    if !image_dir.join("inventory.img").exists() {
        bail!("checkpoint incomplete: {image_dir:?}/inventory.img missing");
    }

    Ok(())
}

pub fn build_checkpoint_command(
    bundle_path: &Path,
    id: &str,
    image_dir: &Path,
    work_dir: Option<&Path>,
    checkpoint_args: &[&str],
    global_args: &[&str],
) -> Command {
    let mut command = Command::new(get_runtime_path());
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    for a in global_args {
        command.arg(a);
    }

    command.arg("--root").arg(bundle_path.join("runtime"));
    command.arg("checkpoint").arg("--image-path").arg(image_dir);

    if let Some(wp) = work_dir {
        command.arg("--work-path").arg(wp);
    }

    for a in checkpoint_args {
        command.arg(a);
    }

    command.arg(id);
    command
}

// Execute checkpoint command and return the raw output instead of bailing on failure.
pub fn try_checkpoint_container(
    bundle_path: &Path,
    id: &str,
    image_dir: &Path,
    work_dir: Option<&Path>,
    checkpoint_args: &[&str],
    global_args: &[&str],
) -> Result<std::process::Output> {
    build_checkpoint_command(
        bundle_path,
        id,
        image_dir,
        work_dir,
        checkpoint_args,
        global_args,
    )
    .spawn()
    .context("failed to spawn checkpoint")?
    .wait_with_output()
    .context("failed to wait for checkpoint")
}

/// Restore a checkpointed container from `image_dir` using `restore -d`.
/// `global_args` are runtime-level arguments passed before the subcommand (e.g., `youki --debug restore`).
/// `restore_args` are subcommand-level arguments passed after the subcommand (e.g., `youki restore --tcp-established`).
pub fn restore_container(
    bundle_path: &Path,
    id: &str,
    image_dir: &Path,
    work_dir: Option<&Path>,
    restore_args: &[&str],
    global_args: &[&str],
) -> Result<()> {
    let stderr_file = tempfile::NamedTempFile::new().context("failed to create temp file")?;

    let mut args: Vec<std::ffi::OsString> = global_args.iter().map(Into::into).collect();
    args.extend(["--root".into(), bundle_path.join("runtime").into()]);
    args.extend(["restore".into(), "-d".into()]);
    args.extend(["--bundle".into(), bundle_path.join("bundle").into()]);
    args.extend(["--image-path".into(), image_dir.into()]);
    if let Some(wp) = work_dir {
        args.extend(["--work-path".into(), wp.into()]);
    }
    for arg in restore_args {
        args.push(arg.into());
    }
    args.push(id.into());

    let status = Command::new(get_runtime_path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr_file.reopen().context("failed to reopen temp file")?)
        .args(&args)
        .spawn()
        .context("failed to spawn restore")?
        .wait()
        .context("failed to wait for restore")?;

    if !status.success() {
        let stderr = std::fs::read_to_string(stderr_file.path()).unwrap_or_default();
        bail!("restore failed ({}): {}", status, stderr);
    }

    Ok(())
}

/// Returns true if CRIU is installed on the host.
pub fn criu_installed() -> bool {
    which::which("criu").is_ok()
}

/// Returns true if the installed CRIU supports the given feature.
pub fn criu_has_feature(feature: &str) -> bool {
    Command::new(which::which("criu").unwrap())
        .arg("check")
        .arg("--feature")
        .arg(feature)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn build_exec_command<P: AsRef<Path>>(
    id: &str,
    dir: P,
    args: &[impl AsRef<OsStr>],
    process_path: Option<&Path>,
    env: &[(&str, &str)],
) -> Command {
    let mut command = runtime_command(&dir);
    command.arg("--debug").arg("exec");

    if let Some(path) = process_path {
        command.arg("--process").arg(path);
    }

    for (k, v) in env {
        command.arg("--env").arg(format!("{k}={v}"));
    }

    if process_path.is_none() {
        let mut opts = vec![];
        let mut cmd = vec![];
        let mut saw_cmd = false;

        for a in args {
            let s = a.as_ref();
            if !s.is_empty() && s.to_string_lossy().starts_with("--") && !saw_cmd {
                opts.push(s.to_owned());
            } else {
                saw_cmd = true;
                cmd.push(s.to_owned());
            }
        }

        command.args(&opts);
        command.arg(id);
        if !cmd.is_empty() {
            command.args(&cmd);
        }
    } else {
        command.arg(id);
    }

    command
}

pub fn exec_container<P: AsRef<Path>>(
    id: &str,
    dir: P,
    args: &[impl AsRef<OsStr>],
    process_path: Option<&Path>,
    env: &[(&str, &str)],
) -> Result<(String, String)> {
    let mut command = build_exec_command(id, dir, args, process_path, env);

    let output = command.output().context("failed to run exec")?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        bail!(
            "exec failed with status: {:?}, stderr: {}",
            output.status,
            stderr
        );
    }

    Ok((stdout, stderr))
}
