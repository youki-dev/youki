//! Contains utility functions for testing
//! Similar to https://github.com/opencontainers/runtime-tools/blob/master/validation/util/test.go
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use oci_spec::runtime::Spec;
use serde::{Deserialize, Serialize};
use test_framework::{test_result, TestResult};

use super::{generate_uuid, get_runtime_path, get_runtimetest_path, prepare_bundle, set_config};

const SLEEP_TIME: Duration = Duration::from_millis(150);
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

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

#[derive(Debug)]
pub struct ContainerData {
    pub id: String,
    pub state: Option<State>,
    pub state_err: String,
    pub create_result: std::io::Result<ExitStatus>,
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

pub fn start_container<P: AsRef<Path>>(id: &str, dir: P) -> Result<Child> {
    let res = runtime_command(dir)
        .arg("start")
        .arg(id)
        .spawn()
        .context("could not start container")?;
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
    spec: Spec,
    execute_test: &dyn Fn(ContainerData) -> TestResult,
) -> TestResult {
    let id = generate_uuid();
    let id_str = id.to_string();
    let bundle = prepare_bundle().unwrap();
    set_config(&bundle, &spec).unwrap();
    let options = CreateOptions::default();
    let create_result = create_container(&id_str, &bundle, &options).unwrap().wait();
    let (out, err) = get_state(&id_str, &bundle).unwrap();
    let state: Option<State> = match serde_json::from_str(&out) {
        Ok(v) => Some(v),
        Err(_) => None,
    };
    let data = ContainerData {
        id: id.to_string(),
        state,
        state_err: err,
        create_result,
    };
    let test_result = execute_test(data);
    kill_container(&id_str, &bundle).unwrap().wait().unwrap();
    delete_container(&id_str, &bundle).unwrap().wait().unwrap();
    test_result
}

// mostly needs a name that better expresses what this actually does
pub fn test_inside_container(
    spec: Spec,
    options: &CreateOptions,
    setup_for_test: &dyn Fn(&Path) -> Result<()>,
) -> TestResult {
    let id = generate_uuid();
    let id_str = id.to_string();
    let bundle = prepare_bundle().unwrap();

    // This will do the required setup for the test
    test_result!(setup_for_test(
        &bundle.as_ref().join("bundle").join("rootfs")
    ));

    set_config(&bundle, &spec).unwrap();
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
        Err(e) => return TestResult::Failed(anyhow!("container start failed : {:?}", e)),
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
        Err(e) => return TestResult::Failed(anyhow!("error in parsing state of container after start in test_inside_container : stdout : {}, parse error : {}",out,e)),
    };
    if state.status != "stopped" {
        return TestResult::Failed(anyhow!("error : unexpected container status in test_inside_runtime : expected stopped, got {}, container state : {:?}",state.status,state));
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
