use std::path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use oci_spec::runtime::{LinuxNamespaceBuilder, LinuxNamespaceType, Spec};
use test_framework::{TestResult, TestableGroup};

use super::{checkpoint, create, delete, exec, kill, start, state};
use crate::utils::{criu_installed, generate_uuid, prepare_bundle, set_config};

/// RAII guard that deletes a named network namespace on drop.
struct NetnsGuard(String);

impl NetnsGuard {
    fn new(name: &str) -> Result<Self, anyhow::Error> {
        let out = Command::new("ip").args(["netns", "add", name]).output()?;
        if !out.status.success() {
            anyhow::bail!(
                "ip netns add {} failed: {}",
                name,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(Self(name.to_string()))
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).output();
    }
}

/// Build a spec that places the container in the given external netns and pidns.
/// Other namespaces retain the defaults from the bundle's config.json.
fn build_external_ns_spec(
    project_path: &path::Path,
    netns_path: &str,
    pidns_path: &str,
) -> Result<Spec, anyhow::Error> {
    let spec_path = project_path.join("bundle").join("config.json");
    let mut spec = Spec::load(spec_path)?;

    let mut namespaces = spec
        .linux()
        .as_ref()
        .and_then(|l| l.namespaces().as_ref())
        .cloned()
        .unwrap_or_default();

    // Replace or add network namespace with external path
    namespaces.retain(|ns| ns.typ() != LinuxNamespaceType::Network);
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Network)
            .path(netns_path)
            .build()?,
    );

    // Replace or add PID namespace with external path
    namespaces.retain(|ns| ns.typ() != LinuxNamespaceType::Pid);
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Pid)
            .path(pidns_path)
            .build()?,
    );

    let linux = spec.linux().as_ref().cloned().unwrap_or_default();
    let mut linux = linux;
    linux.set_namespaces(Some(namespaces));
    spec.set_linux(Some(linux));

    Ok(spec)
}

// By experimenting, somewhere around 50 is enough for youki process
// to get the kill signal and shut down
// here we add a little buffer time as well
const SLEEP_TIME: Duration = Duration::from_millis(75);

pub struct ContainerLifecycle {
    project_path: tempfile::TempDir,
    container_id: String,
}

impl Default for ContainerLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl ContainerLifecycle {
    pub fn new() -> Self {
        let id = generate_uuid();
        let bundle_dir = prepare_bundle().unwrap();
        ContainerLifecycle {
            project_path: bundle_dir,
            container_id: id.to_string(),
        }
    }

    pub fn set_id(&mut self, id: &str) {
        self.container_id = id.to_string();
    }

    pub fn get_id(&self) -> &str {
        &self.container_id
    }

    pub fn get_project_path(&self) -> &path::Path {
        self.project_path.path()
    }

    pub fn create(&self) -> TestResult {
        create::create(self.project_path.path(), &self.container_id).into()
    }

    pub fn create_with_spec(&self, spec: Spec) -> TestResult {
        set_config(&self.project_path, &spec).unwrap();
        create::create(self.project_path.path(), &self.container_id).into()
    }

    #[allow(dead_code)]
    pub fn exec(&self, cmd: Vec<&str>, expected_output: Option<&str>) -> TestResult {
        exec::exec(
            self.project_path.path(),
            &self.container_id,
            cmd,
            expected_output,
        )
        .into()
    }

    pub fn start(&self) -> TestResult {
        start::start(self.project_path.path(), &self.container_id).into()
    }

    pub fn state(&self) -> TestResult {
        state::state(self.project_path.path(), &self.container_id).into()
    }

    pub fn kill(&self) -> TestResult {
        let ret = kill::kill(self.project_path.path(), &self.container_id);
        // sleep a little, so the youki process actually gets the signal and shuts down
        // otherwise, the tester moves on to next tests before the youki has gotten signal, and delete test can fail
        sleep(SLEEP_TIME);
        ret.into()
    }

    pub fn delete(&self) -> TestResult {
        delete::delete(self.project_path.path(), &self.container_id).into()
    }

    pub fn checkpoint_leave_running(&self) -> TestResult {
        if !criu_installed() {
            return TestResult::Skipped;
        }

        checkpoint::checkpoint_leave_running(self.project_path.path(), &self.container_id)
    }

    pub fn checkpoint_leave_running_work_path_tmp(&self) -> TestResult {
        if !criu_installed() {
            return TestResult::Skipped;
        }

        checkpoint::checkpoint_leave_running_work_path_tmp(
            self.project_path.path(),
            &self.container_id,
        )
    }

    // ignore and soft are used as representative cases, as checkpoint behavior
    // primarily differs between ignore and other modes.
    pub fn checkpoint_manage_cgroups_mode_ignore(&self) -> TestResult {
        if !criu_installed() {
            return TestResult::Skipped;
        }

        checkpoint::checkpoint_manage_cgroups_mode_ignore(
            self.project_path.path(),
            &self.container_id,
        )
    }

    pub fn checkpoint_manage_cgroups_mode_soft(&self) -> TestResult {
        if !criu_installed() {
            return TestResult::Skipped;
        }

        checkpoint::checkpoint_manage_cgroups_mode_soft(
            self.project_path.path(),
            &self.container_id,
        )
    }

    /// Checkpoint a container that was started with an external network namespace
    /// and an external PID namespace, then verify CRIU recorded both as external.
    ///
    /// A named netns is created with `ip netns add` and `/proc/self/ns/pid` is
    /// used as the external PID namespace (the test runner's own PID namespace).
    pub fn checkpoint_with_external_namespaces(&self) -> TestResult {
        if !criu_installed() {
            return TestResult::Skipped;
        }

        // Create a dedicated lifecycle so the container starts with the right spec
        let inner = ContainerLifecycle::new();

        let netns_name = format!("youki_ckpt_{}", &inner.container_id[..8]);
        let _netns_guard = match NetnsGuard::new(&netns_name) {
            Ok(g) => g,
            Err(_) => return TestResult::Skipped, // ip netns unavailable
        };

        let netns_path = format!("/var/run/netns/{}", netns_name);
        let pidns_path = "/proc/self/ns/pid".to_string();

        let spec = match build_external_ns_spec(inner.project_path.path(), &netns_path, &pidns_path)
        {
            Ok(s) => s,
            Err(e) => {
                return TestResult::Failed(anyhow::anyhow!(
                    "failed to build spec with external namespaces: {}",
                    e
                ));
            }
        };

        let result = inner.create_with_spec(spec);
        if !matches!(result, TestResult::Passed) {
            return result;
        }

        let result = inner.start();
        if !matches!(result, TestResult::Passed) {
            inner.kill();
            inner.delete();
            return result;
        }

        let result = checkpoint::checkpoint_with_external_namespaces(
            inner.project_path.path(),
            &inner.container_id,
        );

        inner.kill();
        inner.delete();
        // _netns_guard drops here, deleting the named netns

        result
    }

    /// Wait for the container to reach a specific state
    pub fn wait_for_state(&self, expected_state: &str, timeout: Duration) -> TestResult {
        use crate::tests::lifecycle::state;

        match state::wait_for_state(
            self.project_path.path(),
            &self.container_id,
            expected_state,
            timeout,
            Duration::from_millis(100),
        ) {
            Ok(_) => TestResult::Passed,
            Err(e) => TestResult::Failed(anyhow::anyhow!(
                "Container failed to reach {} state: {}",
                expected_state,
                e
            )),
        }
    }
}

impl TestableGroup for ContainerLifecycle {
    fn get_name(&self) -> &'static str {
        "lifecycle"
    }

    fn parallel(&self) -> bool {
        true
    }

    fn run_all(&self) -> Vec<(&'static str, TestResult)> {
        vec![
            ("create", self.create()),
            ("start", self.start()),
            // ("exec", self.exec(vec!["echo", "Hello"], Some("Hello\n"))),
            (
                "checkpoint and leave running with --work-path /tmp",
                self.checkpoint_leave_running_work_path_tmp(),
            ),
            (
                "checkpoint and leave running",
                self.checkpoint_leave_running(),
            ),
            (
                "checkpoint with cgroups-mode ignore",
                self.checkpoint_manage_cgroups_mode_ignore(),
            ),
            (
                "checkpoint with cgroups-mode soft",
                self.checkpoint_manage_cgroups_mode_soft(),
            ),
            (
                "checkpoint with external namespaces",
                self.checkpoint_with_external_namespaces(),
            ),
            ("kill", self.kill()),
            ("state", self.state()),
            ("delete", self.delete()),
        ]
    }

    fn run_selected(&self, selected: &[&str]) -> Vec<(&'static str, TestResult)> {
        let mut ret = Vec::new();
        for name in selected {
            match *name {
                "create" => ret.push(("create", self.create())),
                "start" => ret.push(("start", self.start())),
                "checkpoint_leave_running_work_path_tmp" => ret.push((
                    "checkpoint and leave running with --work-path /tmp",
                    self.checkpoint_leave_running_work_path_tmp(),
                )),
                "checkpoint_leave_running" => ret.push((
                    "checkpoint and leave running",
                    self.checkpoint_leave_running(),
                )),
                "checkpoint_manage_cgroups_mode_ignore" => ret.push((
                    "checkpoint with cgroups-mode ignore",
                    self.checkpoint_manage_cgroups_mode_ignore(),
                )),
                "checkpoint_manage_cgroups_mode_soft" => ret.push((
                    "checkpoint with cgroups-mode soft",
                    self.checkpoint_manage_cgroups_mode_soft(),
                )),
                "checkpoint_with_external_namespaces" => ret.push((
                    "checkpoint with external namespaces",
                    self.checkpoint_with_external_namespaces(),
                )),
                "kill" => ret.push(("kill", self.kill())),
                "state" => ret.push(("state", self.state())),
                "delete" => ret.push(("delete", self.delete())),
                _ => eprintln!("No test named {name} in lifecycle"),
            };
        }
        ret
    }
}
