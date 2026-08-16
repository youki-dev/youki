use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;
use anyhow::{Result, anyhow};
use oci_spec::runtime::{
    LinuxNamespaceBuilder, LinuxNamespaceType, MountBuilder, Spec,
};
use test_framework::{ConditionalTest, TestGroup, TestResult};
use crate::utils::{
    CreateOptions, State, create_container, criu_installed, delete_container, generate_uuid,
    get_runtime_path, kill_container, prepare_bundle, set_config, start_container,
    wait_container_running,
};

fn can_run() -> bool {
    criu_installed()
}

struct CheckpointTestContext {
    id: String,
    bundle: tempfile::TempDir,
}

impl CheckpointTestContext {
    fn new() -> Result<Self, TestResult> {
        let bundle = prepare_bundle()
            .map_err(|e| TestResult::Failed(anyhow!("failed to prepare bundle: {e}")))?;

        Ok(Self {
            id: generate_uuid().to_string(),
            bundle,
        })
    }

    fn bundle_path(&self) -> &Path {
        self.bundle.path()
    }

    fn create(&self) -> TestResult {
        let status = match create_container(
            &self.id,
            self.bundle_path(),
            &CreateOptions::default(),
        ) {
            Ok(mut child) => match child.wait() {
                Ok(status) => status,
                Err(e) => {
                    return TestResult::Failed(anyhow!(
                        "create command could not be waited on: {e}"
                    ));
                }
            },
            Err(e) => {
                return TestResult::Failed(anyhow!(
                    "create command could not be started: {e}"
                ));
            }
        };

        if status.success() {
            TestResult::Passed
        } else {
            TestResult::Failed(anyhow!(
                "created exited unsuccessfully ({status})"
            ))
        }
    }

    fn start(&self) -> TestResult {
        run_child(
            start_container(
                &self.id,
                self.bundle_path()
            ),
            "start"
        )
    }

    fn create_and_start(&self) -> TestResult {
        let result = self.create();
        if !matches!(result, TestResult::Passed) {
            return  result;
        }

        let result = self.start();
        if !matches!(result, TestResult::Passed) {
            return result;
        }

        match wait_container_running(&self.id, self.bundle_path()) {
            Ok(()) => TestResult::Passed,
            Err(e) => TestResult::Failed(anyhow!(
                "container did not reach running state: {e}"
            )),
        }
    }

    fn set_spec(&self, spec: &Spec) -> TestResult {
        match set_config(&self.bundle, spec) {
            Ok(()) => TestResult::Passed,
            Err(e) => TestResult::Failed(anyhow!(
                "failed to write config.json: {e}"
            )),
        }
    }
}

impl Drop for CheckpointTestContext {
    fn drop(&mut self) {
        if let Ok(mut child) = kill_container(&self.id, self.bundle_path()) {
            let _ = child.wait();
        }

        sleep(Duration::from_millis(100));

        if let Ok(mut child) = delete_container(&self.id, self.bundle_path()) {
            let _ = child.wait();
        }
    }
}

fn run_child(child: Result<Child>, action: &str) -> TestResult {
    let output = match child {
        Ok(child) => match child.wait_with_output() {
            Ok(output) => output,
            Err(e) => {
                return TestResult::Failed(anyhow!(
                    "{action} command could not be waited on: {e}"
                ));
            }
        },
        Err(e) => {
            return  TestResult::Failed(anyhow!(
                "{action} command could not be started: {e}"
            ));
        }
    };

    if output.status.success() {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "{action} exited unsuccessfully ({})\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

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

    let output = match checkpoint {
        Ok(output) => output,
        Err(e) => {
            return TestResult::Failed(anyhow!(
                "failed to execute checkpoint command: {e}"
            ));
        }
    };

    if !output.status.success() {
        return TestResult::Failed(anyhow!(
            "checkpoint command exited unsuccessfully ({})\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        ));
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

fn checkpoint_leave_running_work_path_tmp_impl(project_path: &Path, id: &str) -> TestResult {
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

fn checkpoint_leave_running_impl(project_path: &Path, id: &str) -> TestResult {
    let (_temp_dir, image_path) = match create_checkpoint_image_dir() {
        Ok(v) => v,
        Err(e) => return e,
    };

    checkpoint(project_path, id, &image_path, vec!["--leave-running"], None)
}

fn checkpoint_manage_cgroups_mode_ignore_impl(project_path: &Path, id: &str) -> TestResult {
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

fn checkpoint_manage_cgroups_mode_soft_impl(project_path: &Path, id: &str) -> TestResult {
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

fn checkpoint_link_remap(ctx: &CheckpointTestContext) -> TestResult {
    let spec = match link_remap_spec() {
        Ok(spec) => spec,
        Err(e) => return e,
    };

    let result = ctx.set_spec(&spec);
    if !matches!(result, TestResult::Passed) {
        return result;
    }

    let result = ctx.create_and_start();
    if !matches!(result, TestResult::Passed) {
        return result;
    }

    let (_image_temp_dir, image_path) = match create_checkpoint_image_dir() {
        Ok(value) => value,
        Err(e) => return e,
    };

    let result = checkpoint(
        ctx.bundle_path(),
        &ctx.id,
        &image_path,
        vec!["--link-remap"],
        None,
    );
    if !matches!(result, TestResult::Passed) {
        return result;
    }
    // youki cannot restore, so instead verify CRIU recorded the link-remap into
    // the image: dumping the open-but-unlinked file with --link-remap creates
    // remap-fpath.img (a remap entry with the `linked` flag set).
    let remap_img = image_path.join("remap-fpath.img");
    if remap_img.exists() {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "expected remap-fpath.img to be created in the checkpoint image with \
            --link-remap, but it is missing at {remap_img:?}"
        ))
    }
}

fn checkpoint_link_remap_test() -> TestResult {
    let ctx = match CheckpointTestContext::new() {
        Ok(ctx) => ctx,
        Err(e) => return e,
    };

    checkpoint_link_remap(&ctx)
}

// Polls until the listen socket on `port` has a queued, unaccepted connection,
// which is the in-flight state.
fn wait_in_flight(
    project_path: &Path,
    id: &str,
    port: u16,
    timeout: std::time::Duration,
) -> Result<(), TestResult> {
    // The in-flight connection only exists once lo is up. Until then the clients
    // running inside the container cannot reach 127.0.0.1, so no connection is
    // established and nothing accumulates in the accept queue for `ss` to report.
    // The container itself cannot bring lo up because the default spec grants no
    // NET_ADMIN, so we do it here from the host before polling. `checkpoint` brings
    // it up again later, but `ip link set up` is idempotent.
    setup_network_namespace(project_path, id)?;

    let pid = get_container_pid(project_path, id)?;
    let deadline = std::time::Instant::now() + timeout;

    loop {
        let output = Command::new("nsenter")
            .args(["-t", &pid.to_string(), "-n"])
            .args(["ss", "-Htl", &format!("sport = :{port}")])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| TestResult::Failed(anyhow!("failed to exec ss via nsenter: {e}")))?;

        // second column of `ss` is Recv-Q which is the accepted accept backlog depth.
        if String::from_utf8_lossy(&output.stdout).lines().any(|line| {
            line.split_whitespace()
                .nth(1)
                .and_then(|recv_q| recv_q.parse::<u32>().ok())
                .is_some_and(|recv_q| recv_q > 0)
        }) {
            return Ok(());
        }

        if std::time::Instant::now() >= deadline {
            return Err(TestResult::Failed(anyhow!(
                "timed out waiting for an in-flight connection on port {port}"
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn checkpoint_tcp_skip_in_flight(ctx: &CheckpointTestContext) -> TestResult {
    const PORT: u16 = 11111;

    let mut spec = Spec::default();
    let mut process = spec.process().clone().unwrap_or_default();

    process.set_args(Some(vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            "until ip addr show lo | grep -q 127.0.0.1; do sleep 0.1; done; \
            tcpsvd -c 0 0.0.0.0 {PORT} sleep 100000 & \
            sleep 100000 | nc 127.0.0.1 {PORT} & \
            while true; do sleep 1; done"
        ),
    ]));
    spec.set_process(Some(process));

    let result = ctx.set_spec(&spec);
    if !matches!(result, TestResult::Passed) {
        return result;
    }

    let result = ctx.create_and_start();
    if !matches!(result, TestResult::Passed) {
        return result;
    }

    if let Err(e) = wait_in_flight(
        ctx.bundle_path(),
        &ctx.id,
        PORT,
        Duration::from_secs(10),
    ) {
        return e;
    }

    let (_image_temp_dir, image_path) = match create_checkpoint_image_dir() {
        Ok(value) => value,
        Err(e) => return e,
    };

    let result = checkpoint(
        ctx.bundle_path(),
        &ctx.id,
        &image_path,
        vec!["--tcp-established", "--tcp-skip-in-flight"],
        None,
    );
    if !matches!(result, TestResult::Passed) {
        return result;
    }

    let has_tcp_stream_img = match std::fs::read_dir(&image_path) {
        Ok(entries) => entries
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().starts_with("tcp-stream-")),
        Err(e) => {
            return TestResult::Failed(anyhow!(
                "failed to read image dir {image_path:?}: {e}"
            ));
        }
    };

    if has_tcp_stream_img {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "checkpoint with --tcp-skip-in-flight succeeded but no tcp-stream-*.img \
            was written to {image_path:?}; the TCP connection state was not dumped"
        ))
    }
}

fn checkpoint_tcp_skip_in_flight_test() -> TestResult {
    let ctx = match CheckpointTestContext::new() {
        Ok(ctx) => ctx,
        Err(e) => return e,
    };

    checkpoint_tcp_skip_in_flight(&ctx)
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
fn checkpoint_with_external_namespaces_impl(project_path: &Path, id: &str) -> TestResult {
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

fn checkpoint_leave_running() -> TestResult {
    let ctx = match CheckpointTestContext::new() {
        Ok(ctx) => ctx,
        Err(e) => return e,
    };

    let result = ctx.create_and_start();
    if !matches!(result, TestResult::Passed) {
        return result;
    }

    checkpoint_leave_running_impl(ctx.bundle_path(), &ctx.id)
}

fn checkpoint_leave_running_work_path_tmp() -> TestResult {
    let ctx = match CheckpointTestContext::new() {
        Ok(ctx) => ctx,
        Err(e) => return e,
    };

    let result = ctx.create_and_start();
    if !matches!(result, TestResult::Passed) {
        return result;
    }

    checkpoint_leave_running_work_path_tmp_impl(ctx.bundle_path(), &ctx.id)
}

fn checkpoint_manage_cgroups_mode_ignore() -> TestResult {
    let ctx = match CheckpointTestContext::new() {
        Ok(ctx) => ctx,
        Err(e) => return e,
    };

    let result = ctx.create_and_start();
    if !matches!(result, TestResult::Passed) {
        return result;
    }

    checkpoint_manage_cgroups_mode_ignore_impl(ctx.bundle_path(), &ctx.id)
}

fn checkpoint_manage_cgroups_mode_soft() -> TestResult {
    let ctx = match CheckpointTestContext::new() {
        Ok(ctx) => ctx,
        Err(e) => return e,
    };

    let result = ctx.create_and_start();
    if !matches!(result, TestResult::Passed) {
        return result;
    }

    checkpoint_manage_cgroups_mode_soft_impl(ctx.bundle_path(), &ctx.id)
}

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
    project_path: &Path,
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

fn checkpoint_with_external_namespaces() -> TestResult {
    let ctx = match CheckpointTestContext::new() {
        Ok(ctx) => ctx,
        Err(e) => return e,
    };

    let netns_name = format!("youki_ckpt_{}", &ctx.id[..8]);
    let _netns_guard = match NetnsGuard::new(&netns_name) {
        Ok(guard) => guard,
        Err(_) => return TestResult::Skipped("ip netns unavailable".to_string()),
    };

    let netns_path = format!("/var/run/netns/{netns_name}");
    let spec = match build_external_ns_spec(
        ctx.bundle_path(),
        &netns_path,
        "/proc/self/ns/pid",
    ) {
        Ok(spec) => spec,
        Err(e) => {
            return TestResult::Failed(anyhow!(
                "failed to build spec with external namespaces: {e}"
            ));
        }
    };

    let result = ctx.set_spec(&spec);
    if !matches!(result, TestResult::Passed) {
        return  result;
    }

    let result = ctx.create_and_start();
    if !matches!(result, TestResult::Passed) {
        return result;
    }

    checkpoint_with_external_namespaces_impl(ctx.bundle_path(), &ctx.id)
}

pub fn get_checkpoint_tests() -> TestGroup {
    let mut tg = TestGroup::new("checkpoint");
    tg.set_nonparallel();

    macro_rules! checkpoint_test {
        ($name:expr, $function:expr) => {
            ConditionalTest::new($name, Box::new(can_run), Box::new($function))
        };
    }

    tg.add(vec![
        Box::new(checkpoint_test!(
            "checkpoint_leave_running_work_path_tmp",
            checkpoint_leave_running_work_path_tmp
        )),
        Box::new(checkpoint_test!(
            "checkpoint_leave_running",
            checkpoint_leave_running
        )),
        Box::new(checkpoint_test!(
            "checkpoint_manage_cgroups_mode_ignore",
            checkpoint_manage_cgroups_mode_ignore
        )),
        Box::new(checkpoint_test!(
            "checkpoint_manage_cgroups_mode_soft",
            checkpoint_manage_cgroups_mode_soft
        )),
        Box::new(checkpoint_test!(
            "checkpoint_link_remap",
            checkpoint_link_remap_test
        )),
        Box::new(checkpoint_test!(
            "checkpoint_tcp_skip_in_flight",
            checkpoint_tcp_skip_in_flight_test
        )),
        Box::new(checkpoint_test!(
            "checkpoint_with_external_namespaces",
            checkpoint_with_external_namespaces
        )),
    ]);

    tg
}