// Checkpoint and restore tests based on runc's tests/integration/checkpoint.bats.
//
// All tests are skipped when running with youki because checkpoint/restore is
// not yet implemented in youki.  They are also skipped when CRIU is not
// installed on the host.

use std::os::unix::fs::symlink;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use oci_spec::runtime::{LinuxNamespaceBuilder, LinuxNamespaceType, MountBuilder};
use test_framework::{ConditionalTest, TestGroup, TestResult};

use crate::utils::{
    LifecycleStatus, WaitTarget, build_checkpoint_command, checkpoint_container, criu_has_feature,
    criu_installed, delete_container, exec_container, generate_uuid, get_container_pid,
    get_runtime_path, handle_console_socket, is_runtime_youki, kill_container, net, prepare_bundle,
    restore_container, set_config, try_checkpoint_container, wait_container_running,
    wait_for_state,
};

/// Used as check_fn for all ConditionalTests in this module:
/// run only when the runtime is NOT youki and CRIU is installed.
fn can_run() -> bool {
    // TODO: remove this skip for youki once checkpoint/restore is supported.
    !is_runtime_youki() && criu_installed()
}

fn is_cgroups_v1() -> bool {
    Path::new("/sys/fs/cgroup/pids").exists()
}

fn has_cgroupns() -> bool {
    Path::new("/proc/self/ns/cgroup").exists()
}

struct CrTestContext {
    id: String,
    restore_id: Option<String>,
    bundle: tempfile::TempDir,
    image_dir: PathBuf,
    work_dir: PathBuf,
}

impl Drop for CrTestContext {
    fn drop(&mut self) {
        let cleanup = |id: &str, bundle: &Path| {
            if let Ok(mut child) = kill_container(id, bundle) {
                let _ = child.wait();
            }

            std::thread::sleep(Duration::from_millis(100));

            if let Ok(mut child) = delete_container(id, bundle) {
                let _ = child.wait();
            }
        };

        // Clean up primary container
        cleanup(&self.id, self.bundle.path());
        // Clean up the dynamically registered restore ID (if any)
        if let Some(rid) = self.restore_id.as_ref() {
            cleanup(rid, self.bundle.path());
        }
    }
}

impl CrTestContext {
    fn register_restore_id(&mut self, rid: String) {
        self.restore_id = Some(rid);
    }

    // TODO: Consider extracting this into test_utils.rs as run_container_with_console (see issue #3529)
    fn start(&self) -> Result<(), TestResult> {
        let runtime_path = get_runtime_path();
        let actual_bundle_path = self.bundle.path().join("bundle");
        let console_socket = self.bundle.path().join("console.sock");
        let listener = std::os::unix::net::UnixListener::bind(&console_socket)
            .map_err(|e| TestResult::Failed(anyhow!("failed to bind console socket: {e}")))?;

        let run_result = (|| -> Result<()> {
            let mut child = std::process::Command::new(runtime_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .arg("--root")
                .arg(self.bundle.path().join("runtime"))
                .arg("run")
                .arg("-d")
                .arg("--bundle")
                .arg(&actual_bundle_path)
                .arg("--console-socket")
                .arg(&console_socket)
                .arg(&self.id)
                .current_dir(self.bundle.path())
                .spawn()?;

            let (stream, _) = listener.accept()?;
            handle_console_socket(stream);

            let status = child.wait()?;
            if !status.success() {
                bail!("run -d failed ({status})");
            }

            wait_container_running(&self.id, &self.bundle)?;
            ping_container(self.bundle.path())
        })();

        if let Err(e) = run_result {
            return Err(TestResult::Failed(anyhow!(
                "container did not reach running state: {e}"
            )));
        }

        Ok(())
    }
}

/// Verifies that the container process is actively running and responsive
/// by writing a "Ping" message to the FIFO and expecting a "ponG Ping" response.
fn ping_container(bundle: &Path) -> Result<()> {
    let fifo_path = bundle.join("fifo");
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let res = (|| -> Result<()> {
            let mut f_out = std::fs::OpenOptions::new().write(true).open(&fifo_path)?;
            std::io::Write::write_all(&mut f_out, b"Ping\n")?;
            drop(f_out);

            let f_in = std::fs::OpenOptions::new().read(true).open(&fifo_path)?;
            let mut reader = std::io::BufReader::new(f_in);
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line)?;
            if line.trim() != "ponG Ping" {
                bail!("Unexpected response from container: {:?}", line);
            }
            Ok(())
        })();
        let _ = tx.send(res);
    });

    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow!("ping_container timed out")),
    }
}

fn generate_cr_spec(
    bundle_path: &Path,
    fifo_path: &Path,
) -> Result<oci_spec::runtime::Spec, TestResult> {
    let runtime_path = get_runtime_path();
    let actual_bundle_path = bundle_path.join("bundle");

    let existing_config = actual_bundle_path.join("config.json");
    if existing_config.exists() {
        let _ = std::fs::remove_file(&existing_config);
    }

    let output = Command::new(runtime_path)
        .arg("spec")
        .current_dir(&actual_bundle_path)
        .output()
        .map_err(|e| TestResult::Failed(anyhow!("failed to execute youki spec: {e}")))?;

    if !output.status.success() {
        return Err(TestResult::Failed(anyhow!(
            "youki spec failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let config_path = actual_bundle_path.join("config.json");
    let mut spec = oci_spec::runtime::Spec::load(&config_path)
        .map_err(|e| TestResult::Failed(anyhow!("failed to load generated config.json: {e}")))?;

    let mut process = spec.process().clone().unwrap_or_default();
    process.set_args(Some(vec![
        "sh".into(),
        "-c".into(),
        "while true; do read p < /fifo; if [ \"$p\" = 'Ping' ]; then echo \"ponG $p\" > /fifo; fi; done".into(),
    ]));

    process.set_terminal(Some(true));
    spec.set_process(Some(process));

    // The container will read from /fifo and write "ponG <msg>" back to it.
    // This is different from runc's e2e tests, which use Bash process substitution to
    // create anonymous pipes and pass them to runc via standard I/O redirection.
    // Replicating that persistent file-descriptor inheritance across separate Rust
    // `Command` invocations (run -> checkpoint -> restore) is complex and fragile.
    // By using FIFOs on the host filesystem, CRIU automatically dumps and restores
    // the IPC endpoint purely based on the file path, without any orchestrator I/O magic.
    let bind_mount = oci_spec::runtime::MountBuilder::default()
        .source(fifo_path)
        .destination(PathBuf::from("/fifo"))
        .options(vec!["bind".to_string()])
        .build()
        .unwrap();

    let mut mounts = spec.mounts().clone().unwrap_or_default();
    mounts.push(bind_mount);
    spec.set_mounts(Some(mounts));

    Ok(spec)
}

fn setup_cr_test(
    mut setup: impl FnMut(&tempfile::TempDir, &mut oci_spec::runtime::Spec),
) -> Result<CrTestContext, TestResult> {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();

    // Prepare a FIFO path for testing IPC with the container. We use FIFOs instead of pipes
    // because they are simpler to mount and expose a named endpoint on the host.
    let fifo_path = bundle.path().join("fifo");
    if let Err(e) = nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::from_bits_truncate(0o666))
    {
        return Err(TestResult::Failed(anyhow!("mkfifo failed: {e}")));
    }

    let mut spec = generate_cr_spec(bundle.path(), &fifo_path)?;

    setup(&bundle, &mut spec);
    if let Err(e) = set_config(&bundle, &spec) {
        return Err(TestResult::Failed(anyhow!("set_config: {e}")));
    }

    let image_dir = bundle.path().join("image-dir");
    if let Err(e) = std::fs::create_dir_all(&image_dir) {
        return Err(TestResult::Failed(anyhow!("mkdir image-dir: {e}")));
    }

    let work_dir = bundle.path().join("work-dir");
    if let Err(e) = std::fs::create_dir_all(&work_dir) {
        return Err(TestResult::Failed(anyhow!("mkdir work-dir: {e}")));
    }

    Ok(CrTestContext {
        id,
        restore_id: None,
        bundle,
        image_dir,
        work_dir,
    })
}

/// Full checkpoint+restore test: prepares a bundle, calls `setup_cr_test` to allow the
/// caller to customise the spec, then runs 2 checkpoint→restore cycles.
/// The first cycle verifies a normal container can be checkpointed and restored;
/// the second verifies the restored container can itself be checkpointed and
/// restored again.
///
/// The `verify_state` closure is used to assert container state. It is executed twice
/// during the lifecycle:
/// 1. Immediately after the container initially starts.
/// 2. Immediately after the container is successfully restored (in each iteration).
fn simple_cr(
    global_args: &[&str],
    setup: impl Fn(&tempfile::TempDir, &mut oci_spec::runtime::Spec),
    verify_state: impl Fn(&str, &Path) -> Result<()>,
) -> TestResult {
    let ctx = match setup_cr_test(setup) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if let Err(e) = ctx.start() {
        return e;
    }

    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;

    if let Err(e) = verify_state(id, bundle.path()) {
        return TestResult::Failed(anyhow!("verify_state failed after run: {e}"));
    }

    for _ in 0..2 {
        if let Err(e) = checkpoint_container(
            bundle.path(),
            id,
            image_dir,
            Some(work_dir),
            &[],
            global_args,
        ) {
            return TestResult::Failed(anyhow!("checkpoint failed: {e}"));
        }

        // After a successful checkpoint the runtime must remove the container
        // from its state, so `state <id>` should fail (exit code != 0).
        // This mirrors runc's `testcontainer "$CT_ID" checkpointed` check.
        if let Err(e) = wait_for_state(
            id,
            bundle,
            WaitTarget::Deleted,
            Duration::from_secs(5),
            Duration::from_millis(100),
        ) {
            return TestResult::Failed(anyhow!(
                "container state still accessible after checkpoint: {e}"
            ));
        }

        if let Err(e) = restore_container(
            bundle.path(),
            id,
            image_dir,
            Some(work_dir),
            &[],
            global_args,
        ) {
            return TestResult::Failed(anyhow!("restore failed: {e}"));
        }

        if let Err(e) = wait_for_state(
            id,
            bundle,
            WaitTarget::Status(LifecycleStatus::Running),
            Duration::from_secs(10),
            Duration::from_millis(100),
        ) {
            return TestResult::Failed(anyhow!("not running after restore: {e}"));
        }

        if let Err(e) = ping_container(bundle.path()) {
            return TestResult::Failed(anyhow!("ping container failed after restore: {e}"));
        }

        if let Err(e) = verify_state(id, bundle.path()) {
            return TestResult::Failed(anyhow!("verify_state failed after restore: {e}"));
        }
    }

    TestResult::Passed
}

// Test: checkpoint and restore
// (runc: @test "checkpoint and restore")
fn checkpoint_and_restore() -> TestResult {
    simple_cr(&[], |_, _| {}, |_, _| Ok(()))
}

// Test: checkpoint and restore (bind mount, destination is symlink)
// (runc: @test "checkpoint and restore (bind mount, destination is symlink)")
fn checkpoint_and_restore_bind_mount_symlink() -> TestResult {
    simple_cr(
        &[],
        |bundle, spec| {
            let rootfs = bundle.path().join("bundle").join("rootfs");
            std::fs::create_dir_all(rootfs.join("real/conf")).unwrap();
            symlink("/real/conf", rootfs.join("conf")).unwrap();
            let bind_mount = MountBuilder::default()
                .source(bundle.path().join("bundle"))
                .destination("/conf")
                .options(vec!["bind".to_string()])
                .build()
                .unwrap();
            let mut mounts = spec.mounts().clone().unwrap_or_default();
            mounts.push(bind_mount);
            spec.set_mounts(Some(mounts));
        },
        |_, _| Ok(()),
    )
}

// Test: checkpoint and restore (with --debug)
// (runc: @test "checkpoint and restore (with --debug)")
fn checkpoint_and_restore_with_debug() -> TestResult {
    simple_cr(&["--debug"], |_, _| {}, |_, _| Ok(()))
}

// Test: checkpoint and restore (cgroupns)
// (runc: @test "checkpoint and restore (cgroupns)")
// Requires: cgroups v1 + cgroupns
fn checkpoint_and_restore_cgroupns() -> TestResult {
    // cgroupv2 already enables cgroupns, so only run on cgroups v1 with cgroupns
    if !is_cgroups_v1() || !has_cgroupns() {
        return TestResult::Skipped;
    }
    simple_cr(
        &[],
        |_, spec| {
            if let Some(linux) = spec.linux_mut() {
                let mut namespaces = linux.namespaces().clone().unwrap_or_default();
                namespaces.push(
                    LinuxNamespaceBuilder::default()
                        .typ(LinuxNamespaceType::Cgroup)
                        .build()
                        .unwrap(),
                );
                linux.set_namespaces(Some(namespaces));
            }
        },
        |_, _| Ok(()),
    )
}

// Test: checkpoint and restore with netdevice
// (runc: @test "checkpoint and restore with netdevice")
fn checkpoint_and_restore_with_netdevice() -> TestResult {
    let ns_name = net::create_unique_name("cr-net");
    let dev_name = net::create_unique_name("cr-dev");
    let _netns = match net::NetNamespace::create(ns_name.clone()) {
        Ok(ns) => ns,
        Err(e) => return TestResult::Failed(anyhow!("Failed to create netns: {e}")),
    };
    let _dev = match net::DummyDevice::create(dev_name.clone()) {
        Ok(d) => d,
        Err(e) => return TestResult::Failed(anyhow!("Failed to create dummy dev: {e}")),
    };

    let mtu = "1789";
    let mac = "00:11:22:33:44:55";
    let ip = "169.254.169.77/32";

    let out = match Command::new("ip")
        .args(["link", "set", &dev_name, "netns", &ns_name])
        .output()
    {
        Ok(out) => out,
        Err(e) => return TestResult::Failed(anyhow!("ip link set netns execution failed: {e}")),
    };
    if !out.status.success() {
        return TestResult::Failed(anyhow!(
            "ip link set netns failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let out = match Command::new("ip")
        .args(["-n", &ns_name, "link", "set", "mtu", mtu, "dev", &dev_name])
        .output()
    {
        Ok(out) => out,
        Err(e) => return TestResult::Failed(anyhow!("ip link set mtu execution failed: {e}")),
    };
    if !out.status.success() {
        return TestResult::Failed(anyhow!(
            "ip link set mtu failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let out = match Command::new("ip")
        .args([
            "-n", &ns_name, "link", "set", "address", mac, "dev", &dev_name,
        ])
        .output()
    {
        Ok(out) => out,
        Err(e) => return TestResult::Failed(anyhow!("ip link set address execution failed: {e}")),
    };
    if !out.status.success() {
        return TestResult::Failed(anyhow!(
            "ip link set address failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let out = match Command::new("ip")
        .args(["-n", &ns_name, "address", "add", ip, "dev", &dev_name])
        .output()
    {
        Ok(out) => out,
        Err(e) => return TestResult::Failed(anyhow!("ip address add execution failed: {e}")),
    };
    if !out.status.success() {
        return TestResult::Failed(anyhow!(
            "ip address add failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let ns_path = format!("/run/netns/{ns_name}");

    simple_cr(
        &[],
        move |_, spec| {
            let mut namespaces = spec
                .linux()
                .as_ref()
                .and_then(|l| l.namespaces().clone())
                .unwrap_or_default();
            namespaces.retain(|ns| ns.typ() != LinuxNamespaceType::Network);
            namespaces.push(
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Network)
                    .path(ns_path.clone())
                    .build()
                    .unwrap(),
            );

            if let Some(linux) = spec.linux_mut() {
                linux.set_namespaces(Some(namespaces));
            }
        },
        move |id, bundle_path| {
            let (stdout, _) = exec_container(
                id,
                bundle_path,
                &["ip", "address", "show", "dev", &dev_name],
                None,
                &[],
            )?;
            if !stdout.contains(ip) {
                bail!("ip address not found in {stdout}");
            }
            if !stdout.contains(&format!("ether {mac}")) {
                bail!("mac address not found in {stdout}");
            }
            if !stdout.contains(&format!("mtu {mtu}")) {
                bail!("mtu not found in {stdout}");
            }
            Ok(())
        },
    )
}

// Test: checkpoint --pre-dump (bad --parent-path)
// (runc: @test "checkpoint --pre-dump (bad --parent-path)")
fn checkpoint_pre_dump_bad_parent_path() -> TestResult {
    let ctx = match setup_cr_test(|_, _| {}) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = ctx.start() {
        return e;
    }

    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;

    let absolute_parent = bundle.path().join("parent-dir");
    let output1 = try_checkpoint_container(
        bundle.path(),
        id,
        image_dir,
        Some(work_dir),
        &["--parent-path", absolute_parent.to_str().unwrap()],
        &[],
    )
    .unwrap();

    // We expect an absolute parent-path to fail. This mimics runc's integration test behavior.
    // Under the hood, runc maps `--parent-path` to CRIU's `--prev-images-dir` flag.
    // CRIU links incremental dumps by creating a "parent" symlink between image directories.
    // If the path is absolute, the symlink hardcodes the host path, which can break when
    // restoring the container in a different environment or mount space. Thus, CRIU and runc
    // strictly enforce relative paths to ensure self-contained, portable image directories.
    // See CRIU source: `criu/image.c` symlinkat logic for CR_PARENT_LINK
    // https://github.com/checkpoint-restore/criu/blob/criu-dev/criu/image.c#L746
    if output1.status.success() {
        return TestResult::Failed(anyhow!(
            "expected checkpoint to fail with absolute --parent-path"
        ));
    }
    let stderr1 = String::from_utf8_lossy(&output1.stderr);
    if !stderr1.contains("--parent-path") {
        return TestResult::Failed(anyhow!(
            "expected error containing '--parent-path' but got stderr: {stderr1}"
        ));
    }

    let output2 = try_checkpoint_container(
        bundle.path(),
        id,
        image_dir,
        Some(work_dir),
        &["--parent-path", "./parent-dir"],
        &[],
    )
    .unwrap();

    if output2.status.success() {
        return TestResult::Failed(anyhow!(
            "expected checkpoint to fail with non-existent relative --parent-path"
        ));
    }
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    if !stderr2.contains("--parent-path") {
        return TestResult::Failed(anyhow!(
            "expected error containing '--parent-path' but got stderr: {stderr2}"
        ));
    }

    TestResult::Passed
}

// Test: checkpoint --pre-dump and restore
// (runc: @test "checkpoint --pre-dump and restore")
fn checkpoint_pre_dump_and_restore() -> TestResult {
    if !criu_has_feature("mem_dirty_track") {
        return TestResult::Skipped;
    }

    let ctx = match setup_cr_test(|_, _| {}) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = ctx.start() {
        return e;
    }

    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;

    let parent_dir = bundle.path().join("parent-dir");
    if let Err(e) = std::fs::create_dir_all(&parent_dir) {
        return TestResult::Failed(anyhow!("failed to create parent dir: {e}"));
    }

    if let Err(e) = checkpoint_container(bundle.path(), id, &parent_dir, None, &["--pre-dump"], &[])
    {
        return TestResult::Failed(anyhow!("pre-dump checkpoint failed: {e}"));
    }

    if let Err(e) = wait_for_state(
        id,
        bundle,
        WaitTarget::Status(LifecycleStatus::Running),
        Duration::from_secs(5),
        Duration::from_millis(100),
    ) {
        return TestResult::Failed(anyhow!("container not running after pre-dump: {e}"));
    }

    let relative_parent = "../parent-dir";
    let output2 = try_checkpoint_container(
        bundle.path(),
        id,
        image_dir,
        Some(work_dir),
        &["--parent-path", relative_parent],
        &[],
    )
    .unwrap();

    if !output2.status.success() {
        let stderr = String::from_utf8_lossy(&output2.stderr);
        return TestResult::Failed(anyhow!("final checkpoint failed: {stderr}"));
    }

    // Check parent path is valid
    if !image_dir.join("parent").exists() {
        return TestResult::Failed(anyhow!("parent link in image-dir was not created"));
    }

    if let Err(e) = wait_for_state(
        id,
        bundle,
        WaitTarget::Deleted,
        Duration::from_secs(5),
        Duration::from_millis(100),
    ) {
        return TestResult::Failed(anyhow!(
            "container state still accessible after final checkpoint: {e}"
        ));
    }

    if let Err(e) = restore_container(bundle.path(), id, image_dir, Some(work_dir), &[], &[]) {
        return TestResult::Failed(anyhow!("restore failed: {e}"));
    }

    if let Err(e) = wait_for_state(
        id,
        bundle,
        WaitTarget::Status(LifecycleStatus::Running),
        Duration::from_secs(10),
        Duration::from_millis(100),
    ) {
        return TestResult::Failed(anyhow!("not running after restore: {e}"));
    }

    if let Err(e) = ping_container(bundle.path()) {
        return TestResult::Failed(anyhow!("ping container failed after restore: {e}"));
    }

    TestResult::Passed
}

// Test: checkpoint --lazy-pages and restore
// (runc: @test "checkpoint --lazy-pages and restore")
fn checkpoint_lazy_pages_and_restore() -> TestResult {
    if !criu_has_feature("uffd-noncoop") {
        return TestResult::Skipped;
    }

    let mut ctx = match setup_cr_test(|_, _| {}) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = ctx.start() {
        return e;
    }

    let id = ctx.id.clone();
    let restore_id = format!("{id}-restore");
    ctx.register_restore_id(restore_id.clone());
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;

    // For lazy migration we need to know when CRIU is ready to serve
    // the memory pages via TCP. We use a pipe to get the readiness status.
    let (pipe_r, pipe_w) = match nix::unistd::pipe() {
        Ok(p) => p,
        Err(e) => return TestResult::Failed(anyhow!("failed to create pipe: {e}")),
    };

    // Dynamically allocate a free ephemeral port for the CRIU lazy-pages server.
    // Hardcoding a port (like 27277) causes "Address already in use" errors and subsequent
    // test hangs if a previous test run failed/panicked and leaked the page server daemon.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    drop(listener);
    let status_fd_str = pipe_w.as_raw_fd().to_string();

    // Spawn checkpoint command in background.
    // We use spawn() instead of try_checkpoint_container() (which uses output() and blocks)
    // because we need to read from the status-fd pipe concurrently to wait for the page server readiness.
    let port_str = format!("0.0.0.0:{}", port);
    let mut checkpoint_cmd = build_checkpoint_command(
        bundle.path(),
        &id,
        image_dir,
        Some(work_dir),
        &[
            "--lazy-pages",
            "--page-server",
            &port_str,
            "--status-fd",
            &status_fd_str,
            "--manage-cgroups-mode=ignore",
        ],
        &[],
    );

    checkpoint_cmd.stdout(std::process::Stdio::null());
    checkpoint_cmd.stderr(std::process::Stdio::piped());

    let pipe_w_raw = pipe_w.as_raw_fd();

    // Ensure the child process inherits the write end of the pipe
    unsafe {
        checkpoint_cmd.pre_exec(move || {
            let flags = FdFlag::from_bits_truncate(
                fcntl(pipe_w_raw, FcntlArg::F_GETFD).expect("fcntl failed"),
            );
            fcntl(pipe_w_raw, FcntlArg::F_SETFD(flags & !FdFlag::FD_CLOEXEC))
                .expect("fcntl failed");
            Ok(())
        });
    }

    let mut checkpoint_child = match checkpoint_cmd.spawn() {
        Ok(c) => c,
        Err(e) => return TestResult::Failed(anyhow!("failed to spawn checkpoint: {e}")),
    };

    // Close the write end in the parent immediately so read() will get EOF if CRIU exits
    drop(pipe_w);

    // Set read pipe to non-blocking so the timeout loop isn't blocked forever if no data arrives
    let flags = nix::fcntl::OFlag::from_bits_truncate(
        fcntl(pipe_r.as_raw_fd(), nix::fcntl::FcntlArg::F_GETFL).expect("F_GETFL failed"),
    );
    fcntl(
        pipe_r.as_raw_fd(),
        nix::fcntl::FcntlArg::F_SETFL(flags | nix::fcntl::OFlag::O_NONBLOCK),
    )
    .expect("F_SETFL failed");

    // Wait for CRIU to become ready by reading from the pipe
    let mut buf = [0u8; 1];
    let mut ready = false;

    // Timeout reading after 2 seconds
    for _ in 0..20 {
        match nix::unistd::read(pipe_r.as_raw_fd(), &mut buf) {
            Ok(1) => {
                ready = true;
                break;
            }
            Ok(0) => {
                // EOF - CRIU died or closed its end early
                break;
            }
            Err(nix::errno::Errno::EAGAIN) => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }

    if !ready {
        let _ = checkpoint_child.kill();
        let _ = checkpoint_child.wait();
        let stderr_msg = checkpoint_child
            .stderr
            .take()
            .map(|mut s| {
                let mut msg = String::new();
                let _ = std::io::Read::read_to_string(&mut s, &mut msg);
                msg
            })
            .unwrap_or_default();
        return TestResult::Failed(anyhow!(
            "lazy-page server readiness timeout. stderr: {}",
            stderr_msg.trim()
        ));
    }

    // Check if inventory.img was written
    if !image_dir.join("inventory.img").exists() {
        let _ = checkpoint_child.kill();
        let _ = checkpoint_child.wait();
        return TestResult::Failed(anyhow!("inventory.img was not written to image-dir"));
    }

    // Start CRIU in lazy-daemon mode
    let criu_daemon_child = match std::process::Command::new("criu")
        .args([
            "lazy-pages",
            "--page-server",
            "--address",
            "127.0.0.1",
            "--port",
            port.as_str(),
            "-D",
            image_dir.to_str().unwrap(),
        ])
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = checkpoint_child.kill();
            return TestResult::Failed(anyhow!("failed to spawn criu lazy-pages: {e}"));
        }
    };

    // We must restore the container into a different cgroup because the original
    // container is still running. If we don't use a different cgroup, the restored
    // container and the original container will conflict.
    // This is particularly due to the behavior when systemd is used as the cgroup
    // manager, as it can cause `systemd` to become confused about the container's
    // state and potentially send SIGTERM to the process.
    // See also runc's checkpoint tests:
    // https://github.com/opencontainers/runc/blob/eb7eaf19b6eec5d1143b257057899e4a7b738c81/tests/integration/checkpoint.bats#L303
    let new_cgroup = format!("/runtime-test/cgroup-2-{restore_id}");
    let mut spec =
        oci_spec::runtime::Spec::load(bundle.path().join("bundle").join("config.json")).unwrap();
    if let Some(linux) = spec.linux_mut() {
        linux.set_cgroups_path(Some(PathBuf::from(&new_cgroup)));
    }
    set_config(bundle.path(), &spec).unwrap();

    let restore_result = restore_container(
        bundle.path(),
        &restore_id,
        image_dir,
        Some(image_dir),
        &["--lazy-pages", "--manage-cgroups-mode=ignore"],
        &[],
    );

    // When the container is successfully restored, the restore process sends a close command
    // to the CRIU lazy-page daemon, causing it to exit naturally. However, if the restore fails
    // or hangs, the daemon will remain alive indefinitely waiting for TCP connections.
    // We unconditionally send a kill signal to ensure cleanup, safely ignoring any errors
    // if the daemon has already exited.
    let mut criu_daemon = criu_daemon_child;

    if let Err(e) = restore_result {
        let _ = criu_daemon.kill();
        let _ = criu_daemon.wait();
        let _ = checkpoint_child.kill();
        let _ = checkpoint_child.wait();
        return TestResult::Failed(anyhow!("restore --lazy-pages failed: {e}"));
    }

    // Wait for background jobs to finish
    let _ = criu_daemon.wait();
    let _ = checkpoint_child.wait();

    if let Err(e) = wait_for_state(
        &restore_id,
        bundle,
        WaitTarget::Status(LifecycleStatus::Running),
        Duration::from_secs(10),
        Duration::from_millis(100),
    ) {
        return TestResult::Failed(anyhow!("not running after restore: {e}"));
    }

    if let Err(e) = ping_container(bundle.path()) {
        return TestResult::Failed(anyhow!("ping container failed after restore: {e}"));
    }

    TestResult::Passed
}

// Test: checkpoint and restore in external network namespace
// (runc: @test "checkpoint and restore in external network namespace")
fn checkpoint_and_restore_in_external_netns() -> TestResult {
    if !criu_has_feature("external_net_ns") {
        return TestResult::Skipped;
    }

    let ns_name = format!("contest-{}", generate_uuid());
    let _netns = match net::NetNamespace::create(ns_name.clone()) {
        Ok(ns) => ns,
        Err(e) => return TestResult::Failed(anyhow!("Failed to create netns: {e}")),
    };
    let ext_netns_path = format!("/run/netns/{ns_name}");

    let ctx = match setup_cr_test(|_, spec| {
        if let Some(linux) = spec.linux_mut()
            && let Some(namespaces) = linux.namespaces_mut()
        {
            namespaces
                .iter_mut()
                .filter(|ns| ns.typ() == LinuxNamespaceType::Network)
                .for_each(|ns| {
                    ns.set_path(Some(PathBuf::from(&ext_netns_path)));
                });
        }
    }) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = ctx.start() {
        return e;
    }

    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;

    let pid = get_container_pid(id, bundle.path()).unwrap();
    let original_inode = std::fs::read_link(format!("/proc/{pid}/ns/net")).unwrap();

    for _ in 0..2 {
        let cp_result =
            try_checkpoint_container(bundle.path(), id, image_dir, Some(work_dir), &[], &[])
                .unwrap();

        if !cp_result.status.success() {
            return TestResult::Failed(anyhow!(
                "checkpoint failed: {}",
                String::from_utf8_lossy(&cp_result.stderr)
            ));
        }

        if let Err(e) = wait_for_state(
            id,
            bundle,
            WaitTarget::Deleted,
            Duration::from_secs(10),
            Duration::from_millis(100),
        ) {
            return TestResult::Failed(anyhow!("not deleted after checkpoint: {e}"));
        }

        if let Err(e) = restore_container(bundle.path(), id, image_dir, Some(work_dir), &[], &[]) {
            return TestResult::Failed(anyhow!("restore failed: {e}"));
        }

        if let Err(e) = wait_for_state(
            id,
            bundle,
            WaitTarget::Status(LifecycleStatus::Running),
            Duration::from_secs(10),
            Duration::from_millis(100),
        ) {
            return TestResult::Failed(anyhow!("not running after restore: {e}"));
        }

        if let Err(e) = ping_container(bundle.path()) {
            return TestResult::Failed(anyhow!("ping container failed after restore: {e}"));
        }

        let new_pid = get_container_pid(id, bundle.path()).unwrap();
        let new_inode = std::fs::read_link(format!("/proc/{new_pid}/ns/net")).unwrap();

        if original_inode != new_inode {
            return TestResult::Failed(anyhow!(
                "inode mismatch: original {original_inode:?}, new {new_inode:?}",
            ));
        }
    }

    TestResult::Passed
}

// Test: checkpoint and restore with container specific CRIU config
// (runc: @test "checkpoint and restore with container specific CRIU config")
fn checkpoint_and_restore_with_container_specific_criu_config() -> TestResult {
    let custom_log_name = "custom_criu.log";
    let ctx = match setup_cr_test(|bundle, spec| {
        let custom_config_path = bundle.path().join("custom_criu.conf");
        std::fs::write(&custom_config_path, format!("log-file={custom_log_name}\n")).unwrap();

        let mut annotations = std::collections::HashMap::new();
        annotations.insert(
            "org.criu.config".to_string(),
            custom_config_path.to_str().unwrap().to_string(),
        );
        spec.set_annotations(Some(annotations));
    }) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = ctx.start() {
        return e;
    }

    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;
    let log_file_path = work_dir.join(custom_log_name);

    if let Err(e) = checkpoint_container(bundle.path(), id, image_dir, Some(work_dir), &[], &[]) {
        return TestResult::Failed(anyhow!("checkpoint failed: {e:?}"));
    }

    // Verify custom log file was created during checkpoint
    if !log_file_path.exists() {
        return TestResult::Failed(anyhow!("custom log file was not created during checkpoint"));
    }

    // Delete the log file so we can verify it's created again during restore
    std::fs::remove_file(&log_file_path).unwrap();

    if let Err(e) = wait_for_state(
        id,
        bundle,
        WaitTarget::Deleted,
        Duration::from_secs(10),
        Duration::from_millis(100),
    ) {
        return TestResult::Failed(anyhow!("container not deleted after checkpoint: {e}"));
    }

    if let Err(e) = restore_container(bundle.path(), id, image_dir, Some(work_dir), &[], &[]) {
        return TestResult::Failed(anyhow!("restore failed: {e}"));
    }

    // Verify custom log file was created during restore
    if !log_file_path.exists() {
        return TestResult::Failed(anyhow!("custom log file was not created during restore"));
    }

    if let Err(e) = wait_for_state(
        id,
        bundle,
        WaitTarget::Status(LifecycleStatus::Running),
        Duration::from_secs(10),
        Duration::from_millis(100),
    ) {
        return TestResult::Failed(anyhow!("not running after restore: {e}"));
    }

    if let Err(e) = ping_container(bundle.path()) {
        return TestResult::Failed(anyhow!("ping container failed after restore: {e}"));
    }

    TestResult::Passed
}

// Test: checkpoint and restore with nested bind mounts
// (runc: @test "checkpoint and restore with nested bind mounts")
fn checkpoint_and_restore_with_nested_bind_mounts() -> TestResult {
    let mut bind1_path = PathBuf::new();
    let ctx = match setup_cr_test(|bundle, spec| {
        // Create bind mount source directories
        let bind1 = bundle.path().join("bind1");
        let bind2 = bundle.path().join("bind2");
        std::fs::create_dir_all(&bind1).unwrap();
        std::fs::create_dir_all(&bind2).unwrap();
        bind1_path = bind1.clone();

        let mnt1 = MountBuilder::default()
            .typ("bind".to_string())
            .source(&bind1)
            .destination(PathBuf::from("/test"))
            .options(vec!["rw".to_string(), "bind".to_string()])
            .build()
            .unwrap();

        let mnt2 = MountBuilder::default()
            .typ("bind".to_string())
            .source(&bind2)
            .destination(PathBuf::from("/test/for/nested"))
            .options(vec!["rw".to_string(), "bind".to_string()])
            .build()
            .unwrap();

        let mut mounts = spec.mounts().clone().unwrap_or_default();
        mounts.push(mnt1);
        mounts.push(mnt2);
        spec.set_mounts(Some(mounts));
    }) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = ctx.start() {
        return e;
    }

    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;
    let bind1 = bind1_path;

    if let Err(e) = checkpoint_container(bundle.path(), id, image_dir, Some(work_dir), &[], &[]) {
        return TestResult::Failed(anyhow!("checkpoint failed: {e}"));
    }

    if let Err(e) = wait_for_state(
        id,
        bundle,
        WaitTarget::Deleted,
        Duration::from_secs(10),
        Duration::from_millis(100),
    ) {
        return TestResult::Failed(anyhow!("container not deleted after checkpoint: {e}"));
    }

    // Cleanup mountpoints created by runc/youki during creation
    // The mountpoints should be recreated during restore - that is the actual thing tested here
    // Simulating `rm -rf "${bind1:?}"/*` to delete the contents only and preserve the bind1 folder's inode.
    for entry in std::fs::read_dir(&bind1).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            std::fs::remove_dir_all(&path).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
    }

    if let Err(e) = restore_container(bundle.path(), id, image_dir, Some(work_dir), &[], &[]) {
        return TestResult::Failed(anyhow!("restore failed: {e}"));
    }

    if let Err(e) = wait_for_state(
        id,
        bundle,
        WaitTarget::Status(LifecycleStatus::Running),
        Duration::from_secs(10),
        Duration::from_millis(100),
    ) {
        return TestResult::Failed(anyhow!("container not running after restore: {e}"));
    }

    if let Err(e) = ping_container(bundle.path()) {
        return TestResult::Failed(anyhow!("ping container failed after restore: {e}"));
    }

    TestResult::Passed
}

// Test: checkpoint then restore into a different cgroup (via --manage-cgroups-mode ignore)
// (runc: @test "checkpoint then restore into a different cgroup (via --manage-cgroups-mode ignore)")
fn checkpoint_then_restore_into_a_different_cgroup() -> TestResult {
    let ctx = match setup_cr_test(|_, spec| {
        // Set initial cgroup path
        let mut linux = oci_spec::runtime::Linux::default();
        // Since id is inside ctx which is built later, we just generate one here
        let initial_cgroup = format!("/runtime-test/cgroup-1-{}", generate_uuid());
        linux.set_cgroups_path(Some(PathBuf::from(&initial_cgroup)));
        spec.set_linux(Some(linux));
    }) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = ctx.start() {
        return e;
    }

    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;

    // Get the container PID and use it to find the real cgroup path on the host
    let pid = get_container_pid(id, bundle.path()).unwrap();
    let cgroup_data = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
    // Parse the /proc/<pid>/cgroup file.
    // Format is typically `0::/path/to/cgroup` for v2, or `N:name:/path` for v1.
    // We'll just grab the path from the end of the line.
    let cgroup_path_suffix = cgroup_data
        .lines()
        .next()
        .map(|line| line.split(':').next_back().unwrap())
        .unwrap();

    // The actual mount point of the cgroup fs is typically /sys/fs/cgroup.
    // So the host path to this container's cgroup is /sys/fs/cgroup + cgroup_path_suffix.
    let host_cgroup_path =
        PathBuf::from("/sys/fs/cgroup").join(cgroup_path_suffix.trim_start_matches('/'));

    if !host_cgroup_path.exists() {
        return TestResult::Failed(anyhow!(
            "initial cgroup path does not exist: {host_cgroup_path:?}",
        ));
    }

    // Checkpoint with --manage-cgroups-mode ignore
    let cp_result = try_checkpoint_container(
        bundle.path(),
        id,
        image_dir,
        Some(work_dir),
        &["--manage-cgroups-mode=ignore"],
        &[],
    );
    match cp_result {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            return TestResult::Failed(anyhow!(
                "checkpoint failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Err(e) => return TestResult::Failed(anyhow!("failed to spawn checkpoint: {e}")),
    }

    if let Err(e) = wait_for_state(
        id,
        bundle,
        WaitTarget::Deleted,
        Duration::from_secs(5),
        Duration::from_millis(100),
    ) {
        return TestResult::Failed(anyhow!(
            "container state still accessible after checkpoint: {e}"
        ));
    }

    // Verify the original cgroup is gone
    if host_cgroup_path.exists() {
        return TestResult::Failed(anyhow!(
            "initial cgroup path still exists after checkpoint: {:?}",
            host_cgroup_path
        ));
    }

    // Update config to a DIFFERENT cgroup
    let new_cgroup = format!("/runtime-test/cgroup-2-{}", id);
    let mut spec =
        oci_spec::runtime::Spec::load(bundle.path().join("bundle").join("config.json")).unwrap();
    spec.linux_mut()
        .as_mut()
        .unwrap()
        .set_cgroups_path(Some(PathBuf::from(&new_cgroup)));
    set_config(bundle.path(), &spec).unwrap();

    // Restore into the new cgroup
    let pid_file = bundle.path().join("pid");
    if let Err(e) = restore_container(
        bundle.path(),
        id,
        image_dir,
        Some(work_dir),
        &[
            "--manage-cgroups-mode=ignore",
            "--pid-file",
            pid_file.to_str().unwrap(),
        ],
        &[],
    ) {
        return TestResult::Failed(anyhow!("restore failed: {e}"));
    }

    if let Err(e) = wait_for_state(
        id,
        bundle,
        WaitTarget::Status(LifecycleStatus::Running),
        Duration::from_secs(10),
        Duration::from_millis(100),
    ) {
        return TestResult::Failed(anyhow!("not running after restore: {e}"));
    }

    if let Err(e) = ping_container(bundle.path()) {
        return TestResult::Failed(anyhow!("ping container failed after restore: {e}"));
    }

    // Verify the new cgroup
    let pid_restored = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap();
    let cgroup_data_restored =
        std::fs::read_to_string(format!("/proc/{pid_restored}/cgroup")).unwrap();
    let cgroup_path_suffix_restored = cgroup_data_restored
        .lines()
        .next()
        .map(|line| line.split(':').next_back().unwrap())
        .unwrap();

    let new_host_cgroup_path =
        PathBuf::from("/sys/fs/cgroup").join(cgroup_path_suffix_restored.trim_start_matches('/'));

    if !new_host_cgroup_path.exists() {
        return TestResult::Failed(anyhow!(
            "new cgroup path does not exist after restore: {new_host_cgroup_path:?}",
        ));
    }

    if !cgroup_path_suffix_restored.ends_with(&new_cgroup) {
        return TestResult::Failed(anyhow!(
            "restored container is not in the expected cgroup. Expected suffix to end with {new_cgroup}, found {cgroup_path_suffix_restored}",
        ));
    }

    // Verify the old one still does NOT exist
    if host_cgroup_path.exists() {
        return TestResult::Failed(anyhow!(
            "initial cgroup path magically reappeared after restore: {host_cgroup_path:?}",
        ));
    }

    TestResult::Passed
}

fn checkpoint_and_restore_and_exec() -> TestResult {
    let ctx = match setup_cr_test(|_, _| {}) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if let Err(e) = ctx.start() {
        return e;
    }

    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;

    let mut execed_pid: Option<String> = None;

    for _ in 0..2 {
        if let Err(e) = checkpoint_container(bundle.path(), id, image_dir, Some(work_dir), &[], &[])
        {
            return TestResult::Failed(anyhow!("checkpoint failed: {e}"));
        }

        if let Err(e) = wait_for_state(
            id,
            bundle,
            WaitTarget::Deleted,
            Duration::from_secs(5),
            Duration::from_millis(100),
        ) {
            return TestResult::Failed(anyhow!(
                "container state still accessible after checkpoint: {e}"
            ));
        }

        if let Err(e) = restore_container(bundle.path(), id, image_dir, Some(work_dir), &[], &[]) {
            return TestResult::Failed(anyhow!("restore failed: {e}"));
        }

        if let Err(e) = wait_for_state(
            id,
            bundle,
            WaitTarget::Status(LifecycleStatus::Running),
            Duration::from_secs(10),
            Duration::from_millis(100),
        ) {
            return TestResult::Failed(anyhow!("not running after restore: {e}"));
        }

        if let Err(e) = ping_container(bundle.path()) {
            return TestResult::Failed(anyhow!("ping container failed after restore: {e}"));
        }

        // Verify that previously exec'd process is restored
        if let Some(pid) = &execed_pid {
            let proc_path = format!("/proc/{pid}");
            if let Err(e) = exec_container(id, bundle.path(), &["ls", "-ld", &proc_path], None, &[])
            {
                return TestResult::Failed(anyhow!(
                    "failed to verify restored exec'd process: {e}"
                ));
            }
        }

        // Exec a new background process
        match exec_container(
            id,
            bundle.path(),
            &[
                "sh",
                "-c",
                "sleep 1000 < /dev/null > /dev/null 2>&1 & echo $!",
            ],
            None,
            &[],
        ) {
            Ok((stdout, _stderr)) => {
                let pid = stdout.trim().to_string();
                if pid.is_empty() {
                    return TestResult::Failed(anyhow!("exec'd process pid is empty"));
                }
                execed_pid = Some(pid);
            }
            Err(e) => {
                return TestResult::Failed(anyhow!("failed to exec new background process: {e}"));
            }
        }
    }

    TestResult::Passed
}

pub fn get_checkpoint_restore_tests() -> TestGroup {
    let mut tg = TestGroup::new("checkpoint_restore");
    // Run sequentially: CRIU uses global kernel resources and parallel
    // checkpoint/restore operations can interfere with each other.
    tg.set_nonparallel();

    macro_rules! cr_test {
        ($name:expr, $fn:expr) => {
            ConditionalTest::new($name, Box::new(can_run), Box::new($fn))
        };
    }

    tg.add(vec![Box::new(cr_test!(
        "checkpoint_and_restore",
        checkpoint_and_restore
    ))]);
    tg.add(vec![Box::new(cr_test!(
        "checkpoint_and_restore_bind_mount_symlink",
        checkpoint_and_restore_bind_mount_symlink
    ))]);
    tg.add(vec![Box::new(cr_test!(
        "checkpoint_and_restore_with_debug",
        checkpoint_and_restore_with_debug
    ))]);
    tg.add(vec![Box::new(cr_test!(
        "checkpoint_and_restore_cgroupns",
        checkpoint_and_restore_cgroupns
    ))]);
    tg.add(vec![Box::new(cr_test!(
        "checkpoint_and_restore_with_netdevice",
        checkpoint_and_restore_with_netdevice
    ))]);
    tg.add(vec![Box::new(cr_test!(
        "checkpoint_pre_dump_bad_parent_path",
        checkpoint_pre_dump_bad_parent_path
    ))]);
    tg.add(vec![Box::new(cr_test!(
        "checkpoint_pre_dump_and_restore",
        checkpoint_pre_dump_and_restore
    ))]);
    tg.add(vec![Box::new(cr_test!(
        "checkpoint_lazy_pages_and_restore",
        checkpoint_lazy_pages_and_restore
    ))]);
    tg.add(vec![Box::new(cr_test!(
        "checkpoint_and_restore_in_external_netns",
        checkpoint_and_restore_in_external_netns
    ))]);
    tg.add(vec![Box::new(cr_test!(
        "checkpoint_and_restore_with_container_specific_criu_config",
        checkpoint_and_restore_with_container_specific_criu_config
    ))]);
    tg.add(vec![Box::new(cr_test!(
        "checkpoint_and_restore_with_nested_bind_mounts",
        checkpoint_and_restore_with_nested_bind_mounts
    ))]);
    tg.add(vec![Box::new(cr_test!(
        "checkpoint_then_restore_into_a_different_cgroup",
        checkpoint_then_restore_into_a_different_cgroup
    ))]);
    tg.add(vec![Box::new(cr_test!(
        "checkpoint_and_restore_and_exec",
        checkpoint_and_restore_and_exec
    ))]);

    tg
}
