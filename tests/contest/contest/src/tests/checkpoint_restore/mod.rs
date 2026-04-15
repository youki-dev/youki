// Checkpoint and restore tests based on runc's tests/integration/checkpoint.bats.
//
// All tests are skipped when running with youki because checkpoint/restore is
// not yet implemented in youki.  They are also skipped when CRIU is not
// installed on the host.

use std::os::unix::fs::symlink;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::anyhow;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use oci_spec::runtime::{LinuxNamespaceBuilder, LinuxNamespaceType, MountBuilder};
use test_framework::{ConditionalTest, TestGroup, TestResult};

use crate::utils::{
    LifecycleStatus, WaitTarget, build_checkpoint_command, checkpoint_container, criu_installed,
    delete_container, exec_container, generate_uuid, get_state, is_runtime_youki, kill_container,
    net, prepare_bundle, restore_container, run_container, set_config, try_checkpoint_container,
    wait_container_running, wait_for_state,
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
    pub id: String,
    pub bundle: tempfile::TempDir,
    pub image_dir: std::path::PathBuf,
    pub work_dir: std::path::PathBuf,
}

impl Drop for CrTestContext {
    fn drop(&mut self) {
        if let Ok(mut child) = kill_container(&self.id, &self.bundle) {
            let _ = child.wait();
        }
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(mut child) = delete_container(&self.id, &self.bundle) {
            let _ = child.wait();
        }
    }
}

fn ping_container(bundle: &Path) -> anyhow::Result<()> {
    let fifo_path = bundle.join("fifo");
    let (tx, rx) = std::sync::mpsc::channel();
    
    std::thread::spawn(move || {
        let res = (|| -> anyhow::Result<()> {
            let mut f_out = std::fs::OpenOptions::new().write(true).open(&fifo_path)?;
            std::io::Write::write_all(&mut f_out, b"Ping\n")?;
            drop(f_out);

            let f_in = std::fs::OpenOptions::new().read(true).open(&fifo_path)?;
            let mut reader = std::io::BufReader::new(f_in);
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line)?;
            if line.trim() != "ponG Ping" {
                anyhow::bail!("Unexpected response from container: {:?}", line);
            }
            Ok(())
        })();
        let _ = tx.send(res);
    });

    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow::anyhow!("ping_container timed out")),
    }
}

fn setup_cr_test(
    setup_spec: impl FnOnce(&tempfile::TempDir, &mut oci_spec::runtime::Spec),
) -> Result<CrTestContext, TestResult> {
    let id = generate_uuid().to_string();
    let bundle = match prepare_bundle() {
        Ok(b) => b,
        Err(e) => return Err(TestResult::Failed(anyhow!("prepare bundle: {e}"))),
    };

    let fifo_path = bundle.path().join("fifo");
    if let Err(e) = nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU) {
        return Err(TestResult::Failed(anyhow!("mkfifo failed: {e}")));
    }

    let mut spec = oci_spec::runtime::Spec::default();
    let mut process = oci_spec::runtime::Process::default();
    process.set_args(Some(vec![
        "sh".into(),
        "-c".into(),
        "while true; do read line < /fifo; echo ponG $line > /fifo; done".into(),
    ]));
    spec.set_process(Some(process));

    let fifo_mount = oci_spec::runtime::MountBuilder::default()
        .source(fifo_path)
        .destination(PathBuf::from("/fifo"))
        .typ("bind".to_string())
        .options(vec!["bind".to_string(), "rw".to_string()])
        .build()
        .unwrap();

    let mut mounts = spec.mounts().clone().unwrap_or_default();
    mounts.push(fifo_mount);
    spec.set_mounts(Some(mounts));

    setup_spec(&bundle, &mut spec);

    if let Err(e) = set_config(&bundle, &spec) {
        return Err(TestResult::Failed(anyhow!("set_config: {e}")));
    }

    let run_result = (|| -> anyhow::Result<()> {
        let status = run_container(&id, &bundle)?.wait()?;
        if !status.success() {
            anyhow::bail!("run -d failed ({})", status);
        }
        wait_container_running(&id, &bundle)?;
        ping_container(bundle.path())
    })();

    if let Err(e) = run_result {
        if let Ok(mut child) = kill_container(&id, &bundle) {
            let _ = child.wait();
        }
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(mut child) = delete_container(&id, &bundle) {
            let _ = child.wait();
        }
        return Err(TestResult::Failed(anyhow!(
            "container did not reach running state: {e}"
        )));
    }

    let (image_dir, work_dir) = match make_cr_dirs(bundle.path()) {
        Ok(d) => d,
        Err(r) => {
            if let Ok(mut child) = kill_container(&id, &bundle) {
                let _ = child.wait();
            }
            std::thread::sleep(Duration::from_millis(100));
            if let Ok(mut child) = delete_container(&id, &bundle) {
                let _ = child.wait();
            }
            return Err(r);
        }
    };

    Ok(CrTestContext {
        id,
        bundle,
        image_dir,
        work_dir,
    })
}

/// Create image-dir and work-dir inside the bundle temp directory.
fn make_cr_dirs(bundle_path: &Path) -> Result<(PathBuf, PathBuf), TestResult> {
    let image_dir = bundle_path.join("image-dir");
    let work_dir = bundle_path.join("work-dir");
    std::fs::create_dir_all(&image_dir)
        .map_err(|e| TestResult::Failed(anyhow!("mkdir image-dir: {e}")))?;
    std::fs::create_dir_all(&work_dir)
        .map_err(|e| TestResult::Failed(anyhow!("mkdir work-dir: {e}")))?;
    Ok((image_dir, work_dir))
}

/// Full checkpoint+restore test: prepares a bundle, calls `setup` to allow the
/// caller to customise the spec, then runs 2 checkpoint→restore cycles.
/// The first cycle verifies a normal container can be checkpointed and restored;
/// the second verifies the restored container can itself be checkpointed and
/// restored again.
fn simple_cr(
    global_args: &[&str],
    setup: impl Fn(&tempfile::TempDir, &mut oci_spec::runtime::Spec),
    verify: impl Fn(&str, &Path) -> anyhow::Result<()>,
) -> TestResult {
    let ctx = match setup_cr_test(setup) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;

    if let Err(e) = verify(id, bundle.path()) {
        return TestResult::Failed(anyhow!("verify failed after run: {e}"));
    }

    for _ in 0..2 {
        if let Err(e) =
            checkpoint_container(bundle.path(), id, image_dir, Some(work_dir), global_args)
        {
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

        if let Err(e) = verify(id, bundle.path()) {
            return TestResult::Failed(anyhow!("verify failed after restore: {e}"));
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

    let out = match std::process::Command::new("ip")
        .args(["link", "set", "mtu", mtu, "dev", &dev_name])
        .output()
    {
        Ok(out) => out,
        Err(e) => return TestResult::Failed(anyhow!("ip link set mtu execution failed: {e}")),
    };
    if !out.status.success() {
        return TestResult::Failed(anyhow!("ip link set mtu failed: {}", String::from_utf8_lossy(&out.stderr)));
    }

    let out = match std::process::Command::new("ip")
        .args(["link", "set", "address", mac, "dev", &dev_name])
        .output()
    {
        Ok(out) => out,
        Err(e) => return TestResult::Failed(anyhow!("ip link set address execution failed: {e}")),
    };
    if !out.status.success() {
        return TestResult::Failed(anyhow!("ip link set address failed: {}", String::from_utf8_lossy(&out.stderr)));
    }

    let out = match std::process::Command::new("ip")
        .args(["address", "add", ip, "dev", &dev_name])
        .output()
    {
        Ok(out) => out,
        Err(e) => return TestResult::Failed(anyhow!("ip address add execution failed: {e}")),
    };
    if !out.status.success() {
        return TestResult::Failed(anyhow!("ip address add failed: {}", String::from_utf8_lossy(&out.stderr)));
    }

    let dev_name_clone = dev_name.clone();
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

            let mut net_devices = std::collections::HashMap::new();
            net_devices.insert(
                dev_name_clone.clone(),
                oci_spec::runtime::LinuxNetDeviceBuilder::default()
                    .build()
                    .unwrap(),
            );

            if let Some(linux) = spec.linux_mut() {
                linux.set_namespaces(Some(namespaces));
                linux.set_net_devices(Some(net_devices));
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
                anyhow::bail!("ip address not found in {stdout}");
            }
            if !stdout.contains(&format!("ether {mac}")) {
                anyhow::bail!("mac address not found in {stdout}");
            }
            if !stdout.contains(&format!("mtu {mtu}")) {
                anyhow::bail!("mtu not found in {stdout}");
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
        &[
            "--pre-dump",
            "--parent-path",
            absolute_parent.to_str().unwrap(),
        ],
        &[],
    )
    .unwrap();

    if output1.status.success() {
        return TestResult::Failed(anyhow!(
            "expected checkpoint to fail with absolute --parent-path"
        ));
    }
    let stderr1 = String::from_utf8_lossy(&output1.stderr);
    if !stderr1.contains("--parent-path must be relative") {
        return TestResult::Failed(anyhow!(
            "expected '--parent-path must be relative' but got stderr: {stderr1}"
        ));
    }

    let output2 = try_checkpoint_container(
        bundle.path(),
        id,
        image_dir,
        Some(work_dir),
        &["--pre-dump", "--parent-path", "../parent-dir"],
        &[],
    )
    .unwrap();

    if output2.status.success() {
        return TestResult::Failed(anyhow!(
            "expected checkpoint to fail with non-existent relative --parent-path"
        ));
    }
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    if !stderr2.contains("invalid --parent-path") {
        return TestResult::Failed(anyhow!(
            "expected 'invalid --parent-path' but got stderr: {stderr2}"
        ));
    }

    TestResult::Passed
}

// Test: checkpoint --pre-dump and restore
// (runc: @test "checkpoint --pre-dump and restore")
fn checkpoint_pre_dump_and_restore() -> TestResult {
    let ctx = match setup_cr_test(|_, _| {}) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let id = &ctx.id;
    let bundle = &ctx.bundle;

    let pre_dump_dir = bundle.path().join("pre-dump");
    let final_dump_dir = bundle.path().join("final-dump");
    if let Err(e) = std::fs::create_dir_all(&pre_dump_dir) {
        return TestResult::Failed(anyhow!("failed to create pre-dump dir: {e}"));
    }
    if let Err(e) = std::fs::create_dir_all(&final_dump_dir) {
        return TestResult::Failed(anyhow!("failed to create final-dump dir: {e}"));
    }

    // Execute pre-dump
    let output1 =
        try_checkpoint_container(bundle.path(), id, &pre_dump_dir, None, &["--pre-dump"], &[])
            .unwrap();

    if !output1.status.success() {
        let stderr = String::from_utf8_lossy(&output1.stderr);
        return TestResult::Failed(anyhow!("pre-dump checkpoint failed: {}", stderr));
    }

    // After pre-dump, container must still be running
    if let Err(e) = wait_for_state(
        id,
        bundle,
        WaitTarget::Status(LifecycleStatus::Running),
        Duration::from_secs(5),
        Duration::from_millis(100),
    ) {
        return TestResult::Failed(anyhow!("container not running after pre-dump: {e}"));
    }

    // Execute final dump using relative parent path pointing to pre-dump
    let relative_parent = "../pre-dump";
    let output2 = try_checkpoint_container(
        bundle.path(),
        id,
        &final_dump_dir,
        None,
        &["--parent-path", relative_parent],
        &[],
    )
    .unwrap();

    if !output2.status.success() {
        let stderr = String::from_utf8_lossy(&output2.stderr);
        return TestResult::Failed(anyhow!("final checkpoint failed: {}", stderr));
    }

    // After final dump, container must be deleted
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

    // Restore the container from the final dump directory
    if let Err(e) = restore_container(bundle.path(), id, &final_dump_dir, None, &[], &[]) {
        return TestResult::Failed(anyhow!("restore failed: {e}"));
    }

    // After restore, container must be running again
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
    let ctx = match setup_cr_test(|_, _| {}) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let id = &ctx.id;
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

    // Spawn checkpoint command in background
    let port_str = format!("0.0.0.0:{}", port);
    let mut checkpoint_cmd = build_checkpoint_command(
        bundle.path(),
        id,
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
    checkpoint_cmd.stderr(std::process::Stdio::null());

    let pipe_w_raw = pipe_w.as_raw_fd();

    // Ensure the child process inherits the write end of the pipe
    unsafe {
        checkpoint_cmd.pre_exec(move || {
            let flags = FdFlag::from_bits_truncate(
                fcntl(pipe_w_raw, FcntlArg::F_GETFD).expect("from_bits_truncate failed"),
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
    let _ = nix::unistd::close(pipe_w.as_raw_fd());

    // Set read pipe to non-blocking so the timeout loop isn't blocked forever if no data arrives
    let flags = nix::fcntl::OFlag::from_bits_truncate(
        nix::fcntl::fcntl(pipe_r.as_raw_fd(), nix::fcntl::FcntlArg::F_GETFL)
            .expect("F_GETFL failed"),
    );
    nix::fcntl::fcntl(
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

    // Cleanup read pipe
    let _ = nix::unistd::close(pipe_r.as_raw_fd());

    if !ready {
        let _ = checkpoint_child.kill();
        let _ = checkpoint_child.wait();
        let mut stderr_msg = String::new();
        if let Some(mut stderr) = checkpoint_child.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut stderr, &mut stderr_msg);
        }
        return TestResult::Failed(anyhow!(
            "lazy-page server readiness timeout. stderr: {}",
            stderr_msg.trim()
        ));
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
            "-W",
            work_dir.to_str().unwrap(),
        ])
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = checkpoint_child.kill();
            return TestResult::Failed(anyhow!("failed to spawn criu lazy-pages: {e}"));
        }
    };

    let restore_id = format!("{id}-restore");
    let new_cgroup = format!("/runtime-test/cgroup-2-{restore_id}");
    let mut spec =
        oci_spec::runtime::Spec::load(bundle.path().join("bundle").join("config.json")).unwrap();
    if let Some(linux) = spec.linux_mut() {
        linux.set_cgroups_path(Some(PathBuf::from(&new_cgroup)));
    }
    set_config(bundle.path(), &spec).unwrap();

    // Restore lazily from checkpoint
    let restore_result = restore_container(
        bundle.path(),
        &restore_id,
        image_dir,
        Some(work_dir),
        &["--lazy-pages", "--manage-cgroups-mode=ignore"],
        &[],
    );

    // Terminate criu daemon if it's still running, it might stay alive if restore failed
    let mut criu_daemon = criu_daemon_child;
    let _ = criu_daemon.kill();
    let _ = criu_daemon.wait();

    if let Err(e) = restore_result {
        let _ = checkpoint_child.kill();
        let _ = checkpoint_child.wait();
        return TestResult::Failed(anyhow!("restore --lazy-pages failed: {e}"));
    }

    // Wait for background jobs to finish
    let _ = checkpoint_child.wait();

    // After restore, container must be running again
    if let Err(e) = wait_for_state(
        &restore_id,
        bundle,
        WaitTarget::Status(LifecycleStatus::Running),
        Duration::from_secs(10),
        Duration::from_millis(100),
    ) {
        let _ = kill_container(&restore_id, bundle).map(|mut c| c.wait());
        let _ = delete_container(&restore_id, bundle).map(|mut c| c.wait());
        return TestResult::Failed(anyhow!("not running after restore: {e}"));
    }

    if let Err(e) = ping_container(bundle.path()) {
        let _ = kill_container(&restore_id, bundle).map(|mut c| c.wait());
        let _ = delete_container(&restore_id, bundle).map(|mut c| c.wait());
        return TestResult::Failed(anyhow!("ping container failed after restore: {e}"));
    }

    let _ = kill_container(&restore_id, bundle).map(|mut c| c.wait());
    let _ = delete_container(&restore_id, bundle).map(|mut c| c.wait());

    TestResult::Passed
}

// Test: checkpoint and restore in external network namespace
// (runc: @test "checkpoint and restore in external network namespace")
fn checkpoint_and_restore_in_external_netns() -> TestResult {
    let ns_name = format!("contest-{}", generate_uuid());

    // Ensure we delete the netns when the test finishes
    let _netns_guard = crate::utils::net::NetNamespace::create(ns_name.clone()).unwrap();
    let ext_netns_path = format!("/run/netns/{ns_name}");

    let ctx = match setup_cr_test(|_, spec| {
        // Modify the spec to point the network namespace to the external path
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
    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;

    let (stdout, _) = get_state(id, bundle.path()).unwrap();
    let state: crate::utils::State = serde_json::from_str(&stdout).unwrap();
    let pid = state.pid.unwrap();
    let original_inode = std::fs::read_link(format!("/proc/{}/ns/net", pid)).unwrap();

    let cp_result =
        try_checkpoint_container(bundle.path(), id, image_dir, Some(work_dir), &[], &[]).unwrap();

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

    let (stdout, _) = get_state(id, bundle.path()).unwrap();
    let state: crate::utils::State = serde_json::from_str(&stdout).unwrap();
    let new_pid = state.pid.unwrap();
    let new_inode = std::fs::read_link(format!("/proc/{new_pid}/ns/net")).unwrap();

    if original_inode != new_inode {
        return TestResult::Failed(anyhow!(
            "inode mismatch: original {original_inode:?}, new {new_inode:?}",
        ));
    }

    TestResult::Passed
}

// Test: checkpoint and restore with container specific CRIU config
// (runc: @test "checkpoint and restore with container specific CRIU config")
fn checkpoint_and_restore_with_container_specific_criu_config() -> TestResult {
    let custom_log_name = "custom_criu.log";
    let ctx = match setup_cr_test(|bundle, spec| {
        // Create custom CRIU config inside the bundle
        let custom_config_path = bundle.path().join("custom_criu.conf");
        std::fs::write(&custom_config_path, format!("log-file={custom_log_name}\n")).unwrap();

        // Add annotation for youki to pick up the CRIU config
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

    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;

    let log_file_path = work_dir.join(custom_log_name);

    if let Err(e) = try_checkpoint_container(bundle.path(), id, image_dir, Some(work_dir), &[], &[])
    {
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

    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;
    let bind1 = bind1_path;

    if let Err(e) = checkpoint_container(bundle.path(), id, image_dir, Some(work_dir), &[]) {
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

    // cleanup mountpoints created by runc/youki during creation
    // the mountpoints should be recreated during restore - that is the actual thing tested here
    std::fs::remove_dir_all(&bind1).unwrap();
    std::fs::create_dir_all(&bind1).unwrap();

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
    let mut initial_cgroup_val = String::new();
    let ctx = match setup_cr_test(|_, spec| {
        // Set initial cgroup path
        let mut linux = oci_spec::runtime::Linux::default();
        // Since id is inside ctx which is built later, we just generate one here
        let initial_cgroup = format!("/runtime-test/cgroup-1-{}", generate_uuid());
        linux.set_cgroups_path(Some(PathBuf::from(&initial_cgroup)));
        spec.set_linux(Some(linux));
        initial_cgroup_val = initial_cgroup;
    }) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;

    // Get the container PID and use it to find the real cgroup path on the host
    let (stdout, _) = get_state(id, bundle.path()).unwrap();
    let state: oci_spec::runtime::State = serde_json::from_str(&stdout).unwrap();
    let pid = state.pid().unwrap();
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
    if let Err(e) = restore_container(
        bundle.path(),
        id,
        image_dir,
        Some(work_dir),
        &["--manage-cgroups-mode=ignore"],
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
    let (stdout_restored, _) = get_state(id, bundle.path()).unwrap();
    let state_restored: oci_spec::runtime::State = serde_json::from_str(&stdout_restored).unwrap();
    let pid_restored = state_restored.pid().unwrap();
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
    let id = &ctx.id;
    let bundle = &ctx.bundle;
    let image_dir = &ctx.image_dir;
    let work_dir = &ctx.work_dir;

    let mut execed_pid: Option<String> = None;

    for _ in 0..2 {
        if let Err(e) = checkpoint_container(bundle.path(), id, image_dir, Some(work_dir), &[]) {
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
