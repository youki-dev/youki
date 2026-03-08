// Checkpoint and restore tests based on runc's tests/integration/checkpoint.bats.
//
// All tests are skipped when running with youki because checkpoint/restore is
// not yet implemented in youki.  They are also skipped when CRIU is not
// installed on the host.

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::anyhow;
use oci_spec::runtime::{LinuxNamespaceBuilder, LinuxNamespaceType, MountBuilder};
use test_framework::{ConditionalTest, TestGroup, TestResult};

use crate::utils::{
    LifecycleStatus, WaitTarget, delete_container, generate_uuid, get_runtime_path,
    is_runtime_youki, kill_container, prepare_bundle, set_config, wait_for_state,
};

fn criu_installed() -> bool {
    which::which("criu").is_ok()
}

/// Used as check_fn for all ConditionalTests in this module:
/// run only when the runtime is NOT youki and CRIU is installed.
fn can_run() -> bool {
    !is_runtime_youki() && criu_installed()
}

fn is_cgroups_v1() -> bool {
    Path::new("/sys/fs/cgroup/pids").exists()
}

fn has_cgroupns() -> bool {
    Path::new("/proc/self/ns/cgroup").exists()
}

fn do_checkpoint(
    bundle_path: &Path,
    id: &str,
    image_dir: &Path,
    work_dir: Option<&Path>,
    global_args: &[&str],
) -> TestResult {
    let mut args: Vec<std::ffi::OsString> = global_args.iter().map(Into::into).collect();
    args.extend(["--root".into(), bundle_path.join("runtime").into()]);
    args.extend(["checkpoint".into(), "--image-path".into(), image_dir.into()]);
    if let Some(wp) = work_dir {
        args.extend(["--work-path".into(), wp.into()]);
    }
    args.push(id.into());

    let output = Command::new(get_runtime_path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(&args)
        .spawn()
        .expect("failed to spawn checkpoint")
        .wait_with_output()
        .expect("failed to wait for checkpoint");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return TestResult::Failed(anyhow!(
            "checkpoint failed ({}): stdout={stdout}, stderr={stderr}",
            output.status,
        ));
    }

    if !image_dir.join("inventory.img").exists() {
        return TestResult::Failed(anyhow!(
            "checkpoint incomplete: {image_dir:?}/inventory.img missing"
        ));
    }

    TestResult::Passed
}

fn do_restore(
    bundle_path: &Path,
    id: &str,
    image_dir: &Path,
    work_dir: Option<&Path>,
    global_args: &[&str],
) -> TestResult {
    // Use a temp file for stderr so we can report errors without the pipe
    // blocking issue (detached restore: container init would keep a piped
    // write-end open, causing wait_with_output() to block until it stops).
    let stderr_file = tempfile::NamedTempFile::new().expect("failed to create temp file");

    let mut args: Vec<std::ffi::OsString> = global_args.iter().map(Into::into).collect();
    args.extend(["--root".into(), bundle_path.join("runtime").into()]);
    args.extend(["restore".into(), "-d".into()]);
    args.extend(["--bundle".into(), bundle_path.join("bundle").into()]);
    args.extend(["--image-path".into(), image_dir.into()]);
    if let Some(wp) = work_dir {
        args.extend(["--work-path".into(), wp.into()]);
    }
    args.push(id.into());

    let status = Command::new(get_runtime_path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr_file.reopen().expect("failed to reopen temp file"))
        .args(&args)
        .spawn()
        .expect("failed to spawn restore")
        .wait()
        .expect("failed to wait for restore");

    if !status.success() {
        let stderr = std::fs::read_to_string(stderr_file.path()).unwrap_or_default();
        return TestResult::Failed(anyhow!("restore failed ({}): {}", status, stderr));
    }

    TestResult::Passed
}

fn cleanup(bundle: &tempfile::TempDir, id: &str) {
    if let Ok(mut child) = kill_container(id, bundle) {
        let _ = child.wait();
    }
    std::thread::sleep(Duration::from_millis(100));
    if let Ok(mut child) = delete_container(id, bundle) {
        let _ = child.wait();
    }
}

/// Start a container with `run -d` and wait until it reaches Running state.
/// Mirrors runc's checkpoint.bats which uses `runc run -d --console-socket`.
/// Since the container spec has terminal:false, --console-socket is not needed.
/// Like `restore -d`, we use Stdio::null() to avoid the detached child
/// process inheriting pipe write-ends and blocking wait().
fn run_and_wait(id: &str, bundle: &tempfile::TempDir) -> Result<(), TestResult> {
    let args: &[std::ffi::OsString] = &[
        "--root".into(),
        bundle.path().join("runtime").into(),
        "run".into(),
        "-d".into(),
        "--bundle".into(),
        bundle.path().join("bundle").into(),
        id.into(),
    ];
    let status = Command::new(get_runtime_path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .args(args)
        .spawn()
        .map_err(|e| TestResult::Failed(anyhow!("run failed to spawn: {e}")))?
        .wait()
        .map_err(|e| TestResult::Failed(anyhow!("run wait failed: {e}")))?;

    if !status.success() {
        return Err(TestResult::Failed(anyhow!("run -d failed ({})", status)));
    }

    wait_for_state(
        id,
        bundle,
        WaitTarget::Status(LifecycleStatus::Running),
        Duration::from_secs(10),
        Duration::from_millis(100),
    )
    .map_err(|e| TestResult::Failed(anyhow!("container did not reach running state: {e}")))
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
) -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();

    // Apply caller-specific spec customisations on top of the base spec
    let mut spec = oci_spec::runtime::Spec::default();
    let mut process = oci_spec::runtime::Process::default();
    process.set_args(Some(vec!["sleep".into(), "10".into()]));
    spec.set_process(Some(process));
    setup(&bundle, &mut spec);
    set_config(&bundle, &spec).unwrap();

    if let Err(r) = run_and_wait(&id, &bundle) {
        return r;
    }

    let (image_dir, work_dir) = match make_cr_dirs(bundle.path()) {
        Ok(d) => d,
        Err(r) => {
            cleanup(&bundle, &id);
            return r;
        }
    };

    for _ in 0..2 {
        let r = do_checkpoint(bundle.path(), &id, &image_dir, Some(&work_dir), global_args);
        if !matches!(r, TestResult::Passed) {
            cleanup(&bundle, &id);
            return r;
        }

        let r = do_restore(bundle.path(), &id, &image_dir, Some(&work_dir), global_args);
        if !matches!(r, TestResult::Passed) {
            cleanup(&bundle, &id);
            return r;
        }

        if let Err(e) = wait_for_state(
            &id,
            &bundle,
            WaitTarget::Status(LifecycleStatus::Running),
            Duration::from_secs(10),
            Duration::from_millis(100),
        ) {
            cleanup(&bundle, &id);
            return TestResult::Failed(anyhow!("not running after restore: {e}"));
        }
    }

    cleanup(&bundle, &id);
    TestResult::Passed
}

// Test: checkpoint and restore
// (runc: @test "checkpoint and restore")
fn checkpoint_and_restore() -> TestResult {
    simple_cr(&[], |_, _| {})
}

// Test: checkpoint and restore (bind mount, destination is symlink)
// (runc: @test "checkpoint and restore (bind mount, destination is symlink)")
fn checkpoint_and_restore_bind_mount_symlink() -> TestResult {
    simple_cr(&[], |bundle, spec| {
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
    })
}

// Test: checkpoint and restore (with --debug)
// (runc: @test "checkpoint and restore (with --debug)")
fn checkpoint_and_restore_with_debug() -> TestResult {
    simple_cr(&["--debug"], |_, _| {})
}

// Test: checkpoint and restore (cgroupns)
// (runc: @test "checkpoint and restore (cgroupns)")
// Requires: cgroups v1 + cgroupns
fn checkpoint_and_restore_cgroupns() -> TestResult {
    // cgroupv2 already enables cgroupns, so only run on cgroups v1 with cgroupns
    if !is_cgroups_v1() || !has_cgroupns() {
        return TestResult::Skipped;
    }
    simple_cr(&[], |_, spec| {
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
    })
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

    tg
}
