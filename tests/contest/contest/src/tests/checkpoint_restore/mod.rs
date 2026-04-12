// Checkpoint and restore tests based on runc's tests/integration/checkpoint.bats.
//
// All tests are skipped when running with youki because checkpoint/restore is
// not yet implemented in youki.  They are also skipped when CRIU is not
// installed on the host.

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::anyhow;
use oci_spec::runtime::{LinuxNamespaceBuilder, LinuxNamespaceType, MountBuilder};
use test_framework::{ConditionalTest, TestGroup, TestResult};

use crate::utils::{
    LifecycleStatus, WaitTarget, checkpoint_container, criu_installed, delete_container,
    exec_container, generate_uuid, is_runtime_youki, kill_container, prepare_bundle,
    restore_container, run_container, set_config, try_checkpoint_container, wait_container_running,
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

/// RAII guard that kills and deletes the container on drop.
struct ContainerGuard<'a> {
    bundle: &'a tempfile::TempDir,
    id: &'a str,
}

impl Drop for ContainerGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut child) = kill_container(self.id, self.bundle) {
            let _ = child.wait();
        }
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(mut child) = delete_container(self.id, self.bundle) {
            let _ = child.wait();
        }
    }
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
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();

    // Apply caller-specific spec customisations on top of the base spec
    let mut spec = oci_spec::runtime::Spec::default();
    let mut process = oci_spec::runtime::Process::default();
    process.set_args(Some(vec!["sleep".into(), "10".into()]));
    spec.set_process(Some(process));
    setup(&bundle, &mut spec);
    set_config(&bundle, &spec).unwrap();

    let run_result = (|| -> anyhow::Result<()> {
        let status = run_container(&id, &bundle)?.wait()?;
        if !status.success() {
            anyhow::bail!("run -d failed ({})", status);
        }
        wait_container_running(&id, &bundle)
    })();
    if let Err(e) = run_result {
        return TestResult::Failed(anyhow!("container did not reach running state: {e}"));
    }

    if let Err(e) = verify(&id, bundle.path()) {
        return TestResult::Failed(anyhow!("verify failed after run: {e}"));
    }

    // Container is running: guard ensures kill+delete on any return path.
    let _guard = ContainerGuard {
        bundle: &bundle,
        id: &id,
    };

    let (image_dir, work_dir) = match make_cr_dirs(bundle.path()) {
        Ok(d) => d,
        Err(r) => return r,
    };

    for _ in 0..2 {
        if let Err(e) =
            checkpoint_container(bundle.path(), &id, &image_dir, Some(&work_dir), global_args)
        {
            return TestResult::Failed(anyhow!("checkpoint failed: {e}"));
        }

        // After a successful checkpoint the runtime must remove the container
        // from its state, so `state <id>` should fail (exit code != 0).
        // This mirrors runc's `testcontainer "$CT_ID" checkpointed` check.
        if let Err(e) = wait_for_state(
            &id,
            &bundle,
            WaitTarget::Deleted,
            Duration::from_secs(5),
            Duration::from_millis(100),
        ) {
            return TestResult::Failed(anyhow!(
                "container state still accessible after checkpoint: {e}"
            ));
        }

        if let Err(e) =
            restore_container(bundle.path(), &id, &image_dir, Some(&work_dir), global_args)
        {
            return TestResult::Failed(anyhow!("restore failed: {e}"));
        }

        if let Err(e) = wait_for_state(
            &id,
            &bundle,
            WaitTarget::Status(LifecycleStatus::Running),
            Duration::from_secs(10),
            Duration::from_millis(100),
        ) {
            return TestResult::Failed(anyhow!("not running after restore: {e}"));
        }

        if let Err(e) = verify(&id, bundle.path()) {
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
    let ns_name = crate::utils::net::create_unique_name("cr-net");
    let dev_name = crate::utils::net::create_unique_name("cr-dev");
    let _netns = match crate::utils::net::NetNamespace::create(ns_name.clone()) {
        Ok(ns) => ns,
        Err(e) => return TestResult::Failed(anyhow!("Failed to create netns: {e}")),
    };
    let _dev = match crate::utils::net::DummyDevice::create(dev_name.clone()) {
        Ok(d) => d,
        Err(e) => return TestResult::Failed(anyhow!("Failed to create dummy dev: {e}")),
    };

    let mtu = "1789";
    let mac = "00:11:22:33:44:55";
    let ip = "169.254.169.77/32";

    if let Err(e) = std::process::Command::new("ip")
        .args(["link", "set", "mtu", mtu, "dev", &dev_name])
        .output()
    {
        return TestResult::Failed(anyhow!("ip link set mtu failed: {e}"));
    }
    if let Err(e) = std::process::Command::new("ip")
        .args(["link", "set", "address", mac, "dev", &dev_name])
        .output()
    {
        return TestResult::Failed(anyhow!("ip link set address failed: {e}"));
    }
    if let Err(e) = std::process::Command::new("ip")
        .args(["address", "add", ip, "dev", &dev_name])
        .output()
    {
        return TestResult::Failed(anyhow!("ip address add failed: {e}"));
    }

    let dev_name_clone = dev_name.clone();
    let ns_path = format!("/run/netns/{}", ns_name);

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
            if !stdout.contains(&format!("ether {}", mac)) {
                anyhow::bail!("mac address not found in {stdout}");
            }
            if !stdout.contains(&format!("mtu {}", mtu)) {
                anyhow::bail!("mtu not found in {stdout}");
            }
            Ok(())
        },
    )
}

// Test: checkpoint --pre-dump (bad --parent-path)
// (runc: @test "checkpoint --pre-dump (bad --parent-path)")
fn checkpoint_pre_dump_bad_parent_path() -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();

    let mut spec = oci_spec::runtime::Spec::default();
    let mut process = oci_spec::runtime::Process::default();
    process.set_args(Some(vec!["sleep".into(), "10".into()]));
    spec.set_process(Some(process));
    set_config(&bundle, &spec).unwrap();

    let run_result = (|| -> anyhow::Result<()> {
        let status = run_container(&id, &bundle)?.wait()?;
        if !status.success() {
            anyhow::bail!("run -d failed ({})", status);
        }
        wait_container_running(&id, &bundle)
    })();
    if let Err(e) = run_result {
        return TestResult::Failed(anyhow!("container did not reach running state: {e}"));
    }

    let _guard = ContainerGuard {
        bundle: &bundle,
        id: &id,
    };

    let (image_dir, work_dir) = match make_cr_dirs(bundle.path()) {
        Ok(d) => d,
        Err(r) => return r,
    };

    let absolute_parent = bundle.path().join("parent-dir");
    let output1 = try_checkpoint_container(
        bundle.path(),
        &id,
        &image_dir,
        Some(&work_dir),
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
        &id,
        &image_dir,
        Some(&work_dir),
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

    tg
}
