// Modelled on runc's tests/integration/selinux.bats.
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use serde_json::json;
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_utils::{
    check_container_created, exec_container, get_container_pid, start_container,
    test_outside_container,
};

const LABEL: &str = "system_u:system_r:container_t:s0:c4,c5";
const EXEC_LABEL: &str = "system_u:system_r:container_t:s0:c6,c7";
const FILE_LABEL: &str = "system_u:system_r:container_t:s0:c8,c9";

fn create_spec(label: Option<&str>) -> Result<Spec> {
    let mut process = ProcessBuilder::default()
        .args(vec!["sleep".to_string(), "1000".to_string()])
        .build()?;
    process.set_selinux_label(label.map(str::to_owned));
    SpecBuilder::default()
        .process(process)
        .build()
        .context("failed to build spec")
}

fn trim_label(label: &str) -> &str {
    label.trim_end_matches(['\0', '\n'])
}

// The container program can only enter container_t from a container_file_t file.
fn label_rootfs(bundle: &Path) -> Result<()> {
    let status = Command::new("chcon")
        .args([
            "-R",
            "-u",
            "system_u",
            "-r",
            "object_r",
            "-t",
            "container_file_t",
        ])
        .arg(bundle.join("bundle/rootfs"))
        .status()?;
    if !status.success() {
        bail!("chcon failed: {status}");
    }
    Ok(())
}

fn exec_label(
    id: &str,
    bundle: &Path,
    args: &[&str],
    process_label: Option<&str>,
) -> Result<String> {
    let process_path = bundle.join("process.json");
    if let Some(label) = process_label {
        let process = json!({
            "cwd": "/",
            "args": ["cat", "/proc/self/attr/current"],
            "user": {"uid": 0, "gid": 0},
            "selinuxLabel": label,
        });
        fs::write(&process_path, serde_json::to_vec(&process)?)?;
    }
    let mut cmd: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    if process_label.is_none() {
        cmd.extend(["cat", "/proc/self/attr/current"].map(OsStr::new));
    }
    let process_path = process_label.is_some().then_some(process_path.as_path());
    let (stdout, _) = exec_container(id, bundle, &cmd, process_path, &[])?;
    Ok(trim_label(&stdout).to_owned())
}

// The rootfs is labelled after create: the container program is only exec'd at start.
fn label_and_start(id: &str, bundle: &Path) -> Result<()> {
    label_rootfs(bundle)?;
    let status = start_container(id, bundle)?.wait()?;
    if !status.success() {
        bail!("container start failed: {status}");
    }
    Ok(())
}

fn expect(what: &str, got: &str, want: &str) -> Result<()> {
    if got != want {
        bail!("{what}: label {got:?}, want {want:?}");
    }
    Ok(())
}

// runc run (no selinux label)
fn run_no_label_test() -> TestResult {
    let spec = test_result!(create_spec(None));
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(label_and_start(&data.id, &data.bundle));
        TestResult::Passed
    })
}

// runc run (custom selinux label), and runc exec: the exec'd process gets --process-label, else
// its process file's label (which wins over --process-label), else the container's.
fn run_exec_label_test() -> TestResult {
    let spec = test_result!(create_spec(Some(LABEL)));
    test_outside_container(&spec, &|data| {
        let (id, bundle) = (&data.id, &data.bundle);
        test_result!(check_container_created(&data));
        test_result!(label_and_start(id, bundle));

        let pid = test_result!(get_container_pid(id, bundle));
        let init = test_result!(
            fs::read_to_string(format!("/proc/{pid}/attr/current")).map_err(anyhow::Error::from)
        );
        test_result!(expect("init", trim_label(&init), LABEL));

        let exec = test_result!(exec_label(id, bundle, &[], None));
        test_result!(expect("exec", &exec, LABEL));

        let flag = format!("--process-label={EXEC_LABEL}");
        let exec = test_result!(exec_label(id, bundle, &[&flag], None));
        test_result!(expect("exec --process-label", &exec, EXEC_LABEL));

        let exec = test_result!(exec_label(id, bundle, &[&flag], Some(FILE_LABEL)));
        test_result!(expect("exec --process --process-label", &exec, FILE_LABEL));

        TestResult::Passed
    })
}

// A label on a host without SELinux is refused, as runc's validateProcessSpec does.
fn label_without_selinux_test() -> TestResult {
    let spec = test_result!(create_spec(Some(LABEL)));
    test_outside_container(&spec, &|data| {
        if check_container_created(&data).is_ok() {
            return TestResult::Failed(anyhow!(
                "a container with an SELinux label was created without SELinux"
            ));
        }
        TestResult::Passed
    })
}

fn selinux_enabled() -> bool {
    fs::read_to_string("/proc/filesystems").is_ok_and(|f| f.contains("selinuxfs"))
}

// SELinux is enabled and its policy knows container_t (container-selinux).
fn can_run() -> bool {
    selinux_enabled() && fs::write("/sys/fs/selinux/context", LABEL).is_ok()
}

pub fn get_selinux_test() -> TestGroup {
    let mut tg = TestGroup::new("selinux");
    tg.add(vec![
        Box::new(ConditionalTest::new(
            "selinux_run_no_label",
            Box::new(can_run),
            Box::new(run_no_label_test),
        )),
        Box::new(ConditionalTest::new(
            "selinux_run_exec_label",
            Box::new(can_run),
            Box::new(run_exec_label_test),
        )),
        Box::new(ConditionalTest::new(
            "selinux_label_without_selinux",
            Box::new(|| !selinux_enabled()),
            Box::new(label_without_selinux_test),
        )),
    ]);
    tg
}
