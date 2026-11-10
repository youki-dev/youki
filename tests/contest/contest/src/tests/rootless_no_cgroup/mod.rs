//! Rootless cgroup-v2 fallback must not leave container processes behind.
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use caps::{CapSet, Capability};
use clap::{Subcommand, ValueEnum};
use nix::errno::Errno;
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, setns, unshare};
use nix::sys::signal::{Signal, killpg};
use nix::sys::statvfs::{FsFlags, statvfs};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork, getegid, geteuid};
use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, LinuxResources, MountBuilder,
    ProcessBuilder, RootBuilder, Spec, SpecBuilder, UserBuilder,
};
use procfs::process::Process;
use tempfile::TempDir;
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::support::set_runtime_path;
use crate::utils::test_utils::runtime_command;
use crate::utils::{
    generate_uuid, get_runtime_path, is_cgroup_v2, is_runtime_youki, prepare_bundle, set_config,
};

const WAIT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum Case {
    PrivatePidKillAll,
    PrivatePidForceDelete,
    InaccessibleParentKillAll,
    InaccessibleParentForceDelete,
    EmptyResourcesKillAll,
    AttachedMissingCgroupKillAll,
    AttachedMissingCgroupForceDelete,
    LegacyForceDelete,
    RdtFailureCleanup,
    StateSaveFailureCleanup,
    HookFailureCleanup,
    MemoryLimitRejected,
    PidsLimitRejected,
    HostPidRejected,
    JoinedPidRejected,
}

impl Case {
    fn uses_inaccessible_parent(self) -> bool {
        matches!(
            self,
            Self::InaccessibleParentKillAll | Self::InaccessibleParentForceDelete
        )
    }

    /// Cases that replace an existing cgroup subdirectory with a private one.
    fn masks_cgroup_parent(self) -> bool {
        self.uses_inaccessible_parent() || matches!(self, Self::HookFailureCleanup)
    }

    fn name(self) -> &'static str {
        match self {
            Self::PrivatePidKillAll => "private_pid_kill_all",
            Self::PrivatePidForceDelete => "private_pid_force_delete",
            Self::InaccessibleParentKillAll => "inaccessible_parent_kill_all",
            Self::InaccessibleParentForceDelete => "inaccessible_parent_force_delete",
            Self::EmptyResourcesKillAll => "empty_resources_kill_all",
            Self::AttachedMissingCgroupKillAll => "attached_missing_cgroup_kill_all",
            Self::AttachedMissingCgroupForceDelete => "attached_missing_cgroup_force_delete",
            Self::LegacyForceDelete => "legacy_force_delete",
            Self::RdtFailureCleanup => "rdt_failure_cleanup",
            Self::StateSaveFailureCleanup => "state_save_failure_cleanup",
            Self::HookFailureCleanup => "hook_failure_cleanup",
            Self::MemoryLimitRejected => "memory_limit_rejected",
            Self::PidsLimitRejected => "pids_limit_rejected",
            Self::HostPidRejected => "host_pid_rejected",
            Self::JoinedPidRejected => "joined_pid_rejected",
        }
    }
}

/// Internal self-exec entry points; namespace setup must precede all threads.
#[derive(Debug, Subcommand)]
pub enum Worker {
    Run {
        runtime: PathBuf,
        #[arg(value_enum)]
        case: Case,
    },
    Join {
        namespace: PathBuf,
    },
    FailStateSave {
        path: PathBuf,
    },
}

/// Register the externally observable no-cgroup behaviors.
pub fn get_test_group() -> TestGroup {
    let mut group = TestGroup::new("rootless_no_cgroup");
    for case in [
        Case::PrivatePidKillAll,
        Case::PrivatePidForceDelete,
        Case::InaccessibleParentKillAll,
        Case::InaccessibleParentForceDelete,
        Case::EmptyResourcesKillAll,
        Case::AttachedMissingCgroupKillAll,
        Case::AttachedMissingCgroupForceDelete,
        Case::LegacyForceDelete,
        Case::RdtFailureCleanup,
        Case::StateSaveFailureCleanup,
        Case::HookFailureCleanup,
        Case::MemoryLimitRejected,
        Case::PidsLimitRejected,
        Case::HostPidRejected,
        Case::JoinedPidRejected,
    ] {
        group.add(vec![Box::new(Test::new(
            case.name(),
            Box::new(move || {
                if !is_runtime_youki() || !is_cgroup_v2() {
                    return TestResult::Skipped("requires youki and cgroup v2".into());
                }
                if case.masks_cgroup_parent()
                    && cgroup_subdirectory().is_ok_and(|target| target.is_none())
                {
                    return TestResult::Skipped(
                        "masked-parent fixture needs an existing cgroup subdirectory".into(),
                    );
                }
                run_case_worker(case).into()
            }),
        ))]);
    }
    group
}

fn run_case_worker(case: Case) -> Result<()> {
    // The parent owns these files even when timeout kills the worker before
    // its TempDir destructors can run.
    let work_dir = tempfile::tempdir()?;
    // Userns root cannot bypass permissions on a sudo caller's checkout.
    // Stage inputs before dropping those capabilities, then stay in this root.
    let runtime = work_dir.path().join("youki");
    fs::copy(get_runtime_path(), &runtime).context("could not stage runtime")?;
    fs::copy(
        std::env::current_dir()?.join("bundle.tar.gz"),
        work_dir.path().join("bundle.tar.gz"),
    )
    .context("could not stage bundle")?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["rootless-no-cgroup-worker", "run"])
        .arg(&runtime)
        .arg(case.name())
        .current_dir(work_dir.path())
        .env("TMPDIR", work_dir.path())
        .process_group(0);
    let mut log = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log.try_clone()?)
        .spawn()
        .context("could not spawn no-cgroup worker")?;
    let deadline = Instant::now() + WORKER_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            // The sandbox PID 1 stays in this group. Killing it also tears down
            // detached container processes in its nested PID namespaces.
            let _ = killpg(Pid::from_raw(child.id() as i32), Signal::SIGKILL);
            child.wait()?;
            bail!("no-cgroup worker timed out for {}", case.name());
        }
        sleep(Duration::from_millis(20));
    };
    log.seek(SeekFrom::Start(0))?;
    let mut text = String::new();
    log.read_to_string(&mut text)?;
    ensure!(status.success(), "{} failed: {text}", case.name());
    Ok(())
}

/// Run only from the fresh executable, before logger or test initialization.
pub fn worker(command: Worker) -> Result<()> {
    match command {
        Worker::FailStateSave { path } => {
            fs::remove_file(&path)?;
            fs::create_dir(&path)?;
            Ok(())
        }
        Worker::Join { namespace } => {
            setns(File::open(&namespace)?, CloneFlags::CLONE_NEWPID)
                .with_context(|| format!("could not join {}", namespace.display()))?;
            Ok(())
        }
        Worker::Run { runtime, case } => {
            set_runtime_path(&runtime);
            isolate()?;
            unshare(CloneFlags::CLONE_NEWPID).context("could not create sandbox pid namespace")?;
            // This entry point has just exec'd and has never started threads.
            match unsafe { fork() }.context("could not enter sandbox pid namespace")? {
                ForkResult::Parent { child } => loop {
                    match waitpid(child, None) {
                        Ok(WaitStatus::Exited(_, 0)) => return Ok(()),
                        Ok(status) => bail!("no-cgroup sandbox failed: {status:?}"),
                        Err(Errno::EINTR) => continue,
                        Err(err) => return Err(err).context("could not wait for sandbox"),
                    }
                },
                ForkResult::Child => {
                    let result = (|| {
                        mount(
                            Some("proc"),
                            "/proc",
                            Some("proc"),
                            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                            None::<&str>,
                        )
                        .context("could not mount sandbox procfs")?;
                        check_case(case)
                    })();
                    if let Err(err) = &result {
                        eprintln!("{err:#}");
                    }
                    // Exiting PID 1 kills all remaining descendants, including
                    // workloads from a failed admission or cleanup assertion.
                    std::process::exit(if result.is_ok() { 0 } else { 1 });
                }
            }
        }
    }
}

fn isolate() -> Result<()> {
    let uid = geteuid();
    let gid = getegid();
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)
        .context("could not create rootless user and mount namespaces")?;
    fs::write("/proc/self/setgroups", "deny").context("could not deny setgroups")?;
    fs::write("/proc/self/uid_map", format!("0 {} 1\n", uid.as_raw()))
        .context("could not map rootless uid")?;
    fs::write("/proc/self/gid_map", format!("0 {} 1\n", gid.as_raw()))
        .context("could not map rootless gid")?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("could not isolate mount propagation")?;
    let mounts = Process::myself()?.mountinfo()?;
    let cgroup = mounts
        .iter()
        .rev()
        .find(|entry| entry.mount_point == Path::new("/sys/fs/cgroup"))
        .context("could not find cgroup mount")?;
    let mut flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
    // A bind-remount replaces per-mount flags; inherited restrictions may be
    // locked in a less privileged mount namespace and must not be cleared.
    for (option, flag) in [
        ("nosuid", MsFlags::MS_NOSUID),
        ("nodev", MsFlags::MS_NODEV),
        ("noexec", MsFlags::MS_NOEXEC),
        ("noatime", MsFlags::MS_NOATIME),
        ("nodiratime", MsFlags::MS_NODIRATIME),
        ("relatime", MsFlags::MS_RELATIME),
        ("strictatime", MsFlags::MS_STRICTATIME),
    ] {
        if cgroup.mount_options.contains_key(option) {
            flags |= flag;
        }
    }
    mount(
        Some("/sys/fs/cgroup"),
        "/sys/fs/cgroup",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("could not bind cgroup mount")?;
    mount(
        None::<&str>,
        "/sys/fs/cgroup",
        None::<&str>,
        flags,
        None::<&str>,
    )
    .context("could not make cgroup mount read-only")?;
    ensure!(is_cgroup_v2(), "requires cgroup v2");
    ensure!(
        statvfs("/sys/fs/cgroup")?
            .flags()
            .contains(FsFlags::ST_RDONLY),
        "cgroup mount is not read-only"
    );
    Ok(())
}

struct Container {
    bundle: TempDir,
    id: String,
}

impl Container {
    fn new(
        pid_namespace: Option<Option<&Path>>,
        holder: bool,
        cgroup_parent: &Path,
    ) -> Result<Self> {
        let bundle = prepare_bundle()?;
        let id = generate_uuid().to_string();
        let mut namespaces = [
            LinuxNamespaceType::Mount,
            LinuxNamespaceType::Ipc,
            LinuxNamespaceType::Uts,
        ]
        .into_iter()
        .map(|typ| LinuxNamespaceBuilder::default().typ(typ).build())
        .collect::<std::result::Result<Vec<_>, _>>()?;
        if let Some(path) = pid_namespace {
            let mut builder = LinuxNamespaceBuilder::default().typ(LinuxNamespaceType::Pid);
            if let Some(path) = path {
                builder = builder.path(path);
            }
            namespaces.push(builder.build()?);
        }
        let private = pid_namespace == Some(None);
        let proc_mount = if private {
            MountBuilder::default()
                .destination("/proc")
                .typ("proc")
                .source("proc")
                .build()?
        } else {
            MountBuilder::default()
                .destination("/proc")
                .typ("none")
                .source("/proc")
                .options(vec![
                    "rbind".into(),
                    "nosuid".into(),
                    "nodev".into(),
                    "noexec".into(),
                ])
                .build()?
        };
        let workload = if holder {
            "exec /bin/busybox sleep 1000"
        } else {
            "echo started > /started; /bin/busybox sleep 1000 & exec /bin/busybox sleep 1001"
        };
        let mut linux = LinuxBuilder::default()
            .namespaces(namespaces)
            .cgroups_path(cgroup_parent.join(format!("contest-{id}")))
            .build()?;
        // OCI defaults request device filtering; this test intentionally has
        // no resource rules and must exercise only the unavailable cgroup.
        linux.set_resources(None);
        linux.set_masked_paths(None);
        linux.set_readonly_paths(None);
        let spec: Spec = SpecBuilder::default()
            .process(
                ProcessBuilder::default()
                    .terminal(false)
                    .user(UserBuilder::default().uid(0u32).gid(0u32).build()?)
                    .args(vec![
                        "/bin/busybox".into(),
                        "sh".into(),
                        "-c".into(),
                        workload.into(),
                    ])
                    .env(vec!["PATH=/bin".into()])
                    .cwd("/")
                    .no_new_privileges(true)
                    .build()?,
            )
            .root(
                RootBuilder::default()
                    .path("rootfs")
                    .readonly(false)
                    .build()?,
            )
            .mounts(vec![
                proc_mount,
                MountBuilder::default()
                    .destination("/dev")
                    .typ("tmpfs")
                    .source("tmpfs")
                    .options(vec![
                        "nosuid".into(),
                        "strictatime".into(),
                        "mode=755".into(),
                        "size=65536k".into(),
                    ])
                    .build()?,
                MountBuilder::default()
                    .destination("/sys")
                    .typ("none")
                    .source("/sys")
                    .options(vec![
                        "rbind".into(),
                        "nosuid".into(),
                        "noexec".into(),
                        "nodev".into(),
                        "ro".into(),
                    ])
                    .build()?,
            ])
            .linux(linux)
            .build()?;
        set_config(&bundle, &spec)?;
        Ok(Self { bundle, id })
    }

    fn set_resources(&self, resources: LinuxResources) -> Result<()> {
        let mut spec = Spec::load(self.bundle.path().join("bundle/config.json"))?;
        spec.linux_mut()
            .as_mut()
            .context("spec has no linux config")?
            .set_resources(Some(resources));
        set_config(&self.bundle, &spec)
    }

    fn command(&self) -> Command {
        let mut command = runtime_command(&self.bundle);
        command.args(["--log-level", "warn"]);
        command
    }

    fn start_command(&self) -> Command {
        let mut command = self.command();
        command
            .args(["run", "-d", "-b"])
            .arg(self.bundle.path().join("bundle"))
            .arg(&self.id);
        command
    }

    fn start(&self) -> Result<i32> {
        checked(&mut self.start_command())?;
        let state: serde_json::Value =
            serde_json::from_str(&checked(self.command().args(["state", &self.id]))?)?;
        let pid = state["pid"]
            .as_i64()
            .context("container state has no pid")? as i32;
        ensure!(pid > 1, "invalid container pid {pid}");
        ensure!(
            fs::read_to_string(format!("/proc/{pid}/cgroup"))?
                == fs::read_to_string("/proc/self/cgroup")?,
            "container unexpectedly has its own cgroup"
        );
        Ok(pid)
    }

    fn set_attachment_fixture(
        &self,
        attachment: Option<serde_json::Value>,
    ) -> Result<Option<serde_json::Value>> {
        let path = self
            .bundle
            .path()
            .join("runtime")
            .join(&self.id)
            .join("state.json");
        let mut state: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        let previous = state
            .as_object_mut()
            .context("state is not an object")?
            .remove("cgroupAttachment");
        if let Some(attachment) = attachment {
            state["cgroupAttachment"] = attachment;
        }
        fs::write(path, serde_json::to_vec(&state)?)?;
        Ok(previous)
    }

    fn absent(&self) -> Result<()> {
        let listed = checked(self.command().arg("list"))?;
        ensure!(
            !listed.split_whitespace().any(|word| word == self.id),
            "container is still listed: {}",
            self.id
        );
        ensure!(
            !self.bundle.path().join("runtime").join(&self.id).exists(),
            "container state was not removed"
        );
        Ok(())
    }

    fn reject(&self, reason: &str) -> Result<()> {
        let result = output(&mut self.start_command())?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        ensure!(
            !result.status.success(),
            "container requiring a cgroup ran without one"
        );
        ensure!(text.contains(reason), "unexpected admission error: {text}");
        ensure!(
            text.contains("Read-only file system"),
            "admission did not fail because cgroup is read-only: {text}"
        );
        ensure!(
            !self.bundle.path().join("bundle/rootfs/started").exists(),
            "rejected workload ran"
        );
        self.absent()
    }
}

fn cgroup_subdirectory() -> Result<Option<PathBuf>> {
    for entry in fs::read_dir("/sys/fs/cgroup")? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn check_case(case: Case) -> Result<()> {
    let masked_parent = if case.masks_cgroup_parent() {
        let target = cgroup_subdirectory()?
            .context("masked-parent fixture needs a cgroup subdirectory to mask")?;
        let directory = tempfile::tempdir_in(".")?;
        if case.uses_inaccessible_parent() {
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o600))?;
        }
        // Only this worker's mount namespace sees the masked parent.
        mount(
            Some(directory.path()),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;
        // Userns root could otherwise bypass permission bits in this
        // directory, including after exec into the runtime.
        for capability in [
            Capability::CAP_DAC_OVERRIDE,
            Capability::CAP_DAC_READ_SEARCH,
        ] {
            for set in [CapSet::Bounding, CapSet::Effective, CapSet::Permitted] {
                caps::drop(None, set, capability)?;
            }
        }
        ensure!(
            !case.uses_inaccessible_parent()
                || target
                    .join("container")
                    .try_exists()
                    .is_err_and(|err| err.kind() == std::io::ErrorKind::PermissionDenied),
            "fixture parent must fail path lookup with EACCES"
        );
        Some((directory, target.strip_prefix("/sys/fs/cgroup")?.to_owned()))
    } else {
        None
    };
    let cgroup_parent = masked_parent
        .as_ref()
        .map(|(_, path)| Path::new("/").join(path))
        .unwrap_or_else(|| PathBuf::from("/"));
    match case {
        Case::RdtFailureCleanup | Case::StateSaveFailureCleanup | Case::HookFailureCleanup => {
            let container = Container::new(Some(None), false, &cgroup_parent)?;
            let mut spec = Spec::load(container.bundle.path().join("bundle/config.json"))?;
            let mut foreign_cgroup = None;
            if matches!(case, Case::RdtFailureCleanup) {
                // Only closID is requested: a missing group must fail, never be created.
                spec.linux_mut()
                    .as_mut()
                    .context("missing linux config")?
                    .set_intel_rdt(Some(serde_json::from_value(
                        serde_json::json!({"closID": format!("{}-missing", container.id)}),
                    )?));
            } else if matches!(case, Case::HookFailureCleanup) {
                // An existing cgroup that youki cannot join. Generic cleanup
                // would write its cgroup.kill, killing someone else's tasks.
                let (parent, _) = masked_parent.as_ref().context("missing masked parent")?;
                let cgroup = parent.path().join(format!("contest-{}", container.id));
                fs::create_dir(&cgroup)?;
                fs::write(cgroup.join("cgroup.kill"), "")?;
                fs::write(cgroup.join("cgroup.procs"), "")?;
                fs::set_permissions(
                    cgroup.join("cgroup.procs"),
                    fs::Permissions::from_mode(0o444),
                )?;
                spec.set_hooks(Some(serde_json::from_value(serde_json::json!({
                    "createRuntime": [{"path": "/bin/sh", "args": ["sh", "-c", "exit 7"]}]
                }))?));
                foreign_cgroup = Some(cgroup);
            } else {
                let path = container
                    .bundle
                    .path()
                    .join("runtime")
                    .join(&container.id)
                    .join("state.json");
                spec.set_hooks(Some(serde_json::from_value(serde_json::json!({
                    "createRuntime": [{
                        "path": format!("/proc/{}/exe", nix::unistd::getpid()),
                        "args": ["contest", "rootless-no-cgroup-worker", "fail-state-save", path],
                        "timeout": 5
                    }]
                }))?));
            }
            set_config(&container.bundle, &spec)?;
            let pid_file = container.bundle.path().join("init.pid");
            let result = output(
                container
                    .command()
                    .args(["create", "-b"])
                    .arg(container.bundle.path().join("bundle"))
                    .arg("--pid-file")
                    .arg(&pid_file)
                    .arg(&container.id),
            )?;
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            ensure!(
                !result.status.success(),
                "fault-injected creation succeeded"
            );
            if matches!(case, Case::RdtFailureCleanup) {
                let lower = text.to_ascii_lowercase();
                ensure!(
                    lower.contains("resctrl") || lower.contains("closid"),
                    "unexpected RDT error: {text}"
                );
            } else if matches!(case, Case::HookFailureCleanup) {
                ensure!(
                    text.to_ascii_lowercase().contains("hook"),
                    "unexpected hook error: {text}"
                );
            } else {
                ensure!(
                    text.contains("Is a directory"),
                    "unexpected state-save error: {text}"
                );
            }
            let init: i32 = fs::read_to_string(&pid_file)
                .context("failure preceded init creation")?
                .trim()
                .parse()?;
            ensure!(init > 1, "invalid init pid");
            wait_dead(&[init]).context("failed startup left init alive")?;
            ensure!(
                !container
                    .bundle
                    .path()
                    .join("bundle/rootfs/started")
                    .exists(),
                "failed workload ran"
            );
            container.absent()?;
            if let Some(cgroup) = foreign_cgroup {
                ensure!(
                    fs::read_to_string(cgroup.join("cgroup.kill"))?.is_empty(),
                    "startup cleanup killed a cgroup it never joined"
                );
            }
        }
        Case::PrivatePidKillAll
        | Case::PrivatePidForceDelete
        | Case::InaccessibleParentKillAll
        | Case::InaccessibleParentForceDelete
        | Case::EmptyResourcesKillAll
        | Case::AttachedMissingCgroupKillAll
        | Case::AttachedMissingCgroupForceDelete
        | Case::LegacyForceDelete => {
            let container = Container::new(Some(None), false, &cgroup_parent)?;
            if matches!(case, Case::EmptyResourcesKillAll) {
                container.set_resources(serde_json::from_value(serde_json::json!({
                    "devices": [], "memory": {}, "cpu": {},
                    "blockIO": {"weightDevice": [], "throttleReadBpsDevice": []},
                    "hugepageLimits": [], "network": {"priorities": []},
                    "rdma": {}, "unified": {}
                }))?)?;
            }
            let init = container.start()?;
            let mut child = None;
            wait_for(
                || {
                    child = children(init)?.first().copied();
                    Ok(child.is_some())
                },
                "workload child did not start",
            )?;
            let child = child.unwrap();
            if matches!(case, Case::PrivatePidKillAll | Case::LegacyForceDelete) {
                // Model a container created before attachment status was saved.
                let _ = container.set_attachment_fixture(None)?;
            }
            checked(
                container
                    .command()
                    .args(["exec", &container.id, "/bin/busybox", "true"]),
            )?;
            if matches!(
                case,
                Case::AttachedMissingCgroupKillAll | Case::AttachedMissingCgroupForceDelete
            ) {
                // Model an attached container whose processes were moved out
                // before its cgroup disappeared; no host cgroup is modified.
                let saved = container.set_attachment_fixture(Some("attached".into()))?;
                let mut command = container.command();
                if matches!(case, Case::AttachedMissingCgroupKillAll) {
                    command.args(["kill", "--all", &container.id, "KILL"]);
                } else {
                    command.args(["delete", "--force", &container.id]);
                }
                let result = output(&mut command)?;
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                );
                ensure!(
                    !result.status.success(),
                    "attached container with a missing cgroup reported success"
                );
                ensure!(
                    text.contains("No such file or directory"),
                    "unexpected error: {text}"
                );
                ensure!(
                    alive(init)? && alive(child)?,
                    "missing cgroup error killed the workload"
                );
                let _ = container.set_attachment_fixture(saved)?;
            }
            if case.uses_inaccessible_parent() {
                // A saved attached container must retain its cgroup errors,
                // rather than silently falling back to signaling init.
                let saved_attachment = container.set_attachment_fixture(Some("attached".into()))?;
                permission_denied(container.command().args([
                    "exec",
                    &container.id,
                    "/bin/busybox",
                    "true",
                ]))?;
                for attachment in [Some("attached".into()), None] {
                    let _ = container.set_attachment_fixture(attachment)?;
                    if matches!(case, Case::InaccessibleParentKillAll) {
                        permission_denied(container.command().args([
                            "kill",
                            "--all",
                            &container.id,
                            "KILL",
                        ]))?;
                    } else {
                        permission_denied(container.command().args([
                            "delete",
                            "--force",
                            &container.id,
                        ]))?;
                    }
                    ensure!(
                        alive(init)? && alive(child)?,
                        "cgroup error signaled the workload"
                    );
                }
                let _ = container.set_attachment_fixture(saved_attachment)?;
            }
            if matches!(
                case,
                Case::PrivatePidKillAll
                    | Case::InaccessibleParentKillAll
                    | Case::EmptyResourcesKillAll
                    | Case::AttachedMissingCgroupKillAll
            ) {
                checked(
                    container
                        .command()
                        .args(["kill", "--all", &container.id, "KILL"]),
                )?;
                wait_dead(&[init, child])?;
                checked(container.command().args(["delete", &container.id]))?;
            } else {
                checked(
                    container
                        .command()
                        .args(["delete", "--force", &container.id]),
                )?;
                wait_dead(&[init, child])?;
                container.absent()?;
            }
        }
        Case::MemoryLimitRejected | Case::PidsLimitRejected => {
            let container = Container::new(Some(None), false, &cgroup_parent)?;
            let resources = if matches!(case, Case::MemoryLimitRejected) {
                serde_json::json!({"memory": {"limit": 67108864}})
            } else {
                serde_json::json!({"pids": {"limit": 16}})
            };
            container.set_resources(serde_json::from_value(resources)?)?;
            container.reject("requested resource limits require a cgroup")?;
        }
        Case::HostPidRejected => Container::new(None, false, Path::new("/"))?
            .reject("without a private PID namespace needs a cgroup")?,
        Case::JoinedPidRejected => {
            let holder = Container::new(Some(None), true, Path::new("/"))?;
            let init = holder.start()?;
            let namespace = PathBuf::from(format!("/proc/{init}/ns/pid"));
            checked(
                // The checkout may be inaccessible after entering the userns.
                Command::new("/proc/self/exe")
                    .args(["rootless-no-cgroup-worker", "join"])
                    .arg(&namespace),
            )?;
            Container::new(Some(Some(&namespace)), false, Path::new("/"))?
                .reject("without a private PID namespace needs a cgroup")?;
            ensure!(alive(init)?, "joined namespace holder died");
            ensure!(
                children(init)?.is_empty(),
                "rejected workload left tasks in joined namespace"
            );
            checked(holder.command().args(["delete", "--force", &holder.id]))?;
            wait_dead(&[init])?;
        }
    }
    // As sandbox PID 1, also reap exited orphans left by detached runtimes.
    while matches!(
        waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)),
        Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..))
    ) {}
    Ok(())
}

fn children(pid: i32) -> Result<Vec<i32>> {
    Ok(Process::new(pid)?
        .task_main_thread()?
        .children()?
        .into_iter()
        .map(|pid| pid as i32)
        .collect())
}

fn alive(pid: i32) -> Result<bool> {
    match Process::new(pid).and_then(|process| process.stat()) {
        Ok(stat) => Ok(stat.state != 'Z' && stat.state != 'X'),
        Err(procfs::ProcError::NotFound(_)) => Ok(false),
        Err(err) => Err(err).context("could not inspect workload process"),
    }
}

fn wait_dead(pids: &[i32]) -> Result<()> {
    wait_for(
        || {
            for pid in pids {
                if alive(*pid)? {
                    return Ok(false);
                }
            }
            Ok(true)
        },
        "container processes survived",
    )
}

fn wait_for(mut condition: impl FnMut() -> Result<bool>, message: &str) -> Result<()> {
    let deadline = Instant::now() + WAIT;
    while !condition()? {
        ensure!(Instant::now() < deadline, "{message}");
        sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn permission_denied(command: &mut Command) -> Result<()> {
    let result = output(command)?;
    ensure!(
        !result.status.success(),
        "command {command:?} unexpectedly succeeded"
    );
    ensure!(
        String::from_utf8_lossy(&result.stderr).contains("Permission denied"),
        "command {command:?} did not fail for cgroup permissions: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

fn checked(command: &mut Command) -> Result<String> {
    let result = output(command)?;
    ensure!(
        result.status.success(),
        "command {command:?} failed ({}): {}{}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).context("command stdout is not utf-8")
}

fn output(command: &mut Command) -> Result<Output> {
    // A detached container inherits stdio. Files avoid waiting forever for an
    // inherited pipe to close. Keep diagnostics separate from JSON on stdout.
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()
        .with_context(|| format!("could not spawn {command:?}"))?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            bail!("command timed out: {command:?}");
        }
        sleep(Duration::from_millis(20));
    };
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    stdout.read_to_end(&mut stdout_bytes)?;
    stderr.read_to_end(&mut stderr_bytes)?;
    Ok(Output {
        status,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
    })
}
