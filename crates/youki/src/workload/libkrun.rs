use std::cell::Cell;
use std::ffi::CString;
use std::fs::Permissions;
use std::io;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use libcontainer::error::MissingSpecError;
use libcontainer::oci_spec::runtime::{
    LinuxBuilder, LinuxDevice, LinuxDeviceBuilder, LinuxDeviceCgroup, LinuxDeviceCgroupBuilder,
    LinuxDeviceType, Spec,
};
use libcontainer::workload::{
    ContainerExecutor, EMPTY, Executor, ExecutorError, ExecutorValidationError, HostExecutor,
};
use nix::errno::Errno;
use nix::sys::stat::{major, minor, stat};
use pathrs::Root;
use pathrs::flags::{OpenFlags, ResolverFlags};

const EXECUTOR_NAME: &str = "krun";
const KRUN_CONFIG_FILE: &str = ".krun_config.json";

const DEFAULT_VCPUS: u8 = 1;
const DEFAULT_RAM_MIB: u32 = 2 * 1024; // 2GiB

#[derive(Clone, Default)]
pub struct LibkrunExecutor {
    ctx_id: Cell<Option<u32>>,
}

impl LibkrunExecutor {
    fn set_ctx_id(&self, value: u32) {
        self.ctx_id.set(Some(value));
    }

    fn get_ctx_id(&self) -> Result<u32, ExecutorError> {
        self.ctx_id
            .get()
            .ok_or_else(|| ExecutorError::Other("ctx_id not initialized".into()))
    }
}

pub fn get_executor() -> LibkrunExecutor {
    LibkrunExecutor::default()
}

fn krun_create_ctx() -> Result<u32, ExecutorError> {
    let id = krun::krun_create_ctx();
    if id < 0 {
        Err(ExecutorError::Other(format!("krun_create_ctx rc={id}")))
    } else {
        Ok(id as u32)
    }
}

fn krun_set_vm_config(ctx: u32, vcpus: u8, mem_mb: u32) -> Result<(), ExecutorError> {
    let rc = krun::krun_set_vm_config(ctx, vcpus, mem_mb);
    if rc < 0 {
        Err(ExecutorError::Other(format!("set_vm_config rc={rc}")))
    } else {
        Ok(())
    }
}

fn krun_set_root(ctx: u32, root: &CString) -> Result<(), ExecutorError> {
    let rc = unsafe { krun::krun_set_root(ctx, root.as_ptr()) };
    if rc < 0 {
        Err(ExecutorError::Other(format!("krun_set_root rc={rc}")))
    } else {
        Ok(())
    }
}

// libkrun does not return to Rust on success:
//   - event_manager runs in an infinite loop:
//     https://github.com/containers/libkrun/blob/a3b7ae213195c9f871a17c72f0d020e46ed90584/src/libkrun/src/lib.rs#L2746
//   - VM exit terminates the process via libc::_exit:
//     https://github.com/containers/libkrun/blob/a3b7ae213195c9f871a17c72f0d020e46ed90584/src/vmm/src/lib.rs#L369
fn krun_start_enter(ctx: u32) -> Result<(), ExecutorError> {
    let rc = krun::krun_start_enter(ctx);
    if rc < 0 {
        return Err(ExecutorError::Other(format!("krun_start_enter rc={rc}")));
    }
    unreachable!("krun_start_enter returned {rc} but libkrun should _exit on success");
}

impl HostExecutor for LibkrunExecutor {
    fn modify_spec(&self, spec: Spec) -> Result<Spec, ExecutorError> {
        if !can_handle(&spec) {
            return Err(ExecutorError::CantHandle(EXECUTOR_NAME));
        }
        validate_kvm().map_err(|e| {
            ExecutorError::Other(format!("validate kvm error in host executor: {e}"))
        })?;
        tracing::debug!("executing libkrun host executor");

        let spec = configure_spec_for_libkrun(spec)
            .map_err(|e| ExecutorError::Other(format!("configure_for_libkrun: {e}")))?;

        // krun_create_ctx must be called here (host side, before pivot_root), not in exec.
        // It triggers the lazy dlopen of libkrunfw.so.5 inside libkrun (via a LazyLock in KrunfwBindings::new).
        // After pivot_root, libkrunfw.so.5 is unreachable from the container rootfs,
        // so deferring this call would make krun_start_enter later fail with -ENOENT.
        let ctx_id = krun_create_ctx()?;
        self.set_ctx_id(ctx_id);
        Ok(spec)
    }
}

impl ContainerExecutor for LibkrunExecutor {
    fn exec(&self, spec: &Spec) -> Result<(), ExecutorError> {
        if !can_handle(spec) {
            return Err(ExecutorError::CantHandle(EXECUTOR_NAME));
        }
        tracing::debug!("executing libkrun container executor");

        let process = spec.process().as_ref();
        let args = process.and_then(|p| p.args().as_ref()).unwrap_or(&EMPTY);
        if args.is_empty() {
            tracing::error!("at least one process arg must be specified");
            return Err(ExecutorError::InvalidArg);
        }

        let ctx_id = self.get_ctx_id()?;

        let (vcpus, ram_mib) = read_krun_vm_config_from_annotations(spec);
        krun_set_vm_config(ctx_id, vcpus, ram_mib)?;

        // At this point pivot_root has run, so "/" is the rootfs containing .krun_config.json.
        let root = CString::new("/")
            .map_err(|e| ExecutorError::Other(format!("CString for root: {e}")))?;
        krun_set_root(ctx_id, &root)?;

        krun_start_enter(ctx_id)
    }

    fn validate(&self, spec: &Spec) -> Result<(), ExecutorValidationError> {
        if !can_handle(spec) {
            return Err(ExecutorValidationError::CantHandle(EXECUTOR_NAME));
        }
        Ok(())
    }
}

impl Executor for LibkrunExecutor {}

pub fn can_handle(spec: &Spec) -> bool {
    if let Some(annotations) = spec.annotations()
        && let Some(handler) = annotations.get("run.oci.handler")
    {
        return handler == "krun";
    }

    false
}

pub fn validate_kvm() -> Result<(), KrunError> {
    match stat_dev_numbers("/dev/kvm") {
        Ok((_major, _minor)) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(KrunError::Other("/dev/kvm unavailable".to_string()))
        }
        Err(e) => Err(KrunError::Other(format!("failed to read /dev/kvm: {e}"))),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KrunError {
    #[error("{0}")]
    Other(String),
}

// Add /dev/kvm to `linux.devices` so libkrun can access KVM device.
pub fn add_dev_kvm_to_linux_devices(spec: &mut Spec) -> Result<(), KrunError> {
    let (kvm_major, kvm_minor) = match stat_dev_numbers("/dev/kvm") {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(e) => return Err(KrunError::Other(format!("stat `/dev/kvm`: {e}"))),
    };

    if spec.linux().is_none() {
        let linux = LinuxBuilder::default()
            .build()
            .map_err(|e| KrunError::Other(format!("build default linux section: {e}")))?;
        spec.set_linux(Some(linux));
    }

    let linux = spec
        .linux_mut()
        .as_mut()
        .ok_or_else(|| KrunError::Other("spec.linux is None after initialization".into()))?;

    let devices = linux.devices_mut().get_or_insert_with(Vec::new);

    let exists = devices.iter().any(|d| d.path() == Path::new("/dev/kvm"));
    if !exists {
        devices.push(make_oci_spec_device(
            PathBuf::from("/dev/kvm"),
            LinuxDeviceType::C,
            kvm_major,
            kvm_minor,
            0o666u32,
            0u32,
            0u32,
        )?);
    }
    Ok(())
}

// Add an allow rule for /dev/kvm to linux.resources.devices
// if resources.devices is None or empty, it's effectively permissive, so skip.
pub fn allow_kvm_in_linux_resources_devices(spec: &mut Spec) -> Result<(), KrunError> {
    let linux = match spec.linux_mut() {
        Some(l) => l,
        None => return Ok(()),
    };
    let res = match linux.resources_mut() {
        Some(r) => r,
        None => return Ok(()),
    };
    let device_cgroups = match res.devices_mut().as_mut() {
        Some(v) if !v.is_empty() => v,
        _ => return Ok(()),
    };

    let (kvm_major, kvm_minor) = match stat_dev_numbers("/dev/kvm") {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(KrunError::Other(format!("stat `/dev/kvm`: {e}"))),
    };

    device_cgroups.push(make_oci_spec_dev_cgroup(
        LinuxDeviceType::C,
        kvm_major,
        kvm_minor,
        true,
        "rwm",
    )?);

    Ok(())
}

fn stat_dev_numbers(path: &str) -> std::io::Result<(i64, i64)> {
    match stat(Path::new(path)) {
        Ok(st) => Ok((major(st.st_rdev) as i64, minor(st.st_rdev) as i64)),
        Err(Errno::ENOENT) => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
        Err(e) => Err(io::Error::other(e)),
    }
}

// CVE-2025-24965: the content below rootfs cannot be trusted because it is controlled by the user.  We
// must ensure the file is opened below the rootfs directory.
// see: https://github.com/containers/crun/blob/92977c0fc843e4649fe4611a97ba12b06cb5073f/src/libcrun/handlers/krun.c#L514C1-L515C72
pub fn write_krun_config(rootfs: &Path, json_spec: &str) -> Result<(), KrunError> {
    let mut root =
        Root::open(rootfs).map_err(|e| KrunError::Other(format!("failed to open rootfs {e}")))?;
    root.set_resolver_flags(ResolverFlags::NO_SYMLINKS);
    let perm = Permissions::from_mode(0o444);

    let mut f = root
        .create_file(
            KRUN_CONFIG_FILE,
            OpenFlags::O_WRONLY | OpenFlags::O_TRUNC | OpenFlags::O_CLOEXEC,
            &perm,
        )
        .map_err(|e| KrunError::Other(format!("failed to create file: {e}")))?;

    f.write_all(json_spec.as_bytes())
        .map_err(|e| KrunError::Other(format!("failed to write : {e}")))?;

    Ok(())
}

pub fn configure_spec_for_libkrun(mut spec: Spec) -> Result<Spec, KrunError> {
    let rootfs = spec
        .root()
        .as_ref()
        .ok_or(MissingSpecError::Root)
        .map_err(|e| KrunError::Other(format!("missing root in spec: {e:?}")))?
        .path()
        .to_path_buf();
    add_dev_kvm_to_linux_devices(&mut spec)
        .map_err(|e| KrunError::Other(format!("add_dev_kvm_to_linux_devices: {e:?}")))?;
    allow_kvm_in_linux_resources_devices(&mut spec)
        .map_err(|e| KrunError::Other(format!("allow_kvm_in_linux_resources_devices: {e:?}")))?;

    let json_spec = serde_json::to_string_pretty(&spec)
        .map_err(|e| KrunError::Other(format!("failed to serialize spec to JSON: {}", e)))?;
    write_krun_config(&rootfs, &json_spec)
        .map_err(|e| KrunError::Other(format!("write_krun_config: {e:?}")))?;
    Ok(spec)
}

fn make_oci_spec_dev_cgroup(
    dev_type: LinuxDeviceType,
    major_num: i64,
    minor_num: i64,
    allow: bool,
    access: &str,
) -> Result<LinuxDeviceCgroup, KrunError> {
    LinuxDeviceCgroupBuilder::default()
        .allow(allow)
        .typ(dev_type)
        .major(major_num)
        .minor(minor_num)
        .access(access.to_string())
        .build()
        .map_err(|e| KrunError::Other(format!("device cgroup build: {e}")))
}

fn make_oci_spec_device(
    path: impl Into<PathBuf>,
    dev_type: LinuxDeviceType,
    major_num: i64,
    minor_num: i64,
    file_mode: u32,
    uid: u32,
    gid: u32,
) -> Result<LinuxDevice, KrunError> {
    LinuxDeviceBuilder::default()
        .typ(dev_type)
        .path(path.into())
        .major(major_num)
        .minor(minor_num)
        .file_mode(file_mode)
        .uid(uid)
        .gid(gid)
        .build()
        .map_err(|e| KrunError::Other(format!("device node build: {e}")))
}

fn read_krun_vm_config_from_annotations(spec: &Spec) -> (u8, u32) {
    let ann = spec.annotations().as_ref();
    let vcpus = ann
        .and_then(|a| a.get("krun.cpus"))
        .and_then(|s| s.trim().parse::<u8>().ok())
        .unwrap_or(DEFAULT_VCPUS);
    let ram_mib = ann
        .and_then(|a| a.get("krun.ram_mib"))
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_RAM_MIB);
    tracing::debug!(vcpus, ram_mib, "libkrun VM config");
    (vcpus, ram_mib)
}
