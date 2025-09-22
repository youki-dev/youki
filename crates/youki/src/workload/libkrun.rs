use std::cell::OnceCell;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::Write;
use std::os::raw::c_char;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use libcontainer::error::MissingSpecError;
use libcontainer::oci_spec::runtime::{
    LinuxBuilder, LinuxDevice, LinuxDeviceBuilder, LinuxDeviceCgroup, LinuxDeviceCgroupBuilder,
    LinuxDeviceType, Spec,
};
use libcontainer::workload::{Executor, ExecutorError, ExecutorValidationError, EMPTY};
use libloading::Library;
use nix::errno::Errno;
use nix::fcntl::{open, openat, OFlag};
use nix::sys::stat::{major, minor, stat, Mode};

const EXECUTOR_NAME: &str = "libkrun";
const KRUN_CONFIG_FILE: &str = ".krun_config.json";

const DEFAULT_LIBKRUN_PATH: &str = "libkrun.so.1";
const DEFAULT_VCPUS: u8 = 1;
const DEFAULT_RAM_MIB: u32 = 2 * 1024; // 2GiB
const DEFAULT_LOG_LEVEL: u32 = 1;

struct Krun {
    _lib: Library,
    krun_create_ctx: unsafe extern "C" fn() -> i32,
    krun_set_vm_config: unsafe extern "C" fn(u32, u8, u32) -> i32,
    krun_set_root: unsafe extern "C" fn(u32, *const c_char) -> i32,
    krun_set_log_level: unsafe extern "C" fn(u32) -> i32,
    krun_start_enter: unsafe extern "C" fn(u32) -> i32,
}

impl Krun {
    fn load(libkrun_path: String) -> Result<Self, ExecutorError> {
        unsafe {
            let lib = Library::new(&libkrun_path)
                .map_err(|e| ExecutorError::Other(format!("load {libkrun_path}: {e}")))?;
            let krun_create_ctx = *lib
                .get(b"krun_create_ctx")
                .map_err(|e| ExecutorError::Other(format!("krun_create_ctx: {e}")))?;
            let krun_set_vm_config = *lib
                .get(b"krun_set_vm_config")
                .map_err(|e| ExecutorError::Other(format!("krun_set_vm_config: {e}")))?;
            let krun_set_root = *lib
                .get(b"krun_set_root")
                .map_err(|e| ExecutorError::Other(format!("krun_set_root: {e}")))?;
            let krun_set_log_level = *lib
                .get(b"krun_set_log_level")
                .map_err(|e| ExecutorError::Other(format!("krun_set_log_level: {e}")))?;
            let krun_start_enter = *lib
                .get(b"krun_start_enter")
                .map_err(|e| ExecutorError::Other(format!("krun_start_enter: {e}")))?;

            Ok(Self {
                _lib: lib,
                krun_create_ctx,
                krun_set_vm_config,
                krun_set_root,
                krun_set_log_level,
                krun_start_enter,
            })
        }
    }

    fn create_ctx(&self) -> Result<u32, ExecutorError> {
        let id = unsafe { (self.krun_create_ctx)() };
        if id < 0 {
            Err(ExecutorError::Other(format!("krun_create_ctx rc={id}")))
        } else {
            Ok(id as u32)
        }
    }

    fn set_log_level(&self, level: u32) -> Result<(), ExecutorError> {
        let rc = unsafe { (self.krun_set_log_level)(level) };
        if rc < 0 {
            Err(ExecutorError::Other(format!("set_log_level rc={rc}")))
        } else {
            Ok(())
        }
    }

    fn set_vm_config(&self, ctx: u32, vcpus: u8, mem_mb: u32) -> Result<(), ExecutorError> {
        let rc = unsafe { (self.krun_set_vm_config)(ctx, vcpus, mem_mb) };
        if rc < 0 {
            Err(ExecutorError::Other(format!("set_vm_config rc={rc}")))
        } else {
            Ok(())
        }
    }

    fn set_root(&self, ctx: u32, root: &CString) -> Result<(), ExecutorError> {
        let rc = unsafe { (self.krun_set_root)(ctx, root.as_ptr()) };
        if rc < 0 {
            Err(ExecutorError::Other(format!("krun_set_root rc={rc}")))
        } else {
            Ok(())
        }
    }

    fn start_enter(&self, ctx: u32) -> Result<i32, ExecutorError> {
        let rc = unsafe { (self.krun_start_enter)(ctx) };
        if rc < 0 {
            Err(ExecutorError::Other(format!("krun_start_enter rc={rc}")))
        } else {
            Ok(rc)
        }
    }
}

#[derive(Clone)]
pub struct LibkrunExecutor {
    lib: Rc<OnceCell<Rc<Krun>>>,
    ctx_id: Rc<OnceCell<u32>>,
}

impl LibkrunExecutor {
    fn get_or_load_krun(&self, krun_path: String) -> Result<Rc<Krun>, ExecutorError> {
        if let Some(krun) = self.lib.get() {
            return Ok(krun.clone());
        }
        let krun = Rc::new(Krun::load(krun_path)?);
        let _ = self.lib.set(krun.clone());
        Ok(krun)
    }

    fn lib_loaded(&self) -> Result<Rc<Krun>, ExecutorError> {
        self.lib
            .get()
            .cloned()
            .ok_or_else(|| ExecutorError::Other("libkrun not preloaded".into()))
    }

    fn set_ctx_id(&self, value: u32) -> Result<(), ExecutorError> {
        self.ctx_id
            .set(value)
            .map_err(|_| ExecutorError::Other("ctx_id already initialized".into()))
    }

    fn get_ctx_id(&self) -> Result<u32, ExecutorError> {
        self.ctx_id
            .get()
            .copied()
            .ok_or_else(|| ExecutorError::Other("ctx_id not initialized".into()))
    }
}

pub fn get_executor() -> LibkrunExecutor {
    LibkrunExecutor {
        lib: Rc::new(OnceCell::new()),
        ctx_id: Rc::new(OnceCell::new()),
    }
}

impl Executor for LibkrunExecutor {
    fn pre_exec(&self, spec: Spec) -> Result<Spec, ExecutorError> {
        if !can_handle(&spec) {
            return Err(ExecutorError::CantHandle(EXECUTOR_NAME));
        }
        tracing::debug!("executing libkrun pre executor");

        let spec = configure_spec_for_libkrun(spec)
            .map_err(|e| ExecutorError::Other(format!("configure_for_libkrun: {e}")))?;
        let krun_path = read_krun_path_from_annotations(&spec);
        let krun = self.get_or_load_krun(krun_path)?;
        let ctx_id = krun.create_ctx()?;
        self.set_ctx_id(ctx_id)?;
        Ok(spec)
    }

    fn exec(&self, spec: &Spec) -> Result<(), ExecutorError> {
        if !can_handle(spec) {
            return Err(ExecutorError::CantHandle(EXECUTOR_NAME));
        }
        tracing::debug!("executing libkrun executor");

        let process = spec.process().as_ref();
        let args = process.and_then(|p| p.args().as_ref()).unwrap_or(&EMPTY);
        if args.is_empty() {
            tracing::error!("at least one process arg must be specified");
            return Err(ExecutorError::InvalidArg);
        }

        let krun = self.lib_loaded()?;
        let ctx_id = self.get_ctx_id()?;

        let log_level = read_krun_log_level_from_annotations(spec);
        krun.set_log_level(log_level)?;

        let (vcpus, ram_mib) = read_krun_vm_config_from_annotations(spec);
        tracing::debug!(vcpus = vcpus, ram_mib = ram_mib, "using VM config");
        krun.set_vm_config(ctx_id, vcpus, ram_mib)?;

        let root = CString::new("/")
            .map_err(|e| ExecutorError::Other(format!("CString for root: {e}")))?;
        krun.set_root(ctx_id, &root)?;

        let res = krun.start_enter(ctx_id)?;
        std::process::exit(res)
    }

    fn validate(&self, spec: &Spec) -> Result<(), ExecutorValidationError> {
        if !can_handle(spec) {
            return Err(ExecutorValidationError::CantHandle(EXECUTOR_NAME));
        }
        Ok(())
    }
}

pub fn can_handle(spec: &Spec) -> bool {
    if let Some(annotations) = spec.annotations() {
        if let Some(handler) = annotations.get("run.oci.handler") {
            return handler == "krun";
        }
    }

    false
}

#[derive(Debug, thiserror::Error)]
pub enum KrunError {
    #[error("{0}")]
    Other(String),
}

// Add /dev/kvm to `linux.devices` so libkrun can access KVM device.
pub fn modify_spec_device(spec: &mut Spec) -> Result<(), KrunError> {
    let mut linux = match spec.linux().clone() {
        Some(l) => l,
        None => LinuxBuilder::default()
            .build()
            .map_err(|e| KrunError::Other(format!("build default linux section: {e}")))?,
    };

    let (kvm_major, kvm_minor) = match stat_dev_numbers("/dev/kvm") {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            spec.set_linux(Some(linux));
            return Ok(());
        }
        Err(e) => return Err(KrunError::Other(format!("stat `/dev/kvm`: {e}"))),
    };

    let mut devices: Vec<LinuxDevice> = linux.devices().clone().unwrap_or_default();

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
        linux.set_devices(Some(devices));
    }

    spec.set_linux(Some(linux));
    Ok(())
}

// Add an allow rule for /dev/kvm to linux.resources.devices
// if resources.devices is None or empty, it's effectively permissive, so skip.
pub fn modify_spec_resource_device(spec: &mut Spec) -> Result<(), KrunError> {
    let mut linux = match spec.linux() {
        Some(l) => l.clone(),
        None => return Ok(()),
    };
    let mut res = match linux.resources() {
        Some(r) => r.clone(),
        None => return Ok(()),
    };
    let mut device_cgroups: Vec<LinuxDeviceCgroup> = match res.devices() {
        Some(v) if !v.is_empty() => v.clone(),
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
    res.set_devices(Some(device_cgroups));
    linux.set_resources(Some(res));
    spec.set_linux(Some(linux));

    Ok(())
}

fn stat_dev_numbers(path: &str) -> std::io::Result<(i64, i64)> {
    match stat(Path::new(path)) {
        Ok(st) => Ok((major(st.st_rdev) as i64, minor(st.st_rdev) as i64)),
        Err(Errno::ENOENT) => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
    }
}

// CVE-2025-24965: the content below rootfs cannot be trusted because it is controlled by the user.  We
// must ensure the file is opened below the rootfs directory.
// see: https://github.com/containers/crun/blob/92977c0fc843e4649fe4611a97ba12b06cb5073f/src/libcrun/handlers/krun.c#L514C1-L515C72
pub fn write_krun_config(rootfs: &Path, json_spec: &str) -> Result<(), KrunError> {
    let dirfd = open(
        rootfs,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| KrunError::Other(format!("open rootfs dir {} failed: {e}", rootfs.display())))?;
    let dirfile = unsafe { File::from_raw_fd(dirfd) };

    let oflags =
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_TRUNC | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mode = Mode::S_IRUSR | Mode::S_IRGRP | Mode::S_IROTH; // 0444

    let fd = openat(Some(dirfile.as_raw_fd()), KRUN_CONFIG_FILE, oflags, mode).map_err(|e| {
        KrunError::Other(format!(
            "openat({}, {:?}) failed: {e}",
            KRUN_CONFIG_FILE, oflags
        ))
    })?;

    let mut out = unsafe { File::from_raw_fd(fd) };
    out.write_all(json_spec.as_bytes())
        .map_err(|e| KrunError::Other(format!("write {} failed: {e}", KRUN_CONFIG_FILE)))?;
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
    modify_spec_device(&mut spec)
        .map_err(|e| KrunError::Other(format!("modify_spec_device: {e:?}")))?;
    modify_spec_resource_device(&mut spec)
        .map_err(|e| KrunError::Other(format!("modify_spec_resource_device: {e:?}")))?;

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
    let mut vcpus = DEFAULT_VCPUS;
    let mut ram_mib = DEFAULT_RAM_MIB;

    if let Some(ann) = spec.annotations().as_ref() {
        let cpus = ann
            .get("krun.cpus")
            .and_then(|s| s.trim().parse::<u8>().ok());
        let ram = ann
            .get("krun.ram_mib")
            .and_then(|s| s.trim().parse::<u32>().ok());

        match (cpus, ram) {
            (Some(c), Some(r)) => {
                vcpus = c;
                ram_mib = r;
            }
            _ => {
                tracing::debug!(
                    "invalid or incomplete annotations; using defaults: vcpus={}, ram_mib={}",
                    DEFAULT_VCPUS,
                    DEFAULT_RAM_MIB
                );
            }
        }
    } else {
        tracing::debug!(
            "no annotations; using defaults: vcpus={}, ram_mib={}",
            DEFAULT_VCPUS,
            DEFAULT_RAM_MIB
        );
    }

    (vcpus, ram_mib)
}

fn read_krun_log_level_from_annotations(spec: &Spec) -> u32 {
    let from_ann = spec
        .annotations()
        .as_ref()
        .and_then(|m| m.get("krun.log_level"))
        .map(|s| s.trim())
        .and_then(|s| s.parse::<u32>().ok());

    let log_level = from_ann.unwrap_or(DEFAULT_LOG_LEVEL);

    tracing::debug!(?log_level, "log level selected");
    log_level
}

fn read_krun_path_from_annotations(spec: &Spec) -> String {
    let from_ann = spec
        .annotations()
        .as_ref()
        .and_then(|m| m.get("krun.libkrun.path"))
        .map(|s| s.trim())
        .map(|s| s.to_string());

    let libkrun_path = from_ann.unwrap_or_else(|| DEFAULT_LIBKRUN_PATH.to_string());
    tracing::debug!(?libkrun_path, "libkrun library selected");

    libkrun_path
}
