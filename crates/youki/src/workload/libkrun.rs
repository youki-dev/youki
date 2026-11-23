use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::Permissions;
use std::io;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use libcontainer::error::MissingSpecError;
use libcontainer::oci_spec::runtime::{
    LinuxBuilder, LinuxDevice, LinuxDeviceBuilder, LinuxDeviceCgroup, LinuxDeviceCgroupBuilder,
    LinuxDeviceType, LinuxResources, Spec,
};
use libcontainer::workload::{
    ContainerExecutor, EMPTY, Executor, ExecutorError, ExecutorValidationError, HostExecutor,
};
use nix::errno::Errno;
use nix::sys::stat::{major, minor, stat};
use pathrs::Root;
use pathrs::error::ErrorKind;
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

    /// Creates the krun context and keeps its id for [`ContainerExecutor::exec`].
    ///
    /// This must be called on the host side before pivot_root
    /// (from [`HostExecutor::modify_spec`]), not in [`ContainerExecutor::exec`].
    /// `krun_create_ctx` triggers the lazy dlopen of libkrunfw.so.5 inside libkrun.
    /// After pivot_root, libkrunfw.so.5 is unreachable from the container rootfs,
    /// so deferring this call would make krun_start_enter fail with -ENOENT.
    fn create_krun_ctx(&self) -> Result<(), ExecutorError> {
        let ctx_id = krun_create_ctx()?;
        self.set_ctx_id(ctx_id);
        Ok(())
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
    /// Prepares the host side of a krun container.
    ///
    /// Besides modifying the spec, this also validates the krun annotations and
    /// the host environment (`/dev/kvm`), and creates the krun context.
    fn modify_spec(&self, spec: Spec) -> Result<Spec, ExecutorError> {
        if !can_handle(&spec) {
            return Err(ExecutorError::CantHandle(EXECUTOR_NAME));
        }
        // Decide the VM config here (host side) so that an invalid annotation
        // fails `create` with a clear error instead of failing later in the container.
        let (vcpus, ram_mib) = read_krun_vm_config(&spec)?;
        validate_kvm().map_err(|e| {
            ExecutorError::Other(format!("validate kvm error in host executor: {e}"))
        })?;
        tracing::debug!("executing libkrun host executor");

        let spec = configure_spec_for_libkrun(spec)
            .map_err(|e| ExecutorError::Other(format!("configure_for_libkrun: {e}")))?;

        self.create_krun_ctx()?;
        // The VM config is kept in the krun context, which survives the fork into
        // the container process, so `ContainerExecutor::exec` does not need to read
        // the annotations again.
        krun_set_vm_config(self.get_ctx_id()?, vcpus, ram_mib)?;
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

        // The krun context and its VM config were set up in `HostExecutor::modify_spec`.
        let ctx_id = self.get_ctx_id()?;

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
    is_krun_handler(spec.annotations().as_ref())
}

pub fn is_krun_handler(annotations: Option<&HashMap<String, String>>) -> bool {
    annotations
        .and_then(|a| a.get("run.oci.handler"))
        .is_some_and(|handler| handler == "krun")
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

// Add an allow rule for /dev/kvm to linux.resources.devices.
pub fn allow_kvm_in_linux_resources_devices(spec: &mut Spec) -> Result<(), KrunError> {
    let (kvm_major, kvm_minor) = match stat_dev_numbers("/dev/kvm") {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(KrunError::Other(format!("stat `/dev/kvm`: {e}"))),
    };
    add_kvm_device_cgroup_rule(spec, kvm_major, kvm_minor)
}

// `linux` and `linux.resources` are created when missing, so that the rule is
// always applied.
fn add_kvm_device_cgroup_rule(
    spec: &mut Spec,
    kvm_major: i64,
    kvm_minor: i64,
) -> Result<(), KrunError> {
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
    let res = linux
        .resources_mut()
        .get_or_insert_with(LinuxResources::default);

    // With linux.resources, the device controller denies everything except the
    // default devices, so /dev/kvm must be allowed explicitly.
    let device_cgroups = res.devices_mut().get_or_insert_with(Vec::new);
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

    match root.remove_file(KRUN_CONFIG_FILE) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::OsError(Some(nix::libc::ENOENT)) => {}
        Err(e) => {
            return Err(KrunError::Other(format!(
                "failed to remove stale {KRUN_CONFIG_FILE}: {e}"
            )));
        }
    }

    let perm = Permissions::from_mode(0o444);
    let mut f = root
        .create_file(
            KRUN_CONFIG_FILE,
            OpenFlags::O_WRONLY | OpenFlags::O_EXCL | OpenFlags::O_CLOEXEC,
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

// Decide the guest vCPUs and RAM from the spec.
//
// RAM precedence:
//   1. `krun.ram_mib` annotation
//   2. `linux.resources.memory.limit`, so the guest does not request more memory
//      than the cgroup allows and get OOM-killed
//   3. DEFAULT_RAM_MIB
fn read_krun_vm_config(spec: &Spec) -> Result<(u8, u32), ExecutorError> {
    let vcpus = parse_annotation::<u8>(spec, "krun.cpus")?.unwrap_or(DEFAULT_VCPUS);
    let ram_mib = match parse_annotation::<u32>(spec, "krun.ram_mib")? {
        Some(v) => v,
        None => ram_mib_from_memory_limit(spec)?.unwrap_or(DEFAULT_RAM_MIB),
    };
    tracing::debug!(vcpus, ram_mib, "libkrun VM config");
    Ok((vcpus, ram_mib))
}

// Parse a positive integer annotation.
// Returns None only when the key is missing; a present but invalid value
// (not an integer, out of range, or zero) is an error so that it is not
// silently replaced by the default.
fn parse_annotation<T>(spec: &Spec, key: &str) -> Result<Option<T>, ExecutorError>
where
    T: std::str::FromStr + PartialEq + Default,
{
    let Some(raw) = spec.annotations().as_ref().and_then(|a| a.get(key)) else {
        return Ok(None);
    };
    match raw.trim().parse::<T>() {
        Ok(v) if v != T::default() => Ok(Some(v)),
        _ => Err(ExecutorError::Other(format!(
            "invalid value for annotation {key}: {raw:?} (must be a positive integer)"
        ))),
    }
}

// Convert `linux.resources.memory.limit` (bytes) to MiB.
// Returns None when no limit is set or the limit is unlimited (negative, e.g. -1).
fn ram_mib_from_memory_limit(spec: &Spec) -> Result<Option<u32>, ExecutorError> {
    let limit = spec
        .linux()
        .as_ref()
        .and_then(|l| l.resources().as_ref())
        .and_then(|r| r.memory().as_ref())
        .and_then(|m| m.limit());
    let Some(limit) = limit else {
        return Ok(None);
    };
    if limit < 0 {
        return Ok(None);
    }
    let mib = limit / (1024 * 1024);
    if mib == 0 {
        return Err(ExecutorError::Other(format!(
            "linux.resources.memory.limit ({limit} bytes) is too small for a krun VM"
        )));
    }
    Ok(Some(u32::try_from(mib).unwrap_or(u32::MAX)))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use libcontainer::oci_spec::runtime::{LinuxMemoryBuilder, LinuxResourcesBuilder, SpecBuilder};

    use super::*;

    const MIB: i64 = 1024 * 1024;

    fn spec_with(ram_mib_annotation: Option<&str>, memory_limit: Option<i64>) -> Spec {
        spec_with_annotations(
            ram_mib_annotation
                .map(|v| vec![("krun.ram_mib", v)])
                .unwrap_or_default(),
            memory_limit,
        )
    }

    fn spec_with_annotations(extra: Vec<(&str, &str)>, memory_limit: Option<i64>) -> Spec {
        let mut annotations = HashMap::from([("run.oci.handler".to_string(), "krun".to_string())]);
        for (k, v) in extra {
            annotations.insert(k.to_string(), v.to_string());
        }
        let mut linux = LinuxBuilder::default();
        if let Some(limit) = memory_limit {
            linux = linux.resources(
                LinuxResourcesBuilder::default()
                    .memory(LinuxMemoryBuilder::default().limit(limit).build().unwrap())
                    .build()
                    .unwrap(),
            );
        }
        SpecBuilder::default()
            .annotations(annotations)
            .linux(linux.build().unwrap())
            .build()
            .unwrap()
    }

    #[test]
    fn ram_defaults_without_annotation_or_limit() {
        let (_, ram) = read_krun_vm_config(&spec_with(None, None)).unwrap();
        assert_eq!(ram, DEFAULT_RAM_MIB);
    }

    #[test]
    fn ram_follows_memory_limit() {
        let (_, ram) = read_krun_vm_config(&spec_with(None, Some(512 * MIB))).unwrap();
        assert_eq!(ram, 512);
    }

    #[test]
    fn ram_memory_limit_rounds_down_to_mib() {
        let (_, ram) = read_krun_vm_config(&spec_with(None, Some(512 * MIB + 123))).unwrap();
        assert_eq!(ram, 512);
    }

    #[test]
    fn ram_annotation_overrides_memory_limit() {
        let (_, ram) = read_krun_vm_config(&spec_with(Some("1024"), Some(512 * MIB))).unwrap();
        assert_eq!(ram, 1024);
    }

    #[test]
    fn ram_unlimited_memory_limit_uses_default() {
        let (_, ram) = read_krun_vm_config(&spec_with(None, Some(-1))).unwrap();
        assert_eq!(ram, DEFAULT_RAM_MIB);
    }

    #[test]
    fn ram_memory_limit_below_one_mib_is_error() {
        assert!(read_krun_vm_config(&spec_with(None, Some(MIB - 1))).is_err());
    }

    #[test]
    fn cpus_default_when_missing() {
        let (vcpus, _) = read_krun_vm_config(&spec_with(None, None)).unwrap();
        assert_eq!(vcpus, DEFAULT_VCPUS);
    }

    #[test]
    fn cpus_from_annotation() {
        let spec = spec_with_annotations(vec![("krun.cpus", "4")], None);
        let (vcpus, _) = read_krun_vm_config(&spec).unwrap();
        assert_eq!(vcpus, 4);
    }

    #[test]
    fn invalid_cpus_is_error() {
        for v in ["abc", "", "0", "-1", "1.5", "256"] {
            let spec = spec_with_annotations(vec![("krun.cpus", v)], None);
            assert!(
                read_krun_vm_config(&spec).is_err(),
                "krun.cpus={v:?} should be rejected"
            );
        }
    }

    #[test]
    fn invalid_ram_mib_is_error() {
        // An invalid value must not fall back to the memory limit or the default.
        for v in ["abc", "", "0", "-1", "2GiB", "4294967296"] {
            let spec = spec_with_annotations(vec![("krun.ram_mib", v)], Some(512 * MIB));
            assert!(
                read_krun_vm_config(&spec).is_err(),
                "krun.ram_mib={v:?} should be rejected"
            );
        }
    }

    #[test]
    fn krun_handler_detection() {
        let ann = |k: &str, v: &str| HashMap::from([(k.to_string(), v.to_string())]);
        assert!(is_krun_handler(Some(&ann("run.oci.handler", "krun"))));
        assert!(!is_krun_handler(Some(&ann("run.oci.handler", "wasm"))));
        assert!(!is_krun_handler(Some(&ann("krun.cpus", "2"))));
        assert!(!is_krun_handler(Some(&HashMap::new())));
        assert!(!is_krun_handler(None));
    }

    fn kvm_rules(spec: &Spec) -> Vec<LinuxDeviceCgroup> {
        spec.linux()
            .as_ref()
            .and_then(|l| l.resources().as_ref())
            .and_then(|r| r.devices().clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|d| d.major() == Some(10) && d.minor() == Some(232))
            .collect()
    }

    #[test]
    fn kvm_rule_added_without_linux_resources() {
        let mut spec = spec_with(None, None);
        // LinuxBuilder::default() sets default resources, so remove them explicitly.
        spec.linux_mut().as_mut().unwrap().set_resources(None);
        add_kvm_device_cgroup_rule(&mut spec, 10, 232).unwrap();
        let rules = kvm_rules(&spec);
        assert_eq!(rules.len(), 1);
        assert!(rules[0].allow());
        assert_eq!(rules[0].typ(), Some(LinuxDeviceType::C));
        assert_eq!(rules[0].access().as_deref(), Some("rwm"));
    }

    #[test]
    fn kvm_rule_added_without_linux_section() {
        let mut spec = SpecBuilder::default().build().unwrap();
        spec.set_linux(None);
        add_kvm_device_cgroup_rule(&mut spec, 10, 232).unwrap();
        assert_eq!(kvm_rules(&spec).len(), 1);
    }

    #[test]
    fn kvm_rule_keeps_existing_resources() {
        let mut spec = spec_with(None, Some(512 * MIB));
        add_kvm_device_cgroup_rule(&mut spec, 10, 232).unwrap();
        assert_eq!(kvm_rules(&spec).len(), 1);
        let limit = spec
            .linux()
            .as_ref()
            .and_then(|l| l.resources().as_ref())
            .and_then(|r| r.memory().as_ref())
            .and_then(|m| m.limit());
        assert_eq!(limit, Some(512 * MIB));
    }
}
