//! Common CRIU utilities for checkpoint and restore operations.
//!
//! This module provides shared functionality between container checkpoint and restore,
//! following the patterns established by runc's CRIU integration.

use std::fs::File;
use std::os::unix::io::AsRawFd;

use nix::sys::stat::fstat;
use oci_spec::runtime::{LinuxNamespaceType, Spec};
use rust_criu::Criu;

use crate::error::LibcontainerError;

/// Resolve a bind-mount destination path through symlinks within `rootfs`.
/// The kernel follows symlinks when placing a bind mount, so if the destination
/// is a symlink (e.g. `/conf -> /real/conf`), the mount actually appears at the
/// resolved path. CRIU reads the actual mount table, so we must register the
/// resolved path as the external mount key (matching crun's `chroot_realpath` logic).
pub fn resolve_mount_dest_in_rootfs(rootfs: &std::path::Path, dest: &str) -> String {
    let dest_path = std::path::Path::new(dest);
    let full = rootfs.join(dest_path.strip_prefix("/").unwrap_or(dest_path));
    match std::fs::read_link(&full) {
        Ok(target) if target.is_absolute() => target.to_string_lossy().into_owned(),
        Ok(target) => {
            // Relative symlink: resolve relative to dest's parent directory.
            let parent = dest_path.parent().unwrap_or(std::path::Path::new("/"));
            parent.join(target).to_string_lossy().into_owned()
        }
        Err(_) => dest.to_owned(),
    }
}

/// Minimum CRIU version required for checkpoint/restore functionality.
/// This matches crun's LIBCRIU_MIN_VERSION requirement (3.15.0).
/// Version format: MAJOR * 10000 + MINOR * 100 + PATCH
pub const CRIU_VERSION_MINIMUM: u32 = 31500; // 3.15.0

fn compare_criu_version(version: u32, min_version: u32) -> Result<(), LibcontainerError> {
    if version < min_version {
        return Err(LibcontainerError::Other(format!(
            "CRIU version {} is below minimum required version {}",
            version, min_version,
        )));
    }
    Ok(())
}

/// Check if CRIU version is greater than or equal to min_version.
pub fn check_criu_version(min_version: u32) -> Result<(), LibcontainerError> {
    let mut criu = Criu::new()
        .map_err(|e| LibcontainerError::Other(format!("failed to create CRIU instance: {}", e)))?;

    let version = criu
        .get_criu_version()
        .map_err(|e| LibcontainerError::Other(format!("CRIU version check failed: {}", e)))?;

    compare_criu_version(version, min_version)
}

fn ns_name(ns_type: LinuxNamespaceType) -> &'static str {
    match ns_type {
        LinuxNamespaceType::Network => "net",
        LinuxNamespaceType::Pid => "pid",
        LinuxNamespaceType::Mount => "mnt",
        LinuxNamespaceType::Ipc => "ipc",
        LinuxNamespaceType::Uts => "uts",
        LinuxNamespaceType::User => "user",
        LinuxNamespaceType::Cgroup => "cgroup",
        LinuxNamespaceType::Time => "time",
    }
}

/// Convert a namespace short name to a CRIU external key.
///
/// This follows runc's `criuNsToKey` function which constructs:
/// "extRoot" + capitalize(name) + "NS"
///
/// Result format: "extRootNetNS", "extRootPidNS", etc.
///
/// Ref: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/criu_linux.go
fn criu_ns_to_key(name: &str) -> String {
    let mut chars = name.chars();
    let capitalized = match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect::<String>(),
        None => String::new(),
    };
    format!("extRoot{}NS", capitalized)
}

fn get_namespace_path(spec: &Spec, ns_type: LinuxNamespaceType) -> Option<String> {
    let linux = spec.linux().as_ref()?;
    let namespaces = linux.namespaces().as_ref()?;
    namespaces
        .iter()
        .find_map(|ns: &oci_spec::runtime::LinuxNamespace| {
            if ns.typ() == ns_type {
                ns.path().as_ref().map(|p| p.to_string_lossy().to_string())
            } else {
                None
            }
        })
}

/// Handle checkpointing of external namespaces.
///
/// Only called for network and PID namespaces whose path is set in the spec,
/// meaning they were created externally by the container runtime. If the path
/// is absent the namespace is internal and CRIU handles it on its own.
///
/// CRIU expects the information about an external namespace like this:
/// `--external <TYPE>[<inode>]:<key>`
///
/// For example: `net[4026532008]:extRootNetNS`
///
/// Follows runc's `handleCheckpointingExternalNamespaces` and crun's
/// `libcrun_criu_add_external_namespaces`.
pub fn handle_checkpointing_external_namespaces(
    criu: &mut Criu,
    spec: &Spec,
    ns_type: LinuxNamespaceType,
) -> Result<(), LibcontainerError> {
    let ns_path = match get_namespace_path(spec, ns_type) {
        Some(path) => path,
        None => return Ok(()),
    };

    let ns_file = File::open(&ns_path).map_err(|err| {
        tracing::error!(?ns_path, ?err, "failed to open namespace for checkpoint");
        LibcontainerError::OtherIO(err)
    })?;

    let stat = fstat(ns_file.as_raw_fd()).map_err(|err| {
        tracing::error!(?ns_path, ?err, "failed to stat namespace");
        LibcontainerError::Other(format!("failed to stat namespace: {}", err))
    })?;

    let name = ns_name(ns_type);
    let external = format!("{}[{}]:{}", name, stat.st_ino, criu_ns_to_key(name));

    tracing::debug!(?external, "adding external namespace for checkpoint");
    criu.add_external(external);

    Ok(())
}

/// Handle restoring of external namespaces.
///
/// This follows runc's `handleRestoringExternalNamespaces` function.
/// CRIU wants the information about an existing namespace like this:
/// `--inherit-fd fd[<fd>]:<key>`
///
/// The <key> needs to be the same as during checkpointing.
/// We are always using 'extRoot<TYPE>NS' as the key.
///
/// Ref: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/criu_linux.go
pub(super) fn handle_restoring_external_namespaces(
    criu: &mut Criu,
    spec: &Spec,
    ns_type: LinuxNamespaceType,
    extra_files: &mut Vec<File>,
) -> Result<(), LibcontainerError> {
    let ns_path = match get_namespace_path(spec, ns_type) {
        Some(path) => path,
        None => return Ok(()), // No external namespace configured
    };

    // Open the namespace file.
    // If a specific network namespace is defined it must exist.
    let ns_file = File::open(&ns_path).map_err(|err| {
        tracing::error!(?ns_path, ?err, "failed to open namespace for restore");
        LibcontainerError::OtherIO(err)
    })?;

    let key = criu_ns_to_key(ns_name(ns_type));

    let fd = ns_file.as_raw_fd();

    // The new rust-criu passes the original fd number in the inherit_fd protobuf
    // and relies on CRIU inheriting the fd via fork/exec rather than SCM_RIGHTS.
    // Rust's File::open() sets O_CLOEXEC by default, so we must clear FD_CLOEXEC
    // to ensure CRIU inherits this fd at the same number in its own process.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(LibcontainerError::Other(format!(
            "failed to get fd flags for namespace fd {}: {}",
            fd,
            std::io::Error::last_os_error()
        )));
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if ret < 0 {
        return Err(LibcontainerError::Other(format!(
            "failed to clear FD_CLOEXEC on namespace fd {}: {}",
            fd,
            std::io::Error::last_os_error()
        )));
    }

    criu.add_inherit_fd(fd, key)
        .map_err(|e| LibcontainerError::Other(format!("failed to add inherit_fd: {}", e)))?;

    tracing::debug!(?ns_path, fd, "adding inherit_fd for namespace restore");
    extra_files.push(ns_file);

    Ok(())
}

/// Handle restoring of all namespaces.
///
/// This follows runc's `handleRestoringNamespaces` function.
/// For NET and PID namespaces, use inherit_fd.
/// For other namespaces with paths, use join_ns (not yet implemented in rust_criu).
///
/// Ref: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/criu_linux.go
pub(super) fn handle_restoring_namespaces(
    criu: &mut Criu,
    spec: &Spec,
    extra_files: &mut Vec<File>,
) -> Result<(), LibcontainerError> {
    if let Some(linux) = spec.linux() {
        if let Some(namespaces) = linux.namespaces() {
            for ns in namespaces {
                match ns.typ() {
                    LinuxNamespaceType::Network | LinuxNamespaceType::Pid => {
                        // For network and PID namespaces, use inherit_fd.
                        // CRIU_VERSION_MINIMUM (3.15.0) already satisfies the per-namespace
                        // version requirements (NET >= 3.11.0, PID >= 3.15.0).
                        handle_restoring_external_namespaces(criu, spec, ns.typ(), extra_files)?;
                    }
                    LinuxNamespaceType::Cgroup => {
                        if ns.path().is_some() {
                            // CRIU does not support restoring into an existing cgroup namespace.
                            // Ref: runc handleRestoringNamespaces()
                            return Err(LibcontainerError::Other(
                                "cannot restore into an existing cgroup namespace".to_string(),
                            ));
                        }
                    }
                    _ => {
                        // For other namespaces (IPC, UTS, User, Mount, Time) with a path,
                        // runc uses JoinNs protobuf to pass the namespace fd to CRIU.
                        // TODO: Implement JoinNs support once rust_criu exposes the API.
                        // Ref: runc handleRestoringNamespaces()
                        if ns.path().is_some() {
                            tracing::debug!(
                                ns_type = ?ns.typ(),
                                path = ?ns.path(),
                                "skipping join_ns (not yet implemented)"
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_criu_version_ok() {
        assert!(compare_criu_version(31500, 31500).is_ok());
        assert!(compare_criu_version(31600, 31500).is_ok());
        assert!(compare_criu_version(40000, 31500).is_ok());
    }

    #[test]
    fn test_compare_criu_version_too_low() {
        assert!(compare_criu_version(31499, 31500).is_err());
        assert!(compare_criu_version(30000, 31500).is_err());
    }

    // ── criu_ns_to_key ────────────────────────────────────────────────────────

    #[test]
    fn test_criu_ns_to_key() {
        assert_eq!(criu_ns_to_key("net"), "extRootNetNS");
        assert_eq!(criu_ns_to_key("pid"), "extRootPidNS");
        assert_eq!(criu_ns_to_key("mnt"), "extRootMntNS");
        assert_eq!(criu_ns_to_key("ipc"), "extRootIpcNS");
        assert_eq!(criu_ns_to_key("uts"), "extRootUtsNS");
        assert_eq!(criu_ns_to_key("user"), "extRootUserNS");
        assert_eq!(criu_ns_to_key("cgroup"), "extRootCgroupNS");
        assert_eq!(criu_ns_to_key("time"), "extRootTimeNS");
    }

    // ── resolve_mount_dest_in_rootfs ──────────────────────────────────────────

    #[test]
    fn test_resolve_mount_dest_no_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        std::fs::create_dir_all(rootfs.join("data")).unwrap();

        assert_eq!(resolve_mount_dest_in_rootfs(rootfs, "/data"), "/data");
    }

    #[test]
    fn test_resolve_mount_dest_absolute_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        std::fs::create_dir_all(rootfs.join("real/conf")).unwrap();
        // /conf -> /real/conf (absolute symlink, mirrors the OCI bind-mount test case)
        std::os::unix::fs::symlink("/real/conf", rootfs.join("conf")).unwrap();

        assert_eq!(resolve_mount_dest_in_rootfs(rootfs, "/conf"), "/real/conf");
    }

    #[test]
    fn test_resolve_mount_dest_relative_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        std::fs::create_dir_all(rootfs.join("var/lib")).unwrap();
        // /data -> var/lib (relative symlink)
        std::os::unix::fs::symlink("var/lib", rootfs.join("data")).unwrap();

        assert_eq!(resolve_mount_dest_in_rootfs(rootfs, "/data"), "/var/lib");
    }
}
