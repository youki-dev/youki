//! Common CRIU utilities for checkpoint and restore operations.
//!
//! This module provides shared functionality between container checkpoint and restore,
//! following the patterns established by runc's CRIU integration.

use std::fs::File;
use std::os::unix::io::AsRawFd;

use nix::sys::stat::fstat;
use oci_spec::runtime::{LinuxNamespaceType, Spec};

use super::Container;
use crate::error::LibcontainerError;

/// Get the short name of a namespace type (matching runc's NsName).
pub fn ns_name(ns_type: LinuxNamespaceType) -> &'static str {
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

/// Convert a namespace type to a CRIU external key.
///
/// This follows runc's `criuNsToKey` function which constructs:
/// "extRoot" + capitalize(nsName) + "NS"
///
/// Result format: "extRootNetNS", "extRootPidNS", etc.
///
/// Ref: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/criu_linux.go
pub fn criu_ns_to_key(ns_type: LinuxNamespaceType) -> String {
    let ns_name = match ns_type {
        LinuxNamespaceType::Network => "net",
        LinuxNamespaceType::Pid => "pid",
        LinuxNamespaceType::Mount => "mnt",
        LinuxNamespaceType::Ipc => "ipc",
        LinuxNamespaceType::Uts => "uts",
        LinuxNamespaceType::User => "user",
        LinuxNamespaceType::Cgroup => "cgroup",
        LinuxNamespaceType::Time => "time",
    };

    // Capitalize the first character
    let mut chars = ns_name.chars();
    let capitalized = match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect::<String>(),
        None => String::new(),
    };

    format!("extRoot{}NS", capitalized)
}

/// Minimum CRIU version required for checkpoint/restore functionality.
/// We are relying on the CRIU version RPC which was introduced with CRIU 3.0.0.
/// This matches runc's CRIU version requirement.
/// Version format: MAJOR * 10000 + MINOR * 100 + PATCH
pub const CRIU_VERSION_MINIMUM: u32 = 30000; // 3.0.0

fn compare_criu_version(version: u32, min_version: u32) -> Result<(), LibcontainerError> {
    if version < min_version {
        return Err(LibcontainerError::Other(format!(
            "CRIU version {} is below minimum required version {}.{}.{}",
            version,
            min_version / 10000,
            (min_version % 10000) / 100,
            min_version % 100,
        )));
    }
    Ok(())
}

impl Container {
    /// Check if CRIU version is greater than or equal to min_version.
    /// This follows runc's checkCriuVersion function pattern.
    ///
    /// If the version of CRIU has already been determined there is no need
    /// to ask CRIU for the version again. Use the cached value from criu_version.
    pub fn check_criu_version(&mut self, min_version: u32) -> Result<(), LibcontainerError> {
        // If the version of criu has already been determined there is no need
        // to ask criu for the version again. Use the value from criu_version.
        if let Some(version) = self.criu_version {
            return compare_criu_version(version, min_version);
        }

        let mut criu = rust_criu::Criu::new().map_err(|e| {
            LibcontainerError::Other(format!("failed to create CRIU instance: {}", e))
        })?;

        let version = criu
            .get_criu_version()
            .map_err(|e| LibcontainerError::Other(format!("CRIU version check failed: {}", e)))?;

        self.criu_version = Some(version);

        compare_criu_version(version, min_version)
    }
}

/// Handle checkpointing of external namespaces.
///
/// This follows runc's `handleCheckpointingExternalNamespaces` function.
/// CRIU expects the information about an external namespace like this:
/// `--external <TYPE>[<inode>]:<key>`
///
/// For example: `net[4026532008]:extRootNetNS`
///
/// Ref: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/criu_linux.go
pub fn handle_checkpointing_external_namespaces(
    criu: &mut rust_criu::Criu,
    spec: &Spec,
    ns_type: LinuxNamespaceType,
) -> Result<(), LibcontainerError> {
    let ns_path = get_namespace_path(spec, ns_type);
    let ns_path = match ns_path {
        Some(path) => path,
        None => return Ok(()), // No external namespace configured
    };

    // Stat the namespace file to get the inode
    let ns_file = File::open(&ns_path).map_err(|err| {
        tracing::error!(?ns_path, ?err, "failed to open namespace for checkpoint");
        LibcontainerError::OtherIO(err)
    })?;

    let stat = fstat(ns_file.as_raw_fd()).map_err(|err| {
        tracing::error!(?ns_path, ?err, "failed to stat namespace");
        LibcontainerError::Other(format!("failed to stat namespace: {}", err))
    })?;

    // Format: <type>[<inode>]:<key>
    let external = format!(
        "{}[{}]:{}",
        ns_name(ns_type),
        stat.st_ino,
        criu_ns_to_key(ns_type)
    );

    tracing::debug!(?external, "adding external namespace for checkpoint");
    criu.set_external(external);

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
pub fn handle_restoring_external_namespaces(
    criu: &mut rust_criu::Criu,
    spec: &Spec,
    ns_type: LinuxNamespaceType,
    extra_files: &mut Vec<File>,
) -> Result<(), LibcontainerError> {
    let ns_path = get_namespace_path(spec, ns_type);
    let ns_path = match ns_path {
        Some(path) => path,
        None => return Ok(()), // No external namespace configured
    };

    // Open the namespace file.
    // If a specific network namespace is defined it must exist.
    let ns_file = File::open(&ns_path).map_err(|err| {
        tracing::error!(?ns_path, ?err, "failed to open namespace for restore");
        LibcontainerError::OtherIO(err)
    })?;

    let key = criu_ns_to_key(ns_type);

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

    criu.add_inherit_fd(fd, &key);

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
pub fn handle_restoring_namespaces(
    criu: &mut rust_criu::Criu,
    spec: &Spec,
    extra_files: &mut Vec<File>,
) -> Result<(), LibcontainerError> {
    if let Some(linux) = spec.linux() {
        if let Some(namespaces) = linux.namespaces() {
            for ns in namespaces {
                match ns.typ() {
                    LinuxNamespaceType::Network | LinuxNamespaceType::Pid => {
                        // For network and PID namespaces, use inherit_fd
                        handle_restoring_external_namespaces(criu, spec, ns.typ(), extra_files)?;
                    }
                    _ => {
                        // For other namespaces, runc uses JoinNs
                        // TODO: Implement JoinNs support in rust_criu
                        // For now, we skip these namespaces
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

/// Get the path of a namespace from the spec.
fn get_namespace_path(spec: &Spec, ns_type: LinuxNamespaceType) -> Option<std::path::PathBuf> {
    spec.linux()
        .as_ref()?
        .namespaces()
        .as_ref()?
        .iter()
        .find(|ns| ns.typ() == ns_type)
        .and_then(|ns| ns.path().as_ref().map(|p| p.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_criu_version_ok() {
        assert!(compare_criu_version(30000, 30000).is_ok());
        assert!(compare_criu_version(31100, 30000).is_ok());
        assert!(compare_criu_version(40000, 30000).is_ok());
    }

    #[test]
    fn test_compare_criu_version_too_low() {
        assert!(compare_criu_version(29900, 30000).is_err());
    }

    #[test]
    fn test_criu_ns_to_key() {
        assert_eq!(criu_ns_to_key(LinuxNamespaceType::Network), "extRootNetNS");
        assert_eq!(criu_ns_to_key(LinuxNamespaceType::Pid), "extRootPidNS");
        assert_eq!(criu_ns_to_key(LinuxNamespaceType::Mount), "extRootMntNS");
        assert_eq!(criu_ns_to_key(LinuxNamespaceType::Ipc), "extRootIpcNS");
        assert_eq!(criu_ns_to_key(LinuxNamespaceType::Uts), "extRootUtsNS");
        assert_eq!(criu_ns_to_key(LinuxNamespaceType::User), "extRootUserNS");
        assert_eq!(
            criu_ns_to_key(LinuxNamespaceType::Cgroup),
            "extRootCgroupNS"
        );
    }
}
