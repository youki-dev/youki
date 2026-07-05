//! Common CRIU utilities for checkpoint and restore operations.
//!
//! This module provides shared functionality between container checkpoint and restore,
//! following the patterns established by runc's CRIU integration.

use std::fs::File;
use std::os::unix::io::AsRawFd;

use nix::sys::stat::fstat;
use oci_spec::runtime::{LinuxNamespaceType, Spec};
use rust_criu::{Criu, criu_ns_to_key};

use crate::error::LibcontainerError;

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
}
