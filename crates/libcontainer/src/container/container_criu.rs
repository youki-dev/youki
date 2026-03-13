//! Common CRIU utilities for checkpoint and restore operations.
//!
//! This module provides shared functionality between container checkpoint and restore,
//! following the patterns established by runc's CRIU integration.

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
    let mut criu = rust_criu::Criu::new()
        .map_err(|e| LibcontainerError::Other(format!("failed to create CRIU instance: {}", e)))?;

    let version = criu
        .get_criu_version()
        .map_err(|e| LibcontainerError::Other(format!("CRIU version check failed: {}", e)))?;

    compare_criu_version(version, min_version)
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
