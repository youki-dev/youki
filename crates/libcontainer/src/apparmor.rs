use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use pathrs::flags::OpenFlags;
use pathrs::procfs::{ProcfsBase, ProcfsHandle};

#[derive(Debug, thiserror::Error)]
pub enum AppArmorError {
    #[error("failed to apply AppArmor profile")]
    ActivateProfile {
        path: PathBuf,
        profile: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Pathrs(#[from] pathrs::error::Error),
}

type Result<T> = std::result::Result<T, AppArmorError>;

const ENABLED_PARAMETER_PATH: &str = "/sys/module/apparmor/parameters/enabled";

/// Checks if AppArmor has been enabled on the system.
pub fn is_enabled() -> std::result::Result<bool, std::io::Error> {
    let aa_enabled = fs::read_to_string(ENABLED_PARAMETER_PATH)?;
    Ok(aa_enabled.starts_with('Y'))
}

/// Applies an AppArmor profile to the container.
pub fn apply_profile(profile: &str) -> Result<()> {
    if profile.is_empty() {
        return Ok(());
    }

    // Try the module specific subdirectory. This is the recommended way to configure
    // LSMs since Linux 5.1. AppArmor has such a directory since Linux 5.8.
    activate_profile(Path::new("attr/apparmor/exec"), profile)
        // try the legacy interface
        .or_else(|_| activate_profile(Path::new("attr/exec"), profile))
}

fn activate_profile(subpath: &Path, profile: &str) -> Result<()> {
    ProcfsHandle::new()?
        .open(
            ProcfsBase::ProcSelf,
            subpath,
            OpenFlags::O_WRONLY | OpenFlags::O_CLOEXEC,
        )?
        .write_all(format!("exec {profile}").as_bytes())
        .map_err(|err| AppArmorError::ActivateProfile {
            path: PathBuf::from("/proc/self").join(subpath),
            profile: profile.to_owned(),
            source: err,
        })
}
