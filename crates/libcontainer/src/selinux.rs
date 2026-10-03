//! SELinux process labels.
//!
//! The container process gets `process.selinuxLabel` by writing it to the thread's exec
//! attribute before the execve that starts the container program, as runc and crun do
//! (`label.SetProcessLabel`, `/proc/thread-self/attr/exec`).

use std::fs;
use std::io::Write;

use pathrs::flags::OpenFlags;
use pathrs::procfs::{ProcfsBase, ProcfsHandle};

#[derive(Debug, thiserror::Error)]
pub enum SelinuxError {
    #[error("failed to read /proc/filesystems")]
    Filesystems(#[source] std::io::Error),
    #[error("failed to set the SELinux exec label {label:?}")]
    SetExecLabel {
        label: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Pathrs(#[from] pathrs::error::Error),
}

type Result<T> = std::result::Result<T, SelinuxError>;

/// Whether SELinux is enabled in the kernel: selinuxfs is registered only then. Unlike
/// `/sys/fs/selinux`, `/proc/filesystems` still answers after pivot_root.
pub fn is_enabled() -> Result<bool> {
    let filesystems = fs::read_to_string("/proc/filesystems").map_err(SelinuxError::Filesystems)?;
    Ok(has_selinuxfs(&filesystems))
}

fn has_selinuxfs(filesystems: &str) -> bool {
    filesystems
        .lines()
        .any(|line| line.split_whitespace().last() == Some("selinuxfs"))
}

/// Sets the label the next execve of this thread enters.
pub fn set_exec_label(label: &str) -> Result<()> {
    ProcfsHandle::new()?
        .open(
            ProcfsBase::ProcThreadSelf,
            "attr/exec",
            OpenFlags::O_WRONLY | OpenFlags::O_CLOEXEC,
        )?
        .write_all(label.as_bytes())
        .map_err(|source| SelinuxError::SetExecLabel {
            label: label.to_owned(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_selinuxfs() {
        assert!(has_selinuxfs("nodev\tsysfs\nnodev\tselinuxfs\n\text4\n"));
        assert!(!has_selinuxfs("nodev\tsysfs\n\text4\n"));
    }
}
