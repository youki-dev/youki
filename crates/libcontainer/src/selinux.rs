//! SELinux process labels.
//!
//! The container process gets `process.selinuxLabel` by writing it to the thread's exec
//! attribute before the execve that starts the container program, as runc and crun do
//! (`label.SetProcessLabel`, `/proc/thread-self/attr/exec`).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use nix::sys::statfs::{SELINUX_MAGIC, statfs};
use nix::sys::statvfs::FsFlags;
use pathrs::flags::OpenFlags;
use pathrs::procfs::{ProcfsBase, ProcfsHandle};
use procfs::process::MountInfo;

#[derive(Debug, thiserror::Error)]
pub enum SelinuxError {
    #[error("selinux label is specified, but selinux is disabled or not supported")]
    NotEnabled,
    #[error("failed to set the SELinux exec label {label:?}")]
    SetExecLabel {
        label: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Pathrs(#[from] pathrs::error::Error),
}

type Result<T> = std::result::Result<T, SelinuxError>;

const SELINUXFS_MOUNT: &str = "/sys/fs/selinux";

/// Whether SELinux is enabled, decided as go-selinux's `GetEnabled` does for runc: a writable
/// selinuxfs is mounted and the process does not run with the `kernel` label. It looks at the
/// caller's mounts, so it must run before pivot_root.
pub fn is_enabled() -> bool {
    let Ok(procfs) = ProcfsHandle::new() else {
        return false;
    };
    let read = |base: ProcfsBase, path: &str| {
        let mut content = String::new();
        procfs
            .open(base, path, OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC)
            .ok()?
            .read_to_string(&mut content)
            .ok()?;
        Some(content)
    };
    let selinuxfs = is_selinuxfs(Path::new(SELINUXFS_MOUNT))
        || read(ProcfsBase::ProcRoot, "filesystems").is_some_and(|f| has_selinuxfs(&f))
            && read(ProcfsBase::ProcSelf, "mountinfo")
                .is_some_and(|m| selinuxfs_mounts(&m).any(|mount| is_selinuxfs(&mount)));
    selinuxfs
        && !is_kernel_label(&read(ProcfsBase::ProcThreadSelf, "attr/current").unwrap_or_default())
}

fn is_selinuxfs(path: &Path) -> bool {
    statfs(path).is_ok_and(|fs| {
        fs.filesystem_type() == SELINUX_MAGIC && !fs.flags().contains(FsFlags::ST_RDONLY)
    })
}

fn has_selinuxfs(filesystems: &str) -> bool {
    filesystems
        .lines()
        .any(|line| line.split_whitespace().last() == Some("selinuxfs"))
}

fn selinuxfs_mounts(mountinfo: &str) -> impl Iterator<Item = PathBuf> + '_ {
    mountinfo
        .lines()
        .filter_map(|line| MountInfo::from_line(line).ok())
        .filter(|mount| mount.fs_type == "selinuxfs")
        .map(|mount| mount.mount_point)
}

fn is_kernel_label(label: &str) -> bool {
    label.strip_suffix('\0').unwrap_or(label) == "kernel"
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
    fn test_is_enabled() {
        let filesystems = std::fs::read_to_string("/proc/filesystems").unwrap();
        if is_enabled() {
            assert!(has_selinuxfs(&filesystems));
        }
    }

    #[test]
    fn test_has_selinuxfs() {
        assert!(has_selinuxfs("nodev\tsysfs\nnodev\tselinuxfs\n\text4\n"));
        assert!(!has_selinuxfs("nodev\tsysfs\n\text4\n"));
    }

    #[test]
    fn test_selinuxfs_absent() {
        // The kernel has selinuxfs, but no selinuxfs mount is visible, as in a nested container.
        let tmp = tempfile::tempdir().unwrap();
        assert!(!is_selinuxfs(tmp.path()));
        let mountinfo = "22 1 0:21 / /sys rw,nosuid shared:7 - sysfs sysfs rw\n\
                         23 22 0:22 / /sys/fs/selinux rw,relatime shared:8 - tmpfs tmpfs rw\n";
        assert_eq!(selinuxfs_mounts(mountinfo).count(), 0);
        let mountinfo =
            "23 22 0:22 / /sys/fs/selinux rw,relatime shared:8 - selinuxfs selinuxfs rw\n";
        assert_eq!(
            selinuxfs_mounts(mountinfo).collect::<Vec<_>>(),
            vec![PathBuf::from("/sys/fs/selinux")]
        );
    }

    #[test]
    fn test_is_kernel_label() {
        assert!(is_kernel_label("kernel\0"));
        assert!(is_kernel_label("kernel"));
        assert!(!is_kernel_label("system_u:system_r:container_t:s0:c4,c5\0"));
        assert!(!is_kernel_label(""));
    }
}
