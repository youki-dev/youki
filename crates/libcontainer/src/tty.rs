//! tty (teletype) for user-system interaction
//!
//! This module handles console/TTY setup for containers.
//!
//! Console setup is done AFTER pivot_root (following runc's approach).
//! This follows runc's approach in prepareRootfs():
//! 1. pivot_root is called first
//! 2. Create PTY pair from /dev/pts/ptmx (container's devpts)
//! 3. Mount PTY slave onto /dev/console
//! 4. Send PTY master to console socket
//! 5. Set controlling terminal and connect stdio
//!
//! See: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/rootfs_linux.go

use std::env;
use std::io::IoSlice;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;
use std::path::{Path, PathBuf};

use nix::sys::socket::{self, UnixAddr};
use nix::sys::stat::{fstat, major, minor, SFlag};
use nix::sys::statfs::{fstatfs, FsType, Statfs};
use nix::unistd::{close, dup2};

use crate::syscall::Syscall;

#[derive(Debug)]
pub enum StdIO {
    Stdin = 0,
    Stdout = 1,
    Stderr = 2,
}

impl From<StdIO> for i32 {
    fn from(value: StdIO) -> Self {
        match value {
            StdIO::Stdin => 0,
            StdIO::Stdout => 1,
            StdIO::Stderr => 2,
        }
    }
}

impl std::fmt::Display for StdIO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StdIO::Stdin => write!(f, "stdin"),
            StdIO::Stdout => write!(f, "stdout"),
            StdIO::Stderr => write!(f, "stderr"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TTYError {
    #[error("failed to connect/duplicate {stdio}")]
    ConnectStdIO { source: nix::Error, stdio: StdIO },
    #[error("failed to create console socket")]
    CreateConsoleSocket {
        source: nix::Error,
        socket_name: String,
    },
    #[error("failed to symlink console socket into container_dir")]
    Symlink {
        source: std::io::Error,
        linked: Box<PathBuf>,
        console_socket_path: Box<PathBuf>,
    },
    #[error("invalid socket name: {socket_name:?}")]
    InvalidSocketName {
        socket_name: String,
        source: nix::Error,
    },
    #[error("failed to create console socket fd")]
    CreateConsoleSocketFd { source: nix::Error },
    #[error("could not create pseudo terminal")]
    CreatePseudoTerminal { source: nix::Error },
    #[error("failed to send pty master")]
    SendPtyMaster { source: nix::Error },
    #[error("could not close console socket")]
    CloseConsoleSocket { source: nix::Error },
    #[error("failed to create /dev/console")]
    CreateDevConsole { source: std::io::Error },
    #[error("failed to mount pty on /dev/console")]
    MountConsole {
        source: crate::syscall::SyscallError,
    },
    #[error("invalid PTY device: {reason}")]
    InvalidPty { reason: String },
}

type Result<T> = std::result::Result<T, TTYError>;

// TODO: Handling when there isn't console-socket.
pub fn setup_console_socket(
    container_dir: &Path,
    console_socket_path: &Path,
    socket_name: &str,
) -> Result<OwnedFd> {
    struct CurrentDirGuard {
        path: PathBuf,
    }
    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            let _ = env::set_current_dir(&self.path);
        }
    }
    // Move into the container directory to avoid sun family conflicts with long socket path names.
    // ref: https://github.com/youki-dev/youki/issues/2910

    let prev_dir = env::current_dir().unwrap();
    let _ = env::set_current_dir(container_dir);
    let _guard = CurrentDirGuard { path: prev_dir };

    let linked = PathBuf::from(socket_name);

    symlink(console_socket_path, &linked).map_err(|err| TTYError::Symlink {
        source: err,
        linked: linked.to_path_buf().into(),
        console_socket_path: console_socket_path.to_path_buf().into(),
    })?;
    let csocketfd = socket::socket(
        socket::AddressFamily::Unix,
        socket::SockType::Stream,
        socket::SockFlag::empty(),
        None,
    )
    .map_err(|err| TTYError::CreateConsoleSocketFd { source: err })?;
    socket::connect(
        csocketfd.as_raw_fd(),
        &socket::UnixAddr::new(linked.as_path()).map_err(|err| TTYError::InvalidSocketName {
            source: err,
            socket_name: socket_name.to_string(),
        })?,
    )
    .map_err(|e| TTYError::CreateConsoleSocket {
        source: e,
        socket_name: socket_name.to_string(),
    })?;

    Ok(csocketfd)
}

/// Device numbers from Linux kernel headers.
/// TTYAUX_MAJOR from <linux/major.h>
const PTMX_MAJOR: u64 = 5;
/// From mknod_ptmx in fs/devpts/inode.c
const PTMX_MINOR: u64 = 2;
/// From mknod_ptmx in fs/devpts/inode.c
const PTMX_INO: u64 = 2;
/// PTY slave major number
const PTY_SLAVE_MAJOR: u64 = 136;
/// DEVPTS_SUPER_MAGIC from <linux/magic.h>
const DEVPTS_SUPER_MAGIC: i64 = 0x1cd1;

/// Verify file descriptor using stat and statfs, similar to runc's VerifyInode.
///
/// This is a helper function that gets stat/statfs for a file descriptor and
/// calls the provided verification function with the results.
///
/// Ref: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/system/linux.go
fn verify_inode<F>(fd: &OwnedFd, verify: F) -> Result<()>
where
    F: FnOnce(&libc::stat, &Statfs) -> Result<()>,
{
    let stat = fstat(fd.as_raw_fd()).map_err(|e| TTYError::InvalidPty {
        reason: format!("fstat failed: {}", e),
    })?;

    let fs_stat = fstatfs(fd).map_err(|e| TTYError::InvalidPty {
        reason: format!("fstatfs failed: {}", e),
    })?;

    verify(&stat, &fs_stat)
}

/// Verify that the ptmx handle points to a real /dev/pts/ptmx device.
///
/// This follows runc's checkPtmxHandle pattern (CVE-2025-52565 mitigation):
/// - Must be on a real devpts mount
/// - Must have the correct inode number (2)
/// - Must be a character device with major:minor = 5:2
///
/// Ref: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/console_linux.go
fn verify_ptmx_handle(ptmx: &OwnedFd) -> Result<()> {
    let fd = ptmx.as_raw_fd();

    verify_inode(ptmx, |stat, fs_stat| {
        // 1. Check filesystem type is devpts
        if fs_stat.filesystem_type() != FsType(DEVPTS_SUPER_MAGIC) {
            return Err(TTYError::InvalidPty {
                reason: format!(
                    "ptmx handle is not on a real devpts mount: super magic is {:#x}",
                    fs_stat.filesystem_type().0
                ),
            });
        }

        // 2. Check inode number
        if stat.st_ino != PTMX_INO {
            return Err(TTYError::InvalidPty {
                reason: format!("ptmx handle has wrong inode number: {}", stat.st_ino),
            });
        }

        // 3. Check it's a character device with correct major:minor
        let mode_type = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
        let dev_major = major(stat.st_rdev);
        let dev_minor = minor(stat.st_rdev);

        if mode_type != SFlag::S_IFCHR || dev_major != PTMX_MAJOR || dev_minor != PTMX_MINOR {
            return Err(TTYError::InvalidPty {
                reason: format!(
                    "ptmx handle is not a real char ptmx device: ftype {:#x} {}:{}",
                    mode_type.bits(),
                    dev_major,
                    dev_minor
                ),
            });
        }

        tracing::debug!(fd, ino = stat.st_ino, "verified ptmx handle");
        Ok(())
    })
}

/// Verify that the slave handle points to a real PTY slave device.
///
/// This validates (CVE-2025-52565 mitigation):
/// - Must be on a real devpts mount
/// - Must be a character device with PTY slave major number (136)
///
/// Ref: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/console_linux.go
fn verify_pty_slave(slave: &OwnedFd) -> Result<()> {
    let fd = slave.as_raw_fd();

    verify_inode(slave, |stat, fs_stat| {
        // 1. Check filesystem type is devpts
        if fs_stat.filesystem_type() != FsType(DEVPTS_SUPER_MAGIC) {
            return Err(TTYError::InvalidPty {
                reason: format!(
                    "slave handle is not on a real devpts mount: super magic is {:#x}",
                    fs_stat.filesystem_type().0
                ),
            });
        }

        // 2. Check it's a character device with PTY slave major number
        let mode_type = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
        let dev_major = major(stat.st_rdev);

        if mode_type != SFlag::S_IFCHR || dev_major != PTY_SLAVE_MAJOR {
            return Err(TTYError::InvalidPty {
                reason: format!(
                    "slave handle is not a real PTY slave device: ftype {:#x} major {}",
                    mode_type.bits(),
                    dev_major
                ),
            });
        }

        tracing::debug!(fd, major = dev_major, minor = minor(stat.st_rdev), "verified PTY slave");
        Ok(())
    })
}

/// Setup console AFTER pivot_root.
///
/// This function should be called AFTER pivot_root. This follows runc's approach:
/// setupConsole is called after pivotRoot in prepareRootfs.
///
/// The process:
/// 1. Create PTY pair from /dev/pts/ptmx (we're already in the container)
/// 2. Optionally mount PTY slave on /dev/console (bind mount) - only for init
/// 3. Send PTY master to console socket
/// 4. Set controlling terminal
/// 5. Connect stdio to PTY slave
///
/// # Arguments
/// * `console_fd` - The console socket file descriptor
/// * `mount` - Whether to mount PTY slave on /dev/console (true for init, false for exec)
///
/// By creating PTY from container's devpts, the PTY belongs to a mount that
/// exists within the container's namespace, which is required for CRIU checkpoint.
///
/// See: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/rootfs_linux.go
pub fn setup_console(syscall: &dyn Syscall, console_fd: RawFd, mount: bool) -> Result<()> {
    // Create PTY pair from /dev/pts/ptmx
    // After pivot_root, /dev/pts points to the container's devpts
    let openpty_result = nix::pty::openpty(None, None)
        .map_err(|err| TTYError::CreatePseudoTerminal { source: err })?;

    let master = &openpty_result.master;
    let slave = &openpty_result.slave;

    // Verify both master and slave are real PTY devices (CVE-2025-52565 mitigation)
    verify_ptmx_handle(master)?;
    verify_pty_slave(slave)?;

    // Mount PTY slave on /dev/console (only for init container)
    if mount {
        if let Err(err) = mount_console(syscall, slave) {
            tracing::warn!(
                ?err,
                "failed to mount /dev/console, CRIU checkpoint may not work"
            );
        }
    }

    // Send PTY master to console socket
    let pty_name: &[u8] = b"/dev/ptmx";
    let iov = [IoSlice::new(pty_name)];
    let fds = [master.as_raw_fd()];
    let cmsg = socket::ControlMessage::ScmRights(&fds);
    socket::sendmsg::<UnixAddr>(console_fd, &iov, &[cmsg], socket::MsgFlags::empty(), None)
        .map_err(|err| TTYError::SendPtyMaster { source: err })?;

    // Set controlling terminal
    if unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY) } < 0 {
        tracing::warn!("could not TIOCSCTTY");
    };

    // Connect stdio to PTY slave
    connect_stdio(&slave.as_raw_fd(), &slave.as_raw_fd(), &slave.as_raw_fd())?;

    // Close console socket
    close(console_fd).map_err(|err| TTYError::CloseConsoleSocket { source: err })?;

    Ok(())
}

/// Mount PTY slave on /dev/console.
///
/// This bind-mounts the PTY slave device onto /dev/console so programs
/// that operate on /dev/console use the container's PTY.
///
/// This is called AFTER pivot_root, so we mount onto /dev/console directly.
/// Uses FD-based mounting to avoid path resolution vulnerabilities (CVE-2025-52565).
///
/// See: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/rootfs_linux.go
fn mount_console(syscall: &dyn Syscall, slave: &OwnedFd) -> Result<()> {
    use std::fs::OpenOptions;

    // After pivot_root, the target is /dev/console
    let console_path = Path::new("/dev/console");

    tracing::debug!(
        slave_fd = slave.as_raw_fd(),
        ?console_path,
        "mounting PTY on /dev/console"
    );

    // Create /dev/console mount target.
    // O_NOFOLLOW: prevent symlink attacks (CVE-2025-52565)
    // O_CLOEXEC: close on exec
    // Ref: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/rootfs_linux.go
    OpenOptions::new()
        .create(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o666)
        .open(console_path)
        .map_err(|err| {
            tracing::error!(?err, ?console_path, "failed to create /dev/console");
            TTYError::CreateDevConsole { source: err }
        })?;

    // Bind mount the PTY slave onto /dev/console using FD-based mounting.
    // This avoids path resolution vulnerabilities (CVE-2025-52565).
    syscall.mount_from_fd(slave, console_path).map_err(|err| {
        tracing::error!(
            ?err,
            slave_fd = slave.as_raw_fd(),
            ?console_path,
            "failed to bind mount pty on /dev/console"
        );
        TTYError::MountConsole { source: err }
    })?;

    tracing::debug!(
        slave_fd = slave.as_raw_fd(),
        ?console_path,
        "mounted PTY on /dev/console"
    );
    Ok(())
}

fn connect_stdio(stdin: &RawFd, stdout: &RawFd, stderr: &RawFd) -> Result<()> {
    dup2(stdin.as_raw_fd(), StdIO::Stdin.into()).map_err(|err| TTYError::ConnectStdIO {
        source: err,
        stdio: StdIO::Stdin,
    })?;
    dup2(stdout.as_raw_fd(), StdIO::Stdout.into()).map_err(|err| TTYError::ConnectStdIO {
        source: err,
        stdio: StdIO::Stdout,
    })?;
    // FIXME: Rarely does it fail.
    // error message: `Error: Resource temporarily unavailable (os error 11)`
    dup2(stderr.as_raw_fd(), StdIO::Stderr.into()).map_err(|err| TTYError::ConnectStdIO {
        source: err,
        stdio: StdIO::Stderr,
    })?;

    Ok(())
}

/// Tests for PTY verification and console setup.
///
/// Note on `verify_ptmx_handle` success test:
/// The success case for `verify_ptmx_handle` cannot be reliably tested in unit tests
/// because on host systems, `/dev/ptmx` is typically on tmpfs (not devpts).
/// The function is designed to work inside containers after `pivot_root`,
/// where `/dev/pts/ptmx` is on a proper devpts mount.
/// The success path is covered by integration tests that run inside containers.
///
/// The `verify_pty_slave` success test works on host because the PTY slave
/// is always allocated on `/dev/pts/`, which is a devpts mount.
#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixListener;

    use anyhow::{Ok, Result};
    use serial_test::serial;

    use super::*;

    const CONSOLE_SOCKET: &str = "console-socket";

    #[test]
    #[serial]
    fn test_setup_console_socket() -> Result<()> {
        let testdir = tempfile::tempdir()?;
        let socket_path = Path::join(testdir.path(), "test-socket");
        let lis = UnixListener::bind(&socket_path);
        assert!(lis.is_ok());
        let fd = setup_console_socket(testdir.path(), &socket_path, CONSOLE_SOCKET)?;
        assert_ne!(fd.as_raw_fd(), -1);
        Ok(())
    }

    #[test]
    #[serial]
    fn test_setup_console_socket_empty() -> Result<()> {
        let testdir = tempfile::tempdir()?;
        let socket_path = Path::join(testdir.path(), "test-socket");
        let fd = setup_console_socket(testdir.path(), &socket_path, CONSOLE_SOCKET);
        assert!(fd.is_err());
        Ok(())
    }

    #[test]
    #[serial]
    fn test_setup_console_socket_invalid() -> Result<()> {
        let testdir = tempfile::tempdir()?;
        let socket_path = Path::join(testdir.path(), "test-socket");
        let _socket = File::create(Path::join(testdir.path(), "console-socket"));
        assert!(_socket.is_ok());
        let fd = setup_console_socket(testdir.path(), &socket_path, CONSOLE_SOCKET);
        assert!(fd.is_err());

        Ok(())
    }

    #[test]
    #[serial]
    fn test_setup_console() -> Result<()> {
        use crate::syscall::syscall::create_syscall;

        let testdir = tempfile::tempdir()?;
        let socket_path = Path::join(testdir.path(), "test-socket");

        // duplicate the existing std* fds
        // we need to restore them later, and we cannot simply store them
        // as they themselves get modified in setup_console
        let old_stdin: RawFd = nix::unistd::dup(StdIO::Stdin.into())?;
        let old_stdout: RawFd = nix::unistd::dup(StdIO::Stdout.into())?;
        let old_stderr: RawFd = nix::unistd::dup(StdIO::Stderr.into())?;

        let lis = UnixListener::bind(&socket_path);
        assert!(lis.is_ok());
        let fd = setup_console_socket(testdir.path(), &socket_path, CONSOLE_SOCKET)?;
        // Note: setup_console expects to run after pivot_root, so this test
        // just verifies the function can be called. The /dev/console mount
        // may fail outside a real container environment.
        // mount=false to skip /dev/console mount in test environment
        let syscall = create_syscall();
        let status = setup_console(syscall.as_ref(), fd.into_raw_fd(), false);

        // restore the original std* before doing final assert
        dup2(old_stdin, StdIO::Stdin.into())?;
        dup2(old_stdout, StdIO::Stdout.into())?;
        dup2(old_stderr, StdIO::Stderr.into())?;

        assert!(status.is_ok());

        Ok(())
    }

    #[test]
    fn test_verify_pty_slave_with_real_pty() -> Result<()> {
        // Allocate a real PTY pair
        let openpty_result = nix::pty::openpty(None, None)
            .map_err(|e| TTYError::CreatePseudoTerminal { source: e })?;

        // Verify slave handle should succeed
        let result = verify_pty_slave(&openpty_result.slave);
        assert!(result.is_ok(), "verify_pty_slave failed: {:?}", result);

        Ok(())
    }

    #[test]
    fn test_verify_ptmx_handle_with_regular_file() {
        use std::fs::File;
        use std::os::fd::AsFd;
        use tempfile::tempfile;

        // Create a regular file
        let file: File = tempfile().expect("failed to create tempfile");
        let fd = file.as_fd().try_clone_to_owned().unwrap();

        // Verify should fail for regular file
        let result = verify_ptmx_handle(&fd);
        assert!(result.is_err(), "verify_ptmx_handle should fail for regular file");

        if let Err(TTYError::InvalidPty { reason }) = result {
            assert!(
                reason.contains("devpts") || reason.contains("inode") || reason.contains("device"),
                "unexpected error reason: {}",
                reason
            );
        }
    }

    #[test]
    fn test_verify_pty_slave_with_regular_file() {
        use std::fs::File;
        use std::os::fd::AsFd;
        use tempfile::tempfile;

        // Create a regular file
        let file: File = tempfile().expect("failed to create tempfile");
        let fd = file.as_fd().try_clone_to_owned().unwrap();

        // Verify should fail for regular file
        let result = verify_pty_slave(&fd);
        assert!(result.is_err(), "verify_pty_slave should fail for regular file");

        if let Err(TTYError::InvalidPty { reason }) = result {
            assert!(
                reason.contains("devpts") || reason.contains("device"),
                "unexpected error reason: {}",
                reason
            );
        }
    }
}
