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
}
