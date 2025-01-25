//! tty (teletype) for user-system interaction

use std::env;
use std::io::IoSlice;
use std::os::fd::OwnedFd;
use std::os::unix::fs::symlink;
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;
use std::path::{Path, PathBuf};

use nix::sys::socket::{self, UnixAddr};
use nix::unistd::{close, dup2};

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
    // ref: https://github.com/containers/youki/issues/2910

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

pub fn setup_console(console_fd: RawFd) -> Result<()> {
    // You can also access pty master, but it is better to use the API.
    // ref. https://github.com/containerd/containerd/blob/261c107ffc4ff681bc73988f64e3f60c32233b37/vendor/github.com/containerd/go-runc/console.go#L139-L154
    let openpty_result = nix::pty::openpty(None, None)
        .map_err(|err| TTYError::CreatePseudoTerminal { source: err })?;
    let pty_name: &[u8] = b"/dev/ptmx";
    let iov = [IoSlice::new(pty_name)];

    let [master, slave] = [openpty_result.master, openpty_result.slave];
    // Use ManuallyDrop to keep FDs open.
    let master = std::mem::ManuallyDrop::new(master);
    let slave = std::mem::ManuallyDrop::new(slave);

    let fds = [master.as_raw_fd()];
    let cmsg = socket::ControlMessage::ScmRights(&fds);
    socket::sendmsg::<UnixAddr>(console_fd, &iov, &[cmsg], socket::MsgFlags::empty(), None)
        .map_err(|err| TTYError::SendPtyMaster { source: err })?;

    if unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY) } < 0 {
        tracing::warn!("could not TIOCSCTTY");
    };
    let slave = slave.as_raw_fd();
    connect_stdio(&slave, &slave, &slave)?;
    close(console_fd).map_err(|err| TTYError::CloseConsoleSocket { source: err })?;

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
        let status = setup_console(fd.into_raw_fd());

        // restore the original std* before doing final assert
        dup2(old_stdin, StdIO::Stdin.into())?;
        dup2(old_stdout, StdIO::Stdout.into())?;
        dup2(old_stderr, StdIO::Stderr.into())?;

        assert!(status.is_ok());

        Ok(())
    }
}
