use std::io::prelude::*;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use nix::unistd::close;

pub const NOTIFY_FILE: &str = "notify.sock";

#[derive(Debug, thiserror::Error)]
pub enum NotifyListenerError {
    #[error("failed to chdir {path} while creating notify socket: {source}")]
    Chdir { source: nix::Error, path: PathBuf },
    #[error("invalid path: {0}")]
    InvalidPath(PathBuf),
    #[error("failed to bind notify socket: {name}")]
    Bind {
        source: std::io::Error,
        name: String,
    },
    #[error("failed to connect to notify socket: {name}")]
    Connect {
        source: std::io::Error,
        name: String,
    },
    #[error("failed to get cwd")]
    GetCwd(#[source] std::io::Error),
    #[error("failed to accept notify listener")]
    Accept(#[source] std::io::Error),
    #[error("failed to close notify listener")]
    Close(#[source] nix::errno::Errno),
    #[error("failed to read notify listener")]
    Read(#[source] std::io::Error),
    #[error("failed to send start container")]
    SendStartContainer(#[source] std::io::Error),
}

type Result<T> = std::result::Result<T, NotifyListenerError>;

const MAX_SOCKET_LEN: usize = 108;

fn socket_addr_path(socket_path: &Path) -> Result<(Option<OwnedFd>, PathBuf)> {
    if socket_path.as_os_str().len() < MAX_SOCKET_LEN {
        return Ok((None, socket_path.to_owned()));
    }

    let workdir = socket_path
        .parent()
        .ok_or_else(|| NotifyListenerError::InvalidPath(socket_path.to_owned()))?;
    let socket_name = socket_path
        .file_name()
        .ok_or_else(|| NotifyListenerError::InvalidPath(socket_path.to_owned()))?;
    let dir = open(
        workdir,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| NotifyListenerError::Chdir {
        source,
        path: workdir.to_owned(),
    })?;
    let path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(socket_name);

    Ok((Some(dir), path))
}

pub struct NotifyListener {
    socket: UnixListener,
}

impl NotifyListener {
    pub fn new(socket_path: &Path) -> Result<Self> {
        tracing::debug!(?socket_path, "create notify listener");
        let (_dir, path) = socket_addr_path(socket_path)?;
        let stream = UnixListener::bind(path).map_err(|e| NotifyListenerError::Bind {
            source: e,
            name: socket_path.display().to_string(),
        })?;

        Ok(Self { socket: stream })
    }

    pub fn wait_for_container_start(&self) -> Result<()> {
        match self.socket.accept() {
            Ok((mut socket, _)) => {
                let mut response = String::new();
                socket
                    .read_to_string(&mut response)
                    .map_err(NotifyListenerError::Read)?;
                tracing::debug!("received: {}", response);
            }
            Err(e) => Err(NotifyListenerError::Accept(e))?,
        }

        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        close(self.socket.as_raw_fd()).map_err(NotifyListenerError::Close)?;
        Ok(())
    }
}

impl Clone for NotifyListener {
    fn clone(&self) -> Self {
        let fd = self.socket.as_raw_fd();
        // This is safe because we just duplicate a valid fd. Theoretically, to
        // truly clone a unix listener, we have to use dup(2) to duplicate the
        // fd, and then use from_raw_fd to create a new UnixListener. However,
        // for our purposes, fd is just an integer to pass around for the same
        // socket. Our main usage is to pass the notify_listener across process
        // boundary. Since fd tables are cloned during clone/fork calls, this
        // should be safe to use, as long as we be careful with not closing the
        // same fd in different places. If we observe an issue, we will switch
        // to `dup`.
        let socket = unsafe { UnixListener::from_raw_fd(fd) };
        Self { socket }
    }
}

pub struct NotifySocket {
    path: PathBuf,
}

impl NotifySocket {
    pub fn new<P: Into<PathBuf>>(socket_path: P) -> Self {
        Self {
            path: socket_path.into(),
        }
    }

    pub fn notify_container_start(&mut self) -> Result<()> {
        tracing::debug!("notify container start");
        let (_dir, path) = socket_addr_path(&self.path)?;
        let mut stream = UnixStream::connect(path).map_err(|e| NotifyListenerError::Connect {
            source: e,
            name: self.path.display().to_string(),
        })?;
        stream
            .write_all(b"start container")
            .map_err(NotifyListenerError::SendStartContainer)?;
        tracing::debug!("notify finished");
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::env;

    use tempfile::tempdir;

    use super::*;

    #[test]
    /// Test that the listener can be cloned and function correctly. This test
    /// also serves as a test for the normal case.
    fn test_notify_listener_clone() {
        let tempdir = tempdir().unwrap();
        let socket_path = tempdir.path().join("notify.sock");
        // listener needs to be created first because it will create the socket.
        let listener = NotifyListener::new(&socket_path).unwrap();
        let mut socket = NotifySocket::new(socket_path.clone());
        // This is safe without race because the unix domain socket is already
        // created. It is OK for the socket to send the start notification
        // before the listener wait is called.
        let thread_handle = std::thread::spawn({
            move || {
                // We clone the listener and listen on the cloned listener to
                // make sure the cloned fd functions correctly.
                listener.wait_for_container_start().unwrap();
            }
        });

        socket.notify_container_start().unwrap();
        thread_handle.join().unwrap();
    }

    #[test]
    fn test_notify_listener_long_path() {
        let tempdir = tempdir().unwrap();
        let mut dir = tempdir.path().to_path_buf();
        for _ in 0..8 {
            dir = dir.join("aaaaaaaaaaaaaaaaaaaa");
        }
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join(NOTIFY_FILE);
        assert!(socket_path.as_os_str().len() > 108);

        let listener = NotifyListener::new(&socket_path).unwrap();
        let mut socket = NotifySocket::new(socket_path);
        let thread_handle = std::thread::spawn(move || {
            listener.wait_for_container_start().unwrap();
        });

        socket.notify_container_start().unwrap();
        thread_handle.join().unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn test_notify_listener_leaves_cwd_alone() {
        let before = env::current_dir().unwrap();

        let tempdir = tempdir().unwrap();
        let socket_path = tempdir.path().join(NOTIFY_FILE);
        NotifyListener::new(&socket_path).unwrap();
        assert_eq!(env::current_dir().unwrap(), before);

        let failing = tempdir.path().join("taken");
        std::fs::create_dir_all(failing.join(NOTIFY_FILE)).unwrap();
        assert!(NotifyListener::new(&failing.join(NOTIFY_FILE)).is_err());
        assert_eq!(env::current_dir().unwrap(), before);
    }
}
