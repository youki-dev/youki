use std::env;
use std::io::prelude::*;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use nix::unistd::{self, close};

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

pub struct NotifyListener {
    socket: UnixListener,
}

impl NotifyListener {
    pub fn new(socket_path: &Path) -> Result<Self> {
        tracing::debug!(?socket_path, "create notify listener");
        // Unix domain socket has a maximum length of 108, different from
        // normal path length of 255. Due to how docker create the path name
        // to the container working directory, there is a high chance that
        // the full absolute path is over the limit. To work around this
        // limitation, we chdir first into the workdir where the socket is,
        // and chdir back after the socket is created.
        let workdir = socket_path
            .parent()
            .ok_or_else(|| NotifyListenerError::InvalidPath(socket_path.to_owned()))?;
        let socket_name = socket_path
            .file_name()
            .ok_or_else(|| NotifyListenerError::InvalidPath(socket_path.to_owned()))?;
        let cwd = env::current_dir().map_err(NotifyListenerError::GetCwd)?;
        tracing::debug!(?cwd, "the cwd to create the notify socket");
        unistd::chdir(workdir).map_err(|e| NotifyListenerError::Chdir {
            source: e,
            path: workdir.to_owned(),
        })?;
        let stream = UnixListener::bind(socket_name).map_err(|e| NotifyListenerError::Bind {
            source: e,
            // ok to unwrap here as OsStr should always be utf-8 compatible
            name: socket_name.to_str().unwrap().to_owned(),
        })?;
        unistd::chdir(&cwd).map_err(|e| NotifyListenerError::Chdir {
            source: e,
            path: cwd,
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
        let socket = self
            .socket
            .try_clone()
            .expect("failed to duplicate the notify listener fd");
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
        let cwd = env::current_dir().map_err(NotifyListenerError::GetCwd)?;
        let workdir = self
            .path
            .parent()
            .ok_or_else(|| NotifyListenerError::InvalidPath(self.path.to_owned()))?;
        unistd::chdir(workdir).map_err(|e| NotifyListenerError::Chdir {
            source: e,
            path: workdir.to_owned(),
        })?;
        let socket_name = self
            .path
            .file_name()
            .ok_or_else(|| NotifyListenerError::InvalidPath(self.path.to_owned()))?;
        let mut stream =
            UnixStream::connect(socket_name).map_err(|e| NotifyListenerError::Connect {
                source: e,
                // ok to unwrap as OsStr should always be utf-8 compatible
                name: socket_name.to_str().unwrap().to_owned(),
            })?;
        stream
            .write_all(b"start container")
            .map_err(NotifyListenerError::SendStartContainer)?;
        tracing::debug!("notify finished");
        unistd::chdir(&cwd).map_err(|e| NotifyListenerError::Chdir {
            source: e,
            path: cwd,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use serial_test::serial;
    use tempfile::tempdir;

    use super::*;

    #[test]
    #[serial]
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
    #[serial]
    fn test_notify_listener_works_after_clone_is_dropped() {
        let tempdir = tempdir().unwrap();
        let socket_path = tempdir.path().join("notify.sock");
        let listener = NotifyListener::new(&socket_path).unwrap();
        drop(listener.clone());

        let mut socket = NotifySocket::new(socket_path);
        socket.notify_container_start().unwrap();
        listener.wait_for_container_start().unwrap();
    }
}
