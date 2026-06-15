use std::io::IoSlice;
use std::os::fd::AsRawFd;
use std::path::Path;

use nix::sys::socket::{self, UnixAddr};

#[derive(Debug, thiserror::Error)]
pub enum SeccompListenerError {
    #[error("notify will require seccomp listener path to be set")]
    MissingListenerPath,
    #[error("failed to encode container process state")]
    EncodeState(#[source] serde_json::Error),
    #[error("unix syscall fails")]
    UnixOther(#[source] nix::Error),
}

type Result<T> = std::result::Result<T, SeccompListenerError>;

pub(crate) fn sync_seccomp_send_msg(listener_path: &Path, msg: &[u8], fd: i32) -> Result<()> {
    // The seccomp listener has specific instructions on how to transmit the
    // information through seccomp listener.  Therefore, we have to use
    // libc/nix APIs instead of Rust std lib APIs to maintain flexibility.
    let socket = socket::socket(
        socket::AddressFamily::Unix,
        socket::SockType::Stream,
        socket::SockFlag::empty(),
        None,
    )
    .map_err(|err| {
        tracing::error!(
            ?err,
            "failed to create unix domain socket for seccomp listener"
        );
        SeccompListenerError::UnixOther(err)
    })?;
    let unix_addr = socket::UnixAddr::new(listener_path).map_err(|err| {
        tracing::error!(
            ?err,
            ?listener_path,
            "failed to create unix domain socket address"
        );
        SeccompListenerError::UnixOther(err)
    })?;
    socket::connect(socket.as_raw_fd(), &unix_addr).map_err(|err| {
        tracing::error!(
            ?err,
            ?listener_path,
            "failed to connect to seccomp notify listener path"
        );
        SeccompListenerError::UnixOther(err)
    })?;
    // We have to use sendmsg here because the spec requires us to send seccomp notify fds through
    // SCM_RIGHTS message.
    // Ref: https://man7.org/linux/man-pages/man3/sendmsg.3p.html
    // Ref: https://man7.org/linux/man-pages/man3/cmsg.3.html
    let iov = [IoSlice::new(msg)];
    let fds = [fd];
    let cmsgs = socket::ControlMessage::ScmRights(&fds);
    socket::sendmsg::<UnixAddr>(
        socket.as_raw_fd(),
        &iov,
        &[cmsgs],
        socket::MsgFlags::empty(),
        None,
    )
    .map_err(|err| {
        tracing::error!(?err, "failed to write container state to seccomp listener");
        SeccompListenerError::UnixOther(err)
    })?;
    // The spec requires the listener socket to be closed immediately after sending.
    drop(socket);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::net::UnixListener;
    use std::thread;

    use anyhow::Result;
    use serial_test::serial;

    use super::*;

    // Verifies that the encoded state is delivered with the seccomp notify fd via SCM_RIGHTS.
    #[test]
    #[serial]
    fn test_sync_seccomp_send_msg() -> Result<()> {
        let tmp_dir = tempfile::tempdir()?;
        let scmp_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(tmp_dir.path().join("scmp_file"))?;
        let socket_path = tmp_dir.path().join("socket_file.sock");

        let listener = UnixListener::bind(&socket_path)?;
        let want = "container-process-state";
        let send_path = socket_path.clone();
        let fd = unsafe { OwnedFd::from_raw_fd(scmp_file.into_raw_fd()) };
        let th = thread::spawn(move || {
            sync_seccomp_send_msg(&send_path, want.as_bytes(), fd.as_raw_fd()).unwrap();
        });

        let (mut socket, _) = listener.accept()?;
        let mut got = String::new();
        socket.read_to_string(&mut got)?;
        assert_eq!(want, got);
        assert!(th.join().is_ok());
        Ok(())
    }
}
