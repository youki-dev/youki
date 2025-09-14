use std::io::IoSlice;
use std::os::fd::AsRawFd;
use std::path::Path;

use nix::sys::socket::{self, UnixAddr};
use nix::unistd;
use oci_spec::runtime;

use super::channel;
use crate::container::ContainerProcessState;
use crate::seccomp;

#[derive(Debug, thiserror::Error)]
pub enum SeccompListenerError {
    #[error("notify will require seccomp listener path to be set")]
    MissingListenerPath,
    #[error("failed to encode container process state")]
    EncodeState(#[source] serde_json::Error),
    #[error(transparent)]
    ChannelError(#[from] channel::ChannelError),
    #[error("unix syscall fails")]
    UnixOther(#[source] nix::Error),
}

type Result<T> = std::result::Result<T, SeccompListenerError>;

pub fn sync_seccomp(
    seccomp: &runtime::LinuxSeccomp,
    state: &ContainerProcessState,
    init_sender: &mut channel::InitSender,
    main_receiver: &mut channel::MainReceiver,
) -> Result<()> {
    if seccomp::is_notify(seccomp) {
        tracing::debug!("main process waiting for sync seccomp");
        let seccomp_fd = main_receiver.wait_for_seccomp_request()?;
        let listener_path = seccomp
            .listener_path()
            .as_ref()
            .ok_or(SeccompListenerError::MissingListenerPath)?;
        let encoded_state = serde_json::to_vec(state).map_err(SeccompListenerError::EncodeState)?;
        sync_seccomp_send_msg(listener_path, &encoded_state, seccomp_fd).map_err(|err| {
            tracing::error!("failed to send msg to seccomp listener: {}", err);
            err
        })?;
        init_sender.seccomp_notify_done()?;
        // Once we sent the seccomp notify fd to the seccomp listener, we can
        // safely close the fd. The SCM_RIGHTS msg will duplicate the fd to the
        // process on the other end of the listener.
        let _ = unistd::close(seccomp_fd);
    }

    Ok(())
}

fn sync_seccomp_send_msg(listener_path: &Path, msg: &[u8], fd: i32) -> Result<()> {
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
    use anyhow::Result;
    use oci_spec::runtime::{LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder};
    use serial_test::serial;

    use super::*;
    use crate::container::ContainerProcessState;
    use crate::process::channel;

    #[test]
    #[serial]
    fn test_sync_seccomp() -> Result<()> {
        use std::io::Read;
        use std::os::unix::io::IntoRawFd;
        use std::os::unix::net::UnixListener;
        use std::thread;

        let tmp_dir = tempfile::tempdir()?;
        let scmp_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(tmp_dir.path().join("scmp_file"))?;

        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(tmp_dir.path().join("socket_file.sock"))?;

        let (mut main_sender, mut main_receiver) = channel::main_channel()?;
        let (mut init_sender, mut init_receiver) = channel::init_channel()?;
        let socket_path = tmp_dir.path().join("socket_file.sock");
        let socket_path_seccomp_th = socket_path.clone();

        let state = ContainerProcessState::default();
        let want = serde_json::to_string(&state)?;
        let th = thread::spawn(move || {
            sync_seccomp(
                &LinuxSeccompBuilder::default()
                    .listener_path(socket_path_seccomp_th)
                    .syscalls(vec![
                        LinuxSyscallBuilder::default()
                            .action(LinuxSeccompAction::ScmpActNotify)
                            .build()
                            .unwrap(),
                    ])
                    .build()
                    .unwrap(),
                &state,
                &mut init_sender,
                &mut main_receiver,
            )
            .unwrap();
        });

        let fd = scmp_file.into_raw_fd();
        assert!(main_sender.seccomp_notify_request(fd).is_ok());

        std::fs::remove_file(socket_path.clone())?;
        let lis = UnixListener::bind(socket_path)?;
        let (mut socket, _) = lis.accept()?;
        let mut got = String::new();
        socket.read_to_string(&mut got)?;
        assert!(init_receiver.wait_for_seccomp_request_done().is_ok());

        assert_eq!(want, got);
        assert!(th.join().is_ok());
        Ok(())
    }
}
