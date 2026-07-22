use std::io::IoSlice;
use std::os::fd::AsRawFd;
use std::path::Path;

use nix::sys::socket::{self, UnixAddr};
use nix::unistd::Pid;
use oci_spec::runtime::{SECCOMP_FD_NAME, VERSION as OCI_VERSION};

use crate::container::Container;
use crate::process::args::ContainerType;

#[derive(Debug, thiserror::Error)]
pub enum SeccompListenerError {
    #[error("notify will require seccomp listener path to be set")]
    MissingListenerPath,
    #[error("failed to encode container process state")]
    EncodeState(#[source] serde_json::Error),
    #[error("unix syscall fails")]
    UnixOther(#[source] nix::Error),
    #[error("container state is required")]
    ContainerStateRequired,
    #[error("failed to build OCI state: {0}")]
    OciStateBuild(String),
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

/// Builds the OCI `ContainerProcessState` sent to the seccomp listener
/// alongside the notify fd.
pub(crate) fn build_container_process_state(
    container: Option<&Container>,
    container_type: ContainerType,
    init_pid: Pid,
    seccomp: &oci_spec::runtime::LinuxSeccomp,
) -> Result<oci_spec::runtime::ContainerProcessState> {
    let container = container.ok_or(SeccompListenerError::ContainerStateRequired)?;

    // Determine OCI status based on container type (matching runc behavior)
    let oci_status = match container_type {
        ContainerType::InitContainer => oci_spec::runtime::ContainerState::Creating,
        ContainerType::TenantContainer { .. } => oci_spec::runtime::ContainerState::Running,
    };

    let oci_state = oci_spec::runtime::StateBuilder::default()
        .version(OCI_VERSION)
        .id(container.state.id.clone())
        .status(oci_status)
        .pid(init_pid.as_raw())
        .bundle(container.state.bundle.clone())
        .annotations(container.state.annotations.clone().unwrap_or_default())
        .build()
        .map_err(|e| SeccompListenerError::OciStateBuild(e.to_string()))?;

    oci_spec::runtime::ContainerProcessStateBuilder::default()
        .version(OCI_VERSION)
        .fds(vec![SECCOMP_FD_NAME.to_string()])
        .pid(init_pid.as_raw())
        .metadata(seccomp.listener_metadata().clone().unwrap_or_default())
        .state(oci_state)
        .build()
        .map_err(|e| SeccompListenerError::OciStateBuild(e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::net::UnixListener;
    use std::thread;

    use anyhow::Result;
    use nix::unistd::Pid;
    use oci_spec::runtime::{ContainerState, LinuxSeccompBuilder, SECCOMP_FD_NAME};
    use serial_test::serial;

    use super::*;
    use crate::container::Container;
    use crate::process::args::ContainerType;

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

    // A missing container state must be rejected instead of building a state.
    #[test]
    fn build_container_process_state_requires_container() {
        let seccomp = LinuxSeccompBuilder::default().build().unwrap();
        let err = build_container_process_state(
            None,
            ContainerType::InitContainer,
            Pid::from_raw(42),
            &seccomp,
        )
        .expect_err("missing container state should be rejected");
        assert!(matches!(err, SeccompListenerError::ContainerStateRequired));
    }

    // An init container reports the `Creating` OCI status (matching runc), and
    // the built state carries the init pid and the seccomp notify fd name.
    #[test]
    fn build_container_process_state_maps_init_container_to_creating() {
        let mut container = Container::default();
        container.state.id = "test-id".to_string();
        let seccomp = LinuxSeccompBuilder::default().build().unwrap();

        let state = build_container_process_state(
            Some(&container),
            ContainerType::InitContainer,
            Pid::from_raw(42),
            &seccomp,
        )
        .expect("state should build");

        assert_eq!(*state.pid(), 42);
        assert_eq!(state.fds(), &vec![SECCOMP_FD_NAME.to_string()]);
        assert_eq!(state.state().id().as_str(), "test-id");
        assert_eq!(*state.state().pid(), Some(42));
        assert_eq!(*state.state().status(), ContainerState::Creating);
    }

    // A tenant container reports the `Running` OCI status (matching runc).
    #[test]
    fn build_container_process_state_maps_tenant_container_to_running() {
        let container = Container::default();
        let seccomp = LinuxSeccompBuilder::default().build().unwrap();

        let state = build_container_process_state(
            Some(&container),
            ContainerType::TenantContainer { exec_notify_fd: -1 },
            Pid::from_raw(7),
            &seccomp,
        )
        .expect("state should build");

        assert_eq!(*state.state().status(), ContainerState::Running);
    }
}
