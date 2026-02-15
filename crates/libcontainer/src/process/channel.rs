use std::collections::HashMap;
use std::os::unix::prelude::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use nix::unistd::Pid;

use crate::channel::{Receiver, Sender, channel};
use crate::network::cidr::CidrAddress;
use crate::process::message::{Message, MountMsg};

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("received unexpected message: {received:?}, expected: {expected:?}")]
    UnexpectedMessage {
        expected: Message,
        received: Message,
    },
    #[error("failed to receive. {msg:?}. {source:?}")]
    ReceiveError {
        msg: String,
        #[source]
        source: crate::channel::ChannelError,
    },
    #[error(transparent)]
    BaseChannelError(#[from] crate::channel::ChannelError),
    #[error("missing fds from seccomp request")]
    MissingSeccompFds,
    #[error("exec process failed with error {0}")]
    ExecError(String),
    #[error("intermediate process error {0}")]
    OtherError(String),
    #[error("missing fd from mount request")]
    MissingMountFds,
    #[error("mount request failed: {0}")]
    MountFdError(String),
}

// Channel Design
//
// Each of the main, intermediate, and init process will have a uni-directional
// channel, a sender and a receiver. Each process will hold the receiver and
// listen message on it. Each sender is shared between each process to send
// message to the corresponding receiver. For example, main_sender and
// main_receiver is used for the main process. The main process will use
// receiver to receive all message sent to the main process. The other
// processes will share the main_sender and use it to send message to the main
// process.

pub fn main_channel() -> Result<(MainSender, MainReceiver), ChannelError> {
    let (sender, receiver) = channel::<Message>()?;
    Ok((MainSender { sender }, MainReceiver { receiver }))
}

pub struct MainSender {
    sender: Sender<Message>,
}

impl MainSender {
    // requests the Main to write the id mappings for the intermediate process
    // this needs to be done from the parent see https://man7.org/linux/man-pages/man7/user_namespaces.7.html
    pub fn identifier_mapping_request(&mut self) -> Result<(), ChannelError> {
        tracing::debug!("send identifier mapping request");
        self.sender.send(Message::WriteMapping)?;

        Ok(())
    }

    pub fn seccomp_notify_request(&mut self, fd: RawFd) -> Result<(), ChannelError> {
        self.sender
            .send_fds(Message::SeccompNotify, &[fd.as_raw_fd()])?;

        Ok(())
    }

    pub fn request_mount_fd(&mut self, msg: MountMsg) -> Result<(), ChannelError> {
        self.sender.send(Message::MountFdPlease(msg))?;

        Ok(())
    }

    pub fn network_setup_ready(&mut self) -> Result<(), ChannelError> {
        tracing::debug!("notify network setup ready");
        self.sender.send(Message::SetupNetworkDeviceReady)?;

        Ok(())
    }

    pub fn intermediate_ready(&mut self, pid: Pid) -> Result<(), ChannelError> {
        // Send over the IntermediateReady follow by the pid.
        tracing::debug!("sending init pid ({:?})", pid);
        self.sender.send(Message::IntermediateReady(pid.as_raw()))?;

        Ok(())
    }

    pub fn init_ready(&mut self) -> Result<(), ChannelError> {
        self.sender.send(Message::InitReady)?;

        Ok(())
    }

    pub fn exec_failed(&mut self, err: String) -> Result<(), ChannelError> {
        self.sender.send(Message::ExecFailed(err))?;
        Ok(())
    }

    pub fn send_error(&mut self, err: String) -> Result<(), ChannelError> {
        self.sender.send(Message::OtherError(err))?;
        Ok(())
    }

    pub fn hook_request(&mut self) -> Result<(), ChannelError> {
        self.sender.send(Message::HookRequest)?;
        Ok(())
    }

    pub fn close(&self) -> Result<(), ChannelError> {
        self.sender.close()?;

        Ok(())
    }
}

pub struct MainReceiver {
    receiver: Receiver<Message>,
}

impl MainReceiver {
    /// Waits for associated intermediate process to send ready message
    /// and return the pid of init process which is forked by intermediate process
    pub fn wait_for_intermediate_ready(&mut self) -> Result<Pid, ChannelError> {
        let msg = self
            .receiver
            .recv()
            .map_err(|err| ChannelError::ReceiveError {
                msg: "waiting for intermediate process".to_string(),
                source: err,
            })?;

        match msg {
            Message::IntermediateReady(pid) => Ok(Pid::from_raw(pid)),
            Message::ExecFailed(err) => Err(ChannelError::ExecError(err)),
            Message::OtherError(err) => Err(ChannelError::OtherError(err)),
            msg => Err(ChannelError::UnexpectedMessage {
                expected: Message::IntermediateReady(0),
                received: msg,
            }),
        }
    }

    pub fn wait_for_mapping_request(&mut self) -> Result<(), ChannelError> {
        let msg = self
            .receiver
            .recv()
            .map_err(|err| ChannelError::ReceiveError {
                msg: "waiting for mapping request".to_string(),
                source: err,
            })?;
        match msg {
            Message::WriteMapping => Ok(()),
            msg => Err(ChannelError::UnexpectedMessage {
                expected: Message::WriteMapping,
                received: msg,
            }),
        }
    }

    pub fn wait_for_mount_fd_request(&mut self) -> Result<MountMsg, ChannelError> {
        let msg = self
            .receiver
            .recv()
            .map_err(|err| ChannelError::ReceiveError {
                msg: "waiting for mount fd request".to_string(),
                source: err,
            })?;

        match msg {
            Message::MountFdPlease(req) => Ok(req),
            msg => Err(ChannelError::UnexpectedMessage {
                expected: Message::MountFdPlease(MountMsg {
                    source: String::new(),
                    idmap: None,
                    recursive: false,
                }),
                received: msg,
            }),
        }
    }

    pub fn recv_message_with_fds(&mut self) -> Result<(Message, Option<[RawFd; 1]>), ChannelError> {
        self.receiver
            .recv_with_fds::<[RawFd; 1]>()
            .map_err(|err| ChannelError::ReceiveError {
                msg: "waiting for message".to_string(),
                source: err,
            })
    }

    pub fn wait_for_seccomp_request(&mut self) -> Result<i32, ChannelError> {
        let (msg, fds) = self.receiver.recv_with_fds::<[RawFd; 1]>().map_err(|err| {
            ChannelError::ReceiveError {
                msg: "waiting for seccomp request".to_string(),
                source: err,
            }
        })?;

        match msg {
            Message::SeccompNotify => {
                let fd = match fds {
                    Some(fds) => {
                        if fds.is_empty() {
                            Err(ChannelError::MissingSeccompFds)
                        } else {
                            Ok(fds[0])
                        }
                    }
                    None => Err(ChannelError::MissingSeccompFds),
                }?;
                Ok(fd)
            }
            msg => Err(ChannelError::UnexpectedMessage {
                expected: Message::SeccompNotify,
                received: msg,
            }),
        }
    }

    pub fn wait_for_network_setup_ready(&mut self) -> Result<(), ChannelError> {
        let msg = self
            .receiver
            .recv()
            .map_err(|err| ChannelError::ReceiveError {
                msg: "waiting for init ready".to_string(),
                source: err,
            })?;
        match msg {
            Message::SetupNetworkDeviceReady => Ok(()),
            msg => Err(ChannelError::UnexpectedMessage {
                expected: Message::SetupNetworkDeviceReady,
                received: msg,
            }),
        }
    }

    /// Waits for associated init process to send ready message
    /// and return the pid of init process which is forked by init process
    pub fn wait_for_init_ready(&mut self) -> Result<(), ChannelError> {
        let msg = self
            .receiver
            .recv()
            .map_err(|err| ChannelError::ReceiveError {
                msg: "waiting for init ready".to_string(),
                source: err,
            })?;
        match msg {
            Message::InitReady => Ok(()),
            // this case in unique and known enough to have a special error format
            Message::ExecFailed(err) => Err(ChannelError::ExecError(format!(
                "error in executing process : {err}"
            ))),
            msg => Err(ChannelError::UnexpectedMessage {
                expected: Message::InitReady,
                received: msg,
            }),
        }
    }

    pub fn wait_for_hook_request(&mut self) -> Result<(), ChannelError> {
        let msg = self
            .receiver
            .recv()
            .map_err(|err| ChannelError::ReceiveError {
                msg: "waiting for hook request".to_string(),
                source: err,
            })?;
        match msg {
            Message::HookRequest => Ok(()),
            msg => Err(ChannelError::UnexpectedMessage {
                expected: Message::HookRequest,
                received: msg,
            }),
        }
    }

    pub fn close(&self) -> Result<(), ChannelError> {
        self.receiver.close()?;

        Ok(())
    }
}

pub fn intermediate_channel() -> Result<(IntermediateSender, IntermediateReceiver), ChannelError> {
    let (sender, receiver) = channel::<Message>()?;
    Ok((
        IntermediateSender { sender },
        IntermediateReceiver { receiver },
    ))
}

pub struct IntermediateSender {
    sender: Sender<Message>,
}

impl IntermediateSender {
    pub fn mapping_written(&mut self) -> Result<(), ChannelError> {
        tracing::debug!("identifier mapping written");
        self.sender.send(Message::MappingWritten)?;

        Ok(())
    }

    pub fn close(&self) -> Result<(), ChannelError> {
        self.sender.close()?;

        Ok(())
    }
}

pub struct IntermediateReceiver {
    receiver: Receiver<Message>,
}

impl IntermediateReceiver {
    // wait until the parent process has finished writing the id mappings
    pub fn wait_for_mapping_ack(&mut self) -> Result<(), ChannelError> {
        tracing::debug!("waiting for mapping ack");
        let msg = self
            .receiver
            .recv()
            .map_err(|err| ChannelError::ReceiveError {
                msg: "waiting for mapping ack".to_string(),
                source: err,
            })?;
        match msg {
            Message::MappingWritten => Ok(()),
            msg => Err(ChannelError::UnexpectedMessage {
                expected: Message::MappingWritten,
                received: msg,
            }),
        }
    }

    pub fn close(&self) -> Result<(), ChannelError> {
        self.receiver.close()?;

        Ok(())
    }
}

pub fn init_channel() -> Result<(InitSender, InitReceiver), ChannelError> {
    let (sender, receiver) = channel::<Message>()?;
    Ok((InitSender { sender }, InitReceiver { receiver }))
}

pub struct InitSender {
    sender: Sender<Message>,
}

impl InitSender {
    pub fn seccomp_notify_done(&mut self) -> Result<(), ChannelError> {
        self.sender.send(Message::SeccompNotifyDone)?;

        Ok(())
    }

    pub fn hook_done(&mut self) -> Result<(), ChannelError> {
        self.sender.send(Message::HookDone)?;
        Ok(())
    }

    pub fn move_network_device(
        &mut self,
        addrs: HashMap<String, Vec<CidrAddress>>,
    ) -> Result<(), ChannelError> {
        self.sender.send(Message::MoveNetworkDevice(addrs))?;

        Ok(())
    }

    pub fn close(&self) -> Result<(), ChannelError> {
        self.sender.close()?;

        Ok(())
    }

    pub fn send_mount_fd_reply(&mut self, fd: RawFd) -> Result<(), ChannelError> {
        self.sender.send_fds(Message::MountFdReply, &[fd])?;

        Ok(())
    }

    pub fn send_mount_fd_error(&mut self, err: String) -> Result<(), ChannelError> {
        self.sender.send(Message::MountFdError(err))?;
        Ok(())
    }
}

pub struct InitReceiver {
    receiver: Receiver<Message>,
}

impl InitReceiver {
    pub fn wait_for_seccomp_request_done(&mut self) -> Result<(), ChannelError> {
        let msg = self
            .receiver
            .recv()
            .map_err(|err| ChannelError::ReceiveError {
                msg: "waiting for seccomp request".to_string(),
                source: err,
            })?;

        match msg {
            Message::SeccompNotifyDone => Ok(()),
            msg => Err(ChannelError::UnexpectedMessage {
                expected: Message::SeccompNotifyDone,
                received: msg,
            }),
        }
    }

    pub fn wait_for_move_network_device(
        &mut self,
    ) -> Result<HashMap<String, Vec<CidrAddress>>, ChannelError> {
        let msg = self
            .receiver
            .recv()
            .map_err(|err| ChannelError::ReceiveError {
                msg: "waiting for mapping request".to_string(),
                source: err,
            })?;
        match msg {
            Message::MoveNetworkDevice(addr) => Ok(addr),
            msg => Err(ChannelError::UnexpectedMessage {
                expected: Message::WriteMapping,
                received: msg,
            }),
        }
    }

    pub fn wait_for_hook_request_done(&mut self) -> Result<(), ChannelError> {
        let msg = self
            .receiver
            .recv()
            .map_err(|err| ChannelError::ReceiveError {
                msg: "waiting for hook done".to_string(),
                source: err,
            })?;
        match msg {
            Message::HookDone => Ok(()),
            msg => Err(ChannelError::UnexpectedMessage {
                expected: Message::HookDone,
                received: msg,
            }),
        }
    }

    pub fn close(&self) -> Result<(), ChannelError> {
        self.receiver.close()?;

        Ok(())
    }

    pub fn wait_for_mount_fd_reply(&mut self) -> Result<OwnedFd, ChannelError> {
        let (msg, fds) = self.receiver.recv_with_fds::<[RawFd; 1]>().map_err(|err| {
            ChannelError::ReceiveError {
                msg: "waiting for mount fd reply".to_string(),
                source: err,
            }
        })?;

        match msg {
            Message::MountFdReply => {
                let fd = match fds {
                    Some([fd]) => fd,
                    _ => return Err(ChannelError::MissingMountFds),
                };
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
            Message::MountFdError(err) => Err(ChannelError::MountFdError(err)),
            msg => Err(ChannelError::UnexpectedMessage {
                expected: Message::MountFdReply,
                received: msg,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;

    use anyhow::{Context, Result};
    use nix::sys::wait;
    use nix::unistd;
    use serial_test::serial;

    use super::*;

    // Note: due to cargo test by default runs tests in parallel using a single
    // process, these tests should not be running in parallel with other tests.
    // Because we run tests in the same process, other tests may decide to close
    // down file descriptors or saturate the IOs in the OS.  The channel uses
    // pipe to communicate and can potentially become flaky as a result. There
    // is not much else we can do other than to run the tests in serial.

    #[test]
    #[serial]
    fn test_channel_intermadiate_ready() -> Result<()> {
        let (sender, receiver) = &mut main_channel()?;
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                wait::waitpid(child, None)?;
                let pid = receiver
                    .wait_for_intermediate_ready()
                    .with_context(|| "Failed to wait for intermadiate ready")?;
                receiver.close()?;
                assert_eq!(pid, child);
            }
            unistd::ForkResult::Child => {
                let pid = unistd::getpid();
                sender.intermediate_ready(pid)?;
                sender.close()?;
                std::process::exit(0);
            }
        };

        Ok(())
    }

    #[test]
    #[serial]
    fn test_channel_id_mapping_request() -> Result<()> {
        let (sender, receiver) = &mut main_channel()?;
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                wait::waitpid(child, None)?;
                receiver.wait_for_mapping_request()?;
                receiver.close()?;
            }
            unistd::ForkResult::Child => {
                sender
                    .identifier_mapping_request()
                    .with_context(|| "Failed to send mapping written")?;
                sender.close()?;
                std::process::exit(0);
            }
        };

        Ok(())
    }

    #[test]
    #[serial]
    fn test_channel_id_mapping_ack() -> Result<()> {
        let (sender, receiver) = &mut intermediate_channel()?;
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                wait::waitpid(child, None)?;
                receiver.wait_for_mapping_ack()?;
            }
            unistd::ForkResult::Child => {
                sender
                    .mapping_written()
                    .with_context(|| "Failed to send mapping written")?;
                std::process::exit(0);
            }
        };

        Ok(())
    }

    #[test]
    #[serial]
    fn test_channel_mount_fd_error() -> Result<()> {
        let (sender, receiver) = &mut init_channel()?;
        sender.send_mount_fd_error("boom".to_string())?;
        let err = receiver.wait_for_mount_fd_reply().unwrap_err();
        assert!(matches!(err, ChannelError::MountFdError(msg) if msg == "boom"));
        sender.close()?;
        receiver.close()?;
        Ok(())
    }

    #[test]
    #[serial]
    fn test_channel_mount_fd_reply_success() -> Result<()> {
        let (sender, receiver) = &mut init_channel()?;
        let mut file = tempfile::tempfile()?;
        file.write_all(b"ok")?;

        sender.send_mount_fd_reply(file.as_raw_fd())?;
        let fd = receiver.wait_for_mount_fd_reply()?;
        let mut received = std::fs::File::from(fd);
        received.seek(SeekFrom::Start(0))?;
        let mut buf = String::new();
        received.read_to_string(&mut buf)?;
        assert_eq!(buf, "ok");

        sender.close()?;
        receiver.close()?;
        Ok(())
    }

    #[test]
    #[serial]
    fn test_channel_mount_fd_reply_missing_fds() -> Result<()> {
        let (mut sender, receiver) = channel::<Message>()?;
        let mut receiver = InitReceiver { receiver };

        sender.send(Message::MountFdReply)?;
        let err = receiver.wait_for_mount_fd_reply().unwrap_err();
        assert!(matches!(err, ChannelError::MissingMountFds));

        sender.close()?;
        receiver.close()?;
        Ok(())
    }

    #[test]
    #[serial]
    fn test_channel_init_ready() -> Result<()> {
        let (sender, receiver) = &mut main_channel()?;
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                wait::waitpid(child, None)?;
                receiver.wait_for_init_ready()?;
                receiver.close()?;
            }
            unistd::ForkResult::Child => {
                sender
                    .init_ready()
                    .with_context(|| "Failed to send init ready")?;
                sender.close()?;
                std::process::exit(0);
            }
        };

        Ok(())
    }

    #[test]
    #[serial]
    fn test_channel_main_graceful_exit() -> Result<()> {
        let (sender, receiver) = &mut main_channel()?;
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                sender.close().context("failed to close sender")?;
                // The child process will exit without send the intermediate ready
                // message. This should cause the wait_for_intermediate_ready to error
                // out, instead of keep blocking.
                let ret = receiver.wait_for_intermediate_ready();
                assert!(ret.is_err());
                wait::waitpid(child, None)?;
            }
            unistd::ForkResult::Child => {
                receiver.close()?;
                std::process::exit(0);
            }
        };

        Ok(())
    }

    #[test]
    #[serial]
    fn test_channel_intermediate_graceful_exit() -> Result<()> {
        let (sender, receiver) = &mut main_channel()?;
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                sender.close().context("failed to close sender")?;
                // The child process will exit without send the init ready
                // message. This should cause the wait_for_init_ready to error
                // out, instead of keep blocking.
                let ret = receiver.wait_for_init_ready();
                assert!(ret.is_err());
                wait::waitpid(child, None)?;
            }
            unistd::ForkResult::Child => {
                receiver.close()?;
                std::process::exit(0);
            }
        };

        Ok(())
    }

    #[test]
    #[serial]
    fn test_move_network_device_message() -> Result<()> {
        use crate::network::cidr::CidrAddress;

        let device_name = "dummy".to_string();
        let ip = "10.0.0.1".parse().unwrap();
        let addr = CidrAddress {
            prefix_len: 24,
            address: ip,
        };
        let mut addrs = HashMap::new();
        addrs.insert(device_name.clone(), vec![addr.clone()]);

        let (sender, receiver) = &mut init_channel()?;

        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                sender.move_network_device(addrs)?;
                sender.close().context("failed to close sender")?;
                let status = wait::waitpid(child, None)?;
                if let nix::sys::wait::WaitStatus::Exited(_, code) = status {
                    assert_eq!(code, 0, "Child process failed assertions");
                } else {
                    panic!("Child did not exit normally: {:?}", status);
                }
            }
            unistd::ForkResult::Child => {
                let received_addrs = receiver.wait_for_move_network_device()?;
                receiver.close()?;
                if let Some(received_addr) = received_addrs.get(&device_name) {
                    if !(received_addr[0].prefix_len == addr.prefix_len
                        && received_addr[0].address == addr.address)
                    {
                        eprintln!("assertion failed in child");
                        std::process::exit(1);
                    }
                } else {
                    eprintln!("assertion failed in child");
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
        };

        Ok(())
    }

    #[test]
    #[serial]
    fn test_network_setup_ready() -> Result<()> {
        let (sender, receiver) = &mut main_channel()?;
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                wait::waitpid(child, None)?;
                receiver.wait_for_network_setup_ready()?;
                receiver.close()?;
            }
            unistd::ForkResult::Child => {
                sender
                    .network_setup_ready()
                    .with_context(|| "Failed to send network setup ready")?;
                sender.close()?;
                std::process::exit(0);
            }
        };

        Ok(())
    }
}
