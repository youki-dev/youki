use std::os::unix::prelude::{AsRawFd, RawFd};

use nix::unistd::Pid;

use crate::channel::{channel, Receiver, Sender};
use crate::network::serialize::SerializableAddress;
use crate::process::message::Message;

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

    pub fn move_network_device(&mut self, addr: Vec<SerializableAddress>) -> Result<(), ChannelError> {
        self.sender.send(Message::MoveNetworkDevice(addr))?;

        Ok(())
    }

    pub fn close(&self) -> Result<(), ChannelError> {
        self.sender.close()?;

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

    pub fn wait_for_move_network_device(&mut self) -> Result<Vec<SerializableAddress>, ChannelError> {
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

    pub fn close(&self) -> Result<(), ChannelError> {
        self.receiver.close()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
    fn test_move_network_device_message() -> Result<()> {
        use crate::network::serialize::SerializableAddress;

        let ip = "10.0.0.1".parse().unwrap();
        let addr = SerializableAddress {
            index: 1,
            prefix_len: 24,
            family: 2,
            scope: 0,
            address: Some(ip),
            flags: Some(0x10),
        };
        let addrs = vec![addr.clone()];

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
                if !(received_addrs.len() == 1 && received_addrs[0].index == addr.index && received_addrs[0].address == addr.address) {
                    eprintln!("assertion failed in child");
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
        };

        Ok(())
    }
}
