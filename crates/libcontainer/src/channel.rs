use std::io::{IoSlice, IoSliceMut};
use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::os::unix::prelude::RawFd;

use nix::sys::socket::{self, UnixAddr};
use nix::unistd::{self};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("failed unix syscalls")]
    Nix(#[from] nix::Error),
    #[error("failed serde serialization")]
    Serde(#[from] serde_json::Error),
    #[error("channel connection broken")]
    BrokenChannel,
}
pub struct Receiver<T> {
    receiver: RawFd,
    phantom: PhantomData<T>,
}

pub struct Sender<T> {
    sender: RawFd,
    phantom: PhantomData<T>,
}

impl<T> Sender<T>
where
    T: Serialize,
{
    fn send_iovec(
        &mut self,
        iov: &[IoSlice],
        fds: Option<&[RawFd]>,
    ) -> Result<usize, ChannelError> {
        let cmsgs = if let Some(fds) = fds {
            vec![socket::ControlMessage::ScmRights(fds)]
        } else {
            vec![]
        };
        socket::sendmsg::<UnixAddr>(self.sender, iov, &cmsgs, socket::MsgFlags::empty(), None)
            .map_err(|e| e.into())
    }

    fn send_slice_with_len(
        &mut self,
        data: &[u8],
        fds: Option<&[RawFd]>,
    ) -> Result<usize, ChannelError> {
        let len = data.len() as u64;
        // Here we prefix the length of the data onto the serialized data.
        let iov = [
            IoSlice::new(unsafe {
                std::slice::from_raw_parts(
                    (&len as *const u64) as *const u8,
                    std::mem::size_of::<u64>(),
                )
            }),
            IoSlice::new(data),
        ];
        self.send_iovec(&iov[..], fds)
    }

    pub fn send(&mut self, object: T) -> Result<(), ChannelError> {
        let payload = serde_json::to_vec(&object)?;
        self.send_slice_with_len(&payload, None)?;

        Ok(())
    }

    pub fn send_fds(&mut self, object: T, fds: &[RawFd]) -> Result<(), ChannelError> {
        let payload = serde_json::to_vec(&object)?;
        self.send_slice_with_len(&payload, Some(fds))?;

        Ok(())
    }

    pub fn close(&self) -> Result<(), ChannelError> {
        Ok(unistd::close(self.sender)?)
    }
}

impl<T> Receiver<T>
where
    T: serde::de::DeserializeOwned,
{
    fn peek_size_iovec(&mut self) -> Result<u64, ChannelError> {
        let mut len: u64 = 0;
        let mut iov = [IoSliceMut::new(unsafe {
            std::slice::from_raw_parts_mut(
                (&mut len as *mut u64) as *mut u8,
                std::mem::size_of::<u64>(),
            )
        })];
        let _ =
            socket::recvmsg::<UnixAddr>(self.receiver, &mut iov, None, socket::MsgFlags::MSG_PEEK)?;
        match len {
            0 => Err(ChannelError::BrokenChannel),
            _ => Ok(len),
        }
    }

    fn recv_into_iovec<F>(
        &mut self,
        iov: &mut [IoSliceMut],
    ) -> Result<(usize, Option<F>), ChannelError>
    where
        F: Default + AsMut<[RawFd]>,
    {
        let mut cmsgspace = nix::cmsg_space!(F);
        let msg = socket::recvmsg::<UnixAddr>(
            self.receiver,
            iov,
            Some(&mut cmsgspace),
            socket::MsgFlags::MSG_CMSG_CLOEXEC,
        )?;

        // Sending multiple SCM_RIGHTS message will led to platform dependent
        // behavior, with some system choose to return EINVAL when sending or
        // silently only process the first msg or send all of it. Here we assume
        // there is only one SCM_RIGHTS message and will only process the first
        // message.
        let fds: Option<F> = msg
            .cmsgs()?
            .find_map(|cmsg| {
                if let socket::ControlMessageOwned::ScmRights(fds) = cmsg {
                    Some(fds)
                } else {
                    None
                }
            })
            .map(|fds| {
                let mut fds_array: F = Default::default();
                <F as AsMut<[RawFd]>>::as_mut(&mut fds_array).clone_from_slice(&fds);
                fds_array
            });

        Ok((msg.bytes, fds))
    }

    fn recv_into_buf_with_len<F>(&mut self) -> Result<(Vec<u8>, Option<F>), ChannelError>
    where
        F: Default + AsMut<[RawFd]>,
    {
        let msg_len = self.peek_size_iovec()?;
        let mut len: u64 = 0;
        let mut buf = vec![0u8; msg_len as usize];
        let (bytes, fds) = {
            let mut iov = [
                IoSliceMut::new(unsafe {
                    std::slice::from_raw_parts_mut(
                        (&mut len as *mut u64) as *mut u8,
                        std::mem::size_of::<u64>(),
                    )
                }),
                IoSliceMut::new(&mut buf),
            ];
            self.recv_into_iovec(&mut iov)?
        };

        match bytes {
            0 => Err(ChannelError::BrokenChannel),
            _ => Ok((buf, fds)),
        }
    }

    // Recv the next message of type T.
    pub fn recv(&mut self) -> Result<T, ChannelError> {
        let (buf, _) = self.recv_into_buf_with_len::<[RawFd; 0]>()?;
        Ok(serde_json::from_slice(&buf[..])?)
    }

    // Works similar to `recv`, but will look for fds sent by SCM_RIGHTS
    // message.  We use F as as `[RawFd; n]`, where `n` is the number of
    // descriptors you want to receive.
    pub fn recv_with_fds<F>(&mut self) -> Result<(T, Option<F>), ChannelError>
    where
        F: Default + AsMut<[RawFd]>,
    {
        let (buf, fds) = self.recv_into_buf_with_len::<F>()?;
        Ok((serde_json::from_slice(&buf[..])?, fds))
    }

    pub fn close(&self) -> Result<(), ChannelError> {
        Ok(unistd::close(self.receiver)?)
    }
}

pub fn channel<T>() -> Result<(Sender<T>, Receiver<T>), ChannelError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let (os_sender, os_receiver) = unix_channel()?;
    let receiver = Receiver {
        receiver: os_receiver,
        phantom: PhantomData,
    };
    let sender = Sender {
        sender: os_sender,
        phantom: PhantomData,
    };
    Ok((sender, receiver))
}

// Use socketpair as the underlying pipe.
fn unix_channel() -> Result<(RawFd, RawFd), ChannelError> {
    let (f1, f2) = socket::socketpair(
        socket::AddressFamily::Unix,
        socket::SockType::SeqPacket,
        None,
        socket::SockFlag::SOCK_CLOEXEC,
    )?;
    // It is not straightforward to share the OwnedFd across forks, so we
    // treat them as i32. We use ManuallyDrop to keep the connection open.
    let f1 = std::mem::ManuallyDrop::new(f1);
    let f2 = std::mem::ManuallyDrop::new(f2);

    Ok((f1.as_raw_fd(), f2.as_raw_fd()))
}
