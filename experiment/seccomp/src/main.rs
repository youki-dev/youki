use seccomp::{
    instruction::{*},
    seccomp::{NotifyFd, Seccomp},
};

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{IntoRawFd, OwnedFd};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::slice;

use anyhow::Result;
use nix::{libc, sys::{
    signal::Signal,
    socket::{
        self, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
    },
    stat::Mode,
    wait::{self, WaitStatus},
}, unistd::{close, mkdir}};

use syscall_numbers::x86_64;
use syscalls::syscall_args;
use seccomp::seccomp::{InstructionData, Rule};

fn send_fd<F: AsRawFd>(sock: OwnedFd, fd: &F) -> nix::Result<()> {
    let fd = fd.as_raw_fd();
    let cmsgs = [ControlMessage::ScmRights(slice::from_ref(&fd))];

    let iov = [IoSlice::new(b"x")];

    socket::sendmsg::<()>(sock.into_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)?;
    Ok(())
}

fn recv_fd<F: FromRawFd>(sock: RawFd) -> nix::Result<Option<F>> {
    let mut iov_buf = [];
    let mut iov = [IoSliceMut::new(&mut iov_buf)];

    let mut cmsg_buf = nix::cmsg_space!(RawFd);
    let msg = socket::recvmsg::<UnixAddr>(sock, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())?;
    match msg.cmsgs().next() {
        Some(ControlMessageOwned::ScmRights(fds)) if !fds.is_empty() => {
            let fd = unsafe { F::from_raw_fd(fds[0]) };
            Ok(Some(fd))
        }
        _ => Ok(None),
    }
}

async fn handle_notifications(notify_fd: NotifyFd) -> nix::Result<()> {
    loop {
        println!("Waiting on next");
        let req = notify_fd.recv()?.notif;
        let syscall_name = x86_64::sys_call_name(req.data.nr.into());
        println!(
            "Got notification: id={}, pid={}, nr={:?}",
            req.id, req.pid, syscall_name
        );

        notify_fd.success(0, req.id)?;
    }
}

async fn handle_signal(pid: nix::unistd::Pid) -> Result<()> {
    let status = wait::waitpid(pid, None)?;
    match status {
        WaitStatus::Signaled(_, signal, _) => {
            if signal == Signal::SIGSYS {
                println!("Got SIGSYS, seccomp filter applied successfully!");
                return Ok(());
            }
            dbg!(signal);
            Ok(())
        }
        wait_status => {
            dbg!("Unexpected wait status: {:?}", wait_status);
            Err(anyhow::anyhow!("Unexpected wait status: {:?}", wait_status))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let (sock_for_child, sock_for_parent) = socket::socketpair(
        socket::AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )?;

    let _ = prctl::set_no_new_privileges(true);
    let inst_data = InstructionData{
        arc: Arch::X86,
        def_action: SECCOMP_RET_KILL_PROCESS,
        rule_arr: vec![
            Rule::new("getcwd".parse()?, 0,  syscall_args!(),false),
            Rule::new("write".parse()?,1, syscall_args!(libc::STDERR_FILENO as usize), false),
            Rule::new("mkdir".parse()?,0, syscall_args!(), true)
        ]
    };
    let seccomp = Seccomp {filters: Vec::from(inst_data)};

    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for event");
        println!("Received ctrl-c event. Bye");
        std::process::exit(0);
    });

    match unsafe { nix::unistd::fork()? } {
        nix::unistd::ForkResult::Child => {
            std::panic::catch_unwind(|| {
                let notify_fd = seccomp.apply().unwrap();
                println!(
                    "Seccomp applied successfully with notify fd: {:?}",
                    notify_fd
                );
                send_fd(sock_for_child, &notify_fd).unwrap();

                if let Err(e) = mkdir("/tmp/test", Mode::S_IRUSR | Mode::S_IWUSR) {
                    eprintln!("Failed to mkdir: {}", e);
                } else {
                    println!("mkdir succeeded");
                }

                eprintln!("stderr should be banned by seccomp");
            })
            .unwrap();

            std::process::exit(0);
        }
        nix::unistd::ForkResult::Parent { child } => {
            let notify_fd = recv_fd::<NotifyFd>(sock_for_parent.as_raw_fd())?.unwrap();

            close(sock_for_child.as_raw_fd())?;
            close(sock_for_parent.as_raw_fd())?;

            tokio::spawn(async move {
                handle_signal(child).await.unwrap();
            });

            handle_notifications(notify_fd).await?;
        }
    };

    Ok(())
}
