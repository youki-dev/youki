use anyhow::{bail, Context, Result};
use nix::{
    libc,
    poll::{PollFd, PollFlags},
};
use std::{os::unix::prelude::RawFd, path::PathBuf};

use libcontainer::{container::builder::ContainerBuilder, syscall::syscall::create_syscall};
use liboci_cli::Exec;

pub fn exec(args: Exec, root_path: PathBuf) -> Result<i32> {
    let syscall = create_syscall();
    let pid = ContainerBuilder::new(args.container_id.clone(), syscall.as_ref())
        .with_root_path(root_path)?
        .with_console_socket(args.console_socket.as_ref())
        .with_pid_file(args.pid_file.as_ref())?
        .as_tenant()
        .with_cwd(args.cwd.as_ref())
        .with_env(args.env.clone().into_iter().collect())
        .with_process(args.process.as_ref())
        .with_no_new_privs(args.no_new_privs)
        .with_container_args(args.command.clone())
        .build()?;

    let pidfd = pidfd_open(pid.as_raw(), 0)?;
    let poll_fd = PollFd::new(pidfd, PollFlags::POLLIN);
    nix::poll::poll(&mut [poll_fd], -1).context("failed to wait for the container id")?;

    // TODO
    Ok(0)
}

fn pidfd_open(pid: libc::pid_t, flags: libc::c_uint) -> Result<RawFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) };
    if fd == -1 {
        bail!("faild to pifd_open syscall")
    } else {
        Ok(fd as RawFd)
    }
}
