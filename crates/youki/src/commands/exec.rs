use std::path::PathBuf;

use anyhow::Result;
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use liboci_cli::Exec;
use nix::sys::wait::{waitpid, WaitStatus};

use crate::workload::executor::default_executor;

pub fn exec(args: Exec, root_path: PathBuf) -> Result<i32> {
    // TODO: not all values from exec are used here. We need to support
    // the remaining ones.
    let user = args.user.map(|(u, _)| u);
    let group = args.user.and_then(|(_, g)| g);

    let pid = ContainerBuilder::new(args.container_id.clone(), SyscallType::default())
        .with_executor(default_executor())
        .with_root_path(root_path)?
        .with_console_socket(args.console_socket.as_ref())
        .with_pid_file(args.pid_file.as_ref())?
        .validate_id()?
        .as_tenant()
        .with_detach(args.detach)
        .with_cwd(args.cwd.as_ref())
        .with_env(args.env.clone().into_iter().collect())
        .with_process(args.process.as_ref())
        .with_no_new_privs(args.no_new_privs)
        .with_container_args(args.command.clone())
        .with_additional_gids(args.additional_gids)
        .with_user(user)
        .with_group(group)
        .build()?;

    // See https://github.com/containers/youki/pull/1252 for a detailed explanation
    // basically, if there is any error in starting exec, the build above will return error
    // however, if the process does start, and detach is given, we do not wait for it
    // if not detached, then we wait for it using waitpid below
    if args.detach {
        return Ok(0);
    }

    match waitpid(pid, None)? {
        WaitStatus::Exited(_, status) => Ok(status),
        WaitStatus::Signaled(_, sig, _) => Ok(sig as i32),
        _ => Ok(0),
    }
}
