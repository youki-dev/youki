use std::path::PathBuf;

use anyhow::Result;
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use liboci_cli::Exec;
use nix::sys::wait::{WaitStatus, waitpid};

use crate::workload::executor::default_executor;

pub fn exec(args: Exec, root_path: PathBuf) -> Result<i32> {
    let Exec {
        console_socket,
        cwd,
        env,
        user,
        additional_gids,
        process,
        detach,
        pid_file,
        no_new_privs,
        cap,
        preserve_fds,
        container_id,
        command,
        // TODO: not all values from exec are used here. We need to support
        //   the remaining ones.
        tty: _,
        process_label: _,
        apparmor: _,
        ignore_paused: _,
        cgroup: _,
    } = args;
    let user_id = user.map(|(u, _)| u);
    let group_id = user.and_then(|(_, g)| g);

    let pid = ContainerBuilder::new(container_id, SyscallType::default())
        .with_executor(default_executor())
        .with_root_path(root_path)?
        .with_console_socket(console_socket.as_ref())
        .with_pid_file(pid_file.as_ref())?
        .with_preserved_fds(preserve_fds)
        .validate_id()?
        .as_tenant()
        .with_detach(detach)
        .with_cwd(cwd.as_ref())
        .with_env(env.into_iter().collect())
        .with_process(process.as_ref())
        .with_no_new_privs(no_new_privs)
        .with_capabilities(cap)
        .with_container_args(command)
        .with_additional_gids(additional_gids)
        .with_user(user_id)
        .with_group(group_id)
        .build()?;

    // See https://github.com/youki-dev/youki/pull/1252 for a detailed explanation
    // basically, if there is any error in starting exec, the build above will return error
    // however, if the process does start, and detach is given, we do not wait for it
    // if not detached, then we wait for it using waitpid below
    if detach {
        return Ok(0);
    }

    match waitpid(pid, None)? {
        WaitStatus::Exited(_, status) => Ok(status),
        WaitStatus::Signaled(_, sig, _) => Ok(sig as i32),
        _ => Ok(0),
    }
}
