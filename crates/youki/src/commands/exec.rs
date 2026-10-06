use std::io::BufReader;
use std::path::PathBuf;

use anyhow::{Context, Result};
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use libcontainer::utils;
use liboci_cli::Exec;
use oci_spec::runtime::Process;

use crate::commands::{foreground, load_container, stdio};
use crate::workload::executor::default_executor;

pub fn exec(args: Exec, root_path: PathBuf) -> Result<i32> {
    let user = args.user.map(|(u, _)| u);
    let group = args.user.and_then(|(_, g)| g);

    let (terminal, uid_in_container) = if let Some(path) = args.process.as_ref() {
        let file = utils::open(path)
            .with_context(|| format!("failed to open process.json {}", path.display()))?;
        let reader = BufReader::new(file);
        let process_spec = serde_json::from_reader::<_, Process>(reader)
            .with_context(|| format!("failed to parse process.json {}", path.display()))?;
        (
            process_spec.terminal().unwrap_or(false),
            process_spec.user().uid(),
        )
    } else {
        (args.tty, user.unwrap_or(0))
    };

    let mut builder = ContainerBuilder::new(args.container_id.clone(), SyscallType::default())
        .with_executor(default_executor())
        .with_root_path(root_path.clone())?
        .with_console_socket(args.console_socket.as_ref())
        .with_pid_file(args.pid_file.as_ref())?
        .with_preserved_fds(args.preserve_fds)
        .validate_id()?;

    // Like runc, a foreground process without a terminal gets its own stdio
    // pipes, which youki relays to its own stdio.
    let mut host_stdio = None;
    if !args.detach && !terminal {
        let init_pid = load_container(&root_path, &args.container_id)?
            .pid()
            .with_context(|| {
                format!("failed to get init pid for container {}", args.container_id)
            })?;
        let (host_uid, host_gid) = stdio::pipe_owner_from_proc(init_pid, uid_in_container)
            .with_context(|| {
                format!(
                    "failed to get pipe owner for container {}",
                    args.container_id
                )
            })?;
        let (host, container_stdio) = stdio::create_stdio_pipes_owned_by(host_uid, host_gid)
            .with_context(|| {
                format!(
                    "failed to create stdio pipes for container {}",
                    args.container_id
                )
            })?;
        builder = container_stdio.apply_to(builder);
        host_stdio = Some(host);
    }

    let builder = builder
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
        .with_capabilities(args.cap)
        .with_ignore_paused(args.ignore_paused)
        .with_sub_cgroup(args.cgroup)
        .with_apparmor(args.apparmor)
        .with_tty(args.tty);

    let (pid, foreground_pty_fd) = builder.build()?;

    // See https://github.com/youki-dev/youki/pull/1252 for a detailed explanation
    // basically, if there is any error in starting exec, the build above will return error
    // however, if the process does start, and detach is given, we do not wait for it
    // if not detached, then we wait for it using waitpid below
    if args.detach {
        return Ok(0);
    }

    foreground::handle_foreground(pid, foreground_pty_fd, host_stdio)
}
