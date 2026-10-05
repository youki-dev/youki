use std::path::PathBuf;

use anyhow::{Context, Result};
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use liboci_cli::Run;
use nix::errno::Errno;
use oci_spec::runtime::Spec;

use crate::commands::{foreground, stdio};
use crate::workload::executor::default_executor;

pub fn run(args: Run, root_path: PathBuf, systemd_cgroup: bool) -> Result<i32> {
    let mut builder = ContainerBuilder::new(args.container_id.clone(), SyscallType::default())
        .with_executor(default_executor())
        .with_pid_file(args.pid_file.as_ref())?
        .with_console_socket(args.console_socket.as_ref())
        .with_root_path(root_path)?
        .with_preserved_fds(args.preserve_fds)
        .validate_id()?;

    let spec = Spec::load(args.bundle.join("config.json"))
        .with_context(|| format!("failed to load config.json from {}", args.bundle.display()))?;
    let terminal = spec
        .process()
        .as_ref()
        .and_then(|process| process.terminal())
        .unwrap_or(false);

    // Like runc, a foreground container without a terminal gets its own stdio
    // pipes, which youki relays to its own stdio.
    let mut host_stdio = None;
    if !args.detach && !terminal {
        // Without a known owner, the container keeps inheriting youki's stdio.
        if let Some((uid, gid)) = stdio::pipe_owner(&spec)? {
            let (host, container) = stdio::create_stdio_pipes()?;
            match container.set_owner(uid, gid) {
                Ok(()) => {}
                // Rootless youki cannot chown to a subordinate UID. The pipes
                // stay owned by youki: relaying still works, but the container
                // user may not reopen them, as with inherited stdio.
                Err(Errno::EPERM) => tracing::warn!(
                    %uid,
                    %gid,
                    "cannot chown the stdio pipes to the container user"
                ),
                Err(err) => return Err(err.into()),
            }
            builder = container.apply_to(builder);
            host_stdio = Some(host);
        }
    }

    let (mut container, foreground_pty_fd) = builder
        .as_init(&args.bundle)
        .with_systemd(systemd_cgroup)
        .with_detach(args.detach)
        .with_no_pivot(args.no_pivot)
        .build()?;

    container
        .start()
        .with_context(|| format!("failed to start container {}", args.container_id))?;

    if args.detach {
        return Ok(0);
    }

    // Using `debug_assert` here rather than returning an error because this is
    // a invariant. The design when the code path arrives to this point, is that
    // the container state must have recorded the container init pid.
    debug_assert!(
        container.pid().is_some(),
        "expects a container init pid in the container state"
    );
    let foreground_result =
        foreground::handle_foreground(container.pid().unwrap(), foreground_pty_fd, host_stdio);
    // execute the destruction action after the container finishes running
    container.delete(true)?;
    // return result
    foreground_result
}
