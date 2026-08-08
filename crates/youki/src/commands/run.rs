use std::path::PathBuf;

use anyhow::{Context, Result};
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use liboci_cli::Run;

use super::handle_foreground;
use crate::workload::executor::default_executor;

pub fn run(args: Run, root_path: PathBuf, systemd_cgroup: bool) -> Result<i32> {
    let mut container = ContainerBuilder::new(args.container_id.clone(), SyscallType::default())
        .with_executor(default_executor())
        .with_pid_file(args.pid_file.as_ref())?
        .with_console_socket(args.console_socket.as_ref())
        .with_root_path(root_path)?
        .with_preserved_fds(args.preserve_fds)
        .validate_id()?
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
    let foreground_result = handle_foreground(container.pid().unwrap());
    // execute the destruction action after the container finishes running
    container.delete(true)?;
    // return result
    foreground_result
}
