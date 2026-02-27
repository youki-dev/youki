//! Contains functionality of restore container command
use std::path::PathBuf;

use anyhow::{Context, Result};
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use liboci_cli::Restore;

use super::handle_foreground;
use crate::workload::executor::default_executor;

/// Restore a container from a previously created checkpoint.
/// This follows the runc startContainer pattern where:
/// 1. Container configuration is created (without starting a process)
/// 2. CRIU restores the checkpointed process
/// 3. The restored PID is tracked for foreground handling
pub fn restore(args: Restore, root_path: PathBuf, systemd_cgroup: bool) -> Result<i32> {
    tracing::debug!("start restoring container {}", args.container_id);

    // Build RestoreOptions from CLI arguments
    let restore_opts = libcontainer::container::RestoreOptions {
        console_socket: args.console_socket.clone(),
        ext_unix_sk: args.ext_unix_sk,
        file_locks: args.file_locks,
        image_path: args.image_path.clone(),
        shell_job: args.shell_job,
        tcp_established: args.tcp_established,
        work_path: args.work_path.clone(),
    };

    // Create container configuration without starting the init process.
    // This follows the runc pattern: createContainer only sets up state,
    // then container.Restore() uses CRIU to restore the process.
    let mut container = ContainerBuilder::new(args.container_id.clone(), SyscallType::default())
        .with_executor(default_executor())
        .with_pid_file(args.pid_file.as_ref())?
        .with_console_socket(args.console_socket.as_ref())
        .with_root_path(root_path)?
        .validate_id()?
        .as_init(&args.bundle)
        .with_systemd(systemd_cgroup)
        .with_detach(args.detach)
        .build_for_restore()?;

    // Restore the container from checkpoint using CRIU.
    // The container state (including PID) is updated in the post_restore callback.
    container
        .restore(&restore_opts)
        .with_context(|| format!("failed to restore container {}", args.container_id))?;

    // If detached, return immediately
    if args.detach {
        return Ok(0);
    }

    // Get the restored PID from container state
    let init_pid = container
        .pid()
        .ok_or_else(|| anyhow::anyhow!("container pid not set after restore"))?;

    // Handle foreground mode (same as run.rs)
    let foreground_result = handle_foreground(init_pid);

    // Clean up the container after it exits
    container.delete(true)?;

    foreground_result
}
