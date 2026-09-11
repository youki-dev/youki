//! Contains functionality of restore container command
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use libcontainer::container::RestoreOptions;
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use liboci_cli::Restore;

use super::parse_cgroups_mode;
use crate::commands::foreground;
use crate::workload::executor::default_executor;

/// Restore a container from a previously created checkpoint.
/// This follows the runc startContainer pattern where:
/// 1. Container configuration is created (without starting a process)
/// 2. CRIU restores the checkpointed process
/// 3. The restored PID is tracked for foreground handling
pub fn restore(args: Restore, root_path: PathBuf, systemd_cgroup: bool) -> Result<i32> {
    tracing::debug!("start restoring container {}", args.container_id);

    // Build RestoreOptions from CLI arguments
    let restore_opts = RestoreOptions {
        console_socket: args.console_socket.clone(),
        ext_unix_sk: args.ext_unix_sk,
        file_locks: args.file_locks,
        image_path: args.image_path,
        manage_cgroups_mode: parse_cgroups_mode(&args.manage_cgroups_mode)?,
        shell_job: args.shell_job,
        tcp_established: args.tcp_established,
        work_path: args.work_path,
    };

    // Create container configuration without starting the init process.
    // build_for_restore only sets up state on disk; console_socket is not
    // used here (no process is started).
    let mut container = ContainerBuilder::new(args.container_id.clone(), SyscallType::default())
        .with_executor(default_executor())
        .with_pid_file(args.pid_file.as_ref())?
        .with_root_path(root_path)?
        .validate_id()?
        .as_init(&args.bundle)
        .with_systemd(systemd_cgroup)
        .with_detach(args.detach)
        .build_for_restore()?;

    // Restore the container from checkpoint using CRIU.
    container
        .restore(&restore_opts)
        .with_context(|| format!("failed to restore container {}", args.container_id))?;

    // The post-restore callback modifies a clone of the container, saving the
    // restored PID and Running status to disk. Reload state to pick up the new PID.
    container
        .refresh_state()
        .with_context(|| "failed to refresh container state after restore")?;

    let init_pid = container
        .pid()
        .ok_or_else(|| anyhow!("container pid not set after restore"))?;

    // Write PID file before detaching, matching runc restore behavior.
    if let Some(pid_file) = &args.pid_file {
        let mut f = File::create(pid_file)
            .with_context(|| format!("failed to create pid file {pid_file:?}"))?;
        write!(f, "{}", init_pid.as_raw())
            .with_context(|| format!("failed to write pid file {pid_file:?}"))?;
    }

    if args.detach {
        return Ok(0);
    }

    // Forward signals to the container init and wait for it to exit.
    let foreground_result = foreground::handle_foreground(init_pid, None);

    container.delete(true)?;

    foreground_result
}
