//! Contains functionality of restore container command
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::container::{Container, RestoreOptions};
use libcontainer::syscall::syscall::SyscallType;
use liboci_cli::Restore;
use nix::sys::signal;
use nix::sys::wait::waitpid;

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
        image_path: args.image_path.clone(),
        manage_cgroups_mode: parse_cgroups_mode(&args.manage_cgroups_mode)?,
        shell_job: args.shell_job,
        tcp_established: args.tcp_established,
        work_path: args.work_path.clone(),
    };

    // Create container configuration without starting the init process.
    // The console socket is passed to the builder so build_for_restore can
    // validate it against the spec's terminal setting, but no process is
    // started and no socket listener is set up here.
    let mut container = ContainerBuilder::new(args.container_id.clone(), SyscallType::default())
        .with_executor(default_executor())
        .with_pid_file(args.pid_file.as_ref())?
        .with_root_path(root_path)?
        .validate_id()?
        .as_init(&args.bundle)
        .with_systemd(systemd_cgroup)
        .with_detach(args.detach)
        .with_console_socket(args.console_socket.clone())
        .build_for_restore()?;

    // Restore the container from checkpoint using CRIU.
    // RestoreContainerError already renders "failed to restore container: ..." along with
    // any cleanup error, so no extra context is added here.
    container.restore(&restore_opts)?;

    // Any failure after CRIU restored the process (state refresh, pid file
    // write, foreground handling) must not leave the restored container
    // running behind: runc kills the restored process via a deferred
    // terminate when the post-restore steps fail (utils_linux.go runner.run),
    // and crun kills it, reaps it and removes the container status
    // (libcrun_container_restore in container.c). Mirror that behavior here.
    match post_restore(&args, &mut container) {
        Ok(exit_code) => Ok(exit_code),
        Err(err) => {
            // Best effort: errors are logged and the original error is returned.
            terminate_restored_container(&mut container);
            Err(err)
        }
    }
}

/// Post-restore steps: refresh the saved state, write the pid file and, when
/// not detaching, wait for the container to exit and delete it.
fn post_restore(args: &Restore, container: &mut Container) -> Result<i32> {
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

/// Kill and clean up a container whose restore already succeeded but whose
/// post-restore steps failed. The restored init process is a child of this
/// process (set_rst_sibling(true) makes it a sibling of the CRIU swrk, which
/// itself is a child of youki), so it can be reaped with waitpid. Best effort:
/// errors are logged so the original error is preserved for the caller.
fn terminate_restored_container(container: &mut Container) {
    if let Err(err) = container.refresh_state() {
        tracing::warn!(err = ?err, "failed to refresh container state during cleanup");
    }

    if let Some(pid) = container.pid() {
        if let Err(err) = signal::kill(pid, signal::Signal::SIGKILL) {
            tracing::warn!(err = ?err, "failed to SIGKILL restored container during cleanup");
        }
        // Reap the killed process so it does not linger as a zombie.
        // Retry on EINTR like crun's TEMP_FAILURE_RETRY(waitpid) (container.c);
        // ECHILD simply means the process is already reaped.
        loop {
            match waitpid(pid, None) {
                Ok(_) => break,
                Err(nix::errno::Errno::ECHILD) => break,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(err) => {
                    tracing::warn!(err = ?err, "failed to wait for restored container during cleanup");
                    break;
                }
            }
        }
    }

    if let Err(err) = container.delete(true) {
        tracing::warn!(err = ?err, "failed to delete container after failed restore");
    }
}
