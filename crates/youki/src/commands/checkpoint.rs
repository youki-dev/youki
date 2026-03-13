//! Contains functionality of pause container command
use std::path::PathBuf;

use anyhow::{Context, Result};
use liboci_cli::Checkpoint;

use crate::commands::load_container;

pub fn checkpoint(args: Checkpoint, root_path: PathBuf) -> Result<()> {
    tracing::debug!("start checkpointing container {}", args.container_id);
    let mut container = load_container(root_path, &args.container_id)?;
    let opts = libcontainer::container::CheckpointOptions {
        ext_unix_sk: args.ext_unix_sk,
        file_locks: args.file_locks,
        image_path: args.image_path,
        leave_running: args.leave_running,
        shell_job: args.shell_job,
        tcp_established: args.tcp_established,
        work_path: args.work_path,
        manage_cgroup_mode: args.manage_cgroups_mode,
    };
    container
        .checkpoint(&opts)
        .with_context(|| format!("failed to checkpoint container {}", args.container_id))
}
