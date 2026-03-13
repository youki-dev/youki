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
        manage_cgroups_mode: parse_cgroups_mode(&args.manage_cgroups_mode)?,
    };
    container
        .checkpoint(&opts)
        .with_context(|| format!("failed to checkpoint container {}", args.container_id))
}

fn parse_cgroups_mode(s: &str) -> Result<rust_criu::CgMode, anyhow::Error> {
    match s {
        "ignore" => Ok(rust_criu::CgMode::IGNORE),
        "full" => Ok(rust_criu::CgMode::FULL),
        "strict" => Ok(rust_criu::CgMode::STRICT),
        "soft" => Ok(rust_criu::CgMode::SOFT),
        _ => Err(anyhow::anyhow!("invalid manage-cgroups-mode: {s}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cgroups_mode_ok() {
        assert!(matches!(
            parse_cgroups_mode("ignore"),
            Ok(rust_criu::CgMode::IGNORE)
        ));
        assert!(matches!(
            parse_cgroups_mode("full"),
            Ok(rust_criu::CgMode::FULL)
        ));
        assert!(matches!(
            parse_cgroups_mode("strict"),
            Ok(rust_criu::CgMode::STRICT)
        ));
        assert!(matches!(
            parse_cgroups_mode("soft"),
            Ok(rust_criu::CgMode::SOFT)
        ));
    }

    #[test]
    fn test_parse_cgroups_mode_ng() {
        assert!(parse_cgroups_mode("IGNORE").is_err());
        assert!(parse_cgroups_mode("Ignore").is_err());
        assert!(parse_cgroups_mode("unknown").is_err());
        assert!(parse_cgroups_mode("").is_err());
    }
}
