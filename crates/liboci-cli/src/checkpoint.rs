use std::path::PathBuf;

use clap::Parser;

/// Checkpoint a running container
/// Reference: https://github.com/opencontainers/runc/blob/main/man/runc-checkpoint.8.md
/// Unimplemented options vs runc: https://github.com/youki-dev/youki/issues/3394
#[derive(Parser, Debug)]
pub struct Checkpoint {
    /// Path for saving criu image files
    #[arg(long, default_value = "checkpoint")]
    pub image_path: PathBuf,
    /// Path for saving work files and logs
    #[arg(long)]
    pub work_path: Option<PathBuf>,
    /// TODO: Path for previous criu image file in pre-dump
    /// #[arg(long)]
    /// pub parent_path: Option<PathBuf>,
    /// Leave the process running after checkpointing
    #[arg(long)]
    pub leave_running: bool,
    /// Allow open tcp connections
    #[arg(long)]
    pub tcp_established: bool,
    /// TODO: Skip in-flight tcp connections
    /// #[arg(long)]
    /// pub tcp_skip_in_flight: bool,
    /// TODO: Allow one to link unlinked files back when possible
    /// #[arg(long)]
    /// pub link_remap: bool,
    /// Allow external unix sockets
    #[arg(long)]
    pub ext_unix_sk: bool,
    /// Allow shell jobs
    #[arg(long)]
    pub shell_job: bool,
    /// TODO: Use lazy migration mechanism
    /// #[arg(long)]
    /// pub lazy_pages: bool,
    /// TODO: Pass a file descriptor fd to criu. Is u32 the right type?
    /// #[arg(long)]
    /// pub status_fd: Option<u32>,
    /// TODO: Start a page server at the given URL
    /// #[arg(long)]
    /// pub page_server: Option<String>,
    /// Allow file locks
    #[arg(long)]
    pub file_locks: bool,
    /// TODO: Do a pre-dump
    /// #[arg(long)]
    /// pub pre_dump: bool,
    /// TODO: Cgroups mode
    /// #[arg(long)]
    /// pub manage_cgroups_mode: Option<String>,
    /// TODO: Checkpoint a namespace, but don't save its properties
    /// #[arg(long)]
    /// pub empty_ns: bool,
    /// TODO: Enable auto-deduplication
    /// #[arg(long)]
    /// pub auto_dedup: bool,

    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
