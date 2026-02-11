use std::path::PathBuf;

use clap::Parser;

/// Checkpoint a running container
/// Reference: https://github.com/opencontainers/runc/blob/main/man/runc-checkpoint.8.md
/// Unimplemented options vs runc: https://github.com/youki-dev/youki/issues/3394
#[derive(Parser, Debug)]
pub struct Checkpoint {
    /// Path for saving criu image files
    #[clap(long, default_value = "checkpoint")]
    pub image_path: PathBuf,
    /// Path for saving work files and logs
    #[clap(long)]
    pub work_path: Option<PathBuf>,
    /// TODO: Path for previous criu image file in pre-dump
    /// #[clap(long)]
    /// pub parent_path: Option<PathBuf>,
    /// Leave the process running after checkpointing
    #[clap(long)]
    pub leave_running: bool,
    /// Allow open tcp connections
    #[clap(long)]
    pub tcp_established: bool,
    /// TODO: Skip in-flight tcp connections
    /// #[clap(long)]
    /// pub tcp_skip_in_flight: bool,
    /// TODO: Allow one to link unlinked files back when possible
    /// #[clap(long)]
    /// pub link_remap: bool,
    /// Allow external unix sockets
    #[clap(long)]
    pub ext_unix_sk: bool,
    /// Allow shell jobs
    #[clap(long)]
    pub shell_job: bool,
    /// TODO: Use lazy migration mechanism
    /// #[clap(long)]
    /// pub lazy_pages: bool,
    /// TODO: Pass a file descriptor fd to criu. Is u32 the right type?
    /// #[clap(long)]
    /// pub status_fd: Option<u32>,
    /// TODO: Start a page server at the given URL
    /// #[clap(long)]
    /// pub page_server: Option<String>,
    /// Allow file locks
    #[clap(long)]
    pub file_locks: bool,
    /// TODO: Do a pre-dump
    /// #[clap(long)]
    /// pub pre_dump: bool,
    /// TODO: Cgroups mode
    /// #[clap(long)]
    /// pub manage_cgroups_mode: Option<String>,
    /// TODO: Checkpoint a namespace, but don't save its properties
    /// #[clap(long)]
    /// pub empty_ns: bool,
    /// TODO: Enable auto-deduplication
    /// #[clap(long)]
    /// pub auto_dedup: bool,

    #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
