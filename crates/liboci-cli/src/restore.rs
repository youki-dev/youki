use std::path::PathBuf;

use clap::Parser;

/// Restore a container from a checkpoint
/// Reference: https://github.com/opencontainers/runc/blob/main/man/runc-restore.8.md
#[derive(Parser, Debug)]
pub struct Restore {
    /// Path to an AF_UNIX socket which will receive a file descriptor
    /// referencing the master end of the console's pseudoterminal
    #[clap(long)]
    pub console_socket: Option<PathBuf>,
    /// Path for saving criu image files
    #[clap(long, default_value = "checkpoint")]
    pub image_path: PathBuf,
    /// Path for saving work files and logs
    #[clap(long)]
    pub work_path: Option<PathBuf>,
    /// Allow open tcp connections
    #[clap(long)]
    pub tcp_established: bool,
    /// Allow external unix sockets
    #[clap(long)]
    pub ext_unix_sk: bool,
    /// Allow shell jobs
    #[clap(long)]
    pub shell_job: bool,
    /// Allow file locks
    #[clap(long)]
    pub file_locks: bool,
    /// Cgroups mode
    #[clap(long)]
    pub manage_cgroups_mode: Option<String>,
    /// Path to the root of the bundle directory
    #[clap(short, long, default_value = ".")]
    pub bundle: PathBuf,
    /// Detach from the container's process
    #[clap(short, long)]
    pub detach: bool,
    /// Specify the file to write the process id to
    #[clap(long)]
    pub pid_file: Option<PathBuf>,

    #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}

