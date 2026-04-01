use std::path::PathBuf;

use clap::Parser;

/// Create a container and immediately start it
#[derive(Parser, Debug)]
pub struct Run {
    /// Path to the bundle directory, containing config.json and root filesystem
    #[clap(short, long, default_value = ".")]
    pub bundle: PathBuf,
    /// Unix socket (file) path , which will receive file descriptor of the writing end of the pseudoterminal
    #[clap(short, long)]
    pub console_socket: Option<PathBuf>,
    /// File to write pid of the container created
    // note that in the end, container is just another process
    #[clap(short, long)]
    pub pid_file: Option<PathBuf>,
    /// Disable the use of the subreaper used to reap reparented processes
    #[clap(long)]
    pub no_subreaper: bool,
    /// Do not use pivot root to jail process inside rootfs
    #[clap(long)]
    pub no_pivot: bool,
    /// Do not create a new session keyring for the container. This will cause the container to inherit the calling processes session key.
    #[clap(long)]
    pub no_new_keyring: bool,
    /// Pass N additional file descriptors to the container (stdio + $LISTEN_FDS + N in total)
    #[clap(long, default_value = "0")]
    pub preserve_fds: i32,
    /// Keep container's state directory and cgroup after the container exits
    #[clap(long)]
    pub keep: bool,
    /// name of the container instance to be started
    #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
    /// Detach from the container process
    #[clap(short, long)]
    pub detach: bool,
}
