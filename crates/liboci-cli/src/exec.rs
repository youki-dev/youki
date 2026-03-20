use std::error::Error;
use std::path::PathBuf;

use clap::Args;

/// Execute a process within an existing container
/// Reference: https://github.com/opencontainers/runc/blob/main/man/runc-exec.8.md
#[derive(Args, Debug)]
pub struct Exec {
    /// Unix socket (file) path , which will receive file descriptor of the writing end of the pseudoterminal
    #[arg(long)]
    pub console_socket: Option<PathBuf>,
    #[arg(long)]
    /// Current working directory of the container
    pub cwd: Option<PathBuf>,
    /// Environment variables that should be set in the container
    #[arg(short, long, value_parser = parse_env::<String, String>, num_args = 1)]
    pub env: Vec<(String, String)>,
    #[arg(short, long)]
    pub tty: bool,
    /// Run the command as a user
    #[arg(short, long, value_parser = parse_user::<u32, u32>)]
    pub user: Option<(u32, Option<u32>)>,
    /// Add additional group IDs. Can be specified multiple times
    #[arg(long, short = 'g', num_args = 1)]
    pub additional_gids: Vec<u32>,
    /// Path to process.json
    #[arg(short, long)]
    pub process: Option<PathBuf>,
    /// Detach from the container process
    #[arg(short, long)]
    pub detach: bool,
    #[arg(long)]
    /// The file to which the pid of the container process should be written to
    pub pid_file: Option<PathBuf>,
    /// Set the asm process label for the process commonly used with selinux
    #[arg(long)]
    pub process_label: Option<String>,
    /// Set the apparmor profile for the process
    #[arg(long)]
    pub apparmor: Option<String>,
    /// Prevent the process from gaining additional privileges
    #[arg(long)]
    pub no_new_privs: bool,
    /// Add a capability to the bounding set for the process
    #[arg(long, num_args = 1)]
    pub cap: Vec<String>,
    /// Pass N additional file descriptors to the container
    #[arg(long, default_value = "0")]
    pub preserve_fds: i32,
    /// Allow exec in a paused container
    #[arg(long)]
    pub ignore_paused: bool,
    /// Execute a process in a sub-cgroup
    #[arg(long)]
    pub cgroup: Option<String>,

    /// Identifier of the container
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,

    /// Command that should be executed in the container
    #[arg(required = false, trailing_var_arg = true)]
    pub command: Vec<String>,
}

fn parse_env<T, U>(s: &str) -> Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid VAR=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

fn parse_user<T, U>(s: &str) -> Result<(T, Option<U>), Box<dyn Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    if let Some(pos) = s.find(':') {
        Ok((s[..pos].parse()?, Some(s[pos + 1..].parse()?)))
    } else {
        Ok((s.parse()?, None))
    }
}
