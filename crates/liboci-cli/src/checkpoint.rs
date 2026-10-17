use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

/// Checkpoint a running container
// Reference: https://github.com/opencontainers/runc/blob/main/man/runc-checkpoint.8.md
// Unimplemented options vs runc: https://github.com/youki-dev/youki/issues/3394
#[derive(Parser, Debug)]
pub struct Checkpoint {
    /// Path for saving criu image files
    #[arg(long, default_value = "checkpoint")]
    pub image_path: PathBuf,
    /// Path for saving work files and logs
    #[arg(long)]
    pub work_path: Option<PathBuf>,
    // TODO: Path for previous criu image file in pre-dump
    // #[arg(long)]
    // pub parent_path: Option<PathBuf>,
    /// Leave the process running after checkpointing
    #[arg(long)]
    pub leave_running: bool,
    /// Allow open tcp connections
    #[arg(long)]
    pub tcp_established: bool,
    /// Skip in-flight tcp connections
    #[arg(long)]
    pub tcp_skip_in_flight: bool,
    /// Allow one to link unlinked files back when possible
    #[arg(long)]
    pub link_remap: bool,
    /// Allow external unix sockets
    #[arg(long)]
    pub ext_unix_sk: bool,
    /// Allow shell jobs
    #[arg(long)]
    pub shell_job: bool,
    // TODO: Use lazy migration mechanism
    // #[arg(long)]
    // pub lazy_pages: bool,
    // TODO: Pass a file descriptor fd to criu. Is u32 the right type?
    // #[arg(long)]
    // pub status_fd: Option<u32>,
    /// ADDRESS:PORT of the page server
    #[arg(long)]
    pub page_server: Option<SocketAddr>,
    /// Allow file locks
    #[arg(long)]
    pub file_locks: bool,
    // TODO: Do a pre-dump
    // #[arg(long)]
    // pub pre_dump: bool,
    #[arg(long, default_value = "soft", value_parser = clap::builder::PossibleValuesParser::new(["ignore", "full", "strict", "soft"]))]
    pub manage_cgroups_mode: String,
    /// Checkpoint a namespace, but don't save its properties
    ///
    /// Only `network` is accepted, and it applies even without this flag: youki does not manage
    /// network devices, so their external dependencies cannot be described to CRIU.
    #[arg(long, default_value = "network")]
    pub empty_ns: String,
    // TODO: Enable auto-deduplication
    // #[arg(long)]
    // pub auto_dedup: bool,
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_page_server(value: &str) -> Result<Option<SocketAddr>, clap::Error> {
        Checkpoint::try_parse_from(["checkpoint", "--page-server", value, "container"])
            .map(|args| args.page_server)
    }

    #[test]
    fn test_page_server_ok() {
        for (input, expected) in [
            ("127.0.0.1:27", "127.0.0.1:27"),
            ("[::1]:1234", "[::1]:1234"),
        ] {
            assert_eq!(
                parse_page_server(input).unwrap(),
                Some(expected.parse().unwrap()),
                "input: {input}"
            );
        }
    }

    #[test]
    fn test_page_server_ng() {
        for input in [
            "",
            "localhost:80",
            "127.0.0.1",
            ":1234",
            "127.0.0.1:",
            "::1:1234",
            "127.0.0.1:port",
            "127.0.0.1:65536",
        ] {
            assert!(parse_page_server(input).is_err(), "input: {input}");
        }
    }

    #[test]
    fn test_page_server_unset() {
        let args = Checkpoint::try_parse_from(["checkpoint", "container"]).unwrap();
        assert_eq!(args.page_server, None);
    }
}
