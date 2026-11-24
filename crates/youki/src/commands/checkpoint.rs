//! Contains functionality of pause container command
use std::path::PathBuf;

use anyhow::{Context, Result};
use libcontainer::container::PageServer;
use liboci_cli::Checkpoint;

use crate::commands::load_container;

const NETWORK_NS: &str = "network";

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
        tcp_skip_in_flight: args.tcp_skip_in_flight,
        work_path: args.work_path,
        manage_cgroups_mode: parse_cgroups_mode(&args.manage_cgroups_mode)?,
        link_remap: args.link_remap,
        empty_net_ns: parse_empty_ns(&args.empty_ns)?,
        page_server: parse_page_server(args.page_server.as_deref())?,
    };
    container
        .checkpoint(&opts)
        .with_context(|| format!("failed to checkpoint container {}", args.container_id))
}

fn parse_empty_ns(s: &str) -> Result<bool, anyhow::Error> {
    match s {
        NETWORK_NS => Ok(true),
        _ => Err(anyhow::anyhow!("namespace {s:?} is not supported")),
    }
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

fn parse_page_server(s: Option<&str>) -> Result<Option<PageServer>, anyhow::Error> {
    let Some(s) = s.filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let (address, port) = split_host_port(s).ok_or_else(|| {
        anyhow::anyhow!("use --page-server ADDRESS:PORT to specify page server, got {s:?}")
    })?;
    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid port {port:?} of page server"))?;
    // runc does not pass the page server to CRIU when the port is 0, and the pages
    // are written to the image path instead.
    // https://github.com/opencontainers/runc/blob/2a603d366e0a59ef456366a7a221aaed4c6bb103/libcontainer/criu_linux.go#L394
    if port == 0 {
        return Ok(None);
    }
    Ok(Some(PageServer {
        address: address.to_string(),
        port,
    }))
}

// Follows net.SplitHostPort of Go, which runc uses to split --page-server.
// https://pkg.go.dev/net#SplitHostPort
fn split_host_port(s: &str) -> Option<(&str, &str)> {
    let (host, port) = match s.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']')?;
            let port = after.strip_prefix(':')?;
            if host.contains('[') || port.contains([':', '[', ']']) {
                return None;
            }
            (host, port)
        }
        None => {
            let (host, port) = s.rsplit_once(':')?;
            if host.contains([':', '[', ']']) || port.contains(['[', ']']) {
                return None;
            }
            (host, port)
        }
    };
    if host.is_empty() || port.is_empty() {
        return None;
    }
    Some((host, port))
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

    #[test]
    fn test_parse_empty_ns_ok() {
        assert!(matches!(parse_empty_ns("network"), Ok(true)));
    }

    #[test]
    fn test_parse_empty_ns_ng() {
        for ns in [
            "pid", "mount", "ipc", "user", "uts", "cgroup", "Network", "",
        ] {
            let err = parse_empty_ns(ns).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("namespace {ns:?} is not supported")
            );
        }
    }

    #[test]
    fn test_parse_page_server_ok() {
        for (input, address, port) in [
            ("127.0.0.1:27", "127.0.0.1", 27),
            ("[::1]:1234", "::1", 1234),
            ("[fe80::1]:1", "fe80::1", 1),
            ("[fe80::1%eth0]:27", "fe80::1%eth0", 27),
            ("[localhost]:1234", "localhost", 1234),
            ("localhost:80", "localhost", 80),
            (
                "page-server.example.com:65535",
                "page-server.example.com",
                65535,
            ),
        ] {
            let ps = parse_page_server(Some(input)).unwrap().unwrap();
            assert_eq!(ps.address, address, "input: {input}");
            assert_eq!(ps.port, port, "input: {input}");
        }
    }

    #[test]
    fn test_parse_page_server_ng() {
        for input in [
            "127.0.0.1",
            "localhost",
            ":1234",
            "127.0.0.1:",
            "::1:1234",
            "[::1]",
            "[]:1234",
            "[::1:1234",
            "::1]:1234",
            "[::1]1234",
            "[::1]x:1234",
            "[::1]:12:34",
            "[::1]:]1234",
            "[[::1]]:1234",
            "127.0.0.1]:1234",
            "[127.0.0.1:1234",
            "local[host:1234",
            "127.0.0.1:12[34",
            "127.0.0.1:port",
            "127.0.0.1:65536",
            "127.0.0.1:-1",
        ] {
            assert!(parse_page_server(Some(input)).is_err(), "input: {input}");
        }
    }

    #[test]
    fn test_parse_page_server_unset() {
        for input in [None, Some(""), Some("127.0.0.1:0"), Some("[::1]:0")] {
            assert!(
                matches!(parse_page_server(input), Ok(None)),
                "input: {input:?}"
            );
        }
    }
}
