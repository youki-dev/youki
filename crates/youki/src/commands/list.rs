//! Contains Functionality of list container command
use std::fmt::Write as _;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::{fs, io};

use anyhow::{Result, bail};
use chrono::{DateTime, Local, Utc};
use libcontainer::config::{ConfigError, YoukiConfig};
use libcontainer::container::Container;
use libcontainer::container::state::{ContainerStatus, State};
use libcontainer::syscall::syscall::create_syscall;
use liboci_cli::List;
use serde::Serialize;
use tabwriter::TabWriter;

/// lists all existing containers
pub fn list(args: List, root_path: PathBuf) -> Result<()> {
    if !args.quiet && !matches!(args.format.as_str(), "table" | "json") {
        bail!("invalid format option: {}", args.format);
    }
    let root_path = fs::canonicalize(root_path)?;
    let mut content = String::new();
    let mut entries = Vec::new();
    let mut container_dirs = fs::read_dir(root_path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?;
    container_dirs.sort_unstable();
    let mut containers = Vec::new();
    for container_dir in container_dirs {
        let state_file = State::file_path(&container_dir);
        if !state_file.exists() {
            continue;
        }

        containers.push(Container::load(container_dir)?);
    }
    for container in &containers {
        if args.quiet {
            writeln!(content, "{}", container.id())?;
            continue;
        }
        if args.format == "json" {
            entries.push(ListEntry::load(container)?);
            continue;
        }
        let pid = if let Some(pid) = container.pid() {
            pid.to_string()
        } else {
            "".to_owned()
        };

        let user_name = container.creator().unwrap_or_default();

        let created = if let Some(utc) = container.created() {
            let local: DateTime<Local> = DateTime::from(utc);
            local.to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
        } else {
            "".to_owned()
        };

        let _ = writeln!(
            content,
            "{}\t{}\t{}\t{}\t{}\t{}",
            container.id(),
            pid,
            container.status().to_string().to_ascii_lowercase(),
            container.bundle().display(),
            created,
            user_name.to_string_lossy()
        );
    }

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    if args.quiet {
        stdout.write_all(content.as_bytes())?;
        return Ok(());
    }
    if args.format == "json" {
        serde_json::to_writer(&mut stdout, &entries)?;
        writeln!(stdout)?;
        return Ok(());
    }
    let mut tab_writer = TabWriter::new(stdout);
    writeln!(&mut tab_writer, "ID\tPID\tSTATUS\tBUNDLE\tCREATED\tCREATOR")?;
    write!(&mut tab_writer, "{content}")?;
    tab_writer.flush()?;

    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListEntry<'a> {
    oci_version: &'a str,
    id: &'a str,
    pid: i32,
    status: ContainerStatus,
    bundle: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    rootfs: Option<PathBuf>,
    created: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<&'a std::collections::HashMap<String, String>>,
    owner: String,
}

impl<'a> ListEntry<'a> {
    fn load(container: &'a Container) -> Result<Self> {
        let rootfs = match YoukiConfig::load(&container.root) {
            Ok(config) => config.rootfs,
            Err(ConfigError::LoadIO { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                None
            }
            Err(err) => return Err(err.into()),
        };
        let uid = container.root.metadata()?.uid();
        Ok(Self {
            oci_version: &container.state.oci_version,
            id: container.id(),
            pid: if container.status() == ContainerStatus::Stopped {
                0
            } else {
                container.pid().map(|pid| pid.as_raw()).unwrap_or_default()
            },
            status: container.status(),
            bundle: container.bundle(),
            rootfs,
            created: container.created(),
            annotations: container
                .state
                .annotations
                .as_ref()
                .filter(|a| !a.is_empty()),
            owner: create_syscall()
                .get_pwuid(uid)
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("#{uid}")),
        })
    }
}
