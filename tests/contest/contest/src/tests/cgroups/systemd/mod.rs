//! Tests for the systemd cgroup manager.
//!
//! The runtime is invoked with `--systemd-cgroup` and a systemd-style cgroupsPath so that
//! the systemd manager is selected over the cgroupfs one, and what it asked systemd for is
//! read back off the transient unit.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::utils::is_cgroup_v2;

pub mod devices;
pub mod unified;

const SCOPE_PREFIX: &str = "contest";

/// `<prefix>-<name>.scope` unit name, see get_unit_name() in the systemd manager.
fn unit_name(cgroup_name: &str) -> String {
    format!("{SCOPE_PREFIX}-{cgroup_name}.scope")
}

fn show_property(unit: &str, property: &str) -> Result<String> {
    let output = Command::new("systemctl")
        .args(["show", unit, "-p", property, "--value"])
        .output()
        .with_context(|| format!("failed to run systemctl show for {unit}"))?;

    if !output.status.success() {
        bail!(
            "systemctl show {unit} -p {property} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(String::from_utf8(output.stdout)
        .context("systemctl output was not utf-8")?
        .trim()
        .to_string())
}

/// The major version of the running systemd, from the first line of `systemctl --version`,
/// which reads `systemd 255 (255.4-1ubuntu8)`.
fn systemd_version() -> Result<u32> {
    let output = Command::new("systemctl")
        .arg("--version")
        .output()
        .context("failed to run systemctl --version")?;
    let stdout = String::from_utf8(output.stdout).context("systemctl output was not utf-8")?;

    stdout
        .split_whitespace()
        .nth(1)
        .and_then(|version| version.parse().ok())
        .with_context(|| format!("failed to read the systemd version from {stdout:?}"))
}

/// The systemd cgroup manager needs a unified cgroup hierarchy, a running systemd to talk
/// to, and root to place units in system.slice.
///
/// Not restricted to one runtime: the properties read back are systemd's own and the entry
/// formats follow runc, so the expectations hold for either runtime.
fn can_run() -> bool {
    nix::unistd::geteuid().is_root() && is_cgroup_v2() && Path::new("/run/systemd/system").is_dir()
}
