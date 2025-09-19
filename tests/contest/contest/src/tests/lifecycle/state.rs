use std::path::Path;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use crate::utils::get_state;

pub fn state(project_path: &Path, id: &str) -> Result<()> {
    match get_state(id, project_path) {
        Ok((stdout, stderr)) => {
            if stderr.contains("Error") || stderr.contains("error") {
                bail!("Error :\nstdout : {}\nstderr : {}", stdout, stderr)
            } else {
                // confirm that the status is stopped, as this is executed after the kill command
                if !(stdout.contains(&format!(r#""id": "{id}""#))
                    && stdout.contains(r#""status": "stopped""#))
                {
                    bail!("Expected state stopped, got : {}", stdout)
                } else {
                    Ok(())
                }
            }
        }
        Err(e) => Err(e.context("failed to get container state")),
    }
}

/// Get the container status as a string
pub fn get_container_status(project_path: &Path, id: &str) -> Result<String> {
    match get_state(id, project_path) {
        Ok((stdout, stderr)) => {
            if stderr.contains("Error") || stderr.contains("error") {
                bail!("Error :\nstdout : {}\nstderr : {}", stdout, stderr)
            } else {
                // Parse JSON to extract status
                match serde_json::from_str::<Value>(&stdout) {
                    Ok(value) => {
                        if let Some(status) = value.get("status")
                            && let Some(status_str) = status.as_str()
                        {
                            return Ok(status_str.to_string());
                        }
                        bail!("Failed to extract status from state output: {}", stdout)
                    }
                    Err(err) => bail!("Failed to parse state output as JSON: {} - {}", stdout, err),
                }
            }
        }
        Err(e) => Err(e.context("failed to get container state")),
    }
}

/// Check if a container is in a specific state
pub fn is_in_state(project_path: &Path, id: &str, expected_state: &str) -> Result<bool> {
    match get_container_status(project_path, id) {
        Ok(status) => Ok(status == expected_state),
        Err(e) => {
            // If the container doesn't exist, it's not in the expected state
            if e.to_string().contains("does not exist") {
                return Ok(false);
            }
            Err(e.context(format!(
                "failed to check if container is in {} state",
                expected_state
            )))
        }
    }
}

/// Wait for a container to reach a specific state with timeout
pub fn wait_for_state(
    project_path: &Path,
    id: &str,
    expected_state: &str,
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
) -> Result<()> {
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        match is_in_state(project_path, id, expected_state) {
            Ok(true) => return Ok(()),
            Ok(false) => std::thread::sleep(poll_interval),
            Err(e) => {
                // If there's a transient error, continue polling
                if e.to_string().contains("does not exist") && expected_state == "stopped" {
                    // Special case: if container doesn't exist and we're waiting for stopped state,
                    // consider it stopped (deletion after stopping)
                    return Ok(());
                }
                std::thread::sleep(poll_interval);
            }
        }
    }

    Err(anyhow!(
        "Timed out waiting for container {} to reach {} state",
        id,
        expected_state
    ))
}
