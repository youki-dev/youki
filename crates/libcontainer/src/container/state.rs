//! Information about status and state of the container
use std::collections::HashMap;
use std::fmt::Display;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use oci_spec::OciSpecError;
use oci_spec::runtime::{
    ContainerState as OciContainerState, State as OciState, StateBuilder as OciStateBuilder,
    VERSION as OCI_RUNTIME_VERSION,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// Indicates status of the container
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum ContainerStatus {
    // The container is being created
    #[default]
    Creating,
    // The runtime has finished the create operation
    Created,
    // The container process has executed the user-specified program but has not exited
    Running,
    // The container process has exited
    Stopped,
    // The container process has paused
    Paused,
}

impl ContainerStatus {
    pub fn can_start(&self) -> bool {
        matches!(self, ContainerStatus::Created)
    }

    pub fn can_kill(&self) -> bool {
        use ContainerStatus::*;
        match self {
            Creating | Stopped => false,
            Created | Running | Paused => true,
        }
    }

    pub fn can_delete(&self) -> bool {
        matches!(self, ContainerStatus::Stopped)
    }

    pub fn can_pause(&self) -> bool {
        matches!(self, ContainerStatus::Running)
    }

    pub fn can_resume(&self) -> bool {
        matches!(self, ContainerStatus::Paused)
    }
}

impl Display for ContainerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let print = match *self {
            Self::Creating => "Creating",
            Self::Created => "Created",
            Self::Running => "Running",
            Self::Stopped => "Stopped",
            Self::Paused => "Paused",
        };

        write!(f, "{print}")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("failed to open container state file {state_file_path:?}")]
    OpenStateFile {
        state_file_path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse container state file {state_file_path:?}")]
    ParseStateFile {
        state_file_path: PathBuf,
        source: serde_json::Error,
    },
    #[error("failed to write container state file {state_file_path:?}")]
    WriteStateFile {
        state_file_path: PathBuf,
        source: std::io::Error,
    },
}

type Result<T> = std::result::Result<T, StateError>;

/// Stores the state information of the container
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct State {
    // Version is the version of the specification that is supported.
    pub oci_version: String,
    // ID is the container ID
    pub id: String,
    // Status is the runtime status of the container.
    pub status: ContainerStatus,
    // Pid is the process ID for the container process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    // Bundle is the path to the container's bundle directory.
    pub bundle: PathBuf,
    // Annotations are key values associated with the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
    // Creation time of the container
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
    // User that created the container
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<u32>,
    // Specifies if systemd should be used to manage cgroups
    pub use_systemd: bool,
    // Specifies if the Intel RDT subdirectory needs be cleaned up.
    pub clean_up_intel_rdt_subdirectory: Option<bool>,
}

impl State {
    const STATE_FILE_PATH: &'static str = "state.json";

    pub fn new(
        container_id: &str,
        status: ContainerStatus,
        pid: Option<i32>,
        bundle: PathBuf,
    ) -> Self {
        Self {
            oci_version: OCI_RUNTIME_VERSION.to_string(),
            id: container_id.to_string(),
            status,
            pid,
            bundle,
            annotations: Some(HashMap::default()),
            created: None,
            creator: None,
            use_systemd: false,
            clean_up_intel_rdt_subdirectory: None,
        }
    }

    #[instrument(level = "trace")]
    pub fn save(&self, container_root: &Path) -> Result<()> {
        let state_file_path = Self::file_path(container_root);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .append(false)
            .create(true)
            .truncate(true)
            .open(&state_file_path)
            .map_err(|err| {
                tracing::error!(
                    state_file_path = ?state_file_path,
                    err = %err,
                    "failed to open container state file",
                );
                StateError::OpenStateFile {
                    state_file_path: state_file_path.to_owned(),
                    source: err,
                }
            })?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, self).map_err(|err| {
            tracing::error!(
                ?state_file_path,
                %err,
                "failed to parse container state file",
            );
            StateError::ParseStateFile {
                state_file_path: state_file_path.to_owned(),
                source: err,
            }
        })?;
        writer.flush().map_err(|err| {
            tracing::error!(
                ?state_file_path,
                %err,
                "failed to write container state file",
            );
            StateError::WriteStateFile {
                state_file_path: state_file_path.to_owned(),
                source: err,
            }
        })?;

        Ok(())
    }

    pub fn load(container_root: &Path) -> Result<Self> {
        let state_file_path = Self::file_path(container_root);
        let state_file = File::open(&state_file_path).map_err(|err| {
            tracing::error!(
                ?state_file_path,
                %err,
                "failed to open container state file",
            );
            StateError::OpenStateFile {
                state_file_path: state_file_path.to_owned(),
                source: err,
            }
        })?;

        let state: Self = serde_json::from_reader(BufReader::new(state_file)).map_err(|err| {
            tracing::error!(
                ?state_file_path,
                %err,
                "failed to parse container state file",
            );
            StateError::ParseStateFile {
                state_file_path: state_file_path.to_owned(),
                source: err,
            }
        })?;

        Ok(state)
    }

    /// Returns the path to the state JSON file for the provided `container_root`.
    ///
    /// ```
    /// # use std::path::Path;
    /// # use libcontainer::container::State;
    ///
    /// let container_root = Path::new("/var/run/containers/container");
    /// let state_file = State::file_path(&container_root);
    /// assert_eq!(state_file.to_str(), Some("/var/run/containers/container/state.json"));
    /// ```
    pub fn file_path(container_root: &Path) -> PathBuf {
        container_root.join(Self::STATE_FILE_PATH)
    }
}

/// Error type for state conversion failures.
#[derive(Debug, thiserror::Error)]
pub enum StateConversionError {
    #[error("failed to build OCI state: {0}")]
    OciStateBuild(#[from] OciSpecError),
    #[error("invalid container status for OCI conversion: {0}")]
    InvalidStatus(ContainerStatus),
}

/// Convert internal State to OCI-compliant State (by value, no cloning).
///
/// Based on runc's implementation:
/// <https://github.com/opencontainers/runc/blob/v2.2.1/libcontainer/container_linux.go#L961>
impl TryFrom<State> for OciState {
    type Error = StateConversionError;

    fn try_from(state: State) -> std::result::Result<Self, Self::Error> {
        let status = OciContainerState::try_from(state.status)?;

        let mut builder = OciStateBuilder::default()
            .version(state.oci_version)
            .id(state.id)
            .status(status)
            .bundle(state.bundle);

        // Preserve None vs empty map distinction per OCI spec
        if let Some(annotations) = state.annotations {
            builder = builder.annotations(annotations);
        }
        if let Some(pid) = state.pid {
            builder = builder.pid(pid);
        }

        Ok(builder.build()?)
    }
}

impl TryFrom<ContainerStatus> for OciContainerState {
    type Error = StateConversionError;

    fn try_from(status: ContainerStatus) -> std::result::Result<Self, Self::Error> {
        match status {
            ContainerStatus::Creating => Ok(OciContainerState::Creating),
            ContainerStatus::Created => Ok(OciContainerState::Created),
            ContainerStatus::Running => Ok(OciContainerState::Running),
            ContainerStatus::Stopped => Ok(OciContainerState::Stopped),
            // Paused is not defined in the OCI spec.
            ContainerStatus::Paused => Err(StateConversionError::InvalidStatus(status)),
        }
    }
}

/// Deprecated: Use [`oci_spec::runtime::ContainerProcessState`] instead.
#[deprecated(
    since = "0.6.0",
    note = "Use oci_spec::runtime::ContainerProcessState instead"
)]
#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ContainerProcessState {
    // Version is the version of the specification that is supported.
    pub oci_version: String,
    // Fds is a string array containing the names of the file descriptors passed.
    // The index of the name in this array corresponds to index of the file
    // descriptor in the `SCM_RIGHTS` array.
    pub fds: Vec<String>,
    // Pid is the process ID as seen by the runtime.
    pub pid: i32,
    // Opaque metadata.
    pub metadata: String,
    // State of the container.
    pub state: State,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creating_status() {
        let cstatus = ContainerStatus::default();
        assert!(!cstatus.can_start());
        assert!(!cstatus.can_delete());
        assert!(!cstatus.can_kill());
        assert!(!cstatus.can_pause());
        assert!(!cstatus.can_resume());
    }

    #[test]
    fn test_create_status() {
        let cstatus = ContainerStatus::Created;
        assert!(cstatus.can_start());
        assert!(!cstatus.can_delete());
        assert!(cstatus.can_kill());
        assert!(!cstatus.can_pause());
        assert!(!cstatus.can_resume());
    }

    #[test]
    fn test_running_status() {
        let cstatus = ContainerStatus::Running;
        assert!(!cstatus.can_start());
        assert!(!cstatus.can_delete());
        assert!(cstatus.can_kill());
        assert!(cstatus.can_pause());
        assert!(!cstatus.can_resume());
    }

    #[test]
    fn test_stopped_status() {
        let cstatus = ContainerStatus::Stopped;
        assert!(!cstatus.can_start());
        assert!(cstatus.can_delete());
        assert!(!cstatus.can_kill());
        assert!(!cstatus.can_pause());
        assert!(!cstatus.can_resume());
    }

    #[test]
    fn test_paused_status() {
        let cstatus = ContainerStatus::Paused;
        assert!(!cstatus.can_start());
        assert!(!cstatus.can_delete());
        assert!(cstatus.can_kill());
        assert!(!cstatus.can_pause());
        assert!(cstatus.can_resume());
    }
}
