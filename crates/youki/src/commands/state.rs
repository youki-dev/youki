use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{DateTime, Utc};
use libcontainer::container::state::{ContainerStatus, State as ContainerState};
use liboci_cli::State;
use serde::Serialize;

use crate::commands::load_container;

pub fn state(args: State, root_path: PathBuf) -> Result<()> {
    let container = load_container(root_path, &args.container_id)?;
    let export = StateExporter::from(&container.state);
    println!("{}", serde_json::to_string_pretty(&export)?);
    std::process::exit(0);
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StateExporter<'a> {
    pub oci_version: &'a str,
    pub id: &'a str,
    pub status: ContainerStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    pub bundle: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<&'a HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<&'a DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<u32>,
}

impl<'a> From<&'a ContainerState> for StateExporter<'a> {
    fn from(state: &'a ContainerState) -> Self {
        Self {
            oci_version: &state.oci_version,
            id: &state.id,
            status: state.status,
            pid: state.pid,
            bundle: &state.bundle,
            annotations: state.annotations.as_ref(),
            created: state.created.as_ref(),
            owner: state.creator,
        }
    }
}
