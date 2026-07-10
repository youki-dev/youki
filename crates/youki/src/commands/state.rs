use std::path::PathBuf;

use anyhow::Result;
use libcontainer::container::state::StateExporter;
use liboci_cli::State;

use crate::commands::load_container;

pub fn state(args: State, root_path: PathBuf) -> Result<()> {
    let container = load_container(root_path, &args.container_id)?;
    let export = StateExporter::from(&container.state);
    println!("{}", serde_json::to_string_pretty(&export)?);
    std::process::exit(0);
}
