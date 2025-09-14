//! Contains functionality of kill container command
use std::convert::TryInto;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use libcontainer::container::ContainerStatus;
use libcontainer::signal::Signal;
use liboci_cli::Kill;

use crate::commands::load_container;

pub fn kill(args: Kill, root_path: PathBuf) -> Result<()> {
    let mut container = load_container(root_path, &args.container_id)?;
    let signal: Signal = args.signal.as_str().try_into()?;
    match container.kill(signal, args.all) {
        Ok(_) => Ok(()),
        Err(e) => {
            // see https://github.com/containers/youki/issues/1314
            if container.status() == ContainerStatus::Stopped {
                return Err(anyhow!(e).context("container not running"));
            }
            Err(anyhow!(e).context("failed to kill container"))
        }
    }
}
