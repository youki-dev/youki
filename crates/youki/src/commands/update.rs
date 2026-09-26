use std::path::PathBuf;
use std::{fs, io};

use anyhow::{Context, Result};
use libcgroups::common::{CgroupManager, ControllerOpt};
use libcgroups::{self};
use libcontainer::oci_spec::runtime::{
    LinuxBlockIoBuilder, LinuxPidsBuilder, LinuxResources, LinuxResourcesBuilder,
};
use liboci_cli::Update;

use crate::commands::create_cgroup_manager;

pub fn update(args: Update, root_path: PathBuf) -> Result<()> {
    let cmanager = create_cgroup_manager(root_path, &args.container_id)?;

    let linux_res: LinuxResources;
    if let Some(resources_path) = args.resources {
        linux_res = if resources_path.to_string_lossy() == "-" {
            serde_json::from_reader(io::stdin())?
        } else {
            let file = fs::File::open(resources_path)?;
            let reader = io::BufReader::new(file);
            serde_json::from_reader(reader)?
        };
    } else {
        let mut builder = LinuxResourcesBuilder::default();
        if let Some(blkio_weight) = args.blkio_weight
            && blkio_weight != 0
        {
            let weight = u16::try_from(blkio_weight)
                .with_context(|| format!("invalid value {blkio_weight} for --blkio-weight"))?;
            let blkio = LinuxBlockIoBuilder::default().weight(weight).build()?;
            builder = builder.block_io(blkio);
        }
        if let Some(new_pids_limit) = args.pids_limit {
            builder = builder.pids(LinuxPidsBuilder::default().limit(new_pids_limit).build()?);
        }
        linux_res = builder.build()?;
    }

    cmanager.apply(&ControllerOpt {
        resources: &linux_res,
        disable_oom_killer: false,
        oom_score_adj: None,
        freezer_state: None,
    })?;
    Ok(())
}
