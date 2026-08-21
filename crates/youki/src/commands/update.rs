use std::path::PathBuf;
use std::{fs, io};

use anyhow::{Result, bail};
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
        if let Some(blkio_weight) = args.blkio_weight {
            if !(10..=1000).contains(&blkio_weight) {
                bail!(
                    "invalid value {blkio_weight} for --blkio-weight, expected value in range [10, 1000]"
                );
            }
            let blkio = LinuxBlockIoBuilder::default()
                .weight(blkio_weight as u16)
                .build()?;
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
