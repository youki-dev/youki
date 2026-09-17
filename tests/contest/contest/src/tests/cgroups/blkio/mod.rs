use std::path::Path;

use anyhow::{Context, Result};
use oci_spec::runtime::{LinuxBlockIo, LinuxBuilder, LinuxResourcesBuilder, Spec, SpecBuilder};

pub mod v2;

fn create_spec(cgroup_name: &str, block_io: LinuxBlockIo) -> Result<Spec> {
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(Path::new(cgroup_name))
                .resources(
                    LinuxResourcesBuilder::default()
                        .block_io(block_io)
                        .build()
                        .context("failed to build resource spec")?,
                )
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}
