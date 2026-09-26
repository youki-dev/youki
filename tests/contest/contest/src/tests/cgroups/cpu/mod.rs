use std::path::Path;

use anyhow::{Context, Result};
use oci_spec::runtime::{LinuxBuilder, LinuxCpu, LinuxResourcesBuilder, Spec, SpecBuilder};

pub mod v2;

fn create_spec(cgroup_name: &str, case: LinuxCpu) -> Result<Spec> {
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(Path::new("/runtime-test").join(cgroup_name))
                .resources(
                    LinuxResourcesBuilder::default()
                        .cpu(case)
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
