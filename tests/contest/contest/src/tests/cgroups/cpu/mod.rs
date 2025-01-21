use std::path::Path;

use anyhow::{Context, Result};
use oci_spec::runtime::{
    LinuxBuilder, LinuxCpu, LinuxCpuBuilder, LinuxResourcesBuilder, Spec, SpecBuilder,
};

pub mod v1;
pub mod v2;

#[allow(clippy::too_many_arguments)]
fn create_cpu_spec(
    shares: u64,
    quota: i64,
    period: u64,
    idle_opt: Option<i64>,
    cpus: &str,
    mems: &str,
    realtime_period_opt: Option<u64>,
    realtime_runtime_opt: Option<i64>,
) -> Result<LinuxCpu> {
    let mut builder = LinuxCpuBuilder::default()
        .shares(shares)
        .quota(quota)
        .period(period)
        .cpus(cpus)
        .mems(mems);

    if let Some(idle) = idle_opt {
        builder = builder.idle(idle);
    }

    if let Some(realtime_period) = realtime_period_opt {
        builder = builder.realtime_period(realtime_period);
    }

    if let Some(realtime_runtime) = realtime_runtime_opt {
        builder = builder.realtime_runtime(realtime_runtime);
    }

    builder.build().context("failed to build cpu spec")
}

fn create_spec_with_cgroup_path(cgroup_path: &str, case: LinuxCpu) -> Result<Spec> {
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(Path::new(cgroup_path))
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

fn create_spec(cgroup_name: &str, case: LinuxCpu) -> Result<Spec> {
    create_spec_with_cgroup_path(&format!("/runtime-test/{}", cgroup_name), case)
}

fn create_empty_spec(cgroup_name: &str) -> Result<Spec> {
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(Path::new("/runtime-test").join(cgroup_name))
                .resources(
                    LinuxResourcesBuilder::default()
                        .cpu(
                            LinuxCpuBuilder::default()
                                .build()
                                .context("failed to build cpus spec")?,
                        )
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
