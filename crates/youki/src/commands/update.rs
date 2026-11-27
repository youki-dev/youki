use std::path::PathBuf;
use std::{fs, io};

use anyhow::{Context, Result};
use libcgroups::common::{CgroupManager, ControllerOpt};
use libcgroups::{self};
use libcontainer::oci_spec::runtime::{
    LinuxBlockIoBuilder, LinuxCpu, LinuxCpuBuilder, LinuxPidsBuilder, LinuxResources,
    LinuxResourcesBuilder,
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
        if let Some(cpuset) = build_cpuset(&args)? {
            builder = builder.cpu(cpuset);
        }
        linux_res = builder.build()?;
    }

    // runc skips the device rules on update (SkipDevices): an update must not replace
    // them, since something else may have added rules after the container started,
    // like a GPU plugin. Updating them is a separate future feature.
    cmanager.apply(&ControllerOpt {
        resources: &linux_res,
        disable_oom_killer: false,
        oom_score_adj: None,
        freezer_state: None,
        skip_devices: true,
    })?;
    Ok(())
}

// An empty value means the flag was not given, as in runc.
fn build_cpuset(args: &Update) -> Result<Option<LinuxCpu>> {
    let cpus = args.cpuset_cpus.as_deref().filter(|v| !v.is_empty());
    let mems = args.cpuset_mems.as_deref().filter(|v| !v.is_empty());
    if cpus.is_none() && mems.is_none() {
        return Ok(None);
    }

    let mut builder = LinuxCpuBuilder::default();
    if let Some(cpus) = cpus {
        builder = builder.cpus(cpus);
    }
    if let Some(mems) = mems {
        builder = builder.mems(mems);
    }
    Ok(Some(builder.build()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Update {
        Update {
            resources: None,
            blkio_weight: None,
            cpu_period: None,
            cpu_quota: None,
            cpu_rt_period: None,
            cpu_rt_runtime: None,
            cpu_share: None,
            cpuset_cpus: None,
            cpuset_mems: None,
            memory: None,
            memory_reservation: None,
            memory_swap: None,
            pids_limit: None,
            l3_cache_schema: None,
            mem_bw_schema: None,
            container_id: "test".to_string(),
        }
    }

    #[test]
    fn build_cpuset_none_when_no_flags() {
        assert!(build_cpuset(&base_args()).unwrap().is_none());
    }

    #[test]
    fn build_cpuset_none_when_flags_are_empty() {
        let args = Update {
            cpuset_cpus: Some(String::new()),
            cpuset_mems: Some(String::new()),
            ..base_args()
        };
        assert!(build_cpuset(&args).unwrap().is_none());
    }

    #[test]
    fn build_cpuset_sets_only_cpus() {
        let args = Update {
            cpuset_cpus: Some("0-1".to_string()),
            ..base_args()
        };
        let cpu = build_cpuset(&args).unwrap().unwrap();
        assert_eq!(cpu.cpus().as_deref(), Some("0-1"));
        assert_eq!(cpu.mems(), &None);
    }

    #[test]
    fn build_cpuset_sets_only_mems() {
        let args = Update {
            cpuset_mems: Some("0".to_string()),
            ..base_args()
        };
        let cpu = build_cpuset(&args).unwrap().unwrap();
        assert_eq!(cpu.cpus(), &None);
        assert_eq!(cpu.mems().as_deref(), Some("0"));
    }

    #[test]
    fn build_cpuset_sets_both() {
        let args = Update {
            cpuset_cpus: Some("0,2-3".to_string()),
            cpuset_mems: Some("0".to_string()),
            ..base_args()
        };
        let cpu = build_cpuset(&args).unwrap().unwrap();
        assert_eq!(cpu.cpus().as_deref(), Some("0,2-3"));
        assert_eq!(cpu.mems().as_deref(), Some("0"));
    }
}
