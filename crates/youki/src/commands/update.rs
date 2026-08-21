use std::path::PathBuf;
use std::{fs, io};

use anyhow::Result;
use libcgroups::common::{CgroupManager, ControllerOpt};
use libcgroups::{self};
use libcontainer::oci_spec::runtime::{
    LinuxCpu, LinuxCpuBuilder, LinuxPidsBuilder, LinuxResources, LinuxResourcesBuilder,
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
        if let Some(new_pids_limit) = args.pids_limit {
            builder = builder.pids(LinuxPidsBuilder::default().limit(new_pids_limit).build()?);
        }
        if let Some(cpu) = build_cpu(&args)? {
            builder = builder.cpu(cpu);
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

fn build_cpu(args: &Update) -> Result<Option<LinuxCpu>> {
    let mut builder = LinuxCpuBuilder::default();
    if let Some(v) = args.cpu_period {
        builder = builder.period(v);
    }
    if let Some(v) = args.cpu_quota {
        builder = builder.quota(v);
    }
    if let Some(v) = args.cpu_share {
        builder = builder.shares(v);
    }
    if let Some(v) = args.cpu_burst {
        builder = builder.burst(v);
    }
    if let Some(v) = args.cpu_idle {
        if v != 0 && v != 1 {
            anyhow::bail!("invalid value for --cpu-idle: {v} (expected 0 or 1)");
        }
        builder = builder.idle(v);
    }

    let cpu = builder.build()?;
    let empty = LinuxCpuBuilder::default()
        .build()
        .expect("building an empty LinuxCpu can't fail");
    Ok((cpu != empty).then_some(cpu))
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
            cpu_burst: None,
            cpu_idle: None,
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
    fn test_build_cpu_none_when_no_flags() {
        let args = base_args();
        assert!(build_cpu(&args).unwrap().is_none());
    }

    #[test]
    fn build_cpu_sets_period() {
        let args = Update {
            cpu_period: Some(900000),
            ..base_args()
        };
        let cpu = build_cpu(&args).unwrap().unwrap();
        assert_eq!(cpu.period(), Some(900000));
    }

    #[test]
    fn build_cpu_sets_quota() {
        let args = Update {
            cpu_quota: Some(500000),
            ..base_args()
        };
        let cpu = build_cpu(&args).unwrap().unwrap();
        assert_eq!(cpu.quota(), Some(500000));
    }

    #[test]
    fn build_cpu_sets_share() {
        let args = Update {
            cpu_share: Some(100),
            ..base_args()
        };
        let cpu = build_cpu(&args).unwrap().unwrap();
        assert_eq!(cpu.shares(), Some(100));
    }

    #[test]
    fn build_cpu_sets_burst() {
        let args = Update {
            cpu_burst: Some(500000),
            ..base_args()
        };
        let cpu = build_cpu(&args).unwrap().unwrap();
        assert_eq!(cpu.burst(), Some(500000));
    }

    #[test]
    fn build_cpu_sets_idle() {
        for idle in [0, 1] {
            let args = Update {
                cpu_idle: Some(idle),
                ..base_args()
            };
            let cpu = build_cpu(&args).unwrap().unwrap();
            assert_eq!(cpu.idle(), Some(idle));
        }
    }

    #[test]
    fn build_cpu_rejects_invalid_idle() {
        let args = Update {
            cpu_idle: Some(2),
            ..base_args()
        };
        assert!(build_cpu(&args).is_err());
    }
}
