use std::path::PathBuf;
use std::{fs, io};

use anyhow::Result;
use libcgroups::common::{CgroupManager, ControllerOpt};
use libcgroups::{self};
use libcontainer::oci_spec::runtime::{
    LinuxMemory, LinuxMemoryBuilder, LinuxPidsBuilder, LinuxResources, LinuxResourcesBuilder,
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

        if let Some(memory) = build_memory(&args)? {
            builder = builder.memory(memory);
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

fn build_memory(args: &Update) -> Result<Option<LinuxMemory>> {
    let mut mem_builder = LinuxMemoryBuilder::default();
    let mut has_memory = false;
    if let Some(memory) = args.memory {
        mem_builder = mem_builder.limit(memory);
        has_memory = true;
    }
    if let Some(reservation) = args.memory_reservation {
        mem_builder = mem_builder.reservation(reservation);
        has_memory = true;
    }
    if let Some(swap) = args.memory_swap {
        mem_builder = mem_builder.swap(swap);
        has_memory = true;
    }

    if has_memory {
        Ok(Some(mem_builder.build()?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_update() -> Update {
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
    fn test_build_memory_none() {
        let args = default_update();
        let mem = build_memory(&args).unwrap();
        assert!(mem.is_none());
    }

    #[test]
    fn test_build_memory_limit() {
        let mut args = default_update();
        args.memory = Some(1024);
        let mem = build_memory(&args).unwrap().unwrap();
        assert_eq!(mem.limit(), Some(1024));
        assert_eq!(mem.reservation(), None);
        assert_eq!(mem.swap(), None);
    }

    #[test]
    fn test_build_memory_reservation() {
        let mut args = default_update();
        args.memory_reservation = Some(512);
        let mem = build_memory(&args).unwrap().unwrap();
        assert_eq!(mem.limit(), None);
        assert_eq!(mem.reservation(), Some(512));
        assert_eq!(mem.swap(), None);
    }

    #[test]
    fn test_build_memory_swap() {
        let mut args = default_update();
        args.memory_swap = Some(2048);
        let mem = build_memory(&args).unwrap().unwrap();
        assert_eq!(mem.limit(), None);
        assert_eq!(mem.reservation(), None);
        assert_eq!(mem.swap(), Some(2048));
    }

    #[test]
    fn test_build_memory_all() {
        let mut args = default_update();
        args.memory = Some(1024);
        args.memory_reservation = Some(512);
        args.memory_swap = Some(2048);
        let mem = build_memory(&args).unwrap().unwrap();
        assert_eq!(mem.limit(), Some(1024));
        assert_eq!(mem.reservation(), Some(512));
        assert_eq!(mem.swap(), Some(2048));
    }
}
