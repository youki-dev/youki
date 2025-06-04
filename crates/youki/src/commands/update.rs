use libcontainer::container::Container;
use libcontainer::oci_spec::runtime::LinuxMemory;
use libcontainer::process::intel_rdt::setup_intel_rdt;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

use crate::commands::create_cgroup_manager;
use anyhow::bail;
use anyhow::Result;
use libcgroups::common::CgroupManager;
use libcgroups::{self, common::ControllerOpt};
use libcontainer::oci_spec::runtime::Spec;
use liboci_cli::Update;

macro_rules! set_resource {
    ($arg:ident,$arg_name:ident,$new_cfg:ident,$existing_cfg:ident,$( $field_path:ident ).+) => {
        if let Some(val) = $arg.$arg_name {
            $new_cfg.resources.$( $field_path).+ = val;
        }else{
            $new_cfg.resources.$( $field_path).+ = $existing_cfg.resources.$( $field_path).+;
        }
    };
}

#[derive(Default, Serialize, Deserialize)]
struct Memory {
    limit: i64,
    swap: i64,
    reservation: i64,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cpu {
    shares: u64,
    quota: i64,
    burst: u64,
    period: u64,
    realtime_runtime: i64,
    realtime_period: u64,
    cpus: String,
    mems: String,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlockIo {
    blkio_weight: u16,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Resources {
    memory: Memory,
    cpu: Cpu,
    block_io: BlockIo,
}

#[derive(Default)]
struct UpdateConfig {
    resources: Resources,
    pids_limit: Option<i64>,
    l3_cache_schema: Option<String>,
    mem_bw_schema: Option<String>,
}

macro_rules! _extract_field {
    ($cfg:ident, $type:ident, $field:ident) => {
        $cfg.resources.$type.$field = $type.$field().clone().unwrap_or_default();
    };
}

fn get_existing_config(spec: &Spec) -> UpdateConfig {
    let mut cfg = UpdateConfig::default();
    let resources = spec.linux().as_ref().unwrap().resources().as_ref().unwrap();

    let memory = resources.memory().as_ref().cloned().unwrap_or_default();
    let cpu = resources.cpu().as_ref().cloned().unwrap_or_default();
    let block_io = resources.block_io().as_ref().cloned().unwrap_or_default();

    _extract_field!(cfg, memory, limit);
    _extract_field!(cfg, memory, swap);
    _extract_field!(cfg, memory, reservation);

    _extract_field!(cfg, cpu, period);
    _extract_field!(cfg, cpu, quota);
    _extract_field!(cfg, cpu, burst);
    _extract_field!(cfg, cpu, realtime_period);
    _extract_field!(cfg, cpu, realtime_runtime);
    _extract_field!(cfg, cpu, shares);
    _extract_field!(cfg, cpu, cpus);
    _extract_field!(cfg, cpu, mems);

    cfg.resources.block_io.blkio_weight = block_io.weight().unwrap_or_default();

    if let Some(pids) = spec
        .linux()
        .as_ref()
        .unwrap()
        .resources()
        .as_ref()
        .unwrap()
        .pids()
    {
        cfg.pids_limit = Some(pids.limit());
    }
    if let Some(rtd) = spec.linux().as_ref().unwrap().intel_rdt() {
        if let Some(schema) = rtd.mem_bw_schema() {
            cfg.mem_bw_schema = Some(schema.clone());
        }
        if let Some(schema) = rtd.l3_cache_schema() {
            cfg.l3_cache_schema = Some(schema.clone());
        }
    }
    cfg
}

pub fn update(args: Update, root_path: PathBuf) -> Result<()> {
    let container = Container::load(root_path.join(&args.container_id))?;
    let spec = Spec::load(container.bundle().join("config.json"))?;
    let existing_config = get_existing_config(&spec);
    let mut existing_resources = spec
        .linux()
        .as_ref()
        .unwrap()
        .resources()
        .as_ref()
        .unwrap()
        .clone();

    let cmanager = create_cgroup_manager(root_path.clone(), &args.container_id)?;

    let update_config: UpdateConfig;
    if let Some(resources_path) = args.resources {
        let linux_res: Resources = if resources_path.to_string_lossy() == "-" {
            serde_json::from_reader(io::stdin())?
        } else {
            let file = fs::File::open(resources_path)?;
            let reader = io::BufReader::new(file);
            serde_json::from_reader(reader)?
        };
        // as per https://github.com/opencontainers/runc/blob/03db4d633d52a4382e8931a37c08564730ab7f9a/man/runc-update.8.mod
        // "when -r is used, all other options are ignored". So we only take resources, and ignore
        // the rest
        update_config = UpdateConfig {
            resources: linux_res,
            pids_limit: None,
            l3_cache_schema: None,
            mem_bw_schema: None,
        };
    } else {
        let mut input_config = UpdateConfig::default();
        // runc allows setting one or other, due to backward comppatibility issues,
        // but we can, so we do the sensible option. see
        // https://github.com/opencontainers/runc/blob/6a2813f16ad4e3be44903f6fb499c02837530ad5/update.go#L277-L287
        match (args.cpu_quota, args.cpu_period) {
            (Some(_), None) | (None, Some(_)) => {
                bail!("cpu quota and cpu period both must be specified");
            }
            _ => {}
        }

        // TODO move this validation to after config merge with existing
        if args.cpu_quota.is_some() && args.cpu_quota.unwrap() < 0 {
            bail!("cpu quota cannot be less than 0");
        }

        if let Some(new_pids_limit) = args.pids_limit {
            input_config.pids_limit = Some(new_pids_limit);
        } else {
            input_config.pids_limit = existing_config.pids_limit;
        }

        input_config.l3_cache_schema = args.l3_cache_schema;
        input_config.mem_bw_schema = args.mem_bw_schema;

        set_resource!(
            args,
            blkio_weight,
            input_config,
            existing_config,
            block_io.blkio_weight
        );

        set_resource!(args, cpu_period, input_config, existing_config, cpu.period);
        set_resource!(args, cpu_quota, input_config, existing_config, cpu.quota);
        set_resource!(args, cpu_burst, input_config, existing_config, cpu.burst);
        set_resource!(
            args,
            cpu_rt_period,
            input_config,
            existing_config,
            cpu.realtime_period
        );
        set_resource!(
            args,
            cpu_rt_runtime,
            input_config,
            existing_config,
            cpu.realtime_runtime
        );
        set_resource!(args, cpu_share, input_config, existing_config, cpu.shares);
        set_resource!(args, cpuset_cpus, input_config, existing_config, cpu.cpus);
        set_resource!(args, cpuset_mems, input_config, existing_config, cpu.mems);

        set_resource!(args, memory, input_config, existing_config, memory.limit);
        set_resource!(
            args,
            memory_reservation,
            input_config,
            existing_config,
            memory.reservation
        );
        set_resource!(
            args,
            memory_swap,
            input_config,
            existing_config,
            memory.swap
        );

        if (input_config.resources.cpu.quota as u64) < input_config.resources.cpu.burst {
            bail!(
                "cpu quota ({}) cannot be less than cpu burst ({})",
                input_config.resources.cpu.quota,
                input_config.resources.cpu.burst
            );
        }
        update_config = input_config;
    }

    // TODO decide how to apply intel
    // add ANOTHER macro to set the values here
    let mut cpu = existing_resources
        .cpu()
        .as_ref()
        .cloned()
        .unwrap_or_default();
    cpu.set_period(Some(update_config.resources.cpu.period));
    cpu.set_quota(Some(update_config.resources.cpu.quota));
    cpu.set_burst(Some(update_config.resources.cpu.burst));
    cpu.set_shares(Some(update_config.resources.cpu.shares));
    // cpu.set_realtime_period(Some(update_config.resources.cpu.realtime_period));
    // cpu.set_realtime_runtime(Some(update_config.resources.cpu.realtime_runtime));
    cpu.set_cpus(Some(update_config.resources.cpu.cpus));
    cpu.set_mems(Some(update_config.resources.cpu.mems));
    existing_resources.set_cpu(Some(cpu));

    let mut mem = existing_resources
        .memory()
        .as_ref()
        .cloned()
        .unwrap_or_default();

    mem.set_limit(Some(update_config.resources.memory.limit));
    mem.set_reservation(Some(update_config.resources.memory.reservation));
    mem.set_swap(Some(update_config.resources.memory.swap));
    existing_resources.set_memory(Some(mem));

    let mut blk_io = existing_resources
        .block_io()
        .as_ref()
        .cloned()
        .unwrap_or_default();
    blk_io.set_weight(Some(update_config.resources.block_io.blkio_weight));
    existing_resources.set_block_io(Some(blk_io));

    if let Some(lim) = update_config.pids_limit {
        let mut pids = existing_resources
            .pids()
            .as_ref()
            .cloned()
            .unwrap_or_default();
        pids.set_limit(lim);
        existing_resources.set_pids(Some(pids));
    }

    cmanager.apply(&ControllerOpt {
        resources: &existing_resources,
        disable_oom_killer: false,
        oom_score_adj: None,
        freezer_state: None,
    })?;

    let mut intel_rdt = spec
        .linux()
        .as_ref()
        .unwrap()
        .intel_rdt()
        .as_ref()
        .unwrap()
        .clone();
    intel_rdt.set_mem_bw_schema(update_config.mem_bw_schema);
    intel_rdt.set_l3_cache_schema(update_config.l3_cache_schema);
    setup_intel_rdt(Some(container.id()), &container.pid().unwrap(), &intel_rdt)?;
    Ok(())
}
