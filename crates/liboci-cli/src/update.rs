use clap::Parser;
use std::path::PathBuf;

/// Update running container resource constraints
#[derive(Parser, Debug)]
pub struct Update {
    /// Read the new resource limits from the given json file. Use - to read from stdin.
    /// If this option is used, all other options are ignored.
    #[clap(short, long)]
    pub resources: Option<PathBuf>,

    /// Set a new I/O weight
    #[clap(long)]
    pub blkio_weight: Option<u16>,

    /// Set CPU CFS period to be used for hardcapping (in microseconds)
    #[clap(long)]
    pub cpu_period: Option<u64>,

    /// Set CPU usage limit within a given period (in microseconds)
    #[clap(long)]
    pub cpu_quota: Option<i64>,

    /// Set CPU realtime period to be used for hardcapping (in microseconds)
    #[clap(long)]
    pub cpu_rt_period: Option<u64>,

    /// Set CPU realtime hardcap limit (in microseconds)
    #[clap(long)]
    pub cpu_rt_runtime: Option<i64>,

    /// Set CPU shares (relative weight vs. other containers)
    #[clap(long)]
    pub cpu_share: Option<u64>,

    /// Set CPU(s) to use. The list can contain commas and ranges. For example: 0-3,7
    #[clap(long)]
    pub cpuset_cpus: Option<String>,

    /// Set memory node(s) to use. The list format is the same as for --cpuset-cpus.
    #[clap(long)]
    pub cpuset_mems: Option<String>,

    #[clap(long)]
    /// Set CPU burst limit within a given period (in microseconds)
    pub cpu_burst: Option<u64>,

    /// Set memory limit to num bytes.
    #[clap(long)]
    pub memory: Option<i64>,

    /// Set memory reservation (or soft limit) to num bytes.
    #[clap(long)]
    pub memory_reservation: Option<i64>,

    /// Set total memory + swap usage to num bytes. Use -1 to unset the limit (i.e. use unlimited swap).
    #[clap(long)]
    pub memory_swap: Option<i64>,

    /// Set the maximum number of processes allowed in the container
    #[clap(long)]
    pub pids_limit: Option<i64>,

    /// Set the value for Intel RDT/CAT L3 cache schema.
    #[clap(long)]
    pub l3_cache_schema: Option<String>,

    /// Set the Intel RDT/MBA memory bandwidth schema.
    #[clap(long)]
    pub mem_bw_schema: Option<String>,

    #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
