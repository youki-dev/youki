use std::path::PathBuf;

use clap::Args;

/// Update running container resource constraints
#[derive(Args, Debug)]
pub struct Update {
    /// Read the new resource limits from the given json file. Use - to read from stdin.
    /// If this option is used, all other options are ignored.
    #[arg(short, long)]
    pub resources: Option<PathBuf>,

    /// Set a new I/O weight
    #[arg(long)]
    pub blkio_weight: Option<u64>,

    /// Set CPU CFS period to be used for hardcapping (in microseconds)
    #[arg(long)]
    pub cpu_period: Option<u64>,

    /// Set CPU usage limit within a given period (in microseconds)
    #[arg(long)]
    pub cpu_quota: Option<u64>,

    /// Set CPU realtime period to be used for hardcapping (in microseconds)
    #[arg(long)]
    pub cpu_rt_period: Option<u64>,

    /// Set CPU realtime hardcap limit (in microseconds)
    #[arg(long)]
    pub cpu_rt_runtime: Option<u64>,

    /// Set CPU shares (relative weight vs. other containers)
    #[arg(long)]
    pub cpu_share: Option<u64>,

    /// Set CPU(s) to use. The list can contain commas and ranges. For example: 0-3,7
    #[arg(long)]
    pub cpuset_cpus: Option<String>,

    /// Set memory node(s) to use. The list format is the same as for --cpuset-cpus.
    #[arg(long)]
    pub cpuset_mems: Option<String>,

    /// Set memory limit to num bytes.
    #[arg(long)]
    pub memory: Option<u64>,

    /// Set memory reservation (or soft limit) to num bytes.
    #[arg(long)]
    pub memory_reservation: Option<u64>,

    /// Set total memory + swap usage to num bytes. Use -1 to unset the limit (i.e. use unlimited swap).
    #[arg(long, allow_hyphen_values = true)]
    pub memory_swap: Option<i64>,

    /// Set the maximum number of processes allowed in the container. Use -1 for no limit (i.e. `max`).
    #[arg(long, allow_hyphen_values = true)]
    pub pids_limit: Option<i64>,

    /// Set the value for Intel RDT/CAT L3 cache schema.
    #[arg(long)]
    pub l3_cache_schema: Option<String>,

    /// Set the Intel RDT/MBA memory bandwidth schema.
    #[arg(long)]
    pub mem_bw_schema: Option<String>,

    /// Container identifier
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Update;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        update: Update,
    }

    fn parse(args: &[&str]) -> Update {
        Wrapper::parse_from(args).update
    }

    #[test]
    fn pids_limit_accepts_negative_value() {
        let update = parse(&["update", "--pids-limit", "-1", "container-id"]);
        assert_eq!(update.pids_limit, Some(-1));
        assert_eq!(update.container_id, "container-id");
    }

    #[test]
    fn pids_limit_accepts_zero_and_positive() {
        assert_eq!(
            parse(&["update", "--pids-limit", "0", "id"]).pids_limit,
            Some(0)
        );
        assert_eq!(
            parse(&["update", "--pids-limit", "12345", "id"]).pids_limit,
            Some(12345)
        );
    }

    #[test]
    fn memory_swap_accepts_negative_value() {
        let update = parse(&["update", "--memory-swap", "-1", "container-id"]);
        assert_eq!(update.memory_swap, Some(-1));
    }
}
