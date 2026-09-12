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
    #[arg(long, allow_hyphen_values = true)]
    pub memory: Option<i64>,

    /// Set memory reservation (or soft limit) to num bytes.
    #[arg(long, allow_hyphen_values = true)]
    pub memory_reservation: Option<i64>,

    /// Set total memory + swap usage to num bytes. Use -1 to unset the limit (i.e. use unlimited swap).
    #[arg(long, allow_hyphen_values = true)]
    pub memory_swap: Option<i64>,

    /// Set the maximum number of processes allowed in the container
    #[arg(long)]
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
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(flatten)]
        update: Update,
    }

    #[test]
    fn test_parse_memory_positive() {
        let cli = TestCli::try_parse_from(["test", "--memory", "1048576", "container1"]).unwrap();
        assert_eq!(cli.update.memory, Some(1048576));
        assert_eq!(cli.update.container_id, "container1");
    }

    #[test]
    fn test_parse_memory_negative() {
        let cli = TestCli::try_parse_from(["test", "--memory", "-1", "container1"]).unwrap();
        assert_eq!(cli.update.memory, Some(-1));
    }

    #[test]
    fn test_parse_memory_reservation_positive() {
        let cli = TestCli::try_parse_from(["test", "--memory-reservation", "524288", "container1"])
            .unwrap();
        assert_eq!(cli.update.memory_reservation, Some(524288));
    }

    #[test]
    fn test_parse_memory_reservation_negative() {
        let cli =
            TestCli::try_parse_from(["test", "--memory-reservation", "-1", "container1"]).unwrap();
        assert_eq!(cli.update.memory_reservation, Some(-1));
    }

    #[test]
    fn test_parse_memory_swap_positive() {
        let cli =
            TestCli::try_parse_from(["test", "--memory-swap", "2097152", "container1"]).unwrap();
        assert_eq!(cli.update.memory_swap, Some(2097152));
    }

    #[test]
    fn test_parse_memory_swap_negative() {
        let cli = TestCli::try_parse_from(["test", "--memory-swap", "-1", "container1"]).unwrap();
        assert_eq!(cli.update.memory_swap, Some(-1));
    }

    #[test]
    fn test_parse_all_memory_flags() {
        let cli = TestCli::try_parse_from([
            "test",
            "--memory",
            "1048576",
            "--memory-reservation",
            "524288",
            "--memory-swap",
            "2097152",
            "container1",
        ])
        .unwrap();
        assert_eq!(cli.update.memory, Some(1048576));
        assert_eq!(cli.update.memory_reservation, Some(524288));
        assert_eq!(cli.update.memory_swap, Some(2097152));
    }

    #[test]
    fn test_parse_all_memory_flags_negative() {
        let cli = TestCli::try_parse_from([
            "test",
            "--memory",
            "-1",
            "--memory-reservation",
            "-1",
            "--memory-swap",
            "-1",
            "container1",
        ])
        .unwrap();
        assert_eq!(cli.update.memory, Some(-1));
        assert_eq!(cli.update.memory_reservation, Some(-1));
        assert_eq!(cli.update.memory_swap, Some(-1));
    }

    #[test]
    fn test_parse_mixed_memory_flags() {
        let cli = TestCli::try_parse_from([
            "test",
            "--memory",
            "1048576",
            "--memory-reservation",
            "-1",
            "--memory-swap",
            "-1",
            "container1",
        ])
        .unwrap();
        assert_eq!(cli.update.memory, Some(1048576));
        assert_eq!(cli.update.memory_reservation, Some(-1));
        assert_eq!(cli.update.memory_swap, Some(-1));
    }

    #[test]
    fn test_parse_with_resources() {
        let cli = TestCli::try_parse_from([
            "test",
            "--resources",
            "resources.json",
            "--memory",
            "1048576",
            "container1",
        ])
        .unwrap();
        assert_eq!(cli.update.resources, Some(PathBuf::from("resources.json")));
        assert_eq!(cli.update.memory, Some(1048576));
    }
}
