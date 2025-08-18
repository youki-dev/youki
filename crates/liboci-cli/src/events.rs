use std::time::Duration;

use clap::Parser;
use parse_duration::parse;

fn parse_interval(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }

    parse(s).map_err(|e| e.to_string())
}
/// Show resource statistics for the container
#[derive(Parser, Debug)]
pub struct Events {
    /// Sets the stats collection interval in seconds (default: 5s)
    #[clap(long, default_value = "5", value_parser = parse_interval)]
    pub interval: Duration,
    /// Display the container stats only once
    #[clap(long)]
    pub stats: bool,
    /// Name of the container instance
    #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
