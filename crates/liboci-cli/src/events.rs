use std::time::Duration;

use clap::Parser;

fn parse_interval(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }

    let (num, unit) = s
        .trim_end_matches(|c: char| !c.is_ascii_alphabetic())
        .chars()
        .partition::<String, _>(|c| c.is_ascii_digit());

    let num = num.parse::<u64>().map_err(|_| "Invalid number")?;

    let dur = match unit.as_str() {
        "s" => Duration::from_secs(num),
        "m" => Duration::from_secs(num * 60),
        "h" => Duration::from_secs(num * 60 * 60),
        _ => return Err("Unsupported unit. Use s, m, or h.".into()),
    };

    Ok(dur)
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
