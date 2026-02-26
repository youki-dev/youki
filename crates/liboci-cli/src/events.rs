use std::time::Duration;

use clap::Parser;

fn parse_duration_string(s: &str) -> Result<Duration, String> {
    let s = s.trim().to_lowercase();
    let mut total_seconds = 0u64;
    let mut current_number = String::new();

    for ch in s.chars() {
        match ch {
            '0'..='9' => {
                current_number.push(ch);
            }
            'h' => {
                if current_number.is_empty() {
                    return Err("Invalid duration format: missing number before 'h'".to_string());
                }
                let hours: u64 = current_number
                    .parse()
                    .map_err(|_| "Invalid number before 'h'".to_string())?;
                total_seconds += hours * 3600;
                current_number.clear();
            }
            'm' => {
                if current_number.is_empty() {
                    return Err("Invalid duration format: missing number before 'm'".to_string());
                }
                let minutes: u64 = current_number
                    .parse()
                    .map_err(|_| "Invalid number before 'm'".to_string())?;
                total_seconds += minutes * 60;
                current_number.clear();
            }
            's' => {
                if current_number.is_empty() {
                    return Err("Invalid duration format: missing number before 's'".to_string());
                }
                let seconds: u64 = current_number
                    .parse()
                    .map_err(|_| "Invalid number before 's'".to_string())?;
                total_seconds += seconds;
                current_number.clear();
            }
            _ => {
                return Err(format!("Invalid character '{}' in duration", ch));
            }
        }
    }

    // If there's a remaining number without unit, treat it as seconds
    if !current_number.is_empty() {
        let seconds: u64 = current_number
            .parse()
            .map_err(|_| "Invalid number at end of duration".to_string())?;
        total_seconds += seconds;
    }

    if total_seconds == 0 {
        return Err("Duration cannot be zero".to_string());
    }

    Ok(Duration::from_secs(total_seconds))
}

fn parse_interval(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }

    parse_duration_string(s)
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
