use std::error::Error;
use std::time::Duration;

use clap::Args;

/// Units accepted in an interval string, ordered so that multi-character
/// suffixes are matched before their single-character prefixes (e.g. `ms`
/// before `m` and `s`). Each entry maps a unit to its length in nanoseconds.
const UNITS: &[(&str, u128)] = &[
    ("ns", 1),
    ("us", 1_000),
    ("µs", 1_000),
    ("ms", 1_000_000),
    ("h", 3_600_000_000_000),
    ("m", 60_000_000_000),
    ("s", 1_000_000_000),
];

/// Parse a stats collection interval such as `1s`, `100ms` or `1h30m`.
///
/// The accepted format mirrors `runc` (which relies on Go's
/// `time.ParseDuration`): one or more decimal numbers, each immediately
/// followed by a unit suffix. Supported units are `h`, `m`, `s`, `ms`, `us`
/// (or `µs`) and `ns`. A bare number without a unit (e.g. `1`) is rejected,
/// matching `runc`'s behaviour.
fn parse_interval(s: &str) -> Result<Duration, Box<dyn Error + Send + Sync + 'static>> {
    let input = s.trim();
    if input.is_empty() {
        return Err(format!("invalid interval {s:?}: empty value").into());
    }

    let mut remainder = input;
    let mut total_nanos: u128 = 0;

    while !remainder.is_empty() {
        // Split off the leading run of ASCII digits.
        let digits_end = remainder
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(remainder.len());
        if digits_end == 0 {
            return Err(format!("invalid interval {s:?}: expected a number before a unit").into());
        }

        let (number, rest) = remainder.split_at(digits_end);
        let value: u128 = number.parse()?;

        // Match the longest known unit at the start of the remainder.
        let (unit, factor) = UNITS
            .iter()
            .find(|(unit, _)| rest.starts_with(unit))
            .ok_or_else(|| {
                format!(
                    "invalid interval {s:?}: missing or unknown unit \
                     (expected h, m, s, ms, us or ns)"
                )
            })?;

        let nanos = value
            .checked_mul(*factor)
            .and_then(|n| total_nanos.checked_add(n))
            .ok_or_else(|| format!("invalid interval {s:?}: value out of range"))?;
        total_nanos = nanos;

        remainder = &rest[unit.len()..];
    }

    let secs = u64::try_from(total_nanos / 1_000_000_000)
        .map_err(|_| format!("invalid interval {s:?}: value out of range"))?;
    let nanos = (total_nanos % 1_000_000_000) as u32;
    Ok(Duration::new(secs, nanos))
}

/// Show resource statistics for the container
#[derive(Args, Debug)]
pub struct Events {
    /// Sets the stats collection interval, e.g. `1s`, `100ms` or `1h30m` (default: 5s)
    #[arg(long, default_value = "5s", value_parser = parse_interval)]
    pub interval: Duration,
    /// Display the container stats only once
    #[arg(long)]
    pub stats: bool,
    /// Name of the container instance
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_units() {
        assert_eq!(parse_interval("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_interval("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_interval("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_interval("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_interval("100ms").unwrap(), Duration::from_millis(100));
        assert_eq!(parse_interval("250us").unwrap(), Duration::from_micros(250));
        assert_eq!(parse_interval("250µs").unwrap(), Duration::from_micros(250));
        assert_eq!(parse_interval("500ns").unwrap(), Duration::from_nanos(500));
    }

    #[test]
    fn parses_compound_durations() {
        assert_eq!(parse_interval("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(
            parse_interval("2h45m30s").unwrap(),
            Duration::from_secs(2 * 3600 + 45 * 60 + 30)
        );
        assert_eq!(
            parse_interval("1s500ms").unwrap(),
            Duration::from_millis(1500)
        );
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(parse_interval("  10s  ").unwrap(), Duration::from_secs(10));
    }

    #[test]
    fn rejects_digit_only_value() {
        // Matches runc, which rejects a unit-less interval such as `1`.
        assert!(parse_interval("1").is_err());
    }

    #[test]
    fn rejects_invalid_values() {
        assert!(parse_interval("").is_err());
        assert!(parse_interval("   ").is_err());
        assert!(parse_interval("abc").is_err());
        assert!(parse_interval("10x").is_err());
        assert!(parse_interval("s").is_err());
        assert!(parse_interval("1s2").is_err());
        assert!(parse_interval("-1s").is_err());
    }
}
