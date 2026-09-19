use std::error::Error;
use std::time::Duration;

use clap::Args;

type ParseError = Box<dyn Error + Send + Sync + 'static>;

const UNITS: &[(&str, i64)] = &[
    ("ns", 1),
    ("us", 1_000),
    ("\u{b5}s", 1_000),  // U+00B5 micro sign
    ("\u{3bc}s", 1_000), // U+03BC greek mu
    ("ms", 1_000_000),
    ("s", 1_000_000_000),
    ("m", 60_000_000_000),
    ("h", 3_600_000_000_000),
];

fn invalid(orig: &str) -> ParseError {
    format!("invalid duration {orig:?}").into()
}

/// Consumes the leading digits. Returns `None` if they overflow an `i64`.
fn leading_int(s: &str) -> Option<(i64, &str)> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let mut x: i64 = 0;
    for b in s[..end].bytes() {
        x = x.checked_mul(10)?.checked_add(i64::from(b - b'0'))?;
    }
    Some((x, &s[end..]))
}

/// Consumes the leading digits of a fractional part, returning them with the
/// scale to divide by. Digits that overflow are dropped rather than rejected:
/// they sit too far past the point to change the result.
fn leading_fraction(s: &str) -> (i64, f64, &str) {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let mut x: i64 = 0;
    let mut scale: f64 = 1.0;
    let mut overflow = false;
    for b in s[..end].bytes() {
        if overflow {
            continue;
        }
        match x
            .checked_mul(10)
            .and_then(|y| y.checked_add(i64::from(b - b'0')))
        {
            Some(y) => {
                x = y;
                scale *= 10.0;
            }
            None => overflow = true,
        }
    }
    (x, scale, &s[end..])
}

/// Parses `[-+]?([0-9]*(\.[0-9]*)?unit)+` into nanoseconds, matching Go's
/// `time.ParseDuration`, which is what runc uses for `--interval`.
///
/// Signed, and bounded by `i64` like Go's `time.Duration`, so that youki
/// accepts and rejects exactly the values runc does.
fn parse_duration_nanos(orig: &str) -> Result<i64, ParseError> {
    let mut s = orig;

    let mut neg = false;
    if let Some(rest) = s.strip_prefix('-') {
        neg = true;
        s = rest;
    } else if let Some(rest) = s.strip_prefix('+') {
        s = rest;
    }

    // A bare "0" is the only value allowed to omit its unit.
    if s == "0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(invalid(orig));
    }

    let mut total: i64 = 0;
    while !s.is_empty() {
        if !(s.starts_with('.') || s.starts_with(|c: char| c.is_ascii_digit())) {
            return Err(invalid(orig));
        }

        let (value, rest) = leading_int(s).ok_or_else(|| invalid(orig))?;
        let has_int = rest.len() != s.len();
        s = rest;

        let mut fraction: i64 = 0;
        let mut scale: f64 = 1.0;
        let mut has_fraction = false;
        if let Some(rest) = s.strip_prefix('.') {
            let (f, sc, remainder) = leading_fraction(rest);
            has_fraction = remainder.len() != rest.len();
            fraction = f;
            scale = sc;
            s = remainder;
        }
        if !has_int && !has_fraction {
            return Err(invalid(orig));
        }

        // Take the whole run up to the next digit, so "1sm" is an unknown unit
        // rather than a missing number.
        let unit_end = s
            .find(|c: char| c == '.' || c.is_ascii_digit())
            .unwrap_or(s.len());
        if unit_end == 0 {
            return Err(format!("missing unit in duration {orig:?}").into());
        }
        let (name, rest) = s.split_at(unit_end);
        s = rest;

        let unit = UNITS
            .iter()
            .find(|(unit, _)| *unit == name)
            .map(|(_, nanos)| *nanos)
            .ok_or_else(|| format!("unknown unit {name:?} in duration {orig:?}"))?;

        let mut nanos = value.checked_mul(unit).ok_or_else(|| invalid(orig))?;
        if fraction > 0 {
            // f64 keeps fractions of an hour nanosecond-accurate.
            let scaled = (fraction as f64 * (unit as f64 / scale)) as i64;
            nanos = nanos.checked_add(scaled).ok_or_else(|| invalid(orig))?;
        }
        total = total.checked_add(nanos).ok_or_else(|| invalid(orig))?;
    }

    Ok(if neg { -total } else { total })
}

/// Parses a stats collection interval such as `1s`, `100ms`, `1.5s` or `1h30m`.
fn parse_interval(s: &str) -> Result<Duration, ParseError> {
    let nanos = parse_duration_nanos(s)?;
    if nanos <= 0 {
        return Err("duration interval must be greater than 0".into());
    }

    Ok(Duration::from_nanos(nanos as u64))
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

    // Expectations below come from running the same input through Go's
    // time.ParseDuration and through `runc events --interval`.

    #[test]
    fn parses_single_units() {
        assert_eq!(parse_interval("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_interval("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_interval("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_interval("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_interval("100ms").unwrap(), Duration::from_millis(100));
        assert_eq!(parse_interval("250us").unwrap(), Duration::from_micros(250));
        assert_eq!(parse_interval("500ns").unwrap(), Duration::from_nanos(500));
    }

    #[test]
    fn parses_both_micro_signs() {
        assert_eq!(
            parse_interval("250\u{b5}s").unwrap(),
            Duration::from_micros(250)
        );
        assert_eq!(
            parse_interval("250\u{3bc}s").unwrap(),
            Duration::from_micros(250)
        );
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
        // A repeated unit accumulates.
        assert_eq!(parse_interval("1h1h").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn parses_fractional_durations() {
        assert_eq!(parse_interval("1.5s").unwrap(), Duration::from_millis(1500));
        assert_eq!(parse_interval("0.5s").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_interval(".5s").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_interval("1.5h").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_interval("1.5m").unwrap(), Duration::from_secs(90));
        assert_eq!(
            parse_interval("1m0.5s").unwrap(),
            Duration::from_millis(60_500)
        );
        // A point with no digits after it.
        assert_eq!(parse_interval("1.s").unwrap(), Duration::from_secs(1));
    }

    #[test]
    fn handles_signs() {
        assert_eq!(parse_interval("+1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_duration_nanos("-1s").unwrap(), -1_000_000_000);
        assert!(parse_interval("-1s").is_err());
    }

    // These parse to zero, then fail the same check runc makes. Without it a
    // zero interval would spin the stats loop without ever sleeping.
    #[test]
    fn rejects_non_positive_intervals() {
        assert_eq!(parse_duration_nanos("0").unwrap(), 0);
        assert_eq!(parse_duration_nanos("0s").unwrap(), 0);
        assert_eq!(parse_duration_nanos("-0s").unwrap(), 0);

        for input in ["0", "0s", "-0s", "-1s", "-1h"] {
            let err = parse_interval(input).unwrap_err().to_string();
            assert_eq!(err, "duration interval must be greater than 0", "{input}");
        }
    }

    #[test]
    fn rejects_unit_less_values() {
        for input in ["1", "00", "3.5", "5m30", "1s2", "1.5.5s"] {
            assert!(parse_interval(input).is_err(), "{input}");
        }
    }

    #[test]
    fn rejects_unknown_units() {
        for input in ["1S", "1H", "1M", "1MS", "10x", "1e3s", "1sm"] {
            assert!(parse_interval(input).is_err(), "{input}");
        }
    }

    // Go does not trim, so padding is a parse error rather than a duration.
    #[test]
    fn rejects_surrounding_whitespace() {
        for input in ["  10s  ", " 10s", "10s ", "1h 30m"] {
            assert!(parse_interval(input).is_err(), "{input}");
        }
    }

    // The i64 nanosecond ceiling Go's time.Duration imposes, just under 2562048h.
    #[test]
    fn rejects_overflowing_values() {
        assert_eq!(
            parse_duration_nanos("9223372036854775807ns").unwrap(),
            i64::MAX
        );
        for input in [
            "9223372036854775808ns",
            "99999999999h",
            "2562048h",
            "9223372036854775807s",
            "9223372036854775807ns1ns",
        ] {
            assert!(parse_interval(input).is_err(), "{input}");
        }
    }

    #[test]
    fn rejects_malformed_values() {
        for input in ["", "   ", "abc", "s", ".", ".s", "-", "+", "-.s", "1..5s"] {
            assert!(parse_interval(input).is_err(), "{input}");
        }
    }
}
