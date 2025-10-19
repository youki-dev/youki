use std::collections::HashMap;

use oci_spec::runtime::LinuxTimeOffset;

pub fn create_time_offset(
    boottime_secs: i64,
    boottime_nanosecs: u32,
    monotonic_secs: i64,
    monotonic_nanosecs: u32,
) -> HashMap<String, LinuxTimeOffset> {
    [
        (
            "boottime".to_owned(),
            LinuxTimeOffset::default()
                .set_secs(Some(boottime_secs))
                .set_nanosecs(Some(boottime_nanosecs))
                .to_owned(),
        ),
        (
            "monotonic".to_owned(),
            LinuxTimeOffset::default()
                .set_secs(Some(monotonic_secs))
                .set_nanosecs(Some(monotonic_nanosecs))
                .to_owned(),
        ),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>()
}
