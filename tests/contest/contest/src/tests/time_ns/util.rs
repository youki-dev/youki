use std::collections::HashMap;

use oci_spec::runtime::LinuxTimeOffset;

pub struct TimeOffsets {
    pub boottime_secs: i64,
    pub boottime_nanosecs: u32,
    pub monotonic_secs: i64,
    pub monotonic_nanosecs: u32,
}

pub fn create_time_offset(time_offsets: &TimeOffsets) -> HashMap<String, LinuxTimeOffset> {
    [
        (
            "boottime".to_owned(),
            LinuxTimeOffset::default()
                .set_secs(Some(time_offsets.boottime_secs))
                .set_nanosecs(Some(time_offsets.boottime_nanosecs))
                .to_owned(),
        ),
        (
            "monotonic".to_owned(),
            LinuxTimeOffset::default()
                .set_secs(Some(time_offsets.monotonic_secs))
                .set_nanosecs(Some(time_offsets.monotonic_nanosecs))
                .to_owned(),
        ),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>()
}
