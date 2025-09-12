use std::fs;

mod controller;
pub mod controller_type;
mod cpu;
mod cpuset;
mod dbus_native;
mod io;
pub mod manager;
mod memory;
mod pids;
mod unified;

/// Checks if the system was booted with systemd
pub fn booted() -> bool {
    fs::symlink_metadata("/run/systemd/system")
        .map(|p| p.is_dir())
        .unwrap_or_default()
}

#[macro_export]
macro_rules! recast {
    ($v:ident, $t:ty) => {{
        let mut buf = Vec::new();
        $v.serialize(&mut buf);
        let mut ctr = 0;
        let ret = <$t>::deserialize(&buf, &mut ctr);
        ret
    }};
}
