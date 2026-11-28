//! Control groups provide a way of controlling groups of processes.
//! Examples: controlling resource limits, execution priority, measuring resource usage,
//! freezing, checkpointing and restarting groups of processes.
#[cfg(test)]
#[macro_use]
extern crate quickcheck;

#[cfg(test)]
#[allow(unused_imports)]
#[macro_use]
extern crate mockall;

mod test;

pub mod common;
pub mod stats;
#[cfg(feature = "systemd")]
pub mod systemd;
#[cfg(not(feature = "systemd"))]
#[path = "stub/systemd/mod.rs"]
pub mod systemd;
pub mod test_manager;
#[cfg(feature = "v2")]
pub mod v2;
#[cfg(not(feature = "v2"))]
#[path = "stub/v2/mod.rs"]
pub mod v2;
