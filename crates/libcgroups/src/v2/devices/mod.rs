pub mod bpf;
// Compiled in tests too (the raw syscall is swappable there); `bpf.rs` tests use the mocks.
#[cfg_attr(test, allow(dead_code))]
mod bpf_sys;
mod bpf_uapi;
pub mod controller;
pub mod emulator;
pub mod program;

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub mod mocks;

pub use controller::Devices;
