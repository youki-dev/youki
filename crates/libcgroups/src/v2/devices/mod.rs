// The emulator is pure Rust and also serves the systemd manager's DeviceAllow rules; only the
// eBPF program needs `cgroupsv2_devices`.
#[cfg(feature = "cgroupsv2_devices")]
pub mod bpf;
#[cfg(feature = "cgroupsv2_devices")]
pub mod controller;
pub mod emulator;
#[cfg(feature = "cgroupsv2_devices")]
pub mod program;

#[cfg(all(test, feature = "cgroupsv2_devices"))]
#[allow(clippy::too_many_arguments)]
pub mod mocks;

#[cfg(feature = "cgroupsv2_devices")]
pub use controller::Devices;
