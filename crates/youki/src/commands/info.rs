//! Contains functions related to printing information about system running Youki
#[cfg(feature = "v2")]
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::Result;
use clap::Parser;
#[cfg(feature = "v2")]
use libcgroups::{common::CgroupSetup, v2::controller_type::ControllerType};
use libcontainer::user_ns;
use procfs::{CpuInfo, Current, Meminfo};
/// Show information about the system
#[derive(Parser, Debug)]
pub struct Info {}

pub fn info(_: Info) -> Result<()> {
    print_youki();
    print_kernel();
    print_os();
    print_hardware();
    print_cgroups();
    print_namespaces();
    print_capabilities();

    Ok(())
}

/// print Version of Youki
#[allow(clippy::vec_init_then_push)]
pub fn print_youki() {
    println!("{:<16}", "Build");
    println!("  {:<16}{}", "Version", env!("CARGO_PKG_VERSION"));
    println!("  {:<16}{}", "Commit", env!("VERGEN_GIT_SHA"));
    let mut enabled_features: Vec<&str> = Vec::new();
    #[cfg(feature = "systemd")]
    enabled_features.push("systemd");
    #[cfg(feature = "v1")]
    enabled_features.push("v1");
    #[cfg(feature = "v2")]
    enabled_features.push("v2");
    #[cfg(feature = "cgroupsv2_devices")]
    enabled_features.push("cgroupsv2_devices");
    #[cfg(feature = "seccomp")]
    enabled_features.push("seccomp");
    #[cfg(feature = "wasm-wasmer")]
    enabled_features.push("wasm-wasmer");
    #[cfg(feature = "wasm-wasmedge")]
    enabled_features.push("wasm-wasmedge");
    #[cfg(feature = "wasm-wasmtime")]
    enabled_features.push("wasm-wasmtime");
    println!("  {:<16}{}", "Features", enabled_features.join(", "));
}

/// Print Kernel Release, Version and Architecture
pub fn print_kernel() {
    let uname = nix::sys::utsname::uname().unwrap();
    println!(
        "{:<18}{}",
        "Kernel-Release",
        uname.release().to_string_lossy()
    );
    println!(
        "{:<18}{}",
        "Kernel-Version",
        uname.version().to_string_lossy()
    );
    println!(
        "{:<18}{}",
        "Architecture",
        uname.machine().to_string_lossy()
    );
}

/// Prints OS Distribution information
// see https://www.freedesktop.org/software/systemd/man/os-release.html
pub fn print_os() {
    if let Some(os) = try_read_os_from("/etc/os-release") {
        println!("{:<18}{}", "Operating System", os);
    } else if let Some(os) = try_read_os_from("/usr/lib/os-release") {
        println!("{:<18}{}", "Operating System", os);
    } else {
        println!("{:<18}UNKNOWN", "Operating System");
    }
}

/// Helper function to read the OS Distribution info
fn try_read_os_from<P: AsRef<Path>>(path: P) -> Option<String> {
    let os_release = path.as_ref();
    if !os_release.exists() {
        return None;
    }

    if let Ok(release_content) = fs::read_to_string(path) {
        let pretty = find_parameter(&release_content, "PRETTY_NAME");

        if let Some(pretty) = pretty {
            return Some(pretty.trim_matches('"').to_owned());
        }

        let name = find_parameter(&release_content, "NAME");
        let version = find_parameter(&release_content, "VERSION");

        if let Some((name, version)) = name.zip(version) {
            return Some(format!(
                "{} {}",
                name.trim_matches('"'),
                version.trim_matches('"')
            ));
        }
    }

    None
}

/// Helper function to find keyword values in OS info string
fn find_parameter<'a>(content: &'a str, param_name: &str) -> Option<&'a str> {
    content
        .lines()
        .find(|l| l.starts_with(param_name))
        .and_then(|l| l.split_terminator('=').last())
}

/// Print Hardware information of system
pub fn print_hardware() {
    if let Ok(cpu_info) = CpuInfo::current() {
        println!("{:<18}{}", "Cores", cpu_info.num_cores());
    }

    if let Ok(mem_info) = Meminfo::current() {
        println!(
            "{:<18}{}",
            "Total Memory",
            mem_info.mem_total / u64::pow(1024, 2)
        );
    }
}

/// Print cgroups info of system
pub fn print_cgroups() {
    print_cgroups_setup();
    print_cgroup_mounts();
    #[cfg(feature = "v2")]
    print_cgroup_v2_controllers();
}

pub fn print_cgroups_setup() {
    let cgroup_setup = libcgroups::common::get_cgroup_setup();
    if let Ok(cgroup_setup) = &cgroup_setup {
        println!("{:<18}{}", "Cgroup setup", cgroup_setup);
    }
}

pub fn print_cgroup_mounts() {
    println!("Cgroup mounts");
    #[cfg(feature = "v1")]
    if let Ok(v1_mounts) = libcgroups::v1::util::list_supported_mount_points() {
        let mut v1_mounts: Vec<String> = v1_mounts
            .iter()
            .map(|kv| format!("  {:<16}{}", kv.0.to_string(), kv.1.display()))
            .collect();

        v1_mounts.sort();
        for cgroup_mount in v1_mounts {
            println!("{cgroup_mount}");
        }
    }

    #[cfg(feature = "v2")]
    if let Ok(mount_point) = libcgroups::v2::util::get_unified_mount_point() {
        println!("  {:<16}{}", "unified", mount_point.display());
    }
}

#[cfg(feature = "v2")]
pub fn print_cgroup_v2_controllers() {
    let cgroup_setup = libcgroups::common::get_cgroup_setup();
    let unified = libcgroups::v2::util::get_unified_mount_point();

    if let Ok(cgroup_setup) = cgroup_setup {
        if let Ok(unified) = &unified {
            if matches!(cgroup_setup, CgroupSetup::Hybrid | CgroupSetup::Unified) {
                if let Ok(controllers) = libcgroups::v2::util::get_available_controllers(unified) {
                    println!("CGroup v2 controllers");
                    let active_controllers: HashSet<ControllerType> =
                        controllers.into_iter().collect();
                    for controller in libcgroups::v2::controller_type::CONTROLLER_TYPES {
                        let status = if active_controllers.contains(controller) {
                            "attached"
                        } else {
                            "detached"
                        };

                        println!("  {:<16}{}", controller.to_string(), status);
                    }
                }

                if let Some(config) = read_kernel_config() {
                    let display = FeatureDisplay::with_status("device", "attached", "detached");
                    print_feature_status(&config, "CONFIG_CGROUP_BPF", display);
                }
            }
        }
    }
}

fn read_kernel_config() -> Option<String> {
    let uname = nix::sys::utsname::uname();
    let kernel_config = Path::new("/boot").join(format!(
        "config-{}",
        uname.unwrap().release().to_string_lossy()
    ));
    if !kernel_config.exists() {
        return None;
    }

    fs::read_to_string(kernel_config).ok()
}

pub fn print_namespaces() {
    if let Some(content) = read_kernel_config() {
        if let Some(ns_enabled) = find_parameter(&content, "CONFIG_NAMESPACES") {
            if ns_enabled == "y" {
                println!("{:<18}enabled", "Namespaces");
            } else {
                println!("{:<18}disabled", "Namespaces");
                return;
            }
        } else {
            println!("{:<18}UNKNOWN", "Namespaces");
            // we don't return as  we can atleast try and see if anything is enabled
        }

        // mount namespace is always enabled if namespaces are enabled
        println!("  {:<16}enabled", "mount");
        print_feature_status(&content, "CONFIG_UTS_NS", FeatureDisplay::new("uts"));
        print_feature_status(&content, "CONFIG_IPC_NS", FeatureDisplay::new("ipc"));

        let user_display = match user_ns::unprivileged_user_ns_enabled() {
            Ok(false) => FeatureDisplay::with_status("user", "enabled (root only)", "disabled"),
            _ => FeatureDisplay::new("user"),
        };
        print_feature_status(&content, "CONFIG_USER_NS", user_display);
        print_feature_status(&content, "CONFIG_PID_NS", FeatureDisplay::new("pid"));
        print_feature_status(&content, "CONFIG_NET_NS", FeatureDisplay::new("network"));
        // While the CONFIG_CGROUP_NS kernel feature exists, it is obsolete and should not be used. CGroup namespaces
        // are instead enabled with CONFIG_CGROUPS.
        print_feature_status(&content, "CONFIG_CGROUPS", FeatureDisplay::new("cgroup"))
    }
}

#[inline]
fn is_cap_available(caps: &caps::CapsHashSet, cap: caps::Capability) -> &'static str {
    if caps.contains(&cap) {
        "available"
    } else {
        "unavailable"
    }
}

pub fn print_capabilities() {
    println!("Capabilities");
    if let Ok(current) = caps::read(None, caps::CapSet::Bounding) {
        println!(
            "{:<17} {}",
            "CAP_BPF",
            is_cap_available(&current, caps::Capability::CAP_BPF)
        );
        println!(
            "{:<17} {}",
            "CAP_PERFMON",
            is_cap_available(&current, caps::Capability::CAP_PERFMON)
        );
        println!(
            "{:<17} {}",
            "CAP_CHECKPOINT_RESTORE",
            is_cap_available(&current, caps::Capability::CAP_CHECKPOINT_RESTORE)
        );
    } else {
        println!("<cannot find cap info>");
    }
}

fn print_feature_status(config: &str, feature: &str, display: FeatureDisplay) {
    if let Some(status_flag) = find_parameter(config, feature) {
        let status = if status_flag == "y" {
            display.enabled
        } else {
            display.disabled
        };

        println!("  {:<16}{}", display.name, status);
    } else {
        println!("  {:<16}UNKNOWN", display.name);
    }
}

struct FeatureDisplay<'a> {
    name: &'a str,
    enabled: &'a str,
    disabled: &'a str,
}

impl<'a> FeatureDisplay<'a> {
    fn new(name: &'a str) -> Self {
        Self {
            name,
            enabled: "enabled",
            disabled: "disabled",
        }
    }

    fn with_status(name: &'a str, enabled: &'a str, disabled: &'a str) -> Self {
        Self {
            name,
            enabled,
            disabled,
        }
    }
}
