//! Contains Functionality of `features` container command
use anyhow::Result;
use libcontainer::oci_spec::runtime::{
    ApparmorBuilder, CgroupBuilder, FeaturesBuilder, IDMapBuilder, IntelRdtBuilder,
    LinuxFeatureBuilder, LinuxNamespaceType, MountExtensionsBuilder, SelinuxBuilder, VERSION,
};
use libcontainer::syscall::linux::MountOption;
use liboci_cli::Features;
use nix::sys::utsname;

// Idmapped mounts were introduced in Linux 5.12.
const IDMAP_MIN_KERNEL_MAJOR: u32 = 5;
const IDMAP_MIN_KERNEL_MINOR: u32 = 12;

// Function to query and return capabilities
fn query_caps() -> Result<Vec<String>> {
    Ok(caps::all().iter().map(|cap| format!("{:?}", cap)).collect())
}

// Function to query and return namespaces
fn query_supported_namespaces() -> Result<Vec<LinuxNamespaceType>> {
    Ok(vec![
        LinuxNamespaceType::Pid,
        LinuxNamespaceType::Network,
        LinuxNamespaceType::Uts,
        LinuxNamespaceType::Ipc,
        LinuxNamespaceType::Mount,
        LinuxNamespaceType::User,
        LinuxNamespaceType::Cgroup,
        LinuxNamespaceType::Time,
    ])
}

fn kernel_supports_idmapped_mounts() -> bool {
    let Ok(uname) = utsname::uname() else {
        return false;
    };
    let release = uname.release().to_string_lossy();
    let Some((major, rest)) = release.split_once('.') else {
        return false;
    };
    let minor = rest
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap_or_default();
    let Ok(major) = major.parse::<u32>() else {
        return false;
    };
    let Ok(minor) = minor.parse::<u32>() else {
        return false;
    };
    major > IDMAP_MIN_KERNEL_MAJOR
        || (major == IDMAP_MIN_KERNEL_MAJOR && minor >= IDMAP_MIN_KERNEL_MINOR)
}

// Return a list of known hooks supported by youki
fn known_hooks() -> Vec<String> {
    [
        "prestart",
        "createRuntime",
        "createContainer",
        "startContainer",
        "poststart",
        "poststop",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// lists all existing containers
pub fn features(_: Features) -> Result<()> {
    // Query supported namespaces
    let namespaces = match query_supported_namespaces() {
        Ok(ns) => ns,
        Err(e) => {
            eprintln!("Error querying supported namespaces: {}", e);
            Vec::new()
        }
    };

    // Query available capabilities
    let capabilities = match query_caps() {
        Ok(caps) => caps,
        Err(e) => {
            eprintln!("Error querying available capabilities: {}", e);
            Vec::new()
        }
    };

    let linux = LinuxFeatureBuilder::default()
        .namespaces(namespaces)
        .capabilities(capabilities)
        .cgroup(
            CgroupBuilder::default()
                .v1(cfg!(feature = "v1"))
                .v2(cfg!(feature = "v2"))
                .systemd(cfg!(feature = "systemd"))
                .systemd_user(cfg!(feature = "systemd"))
                // cgroupv2 rdma controller is not implemented in youki.
                .rdma(false)
                .build()
                .unwrap(),
        )
        // TODO: Expose seccomp support information
        .apparmor(ApparmorBuilder::default().enabled(true).build().unwrap())
        .mount_extensions(
            MountExtensionsBuilder::default()
                .idmap(
                    IDMapBuilder::default()
                        .enabled(kernel_supports_idmapped_mounts())
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        // SELinux is not supported in youki.
        .selinux(SelinuxBuilder::default().enabled(false).build().unwrap())
        .intel_rdt(IntelRdtBuilder::default().enabled(true).build().unwrap())
        .build()
        .unwrap();

    let features = FeaturesBuilder::default()
        .oci_version_max(VERSION)
        .oci_version_min(String::from("1.0.0"))
        .hooks(known_hooks())
        .mount_options(MountOption::known_options())
        .linux(linux)
        .build()
        .unwrap();

    // Print out the created struct to verify
    let pretty_json_str = serde_json::to_string_pretty(&features)?;
    println!("{}", pretty_json_str);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_features() {
        let features = Features {};
        assert!(crate::commands::features::features(features).is_ok());
    }
}
