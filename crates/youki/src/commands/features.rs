//! Contains Functionality of `features` container command
use anyhow::Result;
use libcontainer::oci_spec::runtime::{
    version, ApparmorBuilder, CgroupBuilder, FeaturesBuilder, IDMapBuilder, IntelRdtBuilder,
    LinuxFeatureBuilder, LinuxNamespaceType, MountExtensionsBuilder, SelinuxBuilder,
};
use liboci_cli::Features;

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

// Return a list of known mount options supported by youki
fn known_mount_options() -> Vec<String> {
    [
        "async",
        "atime",
        "bind",
        "defaults",
        "dev",
        "diratime",
        "dirsync",
        "exec",
        "mand",
        "noatime",
        "nodev",
        "nodiratime",
        "noexec",
        "nomand",
        "norelatime",
        "nosuid",
        "nostrictatime",
        "private",
        "rbind",
        "rdev",
        "relatime",
        "remount",
        "rnoatime",
        "rnodev",
        "rnodiratime",
        "rnoexec",
        "rnorelatime",
        "rnosuid",
        "rnostrictatime",
        "ro",
        "rprivate",
        "rrw",
        "rshared",
        "rsuid",
        "rsymfollow",
        "rslave",
        "rstrictatime",
        "runbindable",
        "rw",
        "shared",
        "slave",
        "strictatime",
        "suid",
        "sync",
        "unbindable",
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
                // idmapped mounts is not supported in youki
                .idmap(IDMapBuilder::default().enabled(false).build().unwrap())
                .build()
                .unwrap(),
        )
        // SELinux is not supported in youki.
        .selinux(SelinuxBuilder::default().enabled(false).build().unwrap())
        .intel_rdt(IntelRdtBuilder::default().enabled(true).build().unwrap())
        .build()
        .unwrap();

    let features = FeaturesBuilder::default()
        .oci_version_max(version())
        .oci_version_min(String::from("1.0.0"))
        .hooks(known_hooks())
        .mount_options(known_mount_options())
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
