use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use libcontainer::oci_spec::runtime::{
    LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespace, LinuxNamespaceBuilder, LinuxNamespaceType,
    Mount, Spec,
};
use libcontainer::syscall::syscall::Syscall;
use serde_json::to_writer_pretty;

pub fn get_default() -> Result<Spec> {
    Ok(Spec::default())
}

pub fn get_rootless(syscall: &dyn Syscall) -> Result<Spec> {
    // Remove network and user namespace from the default spec
    let mut namespaces: Vec<LinuxNamespace> =
        libcontainer::oci_spec::runtime::get_default_namespaces()
            .into_iter()
            .filter(|ns| {
                ns.typ() != LinuxNamespaceType::Network && ns.typ() != LinuxNamespaceType::User
            })
            .collect();

    // Add user namespace
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()?,
    );

    let uid = syscall.get_euid().as_raw();
    let gid = syscall.get_egid().as_raw();

    let linux = LinuxBuilder::default()
        .namespaces(namespaces)
        .uid_mappings(vec![
            LinuxIdMappingBuilder::default()
                .host_id(uid)
                .container_id(0_u32)
                .size(1_u32)
                .build()?,
        ])
        .gid_mappings(vec![
            LinuxIdMappingBuilder::default()
                .host_id(gid)
                .container_id(0_u32)
                .size(1_u32)
                .build()?,
        ])
        .build()?;

    // Prepare the mounts

    let mut mounts: Vec<Mount> = libcontainer::oci_spec::runtime::get_default_mounts();
    for mount in &mut mounts {
        if mount.destination().eq(Path::new("/sys")) {
            mount
                .set_source(Some(PathBuf::from("/sys")))
                .set_typ(Some(String::from("none")))
                .set_options(Some(vec![
                    "rbind".to_string(),
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "nodev".to_string(),
                    "ro".to_string(),
                ]));
        } else {
            let options: Vec<String> = mount
                .options()
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .filter(|&o| !o.starts_with("gid=") && !o.starts_with("uid="))
                .map(|o| o.to_string())
                .collect();
            mount.set_options(Some(options));
        }
    }

    let mut spec = get_default()?;
    spec.set_linux(Some(linux)).set_mounts(Some(mounts));
    Ok(spec)
}

/// spec Cli command
pub fn spec(args: liboci_cli::Spec, syscall: &dyn Syscall) -> Result<()> {
    let spec = if args.rootless {
        get_rootless(syscall)?
    } else {
        get_default()?
    };

    // write data to config.json
    let file = File::create("config.json")?;
    let mut writer = BufWriter::new(file);
    to_writer_pretty(&mut writer, &spec)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
// Tests become unstable if not serial. The cause is not known.
mod tests {
    use libcontainer::syscall::syscall::create_syscall;
    use serial_test::serial;

    use super::*;

    #[test]
    #[serial]
    fn test_spec_json() -> Result<()> {
        let syscall = create_syscall();
        let spec = get_rootless(&*syscall)?;
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let path = tmpdir.path().join("config.json");
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        to_writer_pretty(&mut writer, &spec)?;
        writer.flush()?;
        Ok(())
    }
}
