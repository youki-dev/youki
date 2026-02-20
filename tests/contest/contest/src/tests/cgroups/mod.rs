use std::fs;
use std::path::Component::RootDir;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use procfs::process::Process;
pub mod blkio;
pub mod cpu;
pub mod devices;
pub mod memory;
pub mod network;
pub mod pids;

pub fn cleanup_v1() -> Result<()> {
    for subsystem in list_subsystem_mount_points()? {
        let runtime_test = subsystem.join("runtime-test");
        if runtime_test.exists() {
            fs::remove_dir(&runtime_test)
                .with_context(|| format!("failed to delete {runtime_test:?}"))?;
        }
    }

    Ok(())
}

pub fn cleanup_v2() -> Result<()> {
    let runtime_test = Path::new("/sys/fs/cgroup/runtime-test");
    if runtime_test.exists() {
        let _: Result<Vec<_>, _> = fs::read_dir(runtime_test)
            .with_context(|| format!("failed to read {runtime_test:?}"))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|e| e.is_dir())
            .map(fs::remove_dir)
            .collect();

        fs::remove_dir(runtime_test)
            .with_context(|| format!("failed to delete {runtime_test:?}"))?;
    }

    Ok(())
}

pub fn list_subsystem_mount_points() -> Result<Vec<PathBuf>> {
    Ok(Process::myself()
        .context("failed to get self")?
        .mountinfo()
        .context("failed to get mountinfo")?
        .into_iter()
        .filter_map(|m| {
            if m.fs_type == "cgroup" {
                Some(m.mount_point)
            } else {
                None
            }
        })
        .collect())
}

pub fn attach_controller(cgroup_root: &Path, cgroup_path: &Path, controller: &str) -> Result<()> {
    let mut current_path = cgroup_root.to_path_buf();

    let mut components = cgroup_path
        .components()
        .filter(|c| c.ne(&RootDir))
        .peekable();

    write_controller(&current_path, controller)?;
    while let Some(component) = components.next() {
        current_path.push(component);
        if components.peek().is_some() {
            write_controller(&current_path, controller)?;
        }
    }

    Ok(())
}

fn write_controller(cgroup_path: &Path, controller: &str) -> Result<()> {
    let controller_file = cgroup_path.join("cgroup.subtree_control");
    fs::write(controller_file, format!("+{controller}"))
        .with_context(|| format!("failed to attach {controller} controller to {cgroup_path:?}"))
}
