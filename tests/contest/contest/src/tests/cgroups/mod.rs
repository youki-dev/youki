use std::fs;
use std::path::Component::RootDir;
use std::path::Path;

use anyhow::{Context, Result};
pub mod cpu;

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
