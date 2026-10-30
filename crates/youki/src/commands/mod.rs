use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use libcgroups::common::AnyCgroupManager;
use libcontainer::container::{Container, validate_id};

pub mod checkpoint;
pub mod completion;
pub mod create;
pub mod delete;
pub mod events;
pub mod exec;
pub mod features;
pub(crate) mod foreground;
pub mod info;
pub mod kill;
pub mod list;
pub mod pause;
pub mod ps;
pub mod resume;
pub mod run;
pub mod spec_json;
pub mod start;
pub mod state;
pub mod update;

fn construct_container_root<P: AsRef<Path>>(root_path: P, container_id: &str) -> Result<PathBuf> {
    // resolves relative paths, symbolic links etc. and get complete path
    let root_path = fs::canonicalize(&root_path).with_context(|| {
        format!(
            "failed to canonicalize {} for container {}",
            root_path.as_ref().display(),
            container_id
        )
    })?;
    // the state of the container is stored in a directory named after the container id
    Ok(root_path.join(container_id))
}

fn load_container<P: AsRef<Path>>(root_path: P, container_id: &str) -> Result<Container> {
    validate_id(container_id).with_context(|| format!("invalid container id {container_id}"))?;

    let container_root = construct_container_root(root_path, container_id)?;
    if !container_root.exists() {
        bail!("container {} does not exist.", container_id)
    }

    Container::load(container_root)
        .with_context(|| format!("could not load state for container {container_id}"))
}

fn container_exists<P: AsRef<Path>>(root_path: P, container_id: &str) -> Result<bool> {
    let container_root = construct_container_root(root_path, container_id)?;
    Ok(container_root.exists())
}

fn create_cgroup_manager<P: AsRef<Path>>(
    root_path: P,
    container_id: &str,
) -> Result<AnyCgroupManager> {
    let container = load_container(root_path, container_id)?;
    Ok(libcgroups::common::create_cgroup_manager(
        libcgroups::common::CgroupConfig {
            cgroup_path: container.spec()?.cgroup_path,
            systemd_cgroup: container.systemd(),
            container_name: container.id().to_string(),
        },
    )?)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::load_container;

    // An invalid container ID must be rejected before resolving it against the root.
    #[test]
    fn load_container_rejects_invalid_id() {
        let root = tempdir().unwrap();

        for id in ["../foo", "/abs", "a/b", "..", ".", ""] {
            let err = load_container(root.path(), id)
                .expect_err(&format!("id {id:?} should be rejected"));
            assert!(
                err.to_string().contains("invalid container id"),
                "id {id:?} should fail id validation, got: {err:#}",
            );
        }
    }

    // A valid container ID must pass validation and fail later if the container
    // does not exist.
    #[test]
    fn load_container_accepts_valid_id_but_reports_missing_container() {
        let root = tempdir().unwrap();

        let err = load_container(root.path(), "valid-id_1")
            .expect_err("no container exists in an empty root");
        let msg = err.to_string();
        assert!(
            msg.contains("does not exist"),
            "a valid id should pass validation and fail on existence, got: {err:#}",
        );
        assert!(
            !msg.contains("invalid container id"),
            "a valid id must not be rejected by id validation, got: {err:#}",
        );
    }
}
