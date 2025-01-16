use std::collections::HashMap;
use std::fs::create_dir;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::Path;

use anyhow::Result;
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use libcontainer::workload::{
    Executor, ExecutorError, ExecutorSetEnvsError, ExecutorValidationError,
};
use nix::unistd::{getegid, geteuid};
use oci_spec::runtime::{RootBuilder, Spec};
use procfs::process::Process;
use serial_test::serial;
use tempfile::tempdir;

fn prepare_container_root(root: impl AsRef<Path>) -> Result<()> {
    let root = root.as_ref();
    create_dir(root.join("rootfs"))?;

    let uid = geteuid().as_raw();
    let gid = getegid().as_raw();

    let mut spec = Spec::rootless(uid, gid);
    spec.set_root(
        RootBuilder::default()
            .path("rootfs")
            .readonly(false)
            .build()
            .ok(),
    );

    spec.save(root.join("config.json"))?;

    Ok(())
}

fn hash(v: impl Hash) -> u64 {
    let mut hasher = DefaultHasher::default();
    v.hash(&mut hasher);
    hasher.finish()
}

#[derive(Clone)]
struct SomeExecutor;

impl Executor for SomeExecutor {
    fn setup_envs(&self, _: HashMap<String, String>) -> Result<(), ExecutorSetEnvsError> {
        Ok(())
    }

    fn validate(&self, _: &Spec) -> Result<(), ExecutorValidationError> {
        Ok(())
    }

    fn exec(&self, _: &Spec) -> Result<(), ExecutorError> {
        Ok(())
    }
}

#[test]
#[serial]
fn run_init_process_as_child() -> Result<()> {
    let root = tempdir()?;
    prepare_container_root(&root)?;

    let id = format!("test-container-{:x}", hash(root.as_ref()));
    let container = ContainerBuilder::new(id, SyscallType::Linux)
        .with_executor(SomeExecutor)
        .with_root_path(root.as_ref())?
        .as_init(root.as_ref())
        .build()?;

    let container = scopeguard::guard(container, |mut container| {
        let _ = container.delete(true);
    });

    let init_pid = container.pid().unwrap().as_raw();

    let init_ppid = Process::new(init_pid)?.stat()?.ppid;
    let this_pid = Process::myself()?.pid();

    assert_eq!(init_ppid, this_pid);

    Ok(())
}

#[test]
#[serial]
fn run_init_process_as_sibling() -> Result<()> {
    let root = tempdir()?;
    prepare_container_root(&root)?;

    let id = format!("test-container-{:x}", hash(root.as_ref()));
    let container = ContainerBuilder::new(id, SyscallType::Linux)
        .with_executor(SomeExecutor)
        .with_root_path(root.as_ref())?
        .as_init(root.as_ref())
        .as_sibling(true)
        .build()?;

    let container = scopeguard::guard(container, |mut container| {
        let _ = container.delete(true);
    });

    let init_pid = container.pid().unwrap().as_raw();

    let init_ppid = Process::new(init_pid)?.stat()?.ppid;
    let this_ppid = Process::myself()?.stat()?.ppid;

    assert_eq!(init_ppid, this_ppid);

    Ok(())
}
