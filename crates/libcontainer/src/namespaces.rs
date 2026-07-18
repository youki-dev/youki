//! Namespaces provide isolation of resources for processes at a kernel level.
//! The namespaces are: Mount (filesystem),
//! Process (processes in a namespace have two PIDs, one for the global PID,
//! which is used by the main system and the second one is for the child within the process tree),
//! Interprocess Communication (Control or communication between processes),
//! Network (which network devices can be seen by the processes in the namespace), User (User configs),
//! UTS (hostname and domain information, processes will think they're running on servers with different names),
//! Cgroup (Resource limits, execution priority etc.)

use std::collections;

use nix::sched::CloneFlags;
use nix::sys::stat;
use nix::{fcntl, unistd};
use oci_spec::runtime::{LinuxNamespace, LinuxNamespaceType};

use crate::syscall::Syscall;
use crate::syscall::syscall::create_syscall;

type Result<T> = std::result::Result<T, NamespaceError>;

#[derive(Debug, thiserror::Error)]
pub enum NamespaceError {
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    Syscall(#[from] crate::syscall::SyscallError),
    #[error("Namespace type not supported: {0}")]
    NotSupported(String),
}

static ORDERED_NAMESPACES: &[CloneFlags] = &[
    CloneFlags::CLONE_NEWUSER,
    CloneFlags::CLONE_NEWPID,
    CloneFlags::CLONE_NEWUTS,
    CloneFlags::CLONE_NEWIPC,
    CloneFlags::CLONE_NEWNET,
    CloneFlags::CLONE_NEWCGROUP,
    CloneFlags::CLONE_NEWNS,
];

/// Holds information about namespaces
pub struct Namespaces {
    command: Box<dyn Syscall>,
    namespace_map: collections::HashMap<CloneFlags, LinuxNamespace>,
}

fn get_clone_flag(namespace_type: LinuxNamespaceType) -> Result<CloneFlags> {
    let flag = match namespace_type {
        LinuxNamespaceType::User => CloneFlags::CLONE_NEWUSER,
        LinuxNamespaceType::Pid => CloneFlags::CLONE_NEWPID,
        LinuxNamespaceType::Uts => CloneFlags::CLONE_NEWUTS,
        LinuxNamespaceType::Ipc => CloneFlags::CLONE_NEWIPC,
        LinuxNamespaceType::Network => CloneFlags::CLONE_NEWNET,
        LinuxNamespaceType::Cgroup => CloneFlags::CLONE_NEWCGROUP,
        LinuxNamespaceType::Mount => CloneFlags::CLONE_NEWNS,
        LinuxNamespaceType::Time => return Err(NamespaceError::NotSupported("time".to_string())),
    };

    Ok(flag)
}

impl TryFrom<Option<&Vec<LinuxNamespace>>> for Namespaces {
    type Error = NamespaceError;

    fn try_from(namespaces: Option<&Vec<LinuxNamespace>>) -> Result<Self> {
        let command: Box<dyn Syscall> = create_syscall();
        let namespace_map: collections::HashMap<CloneFlags, LinuxNamespace> = namespaces
            .unwrap_or(&vec![])
            .iter()
            .map(|ns| match get_clone_flag(ns.typ()) {
                Ok(flag) => Ok((flag, ns.clone())),
                Err(err) => Err(err),
            })
            .collect::<Result<Vec<(CloneFlags, LinuxNamespace)>>>()?
            .into_iter()
            .collect();

        Ok(Namespaces {
            command,
            namespace_map,
        })
    }
}

impl Namespaces {
    pub fn apply_namespaces<F: Fn(CloneFlags) -> bool>(&self, filter: F) -> Result<()> {
        let to_enter: Vec<(&CloneFlags, &LinuxNamespace)> = ORDERED_NAMESPACES
            .iter()
            .filter(|c| filter(**c))
            .filter_map(|c| self.namespace_map.get_key_value(c))
            .collect();

        for (_, ns) in to_enter {
            self.unshare_or_setns(ns)?;
        }
        Ok(())
    }

    pub fn unshare_or_setns(&self, namespace: &LinuxNamespace) -> Result<()> {
        tracing::debug!("unshare or setns: {:?}", namespace);
        match namespace.path() {
            Some(path) => {
                let fd = fcntl::open(path, fcntl::OFlag::empty(), stat::Mode::empty())
                    .inspect_err(|err| {
                        tracing::error!(?err, ?namespace, "failed to open namespace file");
                    })?;
                self.command
                    .set_ns(fd, get_clone_flag(namespace.typ())?)
                    .map_err(|err| {
                        tracing::error!(?err, ?namespace, "failed to set namespace");
                        err
                    })?;
                unistd::close(fd).inspect_err(|err| {
                    tracing::error!(?err, ?namespace, "failed to close namespace file");
                })?;
            }
            None => {
                self.command
                    .unshare(get_clone_flag(namespace.typ())?)
                    .map_err(|err| {
                        tracing::error!(?err, ?namespace, "failed to unshare namespace");
                        err
                    })?;
            }
        }

        Ok(())
    }

    pub fn get(&self, k: LinuxNamespaceType) -> Result<Option<&LinuxNamespace>> {
        Ok(self.namespace_map.get(&get_clone_flag(k)?))
    }
}

#[cfg(test)]
mod tests {
    use oci_spec::runtime::{LinuxNamespaceBuilder, LinuxNamespaceType};
    use serial_test::serial;

    use super::*;
    use crate::syscall::test::TestHelperSyscall;

    fn gen_sample_linux_namespaces() -> Vec<LinuxNamespace> {
        vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Mount)
                .path("/dev/null")
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Network)
                .path("/dev/null")
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Pid)
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::User)
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Ipc)
                .build()
                .unwrap(),
        ]
    }

    #[test]
    #[serial]
    fn test_apply_namespaces() {
        let sample_linux_namespaces = gen_sample_linux_namespaces();
        let namespaces = Namespaces::try_from(Some(&sample_linux_namespaces))
            .expect("create namespace struct should be good");
        let test_command: &TestHelperSyscall = namespaces.command.as_any().downcast_ref().unwrap();
        assert!(
            namespaces
                .apply_namespaces(|ns_type| { ns_type != CloneFlags::CLONE_NEWIPC })
                .is_ok()
        );

        let mut setns_args: Vec<_> = test_command
            .get_setns_args()
            .into_iter()
            .map(|(_fd, cf)| cf)
            .collect();
        setns_args.sort();
        let mut expect = vec![CloneFlags::CLONE_NEWNS, CloneFlags::CLONE_NEWNET];
        expect.sort();
        assert_eq!(setns_args, expect);

        let mut unshare_args = test_command.get_unshare_args();
        unshare_args.sort();
        let mut expect = vec![CloneFlags::CLONE_NEWUSER, CloneFlags::CLONE_NEWPID];
        expect.sort();
        assert_eq!(unshare_args, expect)
    }
}
