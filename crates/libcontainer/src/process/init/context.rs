use std::collections::HashMap;
use std::path::Path;

use oci_spec::runtime;

use super::Result;
use crate::container::Container;
use crate::error::MissingSpecError;
use crate::namespaces::Namespaces;
use crate::process::args::ContainerArgs;
use crate::syscall::Syscall;
use crate::{notify_socket, utils};

pub(crate) struct InitContext<'a> {
    pub(crate) spec: &'a runtime::Spec,
    pub(crate) linux: &'a runtime::Linux,
    pub(crate) process: &'a runtime::Process,
    pub(crate) rootfs: &'a Path,
    pub(crate) envs: HashMap<String, String>,
    pub(crate) ns: Namespaces,
    pub(crate) syscall: Box<dyn Syscall>,
    pub(crate) notify_listener: &'a notify_socket::NotifyListener,
    pub(crate) hooks: Option<&'a runtime::Hooks>,
    pub(crate) container: Option<&'a Container>,
    pub(crate) rootfs_ro: bool,
}

impl<'a> InitContext<'a> {
    pub fn builder(args: &'a ContainerArgs) -> Result<Self> {
        let spec = args.spec.as_ref();
        let linux = spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;
        let process = spec.process().as_ref().ok_or(MissingSpecError::Process)?;
        let envs: HashMap<String, String> =
            utils::parse_env(process.env().as_ref().unwrap_or(&vec![]));
        let rootfs = spec.root().as_ref().ok_or(MissingSpecError::Root)?;
        let rootfs_ro = rootfs.readonly().unwrap_or(false);

        Ok(Self {
            spec,
            linux,
            process,
            rootfs: &args.rootfs,
            envs,
            rootfs_ro,
            ns: Namespaces::try_from(linux.namespaces().as_ref())?,
            syscall: args.syscall.create_syscall(),
            notify_listener: &args.notify_listener,
            hooks: spec.hooks().as_ref(),
            container: args.container.as_ref(),
        })
    }
}
