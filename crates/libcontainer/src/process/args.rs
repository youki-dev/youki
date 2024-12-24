use std::os::unix::prelude::RawFd;
use std::path::PathBuf;
use std::rc::Rc;

use libcgroups::common::CgroupConfig;
use oci_spec::runtime::Spec;

use crate::container::Container;
use crate::notify_socket::NotifyListener;
use crate::syscall::syscall::SyscallType;
use crate::user_ns::UserNamespaceConfig;
use crate::workload::Executor;

#[derive(Debug, Clone)]
pub enum ContainerType {
    InitContainer { container: Container },
    TenantContainer { exec_notify_fd: RawFd },
}

#[derive(Clone)]
pub struct ContainerArgs {
    /// Indicates if an init or a tenant container should be created
    pub container_type: ContainerType,
    /// Interface to operating system primitives
    pub syscall: SyscallType,
    /// OCI compliant runtime spec
    pub spec: Rc<Spec>,
    /// Root filesystem of the container
    pub rootfs: PathBuf,
    /// Socket to communicate the file descriptor of the ptty
    pub console_socket: Option<RawFd>,
    /// The Unix Domain Socket to communicate container start
    pub notify_listener: NotifyListener,
    /// File descriptors preserved/passed to the container init process.
    pub preserve_fds: i32,
    /// Options for new namespace creation
    pub user_ns_config: Option<UserNamespaceConfig>,
    /// Cgroup Manager Config
    pub cgroup_config: Option<CgroupConfig>,
    /// If the container is to be run in detached mode
    pub detached: bool,
    /// Manage the functions that actually run on the container
    pub executor: Box<dyn Executor>,
    /// If do not use pivot root to jail process inside rootfs
    pub no_pivot: bool,
    // RawFd set to stdin of the container init process.
    pub stdin: Option<RawFd>,
    // RawFd set to stdout of the container init process.
    pub stdout: Option<RawFd>,
    // RawFd set to stderr of the container init process.
    pub stderr: Option<RawFd>,
    // Indicate if the init process should be a sibling of the main process.
    pub as_sibling: bool,
}
