use crate::namespaces::NamespaceError;
use crate::process::channel;
use crate::process::memory_policy::MemoryPolicyError;
#[cfg(feature = "libseccomp")]
use crate::seccomp;
use crate::syscall::SyscallError;
use crate::workload::{ExecutorSetEnvsError, ExecutorValidationError};
use crate::{apparmor, hooks, notify_socket, rootfs, tty, workload};

#[derive(Debug, thiserror::Error)]
pub enum InitProcessError {
    #[error("failed to set sysctl")]
    Sysctl(#[source] std::io::Error),
    #[error("failed to mount path as readonly")]
    MountPathReadonly(#[source] SyscallError),
    #[error("failed to mount path as masked")]
    MountPathMasked(#[source] SyscallError),
    #[error(transparent)]
    Namespaces(#[from] NamespaceError),
    #[error("failed to set hostname")]
    SetHostname(#[source] SyscallError),
    #[error("failed to set domainname")]
    SetDomainname(#[source] SyscallError),
    #[error("failed to reopen /dev/null")]
    ReopenDevNull(#[source] std::io::Error),
    #[error("failed to unix syscall")]
    NixOther(#[source] nix::Error),
    #[error(transparent)]
    MissingSpec(#[from] crate::error::MissingSpecError),
    #[error("failed to setup tty")]
    Tty(#[source] tty::TTYError),
    #[error("failed to run hooks")]
    Hooks(#[from] hooks::HookError),
    #[error("failed to prepare rootfs")]
    RootFS(#[source] rootfs::RootfsError),
    #[error("failed syscall")]
    SyscallOther(#[source] SyscallError),
    #[error("failed apparmor")]
    AppArmor(#[source] apparmor::AppArmorError),
    #[error("invalid umask")]
    InvalidUmask(u32),
    #[error(transparent)]
    #[cfg(feature = "libseccomp")]
    Seccomp(#[from] seccomp::SeccompError),
    #[error("invalid executable: {0}")]
    InvalidExecutable(String),
    #[error("io error")]
    Io(#[source] std::io::Error),
    #[error(transparent)]
    Channel(#[from] channel::ChannelError),
    #[error("setgroup is disabled")]
    SetGroupDisabled,
    #[error(transparent)]
    NotifyListener(#[from] notify_socket::NotifyListenerError),
    #[error(transparent)]
    Workload(#[from] workload::ExecutorError),
    #[error(transparent)]
    WorkloadValidation(#[from] ExecutorValidationError),
    #[error(transparent)]
    WorkloadSetEnvs(#[from] ExecutorSetEnvsError),
    #[error("invalid io priority class: {0}")]
    IoPriorityClass(String),
    #[error("call exec sched_setattr error: {0}")]
    SchedSetattr(String),
    #[error("invalid memory policy: {0}")]
    InvalidMemoryPolicy(String),
    #[error(transparent)]
    MemoryPolicy(#[from] MemoryPolicyError),
    #[error("failed to verify if current working directory is safe")]
    InvalidCwd(#[source] nix::Error),
    #[error("missing linux section in spec")]
    NoLinux,
    #[error("missing process section in spec")]
    NoProcess,
    #[error("personality flag has not supported at this time")]
    UnsupportedPersonalityFlag,
}
