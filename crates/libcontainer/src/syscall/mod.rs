//! Contains a wrapper of syscalls for unit tests
//! This provides a uniform interface for rest of Youki
//! to call syscalls required for container management

pub mod linux;
#[allow(clippy::module_inception)]
pub mod syscall;
pub mod test;

pub use syscall::Syscall;
#[derive(Debug, thiserror::Error)]
pub enum SyscallError {
    #[error("unexpected mount attr option: {0}")]
    UnexpectedMountRecursiveOption(String),
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error("failed to set capabilities: {0}")]
    SetCaps(#[from] caps::errors::CapsError),
    #[error(transparent)]
    Pathrs(#[from] pathrs::error::Error),
}

type Result<T> = std::result::Result<T, SyscallError>;
