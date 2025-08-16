//! During kernel initialization, a minimal replica of the ramfs filesystem is
//! loaded, called rootfs.  Most systems mount another filesystem over it

#[allow(clippy::module_inception)]
pub(crate) mod rootfs;
pub use rootfs::RootFS;

pub mod device;
pub use device::Device;

pub(super) mod mount;
pub use mount::Mount;

pub(super) mod symlink;

pub mod utils;

#[derive(Debug, thiserror::Error)]
pub enum RootfsError {
    #[error("failed syscall")]
    Syscall(#[from] crate::syscall::SyscallError),
    #[error(transparent)]
    MissingSpec(#[from] crate::error::MissingSpecError),
    #[error("unknown rootfs propagation")]
    UnknownRootfsPropagation(String),
    #[error(transparent)]
    Symlink(#[from] symlink::SymlinkError),
    #[error(transparent)]
    Mount(#[from] mount::MountError),
    #[error(transparent)]
    Device(#[from] device::DeviceError),
}

type Result<T> = std::result::Result<T, RootfsError>;
