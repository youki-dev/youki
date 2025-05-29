mod context;
pub mod error;
pub mod process;

pub use process::container_init_process;

type Result<T> = std::result::Result<T, error::InitProcessError>;
