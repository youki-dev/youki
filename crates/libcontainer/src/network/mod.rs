pub mod address;
mod client;
mod fake;
pub mod link;
mod traits;
pub mod wrapper;

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, NetworkError>;

/// Represents a response from a Netlink operation.
///
/// This enum encapsulates the possible outcomes of a Netlink operation:
/// - Success: The operation completed successfully with a response of type T
/// - Error: The operation failed with an error code
/// - Done: The operation completed with no more data to process
#[derive(Debug)]
pub enum NetlinkResponse<T> {
    Success(T),
    Error(i32),
    Done,
}
