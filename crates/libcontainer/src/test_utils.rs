use nix::sys::wait;
use serde::{Deserialize, Serialize};

// Normally, error types are not implemented as serialize/deserialize, but to
// pass the error from the child process to the parent process, we need to
// implement an error type that can be serialized and deserialized.
#[derive(Debug, Serialize, Deserialize)]
struct ErrorEnclosure {
    source: Option<Box<ErrorEnclosure>>,
    description: String,
}

impl ErrorEnclosure {
    pub fn new<T>(e: &T) -> ErrorEnclosure
    where
        T: ?Sized + std::error::Error,
    {
        ErrorEnclosure {
            description: e.to_string(),
            source: e.source().map(|s| Box::new(ErrorEnclosure::new(s))),
        }
    }
}

impl std::fmt::Display for ErrorEnclosure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description)
    }
}

impl std::error::Error for ErrorEnclosure {
    fn source(&self) -> Option<&(dyn 'static + std::error::Error)> {
        self.source
            .as_ref()
            .map(|source| &**source as &(dyn 'static + std::error::Error))
    }

    fn description(&self) -> &str {
        &self.description
    }
}

type ClosureResult = Result<(), ErrorEnclosure>;

#[derive(Debug, thiserror::Error)]
pub enum TestError {
    #[error("failed to create channel")]
    Channel(#[from] crate::channel::ChannelError),
    #[error("failed to fork")]
    Fork(#[source] nix::Error),
    #[error("failed to wait for child process")]
    Wait(#[source] nix::Error),
    #[error("failed to run function in child process")]
    Execution(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("the closure caused the child process to panic")]
    Panic,
}

#[derive(Debug, thiserror::Error)]
pub enum TestCallbackError {
    #[error("{0}")]
    Custom(String),
    #[error("{0:?}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl From<&str> for TestCallbackError {
    fn from(s: &str) -> Self {
        TestCallbackError::Custom(s.to_string())
    }
}

impl From<String> for TestCallbackError {
    fn from(s: String) -> Self {
        TestCallbackError::Custom(s)
    }
}

pub fn test_in_child_process<F>(cb: F) -> Result<(), TestError>
where
    F: FnOnce() -> Result<(), TestCallbackError> + std::panic::UnwindSafe,
{
    let (mut sender, mut receiver) = crate::channel::channel::<ClosureResult>()?;
    match unsafe { nix::unistd::fork().map_err(TestError::Fork)? } {
        nix::unistd::ForkResult::Parent { child } => {
            // Close unused senders
            sender.close().map_err(TestError::Channel)?;
            let res = receiver.recv().map_err(TestError::Channel)?;
            wait::waitpid(child, None).map_err(TestError::Wait)?;
            res.map_err(|err| TestError::Execution(Box::new(err)))?;
        }
        nix::unistd::ForkResult::Child => {
            // Close unused receiver in the child
            receiver.close().map_err(TestError::Channel)?;
            let test_result = match std::panic::catch_unwind(cb) {
                Ok(ret) => ret.map_err(|err| ErrorEnclosure::new(&err)),
                Err(_) => Err(ErrorEnclosure::new(&TestError::Panic)),
            };

            // If we can't send the error to the parent process, there is
            // nothing we can do other than exit properly.
            let _ = sender.send(test_result);
            std::process::exit(0);
        }
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use core::panic;

    use anyhow::{Result, bail};

    use super::*;

    #[test]
    fn test_child_process() -> Result<()> {
        if test_in_child_process(|| Err(TestCallbackError::Custom("test error".to_string())))
            .is_ok()
        {
            bail!("expecting the child process to return an error")
        }

        Ok(())
    }

    #[test]
    fn test_panic_child_process() -> Result<()> {
        let ret = test_in_child_process(|| {
            panic!("test panic");
        });
        if ret.is_ok() {
            bail!("expecting the child process to panic")
        }

        Ok(())
    }
}
