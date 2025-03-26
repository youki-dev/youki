#[derive(Debug, thiserror::Error)]
pub enum MissingSpecError {
    #[error("missing process in spec")]
    Process,
    #[error("missing linux in spec")]
    Linux,
    #[error("missing args in the process spec")]
    Args,
    #[error("missing root in the spec")]
    Root,
}

#[derive(Debug, thiserror::Error)]
pub enum LibcontainerError {
    #[error("failed to perform operation due to incorrect container status")]
    IncorrectStatus,
    #[error("requested operation requires cgroups to be enabled on the container")]
    CgroupsMissing,
    #[error("container already exists")]
    Exist,
    #[error("container state directory does not exist")]
    NoDirectory,
    #[error("invalid input")]
    InvalidInput(String),
    #[error("requires at least one executors")]
    NoExecutors,
    #[error("rootless container requires valid user namespace definition")]
    NoUserNamespace,

    // Invalid inputs
    #[error(transparent)]
    InvalidID(#[from] ErrInvalidID),
    #[error(transparent)]
    MissingSpec(#[from] MissingSpecError),
    #[error("invalid runtime spec")]
    InvalidSpec(#[from] ErrInvalidSpec),

    // Errors from submodules and other errors
    #[error(transparent)]
    Tty(#[from] crate::tty::TTYError),
    #[error(transparent)]
    UserNamespace(#[from] crate::user_ns::UserNamespaceError),
    #[error(transparent)]
    NotifyListener(#[from] crate::notify_socket::NotifyListenerError),
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Hook(#[from] crate::hooks::HookError),
    #[error(transparent)]
    State(#[from] crate::container::state::StateError),
    #[error("oci spec error")]
    Spec(#[from] oci_spec::OciSpecError),
    #[error(transparent)]
    MainProcess(#[from] crate::process::container_main_process::ProcessError),
    #[error(transparent)]
    Procfs(#[from] procfs::ProcError),
    #[error(transparent)]
    Capabilities(#[from] caps::errors::CapsError),
    #[error(transparent)]
    CgroupManager(#[from] libcgroups::common::AnyManagerError),
    #[error(transparent)]
    CgroupCreate(#[from] libcgroups::common::CreateCgroupSetupError),
    #[error(transparent)]
    CgroupGet(#[from] libcgroups::common::GetCgroupSetupError),
    #[error[transparent]]
    Checkpoint(#[from] crate::container::CheckpointError),
    #[error[transparent]]
    CreateContainerError(#[from] CreateContainerError),

    // Catch all errors that are not covered by the above
    #[error("syscall error")]
    OtherSyscall(#[source] nix::Error),
    #[error("io error")]
    OtherIO(#[source] std::io::Error),
    #[error("serialization error")]
    OtherSerialization(#[source] serde_json::Error),
    #[error("{0}")]
    OtherCgroup(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ErrInvalidID {
    #[error("container id can't be empty")]
    Empty,
    #[error("container id contains invalid characters: {0}")]
    InvalidChars(char),
    #[error("container id can't be used to represent a file name (such as . or ..)")]
    FileName,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrInvalidSpec {
    #[error("runtime spec has incompatible version. Only 1.X.Y is supported")]
    UnsupportedVersion,
    #[error("apparmor is specified but not enabled on this system")]
    AppArmorNotEnabled,
    #[error("invalid io priority or class.")]
    IoPriority,
    #[error("invalid scheduler config for process")]
    Scheduler,
}

#[derive(Debug, thiserror::Error)]
pub struct CreateContainerError(Box<LibcontainerError>, Option<Box<LibcontainerError>>);

impl CreateContainerError {
    pub(crate) fn new(
        run_error: LibcontainerError,
        cleanup_error: Option<LibcontainerError>,
    ) -> Self {
        Self(Box::new(run_error), cleanup_error.map(Box::new))
    }
}

impl std::fmt::Display for CreateContainerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to create container: {}", self.0)?;
        if let Some(cleanup_err) = &self.1 {
            write!(f, ". error during cleanup: {}", cleanup_err)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use libcgroups::common::CreateCgroupSetupError;

    use super::{CreateContainerError, ErrInvalidID};

    #[test]
    fn test_create_container() {
        let create_container_err =
            CreateContainerError::new(CreateCgroupSetupError::NonDefault.into(), None);
        let msg = format!("{}", create_container_err);
        assert_eq!(
            "failed to create container: non default cgroup root not supported",
            msg
        );

        let create_container_err = CreateContainerError::new(
            CreateCgroupSetupError::NonDefault.into(),
            Some(ErrInvalidID::Empty.into()),
        );
        let msg = format!("{}", create_container_err);
        assert_eq!(
            "failed to create container: non default cgroup root not supported. \
         error during cleanup: container id can't be empty",
            msg
        );
    }
}
