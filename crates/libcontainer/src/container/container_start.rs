use nix::sys::signal;

use super::{Container, ContainerStatus};
use crate::config::YoukiConfig;
use crate::error::LibcontainerError;
use crate::hooks;
use crate::notify_socket::{NOTIFY_FILE, NotifySocket};

impl Container {
    /// Starts a previously created container
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libcontainer::container::builder::ContainerBuilder;
    /// use libcontainer::syscall::syscall::SyscallType;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// let mut container = ContainerBuilder::new(
    ///     "74f1a4cb3801".to_owned(),
    ///     SyscallType::default(),
    /// )
    /// .as_init("/var/run/docker/bundle")
    /// .build()?;
    ///
    /// container.start();
    /// # Ok(())
    /// # }
    /// ```
    pub fn start(&mut self) -> Result<(), LibcontainerError> {
        self.refresh_status()?;

        if !self.can_start() {
            tracing::error!(status = ?self.status(), id = ?self.id(), "cannot start container due to incorrect state");
            return Err(LibcontainerError::IncorrectStatus);
        }

        let config = YoukiConfig::load(&self.root).map_err(|err| {
            tracing::error!(
                "failed to load runtime spec for container {}: {}",
                self.id(),
                err
            );
            err
        })?;
        if let Some(hooks) = config.hooks.as_ref() {
            // While prestart is marked as deprecated in the OCI spec, the docker and integration test still
            // uses it.
            #[allow(deprecated)]
            hooks::run_hooks(hooks.prestart().as_ref(), Some(self), None).map_err(|err| {
                tracing::error!("failed to run pre start hooks: {}", err);
                // In the case where prestart hook fails, the runtime must
                // stop the container before generating an error and exiting.
                let _ = self.kill(signal::Signal::SIGKILL, true);

                err
            })?;
        }

        let mut notify_socket = NotifySocket::new(self.root.join(NOTIFY_FILE));
        notify_socket.notify_container_start()?;
        self.set_status(ContainerStatus::Running)
            .save()
            .map_err(|err| {
                tracing::error!(id = ?self.id(), ?err, "failed to save state for container");
                err
            })?;

        // Run post start hooks. It runs after the container process is started.
        // It is called in the runtime namespace.
        if let Some(hooks) = config.hooks.as_ref() {
            hooks::run_hooks(hooks.poststart().as_ref(), Some(self), Some(&self.root)).map_err(
                |err| {
                    tracing::error!("failed to run post start hooks: {}", err);
                    err
                },
            )?;
        }

        Ok(())
    }
}
