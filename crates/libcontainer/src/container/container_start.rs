use nix::sys::signal::Signal;

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
    /// let (mut container, _foreground_pty_fd) = ContainerBuilder::new(
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
            return Err(LibcontainerError::IncorrectStatus(self.status()));
        }

        let config = YoukiConfig::load(&self.root).map_err(|err| {
            tracing::error!(
                "failed to load runtime spec for container {}: {}",
                self.id(),
                err
            );
            err
        })?;

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
            if let Err(err) = hooks::run_hooks(
                hooks.poststart().as_ref(),
                Some(&self.state),
                Some(&self.root),
                None,
                None,
            ) {
                // The OCI runtime spec (lifecycle step 9): if any poststart hook
                // fails, the runtime MUST generate an error, stop the container,
                // and continue the lifecycle at step 12 (destroy). Kill every
                // process of the container, as `delete` does, so the container
                // is really stopped, record the state, and then return the hook
                // error; the caller's `delete` runs the poststop hooks.
                tracing::error!("failed to run post start hooks: {}", err);
                if let Err(kill_err) = self.kill(Signal::SIGKILL, true) {
                    tracing::error!(
                        id = ?self.id(),
                        ?kill_err,
                        "failed to stop the container after a post start hook failure"
                    );
                }
                return Err(err.into());
            }
        }

        Ok(())
    }
}
