use std::time::{Duration, Instant};

use nix::sys::signal::Signal;

use super::{Container, ContainerStatus};
use crate::config::YoukiConfig;
use crate::error::LibcontainerError;
use crate::hooks;
use crate::notify_socket::{NOTIFY_FILE, NotifySocket};

/// How long `start` waits for init to exit after a poststart hook failure.
/// runc's `delete --force` waits up to 10 s too (`killContainer` in delete.go).
const INIT_EXIT_TIMEOUT: Duration = Duration::from_secs(10);
/// How often `wait_for_init_exit` checks whether init has exited.
const INIT_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

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
                self.stop_after_poststart_failure();
                return Err(err.into());
            }
        }

        Ok(())
    }

    /// Kills the container after a poststart hook failure.
    /// Then waits up to `INIT_EXIT_TIMEOUT` for the init process to exit.
    /// Saves `Stopped` if init exited, and `Running` if not.
    /// Errors are only logged, because `start` returns the hook error.
    fn stop_after_poststart_failure(&mut self) {
        if let Err(kill_err) = self.kill(Signal::SIGKILL, true) {
            tracing::error!(
                id = ?self.id(),
                ?kill_err,
                "failed to stop the container after a post start hook failure"
            );
        }
        // The cgroup kill reaches only the processes the cgroup lists.
        // A rootless cgroup v2 setup can leave init outside it.
        // Signal init by pid too, so the container stops either way.
        if let Some(pid) = self.pid() {
            match nix::sys::signal::kill(pid, Signal::SIGKILL) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                Err(kill_err) => tracing::error!(
                    id = ?self.id(),
                    ?kill_err,
                    ?pid,
                    "failed to kill the container process after a post start hook failure"
                ),
            }
            // Wait for init to exit before returning, as `runc run` does.
            // If init still runs, `youki run` calls `delete`, which kills the cgroup.
            // Without a cgroup directory that kill fails, like the one above.
            // `delete` then stops early and leaves the state directory behind.
            if !self.wait_for_init_exit(INIT_EXIT_TIMEOUT) {
                tracing::error!(
                    id = ?self.id(),
                    ?pid,
                    timeout = ?INIT_EXIT_TIMEOUT,
                    "the container process did not exit after a post start hook failure"
                );
                // No poll saw init exit, so record it as running.
                // If the last `refresh_status` failed, the status is still what `kill` set.
                // `Running` makes `delete --force` kill again; `Stopped` would skip the kill.
                self.set_status(ContainerStatus::Running);
            }
            // Save the status chosen above. The state on disk is stale here.
            // If the cgroup kill fails, `kill` returns before saving anything.
            // If it succeeds, `kill` saves `Stopped` before init has exited.
            if let Err(save_err) = self.save() {
                tracing::error!(
                    id = ?self.id(),
                    ?save_err,
                    "failed to save the state after a post start hook failure"
                );
            }
        }
    }

    /// Refreshes the status until init has exited or `timeout` passes.
    /// Returns whether init exited.
    /// `refresh_status` reports a zombie init as `Stopped`.
    /// It does the same for a pid without a `/proc` entry.
    fn wait_for_init_exit(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            // A failed `refresh_status` counts as "not exited yet", so poll again.
            // It fails when `/proc/<pid>` vanishes between opening it and reading it.
            // The next poll then finds no `/proc` entry and reports `Stopped`.
            if self.refresh_status().is_ok() && self.status() == ContainerStatus::Stopped {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(INIT_EXIT_POLL_INTERVAL);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Result;
    use nix::sys::wait::waitpid;
    use nix::unistd::{ForkResult, Pid, fork, pause};
    use serial_test::serial;

    use super::*;
    use crate::container::State;

    /// A forked child that waits in `pause()` until it is killed.
    /// Dropping it kills and reaps the child, even after a failed assert.
    struct SleepingChild(Pid);

    impl SleepingChild {
        fn spawn() -> Result<Self> {
            match unsafe { fork()? } {
                ForkResult::Parent { child } => Ok(Self(child)),
                ForkResult::Child => loop {
                    pause();
                },
            }
        }
    }

    impl Drop for SleepingChild {
        fn drop(&mut self) {
            let _ = nix::sys::signal::kill(self.0, Signal::SIGKILL);
            let _ = waitpid(self.0, None);
        }
    }

    #[test]
    #[serial]
    fn test_stop_after_poststart_failure_saves_stopped() -> Result<()> {
        let tmp_dir = tempfile::tempdir()?;
        let child = SleepingChild::spawn()?;
        let mut container = Container::new(
            "container_id",
            ContainerStatus::Running,
            Some(child.0.as_raw()),
            &PathBuf::from("."),
            tmp_dir.path(),
        )?;
        container.save()?;

        // `tmp_dir` has no youki_config.json, so the cgroup kill in `kill` fails.
        // It fails before `kill` saves the state.
        // A missing cgroup directory makes it fail the same way.
        container.stop_after_poststart_failure();

        // Nothing reaps the killed child before `child` is dropped.
        // The wait therefore saw a zombie, which `refresh_status` reports as `Stopped`.
        assert_eq!(
            State::load(tmp_dir.path())?.status,
            ContainerStatus::Stopped
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn test_wait_for_init_exit_sees_a_later_exit() -> Result<()> {
        let child = SleepingChild::spawn()?;
        let pid = child.0;
        let mut container = Container::default();
        container.set_pid(pid.as_raw());
        container.set_status(ContainerStatus::Running);

        // Kill the child 50 ms after `started`; the first polls see it running.
        let started = Instant::now();
        let killer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            nix::sys::signal::kill(pid, Signal::SIGKILL)
        });
        let exited = container.wait_for_init_exit(Duration::from_secs(10));
        let elapsed = started.elapsed();
        killer.join().expect("the killer thread panicked")?;

        assert!(exited);
        assert!(elapsed >= Duration::from_millis(50));
        assert_eq!(container.status(), ContainerStatus::Stopped);
        Ok(())
    }

    #[test]
    #[serial]
    fn test_wait_for_init_exit_times_out() -> Result<()> {
        let child = SleepingChild::spawn()?;
        let mut container = Container::default();
        container.set_pid(child.0.as_raw());
        container.set_status(ContainerStatus::Running);

        let started = Instant::now();
        let exited = container.wait_for_init_exit(Duration::from_millis(100));
        let elapsed = started.elapsed();

        assert!(!exited);
        assert_eq!(container.status(), ContainerStatus::Running);
        assert!(elapsed >= Duration::from_millis(100));
        Ok(())
    }

    #[test]
    #[serial]
    fn test_wait_for_init_exit_ignores_a_stale_stopped() -> Result<()> {
        // A successful cgroup kill saves `Stopped` before init has exited.
        // The wait must therefore read the process, not trust that status.
        let child = SleepingChild::spawn()?;
        let mut container = Container::default();
        container.set_pid(child.0.as_raw());
        container.set_status(ContainerStatus::Stopped);

        let exited = container.wait_for_init_exit(Duration::from_millis(100));

        assert!(!exited);
        assert_eq!(container.status(), ContainerStatus::Running);
        Ok(())
    }
}
