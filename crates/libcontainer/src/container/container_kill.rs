use libcgroups::common::{get_cgroup_setup, CgroupManager};
use nix::sys::signal::{self};

use super::{Container, ContainerStatus};
use crate::error::LibcontainerError;
use crate::signal::Signal;

impl Container {
    /// Sends the specified signal to the container init process
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libcontainer::container::builder::ContainerBuilder;
    /// use libcontainer::syscall::syscall::SyscallType;
    /// use nix::sys::signal::Signal;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// let mut container = ContainerBuilder::new(
    ///     "74f1a4cb3801".to_owned(),
    ///     SyscallType::default(),
    /// )
    /// .as_init("/var/run/docker/bundle")
    /// .build()?;
    ///
    /// container.kill(Signal::SIGKILL, false)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn kill<S: Into<Signal>>(&mut self, signal: S, all: bool) -> Result<(), LibcontainerError> {
        self.refresh_status()?;
        match self.can_kill() {
            true => {
                self.do_kill(signal, all)?;
            }
            false if all && self.status() == ContainerStatus::Stopped => {
                self.do_kill(signal, all)?;
            }
            false => {
                tracing::error!(id = ?self.id(), status = ?self.status(), "cannot kill container due to incorrect state");
                return Err(LibcontainerError::IncorrectStatus);
            }
        }
        self.set_status(ContainerStatus::Stopped).save()?;
        Ok(())
    }

    pub(crate) fn do_kill<S: Into<Signal>>(
        &self,
        signal: S,
        all: bool,
    ) -> Result<(), LibcontainerError> {
        if all {
            self.kill_all_processes(signal)
        } else {
            self.kill_one_process(signal)
        }
    }

    fn kill_one_process<S: Into<Signal>>(&self, signal: S) -> Result<(), LibcontainerError> {
        let signal = signal.into().into_raw();
        let pid = self.pid().ok_or(LibcontainerError::Other(
            "container process pid not found in state".into(),
        ))?;

        tracing::debug!("kill signal {} to {}", signal, pid);

        match signal::kill(pid, signal) {
            Ok(_) => {}
            Err(nix::errno::Errno::ESRCH) => {
                // the process does not exist, which is what we want
            }
            Err(err) => {
                tracing::error!(id = ?self.id(), err = ?err, ?pid, ?signal, "failed to kill process");
                return Err(LibcontainerError::OtherSyscall(err));
            }
        }

        // For cgroup V1, a frozon process cannot respond to signals,
        // so we need to thaw it. Only thaw the cgroup for SIGKILL.
        if self.status() == ContainerStatus::Paused && signal == signal::Signal::SIGKILL {
            if let Some(cgroup_config) = self.spec()?.cgroup_config {
                match get_cgroup_setup()? {
                    libcgroups::common::CgroupSetup::Legacy
                    | libcgroups::common::CgroupSetup::Hybrid => {
                        let cmanager = libcgroups::common::create_cgroup_manager(cgroup_config)?;
                        cmanager.freeze(libcgroups::common::FreezerState::Thawed)?;
                    }
                    libcgroups::common::CgroupSetup::Unified => {}
                }
            } else {
                return Err(LibcontainerError::CgroupsMissing);
            }
        }
        Ok(())
    }

    fn kill_all_processes<S: Into<Signal>>(&self, signal: S) -> Result<(), LibcontainerError> {
        let cgroup_config = match self.spec()?.cgroup_config {
            Some(cc) => cc,
            None => return Err(LibcontainerError::CgroupsMissing),
        };

        let signal = signal.into().into_raw();
        let cmanager = libcgroups::common::create_cgroup_manager(cgroup_config)?;

        if let Err(e) = cmanager.freeze(libcgroups::common::FreezerState::Frozen) {
            tracing::warn!(
                err = ?e,
                id = ?self.id(),
                "failed to freeze container",
            );
        }

        let pids = cmanager.get_all_pids()?;
        pids.iter()
            .try_for_each(|&pid| {
                tracing::debug!("kill signal {} to {}", signal, pid);
                let res = signal::kill(pid, signal);
                match res {
                    Err(nix::errno::Errno::ESRCH) => {
                        // the process does not exist, which is what we want
                        Ok(())
                    }
                    _ => res,
                }
            })
            .map_err(LibcontainerError::OtherSyscall)?;
        if let Err(err) = cmanager.freeze(libcgroups::common::FreezerState::Thawed) {
            tracing::warn!(
                err = ?err,
                id = ?self.id(),
                "failed to thaw container",
            );
        }

        Ok(())
    }
}
