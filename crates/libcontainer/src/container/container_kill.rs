use std::error::Error;

use libcgroups::common::{AnyManagerError, CgroupManager, WrappedIoError, get_cgroup_setup};
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
    /// let (mut container, _foreground_pty_fd) = ContainerBuilder::new(
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
                return Err(LibcontainerError::IncorrectStatus(self.status()));
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
            match get_cgroup_setup()? {
                libcgroups::common::CgroupSetup::Legacy
                | libcgroups::common::CgroupSetup::Hybrid => {
                    let cmanager = libcgroups::common::create_cgroup_manager(
                        libcgroups::common::CgroupConfig {
                            cgroup_path: self.spec()?.cgroup_path,
                            systemd_cgroup: self.systemd(),
                            container_name: self.id().to_string(),
                        },
                    )?;
                    cmanager.freeze(libcgroups::common::FreezerState::Thawed)?;
                }
                libcgroups::common::CgroupSetup::Unified => {}
            }
        }
        Ok(())
    }

    fn kill_all_processes<S: Into<Signal>>(&self, signal: S) -> Result<(), LibcontainerError> {
        if self.has_no_cgroup() {
            return if self.can_kill() {
                self.kill_one_process(signal)
            } else {
                Ok(())
            };
        }
        let signal = signal.into().into_raw();
        let cmanager =
            libcgroups::common::create_cgroup_manager(libcgroups::common::CgroupConfig {
                cgroup_path: self.spec()?.cgroup_path,
                systemd_cgroup: self.systemd(),
                container_name: self.id().to_string(),
            })?;

        if let Err(e) = cmanager.freeze(libcgroups::common::FreezerState::Frozen) {
            tracing::warn!(
                err = ?e,
                id = ?self.id(),
                "failed to freeze container",
            );
        }

        let mut pids = match cmanager.get_all_pids() {
            Ok(pids) => pids,
            // Missing directories are tolerated only for legacy init fallback.
            Err(err) if self.state.cgroup_attachment.is_none() && is_missing_cgroup_root(&err) => {
                Vec::new()
            }
            Err(err) => return Err(err.into()),
        };
        // Preserve the previous init fallback only for legacy state files.
        // New containers record whether cgroup attachment actually succeeded.
        if self.state.cgroup_attachment.is_none()
            && let Some(pid) = self.pid()
            && self.can_kill()
            && !pids.contains(&pid)
        {
            tracing::warn!(
                id = ?self.id(),
                ?pid,
                "container init is not in the container cgroup, other processes survive unless the container has its own PID namespace",
            );
            pids.push(pid);
        }
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

fn is_missing_cgroup_root(error: &AnyManagerError) -> bool {
    error
        .source()
        .and_then(|error| error.downcast_ref::<WrappedIoError>())
        .is_some_and(|error| {
            matches!(error, WrappedIoError::Other { err, .. }
                if err.kind() == std::io::ErrorKind::NotFound)
        })
}

#[cfg(all(test, feature = "v2"))]
mod tests {
    use std::io::{Error, ErrorKind};

    use libcgroups::v2::manager::V2ManagerError;

    use super::*;

    #[test]
    fn test_missing_root_does_not_include_scan_errors() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("missing");
        let cases = [
            (libcgroups::common::get_all_pids(&path).unwrap_err(), true),
            (
                WrappedIoError::Read {
                    err: ErrorKind::NotFound.into(),
                    path: path.clone(),
                },
                false,
            ),
            (
                WrappedIoError::Other {
                    err: ErrorKind::PermissionDenied.into(),
                    path: path.clone(),
                },
                false,
            ),
            (
                WrappedIoError::Open {
                    err: ErrorKind::NotFound.into(),
                    path: path.clone(),
                },
                false,
            ),
            (
                WrappedIoError::Other {
                    err: Error::new(ErrorKind::InvalidData, "bad pid"),
                    path,
                },
                false,
            ),
        ];
        for (error, expected) in cases {
            let error = AnyManagerError::V2(V2ManagerError::WrappedIo(error));
            assert_eq!(is_missing_cgroup_root(&error), expected, "{error}");
        }
    }
}
