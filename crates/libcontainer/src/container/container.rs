use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use nix::unistd::Pid;
use procfs::process::Process;

use crate::config::YoukiConfig;
use crate::container::{ContainerStatus, State};
use crate::error::LibcontainerError;
use crate::syscall::syscall::create_syscall;

/// Structure representing the container data
#[derive(Debug, Clone)]
pub struct Container {
    // State of the container
    pub state: State,
    // indicated the directory for the root path in the container
    pub root: PathBuf,
}

impl Default for Container {
    fn default() -> Self {
        Self {
            state: State::default(),
            root: PathBuf::from("/run/youki"),
        }
    }
}

impl Container {
    pub fn new(
        container_id: &str,
        status: ContainerStatus,
        pid: Option<i32>,
        bundle: &Path,
        container_root: &Path,
    ) -> Result<Self, LibcontainerError> {
        let container_root = fs::canonicalize(container_root).map_err(|err| {
            LibcontainerError::InvalidInput(format!(
                "invalid container root {container_root:?}: {err:?}"
            ))
        })?;
        let bundle = fs::canonicalize(bundle).map_err(|err| {
            LibcontainerError::InvalidInput(format!("invalid bundle {bundle:?}: {err:?}"))
        })?;
        let state = State::new(container_id, status, pid, bundle);

        Ok(Self {
            state,
            root: container_root,
        })
    }

    pub fn id(&self) -> &str {
        &self.state.id
    }

    pub fn can_start(&self) -> bool {
        self.state.status.can_start()
    }

    pub fn can_kill(&self) -> bool {
        self.state.status.can_kill()
    }

    pub fn can_delete(&self) -> bool {
        self.state.status.can_delete()
    }

    pub fn can_exec(&self) -> bool {
        self.state.status == ContainerStatus::Running
    }

    pub fn can_pause(&self) -> bool {
        self.state.status.can_pause()
    }

    pub fn can_resume(&self) -> bool {
        self.state.status.can_resume()
    }

    pub fn bundle(&self) -> &PathBuf {
        &self.state.bundle
    }

    pub fn set_annotations(&mut self, annotations: Option<HashMap<String, String>>) -> &mut Self {
        self.state.annotations = annotations;
        self
    }

    pub fn pid(&self) -> Option<Pid> {
        self.state.pid.map(Pid::from_raw)
    }

    pub fn set_pid(&mut self, pid: i32) -> &mut Self {
        self.state.pid = Some(pid);
        self
    }

    pub fn created(&self) -> Option<DateTime<Utc>> {
        self.state.created
    }

    pub fn creator(&self) -> Option<OsString> {
        if let Some(uid) = self.state.creator {
            let command = create_syscall();
            let user_name = command.get_pwuid(uid);
            if let Some(user_name) = user_name {
                return Some((*user_name).to_owned());
            }
        }

        None
    }

    pub fn set_creator(&mut self, uid: u32) -> &mut Self {
        self.state.creator = Some(uid);
        self
    }

    pub fn set_clean_up_intel_rdt_directory(&mut self, clean_up: bool) -> &mut Self {
        self.state.clean_up_intel_rdt_subdirectory = Some(clean_up);
        self
    }

    pub fn clean_up_intel_rdt_subdirectory(&self) -> Option<bool> {
        self.state.clean_up_intel_rdt_subdirectory
    }

    pub fn status(&self) -> ContainerStatus {
        self.state.status
    }

    pub fn set_status(&mut self, status: ContainerStatus) -> &mut Self {
        let created = match (status, self.state.created) {
            (ContainerStatus::Created, None) => Some(Utc::now()),
            _ => self.state.created,
        };

        self.state.created = created;
        self.state.status = status;

        self
    }

    pub fn refresh_status(&mut self) -> Result<(), LibcontainerError> {
        let new_status = match self.pid() {
            Some(pid) => {
                // Note that Process::new does not spawn a new process
                // but instead creates a new Process structure, and fill
                // it with information about the process with given pid
                if let Ok(proc) = Process::new(pid.as_raw()) {
                    use procfs::process::ProcState;

                    match proc.stat()?.state()? {
                        ProcState::Zombie | ProcState::Dead => ContainerStatus::Stopped,
                        _ => match self.status() {
                            ContainerStatus::Creating
                            | ContainerStatus::Created
                            | ContainerStatus::Paused => self.status(),
                            _ => ContainerStatus::Running,
                        },
                    }
                } else {
                    ContainerStatus::Stopped
                }
            }
            None => ContainerStatus::Stopped,
        };

        self.set_status(new_status);
        Ok(())
    }

    pub fn refresh_state(&mut self) -> Result<&mut Self, LibcontainerError> {
        let state = State::load(&self.root)?;
        self.state = state;

        Ok(self)
    }

    pub fn load(container_root: PathBuf) -> Result<Self, LibcontainerError> {
        let state = State::load(&container_root)?;
        let mut container = Self {
            state,
            root: container_root,
        };
        container.refresh_status()?;
        Ok(container)
    }

    pub fn save(&self) -> Result<(), LibcontainerError> {
        tracing::debug!("Save container status: {:?} in {:?}", self, self.root);
        self.state.save(&self.root)?;

        Ok(())
    }

    pub fn spec(&self) -> Result<YoukiConfig, LibcontainerError> {
        let spec = YoukiConfig::load(&self.root)?;
        Ok(spec)
    }
}

/// Checkpoint parameter structure
pub struct CheckpointOptions {
    pub ext_unix_sk: bool,
    pub file_locks: bool,
    pub image_path: PathBuf,
    pub leave_running: bool,
    pub shell_job: bool,
    pub tcp_established: bool,
    pub work_path: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};
    use serial_test::serial;

    use super::*;

    #[test]
    fn test_get_set_pid() {
        let mut container = Container::default();

        assert_eq!(container.pid(), None);
        container.set_pid(1);
        assert_eq!(container.pid(), Some(Pid::from_raw(1)));
    }

    #[test]
    fn test_basic_getter() -> Result<()> {
        let mut container = Container::new(
            "container_id",
            ContainerStatus::Creating,
            None,
            &PathBuf::from("."),
            &PathBuf::from("."),
        )?;

        // testing id
        assert_eq!(container.id(), "container_id");
        // testing bundle path
        assert_eq!(
            container.bundle(),
            &fs::canonicalize(PathBuf::from(".")).unwrap()
        );
        // testing root path
        assert_eq!(container.root, fs::canonicalize(PathBuf::from("."))?);
        // testing created
        assert_eq!(container.created(), None);
        container.set_status(ContainerStatus::Created);
        assert!(container.created().is_some());

        Ok(())
    }

    #[test]
    fn test_set_annotations() {
        let mut container = Container::default();
        assert_eq!(container.state.annotations, None);

        let mut annotations = std::collections::HashMap::with_capacity(1);
        annotations.insert(
            "org.criu.config".to_string(),
            "/etc/special-youki-criu-options".to_string(),
        );
        container.set_annotations(Some(annotations.clone()));
        assert_eq!(container.state.annotations, Some(annotations));
    }

    #[test]
    fn test_get_set_creator() {
        let mut container = Container::default();
        assert_eq!(container.creator(), None);
        container.set_creator(1000);
        assert_eq!(container.creator(), Some(OsString::from("youki")));
    }

    #[test]
    #[serial]
    fn test_refresh_load_save_state() -> Result<()> {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mut container_1 = Container::new(
            "container_id_1",
            ContainerStatus::Created,
            None,
            &PathBuf::from("."),
            tmp_dir.path(),
        )?;

        container_1.save()?;
        let container_2 = Container::load(tmp_dir.path().to_path_buf())?;
        assert_eq!(container_1.state.id, container_2.state.id);
        assert_eq!(container_2.state.status, ContainerStatus::Stopped);

        container_1.state.id = "container_id_1_modified".to_string();
        container_1.save()?;
        container_1.refresh_state()?;
        assert_eq!(container_1.state.id, "container_id_1_modified".to_string());

        Ok(())
    }

    #[test]
    #[serial]
    fn test_get_spec() -> Result<()> {
        let tmp_dir = tempfile::tempdir().unwrap();
        use oci_spec::runtime::Spec;
        let spec = Spec::default();
        let config = YoukiConfig::from_spec(&spec, None).context("convert spec to config")?;
        config.save(tmp_dir.path()).context("save config")?;

        let container = Container {
            root: tmp_dir.path().to_path_buf(),
            ..Default::default()
        };
        container.spec().context("get config")?;

        Ok(())
    }

    #[test]
    #[serial]
    fn test_get_set_refresh_status() -> Result<()> {
        // there already has a full and well-tested flow of status in state.rs
        // so we just let the coverage run through those can_xxx functions.
        let mut container = Container::default();
        assert_eq!(container.status(), ContainerStatus::Creating);
        assert!(!container.can_start());
        assert!(!container.can_kill());
        assert!(!container.can_delete());
        assert!(!container.can_exec());
        assert!(!container.can_pause());
        assert!(!container.can_resume());

        // no PID case
        container.refresh_status()?;
        assert_eq!(container.status(), ContainerStatus::Stopped);

        // with PID case but PID not exists
        container.set_pid(-1);
        container.refresh_status()?;
        assert_eq!(container.status(), ContainerStatus::Stopped);

        // with PID case
        container.set_pid(1);
        container.set_status(ContainerStatus::Paused);
        container.refresh_status()?;
        assert_eq!(container.status(), ContainerStatus::Paused);
        container.set_status(ContainerStatus::Running);
        container.refresh_status()?;
        assert_eq!(container.status(), ContainerStatus::Running);

        Ok(())
    }
}
