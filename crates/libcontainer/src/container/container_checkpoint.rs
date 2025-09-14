use std::fs::{self, File};
use std::io::Write;
use std::os::unix::io::AsRawFd;

use libcgroups::common::CgroupSetup::{Hybrid, Legacy};
#[cfg(feature = "v1")]
use libcgroups::common::DEFAULT_CGROUP_ROOT;
use oci_spec::runtime::Spec;

use super::{Container, ContainerStatus};
use crate::container::container::CheckpointOptions;
use crate::error::LibcontainerError;

const CRIU_CHECKPOINT_LOG_FILE: &str = "dump.log";
const DESCRIPTORS_JSON: &str = "descriptors.json";

#[derive(thiserror::Error, Debug)]
pub enum CheckpointError {
    #[error("criu error: {0}")]
    CriuError(String),
}

impl Container {
    pub fn checkpoint(&mut self, opts: &CheckpointOptions) -> Result<(), LibcontainerError> {
        self.refresh_status()?;

        // can_pause() checks if the container is running. That also works for
        // checkpoitning. is_running() would make more sense here, but let's
        // just reuse existing functions.
        if !self.can_pause() {
            tracing::error!(status = ?self.status(), id = ?self.id(), "cannot checkpoint container because it is not running");
            return Err(LibcontainerError::IncorrectStatus);
        }

        let mut criu = rust_criu::Criu::new().map_err(|e| {
            LibcontainerError::Checkpoint(CheckpointError::CriuError(format!(
                "error in creating criu struct: {}",
                e
            )))
        })?;
        // We need to tell CRIU that all bind mounts are external. CRIU will fail checkpointing
        // if it does not know that these bind mounts are coming from the outside of the container.
        // This information is needed during restore again. The external location of the bind
        // mounts can change and CRIU will just mount whatever we tell it to mount based on
        // information found in 'config.json'.
        let source_spec_path = self.bundle().join("config.json");
        let spec = Spec::load(source_spec_path)?;
        let mounts = spec.mounts().clone();
        for m in mounts.unwrap_or_default() {
            match m.typ().as_deref() {
                Some("bind") => {
                    let dest = m
                        .destination()
                        .clone()
                        .into_os_string()
                        .into_string()
                        .expect("failed to convert mount destination");
                    criu.set_external_mount(dest.clone(), dest);
                }
                Some("cgroup") => {
                    match libcgroups::common::get_cgroup_setup()? {
                        // For v1 it is necessary to list all cgroup mounts as external mounts
                        Legacy | Hybrid => {
                            #[cfg(not(feature = "v1"))]
                            panic!(
                                "libcontainer can't run in a Legacy or Hybrid cgroup setup without the v1 feature"
                            );
                            #[cfg(feature = "v1")]
                            for mp in libcgroups::v1::util::list_subsystem_mount_points().map_err(
                                |err| {
                                    tracing::error!(?err, "failed to get subsystem mount points");
                                    LibcontainerError::OtherCgroup(err.to_string())
                                },
                            )? {
                                let cgroup_mount = mp
                                    .clone()
                                    .into_os_string()
                                    .into_string()
                                    .expect("failed to convert mount point");
                                if cgroup_mount.starts_with(DEFAULT_CGROUP_ROOT) {
                                    criu.set_external_mount(cgroup_mount.clone(), cgroup_mount);
                                }
                            }
                        }
                        _ => (),
                    }
                }
                _ => (),
            }
        }

        let directory = std::fs::File::open(&opts.image_path).map_err(|err| {
            tracing::error!(path = ?opts.image_path, ?err, "failed to open criu image directory");
            LibcontainerError::OtherIO(err)
        })?;
        criu.set_images_dir_fd(directory.as_raw_fd());

        // It seems to be necessary to be defined outside of 'if' to
        // keep the FD open until CRIU uses it.
        let work_dir: std::fs::File;
        if let Some(wp) = &opts.work_path {
            work_dir = std::fs::File::open(wp).map_err(LibcontainerError::OtherIO)?;
            criu.set_work_dir_fd(work_dir.as_raw_fd());
        }

        let pid: i32 = self
            .pid()
            .ok_or(LibcontainerError::Other(
                "container process pid not found in state".into(),
            ))?
            .into();

        // Remember original stdin, stdout, stderr for container restore.
        let mut descriptors = Vec::new();
        for n in 0..3 {
            let link_path = match fs::read_link(format!("/proc/{pid}/fd/{n}")) {
                // it should not have any non utf-8 or non os safe path,
                // as we are reading from os , so ok to unwrap
                Ok(lp) => lp.into_os_string().into_string().unwrap(),
                Err(..) => "/dev/null".to_string(),
            };
            descriptors.push(link_path);
        }
        let descriptors_json_path = opts.image_path.join(DESCRIPTORS_JSON);
        let mut descriptors_json =
            File::create(descriptors_json_path).map_err(LibcontainerError::OtherIO)?;
        write!(
            descriptors_json,
            "{}",
            serde_json::to_string(&descriptors).map_err(LibcontainerError::OtherSerialization)?
        )
        .map_err(LibcontainerError::OtherIO)?;

        criu.set_log_file(CRIU_CHECKPOINT_LOG_FILE.to_string());
        criu.set_log_level(4);
        criu.set_pid(pid);
        criu.set_leave_running(opts.leave_running);
        criu.set_ext_unix_sk(opts.ext_unix_sk);
        criu.set_shell_job(opts.shell_job);
        criu.set_tcp_established(opts.tcp_established);
        criu.set_file_locks(opts.file_locks);
        criu.set_orphan_pts_master(true);
        criu.set_manage_cgroups(true);
        criu.set_root(
            self.bundle()
                .clone()
                .into_os_string()
                .into_string()
                .unwrap(),
        );

        criu.dump().map_err(|err| {
            tracing::error!(?err, id = ?self.id(), logfile = ?opts.image_path.join(CRIU_CHECKPOINT_LOG_FILE), "checkpointing container failed");
            LibcontainerError::Other(err.to_string())
        })?;

        if !opts.leave_running {
            self.set_status(ContainerStatus::Stopped).save()?;
        }

        tracing::debug!("container {} checkpointed", self.id());
        Ok(())
    }
}
