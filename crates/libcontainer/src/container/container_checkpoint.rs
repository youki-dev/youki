use std::fs::{DirBuilder, File, read_link};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::io::AsRawFd;

use libcgroups::common::CgroupSetup::{Hybrid, Legacy};
use oci_spec::runtime::{LinuxNamespaceType, Spec};

use super::container_criu::{
    CRIU_VERSION_MINIMUM, check_criu_version, handle_checkpointing_external_namespaces,
    resolve_mount_dest_in_rootfs,
};
use super::{Container, ContainerStatus};
use crate::container::container::CheckpointOptions;
use crate::error::LibcontainerError;
use crate::rootfs::utils::is_bind;

const CRIU_CHECKPOINT_LOG_FILE: &str = "dump.log";
const DESCRIPTORS_JSON: &str = "descriptors.json";

#[derive(thiserror::Error, Debug)]
pub enum CheckpointError {
    #[error("criu error: {0}")]
    CriuError(String),
}

impl Container {
    /// Checkpoint a running container using CRIU.
    pub fn checkpoint(&mut self, opts: &CheckpointOptions) -> Result<(), LibcontainerError> {
        self.refresh_status()?;

        // can_pause() checks if the container is running. That also works for
        // checkpointing. is_running() would make more sense here, but let's
        // just reuse existing functions.
        if !self.can_pause() {
            tracing::error!(status = ?self.status(), id = ?self.id(), "cannot checkpoint container because it is not running");
            return Err(LibcontainerError::IncorrectStatus(self.status()));
        }

        // Require CRIU >= 3.15.0, matching crun's LIBCRIU_MIN_VERSION requirement.
        check_criu_version(CRIU_VERSION_MINIMUM)?;

        // Create checkpoint image directory if it doesn't exist (mode 0o700 like crun).
        if let Err(err) = DirBuilder::new().mode(0o700).create(&opts.image_path) {
            if err.kind() != ErrorKind::AlreadyExists {
                tracing::error!(path = ?opts.image_path, ?err, "failed to create checkpoint directory");
                return Err(LibcontainerError::OtherIO(err));
            }
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
        // TODO: read org.criu.config annotation and /etc/criu/runc.conf global config,
        // pass path to criu.set_config_file() (test: checkpoint_and_restore_with_container_specific_criu_config)

        // Determine rootfs path for symlink resolution (mirrors crun's chroot_realpath logic).
        let rootfs = {
            let root = spec.root().as_ref().map(|r| r.path().to_path_buf());
            match root {
                Some(p) if p.is_absolute() => p,
                Some(p) => self.bundle().join(p),
                None => self.bundle().join("rootfs"),
            }
        };

        let mounts = spec.mounts().clone();
        for m in mounts.unwrap_or_default() {
            if is_bind(&m) {
                let dest = m
                    .destination()
                    .clone()
                    .into_os_string()
                    .into_string()
                    .expect("failed to convert mount destination");
                // Resolve the destination path through symlinks in rootfs so that the
                // key we pass to CRIU matches the actual mount point the kernel sees.
                // When a bind-mount destination is a symlink (e.g. /conf -> /real/conf),
                // the kernel follows it and the mount appears at the resolved path.
                let resolved = resolve_mount_dest_in_rootfs(&rootfs, &dest);
                criu.set_external_mount(resolved.clone(), resolved);
            } else if m.typ().as_deref() == Some("cgroup") {
                match libcgroups::common::get_cgroup_setup()? {
                    Legacy | Hybrid => {
                        return Err(LibcontainerError::OtherCgroup(
                            "cgroup v1 is not supported for checkpoint".to_string(),
                        ));
                    }
                    _ => (),
                }
            }
        }

        // Register file masked paths as external mounts.
        //
        // Masked paths come in two kinds depending on whether the target is a
        // file or a directory (see OCI runtime spec, process/init/process.rs):
        //
        //   - Files:       the OCI runtime bind-mounts /dev/null over them.
        //                  The new mount has the same underlying device as the
        //                  /dev tmpfs, so CRIU cannot dump/restore it internally.
        //                  We must explicitly mark it as external so CRIU records
        //                  a stable key that restore can reference.
        //
        //   - Directories: the OCI runtime overlays a fresh read-only tmpfs.
        //                  CRIU can dump and restore this autonomously (it just
        //                  creates a new tmpfs on restore).  Marking it external
        //                  here would force restore to supply a host-side source,
        //                  which is unnecessary and error-prone.
        //
        // Ref: runc addCriuDumpMount for MaskPaths in criu_linux.go
        if let Some(linux) = spec.linux() {
            if let Some(masked_paths) = linux.masked_paths() {
                for path in masked_paths {
                    let resolved = resolve_mount_dest_in_rootfs(&rootfs, path);
                    let rel = resolved.trim_start_matches('/');
                    let full_path = rootfs.join(rel);
                    // Only register FILE masked paths; directories are tmpfs and
                    // CRIU handles them without external mount registration.
                    if !full_path.exists() || full_path.is_dir() {
                        continue;
                    }
                    criu.set_external_mount(resolved.clone(), resolved);
                }
            }
        }

        let directory = File::open(&opts.image_path).map_err(|err| {
            tracing::error!(path = ?opts.image_path, ?err, "failed to open checkpoint directory");
            LibcontainerError::OtherIO(err)
        })?;
        criu.set_images_dir_fd(directory.as_raw_fd());

        // It seems to be necessary to be defined outside of 'if' to
        // keep the FD open until CRIU uses it.
        let work_dir: File;
        // TODO: fall back to image_path when work_path is not specified
        if let Some(wp) = &opts.work_path {
            // Create work directory if it doesn't exist (mode 0o700 like crun).
            if let Err(err) = DirBuilder::new().mode(0o700).create(wp) {
                if err.kind() != ErrorKind::AlreadyExists {
                    tracing::error!(path = ?wp, ?err, "failed to create work directory");
                    return Err(LibcontainerError::OtherIO(err));
                }
            }
            work_dir = File::open(wp).map_err(LibcontainerError::OtherIO)?;
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
            let link_path = match read_link(format!("/proc/{pid}/fd/{n}")) {
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
        // TODO: set freeze cgroup path via criu.set_freeze_cgroup()
        // TODO: configure network lock method (iptables/nftables/skip) via criu.set_network_lock()
        criu.set_root(
            self.bundle()
                .clone()
                .into_os_string()
                .into_string()
                .unwrap(),
        );
        criu.cgroups_mode(opts.manage_cgroups_mode.clone());
        criu.set_link_remap(opts.link_remap);

        // Register network and PID namespaces as external to CRIU.
        //
        // Both namespaces are created by the container runtime (e.g. Podman) on
        // the host side before the container process starts, so CRIU must not
        // try to save or recreate them itself.
        //
        // Network namespace: CRIU would otherwise save the full network
        // configuration (ifaddr, route, iptables, netdev, ...) and attempt to
        // recreate the veth pair on restore. That fails with "Unknown peer net
        // namespace" because the peer end lives in the host namespace which
        // CRIU cannot see. Marking it external tells CRIU to store only a
        // netns reference (netns-*.img) and inherit the existing namespace fd
        // on restore via --inherit-fd.
        //
        // PID namespace: similarly created by the runtime via clone(CLONE_NEWPID).
        // Without external registration CRIU would create a new PID namespace
        // on restore, causing PID reassignment and breaking rst_sibling-based
        // restore where the restored process must be a sibling of the runtime
        // process inside the same existing PID namespace.
        //
        // This follows runc's handleCheckpointingExternalNamespaces.
        handle_checkpointing_external_namespaces(&mut criu, &spec, LinuxNamespaceType::Network)?;
        handle_checkpointing_external_namespaces(&mut criu, &spec, LinuxNamespaceType::Pid)?;

        criu.dump().map_err(|err| {
            tracing::error!(?err, id = ?self.id(), logfile = ?opts.image_path.join(CRIU_CHECKPOINT_LOG_FILE), "checkpointing container failed");
            LibcontainerError::Other(err.to_string())
        })?;

        if !opts.leave_running {
            // Set status to Stopped first so delete() can proceed without force.
            self.set_status(ContainerStatus::Stopped).save()?;
            // Remove cgroups, run poststop hooks, and delete the container state
            // directory, matching runc's behavior where a checkpoint without
            // --leave-running fully removes the container from runtime state.
            self.delete(false)?;
        }

        tracing::debug!("container {} checkpointed", self.id());
        Ok(())
    }
}
