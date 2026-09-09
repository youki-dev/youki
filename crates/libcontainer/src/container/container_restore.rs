use std::cell::RefCell;
use std::fs::{File, canonicalize, create_dir_all, read_to_string, remove_dir_all};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use nix::mount::{MntFlags, MsFlags, mount, umount2};
use oci_spec::runtime::Spec;
use rust_criu::rust_criu_protobuf::rpc::Criu_notify;

use super::container_criu::{
    CRIU_VERSION_MINIMUM, DESCRIPTORS_JSON, check_cgroup_v1_unsupported, check_criu_version,
    configure_criu_common_options, handle_restoring_namespaces, open_image_dir,
    resolve_mount_dest_in_rootfs,
};
use super::{Container, ContainerStatus};
use crate::container::container::RestoreOptions;
use crate::error::LibcontainerError;
use crate::rootfs::utils::is_bind;
use crate::tty::send_pty_master_to_socket;

const CRIU_RESTORE_LOG_FILE: &str = "restore.log";

#[derive(thiserror::Error, Debug)]
pub enum RestoreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("criu error: {0}")]
    CriuError(String),
}

struct RestoreContext {
    container: Container,
    console_socket: Option<PathBuf>,
}

// Thread-local storage for the restore context, used to pass state into the CRIU
// notification callback. The callback must be a bare `fn` pointer (not a closure),
// so it cannot capture variables directly. Thread-local storage is used instead of
// `static mut` to avoid requiring `unsafe` and to satisfy `Sync` bounds.
thread_local! {
    static RESTORE_CTX: RefCell<Option<RestoreContext>> = const { RefCell::new(None) };
}

fn restore_callback(script: &str, notify: &Criu_notify, fd: Option<RawFd>) -> i32 {
    match script {
        "post-restore" => {
            let pid = notify.pid();
            RESTORE_CTX.with(|ctx| {
                let Ok(mut borrow) = ctx.try_borrow_mut() else {
                    tracing::error!("restore context already borrowed in post-restore callback");
                    return -1;
                };
                let Some(context) = borrow.as_mut() else {
                    tracing::error!("restore context not set in post-restore callback");
                    return -1;
                };
                if let Err(e) = context
                    .container
                    .set_pid(pid)
                    .set_status(ContainerStatus::Running)
                    .save()
                {
                    tracing::error!("failed to save container state: {}", e);
                    return -1;
                }
                tracing::debug!(pid, "container state updated to Running");
                // TODO: apply cgroups after restore (criuApplyCgroups equivalent).
                // runc calls cgroupManager.Apply(pid) and cgroupManager.Set(resources)
                // here to move the restored process into the correct cgroup and apply
                // resource limits. Ref: runc criuNotifications "post-restore"
                0
            })
        }
        "orphan-pts-master" => {
            let Some(master_fd) = fd else {
                tracing::error!("orphan-pts-master: no fd received from CRIU");
                return -1;
            };
            tracing::debug!(
                master_fd,
                "received orphan-pts-master notification from CRIU"
            );
            RESTORE_CTX.with(|ctx| {
                let Ok(borrow) = ctx.try_borrow() else {
                    tracing::error!(
                        "restore context already mutably borrowed in orphan-pts-master callback"
                    );
                    return -1;
                };
                let Some(context) = borrow.as_ref() else {
                    tracing::error!("restore context not set in orphan-pts-master callback");
                    return -1;
                };
                let Some(ref console_socket) = context.console_socket else {
                    tracing::debug!("no console socket, skipping PTY master send");
                    return 0;
                };
                tracing::debug!(
                    ?console_socket,
                    master_fd,
                    "sending PTY master to console socket"
                );
                match send_pty_master_to_socket(console_socket, master_fd) {
                    Ok(()) => {
                        tracing::debug!("successfully sent PTY master to conmon");
                        0
                    }
                    Err(e) => {
                        tracing::error!("failed to send PTY master: {}", e);
                        -1
                    }
                }
            })
        }
        "network-lock" => {
            // TODO: implement network locking during restore.
            // runc calls lockNetwork() here to freeze the network namespace before
            // CRIU restores network state. Without this, network interfaces may be
            // briefly visible in an inconsistent state.
            // Ref: runc criuNotifications "network-lock"
            tracing::warn!("network-lock notification received but not implemented");
            0
        }
        "network-unlock" => {
            // TODO: implement network unlocking after restore.
            // runc calls unlockNetwork() here to unfreeze the network namespace after
            // CRIU has restored all network state (interfaces, routes, etc.).
            // Ref: runc criuNotifications "network-unlock"
            tracing::warn!("network-unlock notification received but not implemented");
            0
        }
        "setup-namespaces" => {
            // TODO: execute Prestart and CreateRuntime lifecycle hooks here.
            // runc runs these OCI hooks at the setup-namespaces notify point so that
            // network plugins (CNI) and other runtime hooks can configure the
            // restored container's namespaces before CRIU finishes restore.
            // Ref: runc criuNotifications "setup-namespaces"
            tracing::debug!("setup-namespaces notification received (hooks not yet implemented)");
            0
        }
        _ => 0,
    }
}

impl Container {
    /// Restore a checkpointed container using CRIU.
    /// This follows the runc pattern where:
    /// 1. The rootfs is bind-mounted to satisfy CRIU requirements
    /// 2. External mounts are configured for CRIU
    /// 3. CRIU restores the process
    /// 4. The restored PID is captured via notify callback
    pub fn restore(&mut self, opts: &RestoreOptions) -> Result<(), LibcontainerError> {
        check_criu_version(CRIU_VERSION_MINIMUM)?;

        let mut criu = rust_criu::Criu::new().map_err(|e| {
            LibcontainerError::Restore(RestoreError::CriuError(format!(
                "error in creating criu struct: {}",
                e
            )))
        })?;

        let directory = open_image_dir(&opts.image_path)?;
        criu.set_images_dir_fd(directory.as_raw_fd());

        let _work_dir = opts
            .work_path
            .as_ref()
            .map(|wp| -> Result<File, LibcontainerError> {
                let f = File::open(wp).map_err(LibcontainerError::OtherIO)?;
                criu.set_work_dir_fd(f.as_raw_fd());
                Ok(f)
            })
            .transpose()?;

        // CRIU requires its root directory to be a mount point whose parent is not
        // overmounted, so the rootfs is bind-mounted here. Same pattern as runc.
        let criu_root = self.root.join("criu-root");
        create_dir_all(&criu_root).map_err(|err| {
            tracing::error!(?criu_root, ?err, "failed to create criu-root directory");
            LibcontainerError::OtherIO(err)
        })?;

        let (rootfs, spec) = self.get_rootfs_and_spec()?;

        // TODO: apply cgroups after restore (criuApplyCgroups equivalent).
        // runc calls cgroupManager.Apply(pid) and cgroupManager.Set(resources) in the
        // post-restore notification callback. Ref: runc criuNotifications "post-restore"
        if spec
            .linux()
            .as_ref()
            .and_then(|l| l.resources().as_ref())
            .is_some()
        {
            tracing::warn!(
                "cgroup resource limits are configured but will not be applied after restore \
                 (not yet implemented). The restored container may exceed configured limits."
            );
        }

        mount(
            Some(&rootfs),
            &criu_root,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|err| {
            tracing::error!(?rootfs, ?criu_root, ?err, "failed to bind mount rootfs");
            LibcontainerError::Other(format!("failed to bind mount rootfs: {}", err))
        })?;

        // Ensure we unmount and cleanup even on error
        let _cleanup = scopeguard::guard((), |_| {
            if let Err(e) = umount2(&criu_root, MntFlags::MNT_DETACH) {
                tracing::warn!(err = ?e, "failed to umount criu_root during cleanup");
            }
            if let Err(e) = std::fs::remove_dir(&criu_root) {
                tracing::warn!(err = ?e, "failed to remove criu_root during cleanup");
            }
        });

        criu.set_log_file(CRIU_RESTORE_LOG_FILE.to_string());
        configure_criu_common_options(
            &mut criu,
            opts.ext_unix_sk,
            opts.shell_job,
            opts.tcp_established,
            opts.file_locks,
            opts.manage_cgroups_mode.clone(),
        );
        criu.set_notify_scripts(true);
        // The restored process must end up a sibling of youki rather than a child
        // of CRIU swrk, which dies with the service. This is the same as runc.
        criu.set_rst_sibling(true);
        criu.set_root(
            criu_root
                .to_str()
                .ok_or_else(|| LibcontainerError::Other("invalid criu root path".to_string()))?
                .to_string(),
        );
        // TODO: set EvasiveDevices flag (criu.set_evasive_devices(true)) once rust-criu exposes
        // this option. runc sets EvasiveDevices: true unconditionally on restore.
        // Ref: runc Restore() in criu_linux.go

        // TODO: implement prepareCriuRestoreMounts equivalent.
        // runc calls prepareCriuRestoreMounts() to pre-create missing mount point
        // directories/files inside rootfs and temporarily bind-mount them so that
        // CRIU can attach the external mounts. Without this, restore may fail when
        // a bind-mount destination does not exist in the rootfs image.
        // Ref: runc prepareCriuRestoreMounts() in criu_linux.go

        self.configure_external_mounts(&mut criu, &spec, &rootfs, &criu_root)?;

        self.register_pipe_descriptors(&mut criu, &opts.image_path)?;

        // extra_files keeps the namespace file descriptors alive until criu.restore()
        // sends them to CRIU via SCM_RIGHTS.
        let mut extra_files: Vec<File> = Vec::new();
        handle_restoring_namespaces(&mut criu, &spec, &mut extra_files)?;

        // TODO: implement restoreNetwork equivalent.
        // runc calls restoreNetwork() to configure veth pairs and other network
        // settings (CriuVethPair) for the restored container when --empty-ns does
        // not include the network namespace.
        // Ref: runc restoreNetwork() in criu_linux.go

        criu.set_notify_cb(restore_callback);
        RESTORE_CTX.with(|ctx| {
            *ctx.borrow_mut() = Some(RestoreContext {
                container: self.clone(),
                console_socket: opts.console_socket.clone(),
            });
        });

        let result = criu.restore().map_err(|err| {
            // TODO: implement logCriuErrors equivalent: parse restore.log and extract
            // lines containing "Error" (and surrounding context) for better diagnostics.
            // Ref: runc logCriuErrors() in criu_linux.go
            tracing::error!(?err, id = ?self.id(), logfile = ?opts.image_path.join(CRIU_RESTORE_LOG_FILE), "restoring container failed");
            LibcontainerError::Other(err.to_string())
        });

        RESTORE_CTX.with(|ctx| {
            *ctx.borrow_mut() = None;
        });

        // OCI spec Errors section requires that on failure the operation MUST leave the
        // system in the same state as if it had never been attempted. Clean up the container
        // state directory created by build_for_restore() so no broken state is left behind.
        result.inspect_err(|_| {
            if let Err(e) = remove_dir_all(&self.root) {
                tracing::warn!(
                    err = ?e,
                    root = ?self.root,
                    "failed to clean up container state directory after restore failure"
                );
            }
        })
    }

    /// Register stdin/stdout/stderr pipe fds from descriptors.json as CRIU InheritFd entries.
    ///
    /// During checkpoint, youki records the target of fds 0/1/2 in descriptors.json.
    /// If any of those were pipes, CRIU must inherit the corresponding fd from the
    /// restoring process so it can reconnect the pipe after restore. This matches
    /// runc's descriptor inheritance logic in criu_linux.go.
    fn register_pipe_descriptors(
        &self,
        criu: &mut rust_criu::Criu,
        image_path: &Path,
    ) -> Result<(), LibcontainerError> {
        let descriptors_path = image_path.join(DESCRIPTORS_JSON);
        if !descriptors_path.exists() {
            return Ok(());
        }

        let data = read_to_string(&descriptors_path).map_err(|err| {
            tracing::error!(?descriptors_path, ?err, "failed to read descriptors.json");
            LibcontainerError::OtherIO(err)
        })?;

        let descriptors: Vec<String> =
            serde_json::from_str(&data).map_err(LibcontainerError::OtherSerialization)?;

        for (i, desc) in descriptors.iter().enumerate().take(3) {
            if !desc.starts_with("pipe:") {
                continue;
            }
            // fds 0/1/2 are always open as the process's own stdio, so no dup is needed.
            //
            // The key must match what the checkpoint recorded in descriptors.json:
            // the readlink target of /proc/<pid>/fd/<n>, e.g. "pipe:[12345]".
            // Using "fd:{i}" would not match and CRIU would fail to reconnect the pipe.
            // Ref: runc Restore() in criu_linux.go — InheritFd.Key = desc
            let fd = i as RawFd;
            let key = desc.clone();
            tracing::debug!(fd, key, "registering pipe fd as CRIU inherit_fd");
            criu.add_inherit_fd(fd, key).map_err(|e| {
                LibcontainerError::Other(format!("failed to add inherit_fd for fd {i}: {e}"))
            })?;
        }

        Ok(())
    }

    /// Configure external mounts for CRIU restore.
    /// This follows the runc pattern of addCriuRestoreMount.
    fn configure_external_mounts(
        &self,
        criu: &mut rust_criu::Criu,
        spec: &Spec,
        rootfs: &Path,
        criu_root: &Path,
    ) -> Result<(), LibcontainerError> {
        if let Some(mounts) = spec.mounts() {
            for m in mounts {
                let dest = m.destination();
                let dest_str = dest.to_string_lossy();

                // is_bind() is used here for the same reason as in checkpoint: the set of
                // mounts registered with CRIU must match on both sides.
                if is_bind(m) {
                    if let Some(source) = m.source() {
                        let source_str = source.to_string_lossy();
                        // Symlinks are resolved relative to rootfs so the key matches
                        // what CRIU recorded during checkpoint.
                        let resolved = resolve_mount_dest_in_rootfs(rootfs, &dest_str);
                        tracing::debug!("Adding external mount: {} -> {}", resolved, source_str);
                        criu.set_external_mount(resolved, source_str.to_string());
                    }
                }

                if m.typ().as_deref() == Some("cgroup") {
                    check_cgroup_v1_unsupported("restore")?;
                }
            }
        }

        if let Some(linux) = spec.linux() {
            // Masked paths come in two kinds:
            //   - Files:       the OCI runtime bind-mounts /dev/null over them.
            //                  CRIU records these as external bind mounts and needs
            //                  --ext-mount-map to restore them.
            //   - Directories: the OCI runtime overlays a read-only tmpfs.
            //                  CRIU can restore tmpfs autonomously; no external
            //                  mount registration is required.
            //
            // TODO: crun registers masked directories via criu_add_ext_mount() as a
            // shared empty directory. Containers with directory masked paths may fail
            // to restore until this is implemented. Ref: crun criu_restore_container()
            //
            // For file masked paths we must NOT pass "/dev/null" directly as the
            // CRIU source: CRIU 4.x mnt-v2 uses open_tree(OPEN_TREE_CLONE) on the
            // source path, which requires a proper mount point.  /dev/null is a char
            // device file on devtmpfs, not its own mount point, so move_mount fails
            // with EINVAL.
            //
            // Fix: bind-mount /dev/null onto the corresponding file inside criu_root
            // (which is a bind-copy of the whole rootfs).  That path then becomes an
            // independent bind mount point that open_tree can clone correctly.
            // umount2(criu_root, MNT_DETACH) cleans up all sub-mounts lazily.
            //
            // Ref: runc addCriuRestoreMount / prepareCriuRestoreMounts in criu_linux.go
            if let Some(masked_paths) = linux.masked_paths() {
                for path in masked_paths {
                    let resolved = resolve_mount_dest_in_rootfs(rootfs, path);
                    let rel = resolved.trim_start_matches('/');
                    let path_in_criu_root = criu_root.join(rel);

                    if !path_in_criu_root.exists() || path_in_criu_root.is_dir() {
                        continue;
                    }

                    mount(
                        Some("/dev/null"),
                        &path_in_criu_root,
                        None::<&str>,
                        MsFlags::MS_BIND,
                        None::<&str>,
                    )
                    .map_err(|err| {
                        tracing::error!(
                            ?path_in_criu_root,
                            ?err,
                            "failed to bind /dev/null for masked path"
                        );
                        LibcontainerError::Other(format!(
                            "failed to bind /dev/null for masked path {}: {}",
                            resolved, err
                        ))
                    })?;

                    let source = path_in_criu_root.to_str().ok_or_else(|| {
                        LibcontainerError::Other(format!(
                            "invalid path for masked path {}",
                            resolved
                        ))
                    })?;

                    tracing::debug!(
                        "Adding masked path external mount: {} -> {}",
                        resolved,
                        source
                    );
                    criu.set_external_mount(resolved, source.to_string());
                }
            }

            // Device nodes inside a container are bind-mounted from the host at
            // the same path.  CRIU records them as external bind mounts, so we
            // must tell it where to source each device on restore.
            // The key and source are both the resolved device path (matching
            // runc's criu_linux.go loop that calls addCriuRestoreMount for each
            // entry in config.Devices).
            for device in linux.devices().iter().flatten() {
                let path = device.path().to_string_lossy();
                let resolved = resolve_mount_dest_in_rootfs(rootfs, &path);
                tracing::debug!("Adding device external mount: {}", resolved);
                criu.set_external_mount(resolved.clone(), resolved);
            }
        }

        Ok(())
    }

    /// Get the rootfs path and spec from the bundle.
    fn get_rootfs_and_spec(&self) -> Result<(PathBuf, Spec), LibcontainerError> {
        let bundle = self.bundle();
        let config_path = bundle.join("config.json");
        let spec = Spec::load(&config_path).map_err(|err| {
            tracing::error!(?config_path, ?err, "failed to load spec");
            LibcontainerError::Other(format!("failed to load spec: {}", err))
        })?;

        let root = spec
            .root()
            .as_ref()
            .ok_or_else(|| LibcontainerError::Other("spec has no root".to_string()))?;

        let root_path = root.path();

        let rootfs_path = if root_path.is_absolute() {
            root_path.to_path_buf()
        } else {
            bundle.join(root_path)
        };

        if !rootfs_path.exists() {
            tracing::error!(
                ?rootfs_path,
                "rootfs does not exist - the container runtime caller (e.g. podman) \
                 must mount the rootfs before calling restore"
            );
            return Err(LibcontainerError::Other(format!(
                "rootfs does not exist at {:?}. The container manager must mount the \
                 rootfs before calling restore.",
                rootfs_path
            )));
        }

        let rootfs = canonicalize(&rootfs_path).map_err(|err| {
            tracing::error!(?rootfs_path, ?err, "failed to canonicalize rootfs path");
            LibcontainerError::OtherIO(err)
        })?;

        Ok((rootfs, spec))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use oci_spec::runtime::{
        LinuxBuilder, LinuxDeviceBuilder, LinuxDeviceType, RootBuilder, SpecBuilder,
    };
    use rust_criu::Criu;
    use tempfile::tempdir;

    use super::*;
    use crate::container::ContainerStatus;

    fn make_container(bundle: &Path, root: &Path) -> Container {
        Container::new(
            "test-restore",
            ContainerStatus::Creating,
            None,
            bundle,
            root,
        )
        .unwrap()
    }

    #[test]
    fn test_get_rootfs_and_spec_missing_config() {
        let tmp = tempdir().unwrap();
        let container = make_container(tmp.path(), tmp.path());
        let result = container.get_rootfs_and_spec();
        assert!(result.is_err());
    }

    #[test]
    fn test_get_rootfs_and_spec_missing_rootfs() {
        let tmp = tempdir().unwrap();
        let spec = SpecBuilder::default()
            .root(
                RootBuilder::default()
                    .path(PathBuf::from("nonexistent-rootfs"))
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        spec.save(tmp.path().join("config.json")).unwrap();

        let container = make_container(tmp.path(), tmp.path());
        let result = container.get_rootfs_and_spec();
        assert!(result.is_err());
    }

    #[test]
    fn test_get_rootfs_and_spec_relative_rootfs() {
        let tmp = tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        create_dir_all(&rootfs).unwrap();

        let spec = SpecBuilder::default()
            .root(
                RootBuilder::default()
                    .path(PathBuf::from("rootfs"))
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        spec.save(tmp.path().join("config.json")).unwrap();

        let container = make_container(tmp.path(), tmp.path());
        let (resolved, _) = container.get_rootfs_and_spec().unwrap();
        assert_eq!(resolved, canonicalize(&rootfs).unwrap());
    }

    #[test]
    fn test_get_rootfs_and_spec_absolute_rootfs() {
        let tmp = tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        create_dir_all(&rootfs).unwrap();
        let rootfs_abs = canonicalize(&rootfs).unwrap();

        let spec = SpecBuilder::default()
            .root(
                RootBuilder::default()
                    .path(rootfs_abs.clone())
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        spec.save(tmp.path().join("config.json")).unwrap();

        let container = make_container(tmp.path(), tmp.path());
        let (resolved, _) = container.get_rootfs_and_spec().unwrap();
        assert_eq!(resolved, rootfs_abs);
    }

    // ── configure_external_mounts: device registration ───────────────────────

    fn make_spec_with_devices(devices: Vec<oci_spec::runtime::LinuxDevice>) -> Spec {
        let linux = LinuxBuilder::default().devices(devices).build().unwrap();
        SpecBuilder::default().linux(linux).build().unwrap()
    }

    #[test]
    fn test_configure_external_mounts_no_devices() {
        let tmp = tempdir().unwrap();
        let container = make_container(tmp.path(), tmp.path());
        let mut criu = Criu::new().unwrap();
        let spec = SpecBuilder::default().build().unwrap();
        assert!(
            container
                .configure_external_mounts(&mut criu, &spec, tmp.path(), tmp.path())
                .is_ok()
        );
    }

    #[test]
    fn test_configure_external_mounts_with_char_device() {
        let tmp = tempdir().unwrap();
        let container = make_container(tmp.path(), tmp.path());
        let mut criu = Criu::new().unwrap();
        let device = LinuxDeviceBuilder::default()
            .path("/dev/null")
            .typ(LinuxDeviceType::C)
            .major(1_i64)
            .minor(3_i64)
            .build()
            .unwrap();
        let spec = make_spec_with_devices(vec![device]);
        assert!(
            container
                .configure_external_mounts(&mut criu, &spec, tmp.path(), tmp.path())
                .is_ok()
        );
    }

    #[test]
    fn test_configure_external_mounts_with_block_device() {
        let tmp = tempdir().unwrap();
        let container = make_container(tmp.path(), tmp.path());
        let mut criu = Criu::new().unwrap();
        let device = LinuxDeviceBuilder::default()
            .path("/dev/sda")
            .typ(LinuxDeviceType::B)
            .major(8_i64)
            .minor(0_i64)
            .build()
            .unwrap();
        let spec = make_spec_with_devices(vec![device]);
        assert!(
            container
                .configure_external_mounts(&mut criu, &spec, tmp.path(), tmp.path())
                .is_ok()
        );
    }
}
