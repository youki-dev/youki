use std::cell::RefCell;
use std::fs::File;
use std::io::IoSlice;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sys::socket::{self, UnixAddr};
use oci_spec::runtime::Spec;
use rust_criu::rust_criu_protobuf::rpc::Criu_notify;

use super::container_criu::{CRIU_VERSION_MINIMUM, handle_restoring_namespaces};
use super::{Container, ContainerStatus};
use crate::container::container::RestoreOptions;
use crate::error::LibcontainerError;

const CRIU_RESTORE_LOG_FILE: &str = "restore.log";

#[derive(thiserror::Error, Debug)]
pub enum RestoreError {
    #[error("criu error: {0}")]
    CriuError(String),
}

struct RestoreContext {
    container: Container,
    console_socket: Option<PathBuf>,
}

thread_local! {
    static RESTORE_CTX: RefCell<Option<RestoreContext>> = RefCell::new(None);
}

fn restore_callback(script: &str, notify: &Criu_notify, fds: &[RawFd]) -> i32 {
    match script {
        "post-restore" => {
            let pid = notify.pid();
            RESTORE_CTX.with(|ctx| {
                let mut borrow = ctx.borrow_mut();
                match &mut *borrow {
                    Some(context) => {
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
                        let checkpoint_file = context.container.root.join("checkpoint");
                        if checkpoint_file.exists() {
                            let _ = std::fs::remove_file(&checkpoint_file);
                        }
                        0
                    }
                    None => {
                        tracing::error!("restore context not set in post-restore callback");
                        -1
                    }
                }
            })
        }
        "orphan-pts-master" => {
            let master_fd = match fds.first() {
                Some(&fd) => fd,
                None => {
                    tracing::error!("orphan-pts-master: no fd received from CRIU");
                    return -1;
                }
            };
            tracing::debug!(
                master_fd,
                "received orphan-pts-master notification from CRIU"
            );
            RESTORE_CTX.with(|ctx| {
                let borrow = ctx.borrow();
                match &*borrow {
                    Some(context) => {
                        if let Some(ref console_socket) = context.console_socket {
                            tracing::debug!(
                                ?console_socket,
                                master_fd,
                                "sending PTY master to console socket"
                            );
                            match send_pts_master(console_socket, master_fd) {
                                Ok(()) => {
                                    tracing::debug!("successfully sent PTY master to conmon");
                                    0
                                }
                                Err(e) => {
                                    tracing::error!("failed to send PTY master: {}", e);
                                    -1
                                }
                            }
                        } else {
                            tracing::debug!("no console socket, skipping PTY master send");
                            0
                        }
                    }
                    None => {
                        tracing::error!("restore context not set in orphan-pts-master callback");
                        -1
                    }
                }
            })
        }
        _ => 0,
    }
}

fn send_pts_master(
    console_socket: &Path,
    master_fd: RawFd,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream = UnixStream::connect(console_socket)?;
    let console_fd = stream.as_raw_fd();
    let pty_name: &[u8] = b"/dev/ptmx";
    let iov = [IoSlice::new(pty_name)];
    let fds = [master_fd];
    let cmsg = socket::ControlMessage::ScmRights(&fds);
    socket::sendmsg::<UnixAddr>(console_fd, &iov, &[cmsg], socket::MsgFlags::empty(), None)?;
    Ok(())
}

impl Container {
    /// Restore a checkpointed container using CRIU.
    /// This follows the runc pattern where:
    /// 1. The rootfs is bind-mounted to satisfy CRIU requirements
    /// 2. External mounts are configured for CRIU
    /// 3. CRIU restores the process
    /// 4. The restored PID is captured via notify callback
    pub fn restore(&mut self, opts: &RestoreOptions) -> Result<(), LibcontainerError> {
        // We are relying on the CRIU version RPC which was introduced with CRIU 3.0.0
        self.check_criu_version(CRIU_VERSION_MINIMUM)?;

        let mut criu = rust_criu::Criu::new().map_err(|e| {
            LibcontainerError::Restore(RestoreError::CriuError(format!(
                "error in creating criu struct: {}",
                e
            )))
        })?;

        let directory = std::fs::File::open(&opts.image_path).map_err(|err| {
            tracing::error!(path = ?opts.image_path, ?err, "failed to open criu image directory");
            LibcontainerError::OtherIO(err)
        })?;
        criu.set_images_dir_fd(directory.as_raw_fd());

        let work_dir: std::fs::File;
        if let Some(wp) = &opts.work_path {
            work_dir = std::fs::File::open(wp).map_err(LibcontainerError::OtherIO)?;
            criu.set_work_dir_fd(work_dir.as_raw_fd());
        }

        // Setup CRIU root directory
        // CRIU has a few requirements for a root directory:
        // * it must be a mount point
        // * its parent must not be overmounted
        // The rootfs is bind-mounted to a temporary directory to satisfy these requirements.
        // This is the same pattern as runc.
        let criu_root = self.root.join("criu-root");
        std::fs::create_dir_all(&criu_root).map_err(|err| {
            tracing::error!(?criu_root, ?err, "failed to create criu-root directory");
            LibcontainerError::OtherIO(err)
        })?;

        // Bind mount the rootfs to satisfy CRIU requirements
        let bundle = self.bundle().clone();
        let (rootfs, spec) = self.get_rootfs_and_spec(&bundle)?;

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
            let _ = umount2(&criu_root, MntFlags::MNT_DETACH);
            let _ = std::fs::remove_dir(&criu_root);
        });

        criu.set_log_file(CRIU_RESTORE_LOG_FILE.to_string());
        criu.set_log_level(4);
        criu.set_ext_unix_sk(opts.ext_unix_sk);
        criu.set_shell_job(opts.shell_job);
        criu.set_tcp_established(opts.tcp_established);
        criu.set_file_locks(opts.file_locks);
        criu.set_orphan_pts_master(true);
        criu.set_manage_cgroups(true);
        criu.set_notify_scripts(true);
        // Set rst_sibling to true so the restored process becomes a sibling
        // of youki rather than a child of CRIU swrk. This is the same as runc.
        criu.set_rst_sibling(true);
        criu.set_root(
            criu_root
                .clone()
                .into_os_string()
                .into_string()
                .map_err(|_| LibcontainerError::Other("invalid criu root path".to_string()))?,
        );

        // Configure external mounts for CRIU
        // This follows the runc pattern of addCriuRestoreMount
        self.configure_external_mounts(&mut criu, &spec, &rootfs)?;

        // Configure external namespaces for CRIU
        // This follows the runc pattern for handling network and PID namespaces.
        // extra_files keeps the namespace file descriptors alive until criu.restore()
        // sends them to CRIU via SCM_RIGHTS.
        let mut extra_files: Vec<File> = Vec::new();
        handle_restoring_namespaces(&mut criu, &spec, &mut extra_files)?;

        // Register the notification callback and set its context.
        // The callback captures container state and console socket via thread-local
        // storage since NotifyCallback is a fn pointer that cannot close over variables.
        criu.set_notify_cb(restore_callback);
        RESTORE_CTX.with(|ctx| {
            *ctx.borrow_mut() = Some(RestoreContext {
                container: self.clone(),
                console_socket: opts.console_socket.clone(),
            });
        });

        let result = criu.restore().map_err(|err| {
            tracing::error!(?err, id = ?self.id(), logfile = ?opts.image_path.join(CRIU_RESTORE_LOG_FILE), "restoring container failed");
            LibcontainerError::Other(err.to_string())
        });

        // Clear callback context
        RESTORE_CTX.with(|ctx| {
            *ctx.borrow_mut() = None;
        });

        result
    }

    /// Configure external mounts for CRIU restore.
    /// This follows the runc pattern of addCriuRestoreMount.
    fn configure_external_mounts(
        &self,
        criu: &mut rust_criu::Criu,
        spec: &Spec,
        rootfs: &Path,
    ) -> Result<(), LibcontainerError> {
        if let Some(mounts) = spec.mounts() {
            for m in mounts {
                // Get the destination path relative to rootfs
                let dest = m.destination();
                let dest_str = dest.to_string_lossy();

                // Handle bind mounts
                if let Some(options) = m.options() {
                    if options.iter().any(|o| o == "bind" || o == "rbind") {
                        if let Some(source) = m.source() {
                            let source_str = source.to_string_lossy();
                            tracing::debug!(
                                "Adding external mount: {} -> {}",
                                dest_str,
                                source_str
                            );
                            criu.set_external_mount(dest_str.to_string(), source_str.to_string());
                        }
                    }
                }
            }
        }

        // Add /dev/null for masked paths (same as runc)
        if let Some(linux) = spec.linux() {
            if let Some(masked_paths) = linux.masked_paths() {
                if !masked_paths.is_empty() {
                    criu.set_external_mount("/dev/null".to_string(), "/dev/null".to_string());
                }
            }

            // Add devices
            if let Some(devices) = linux.devices() {
                for device in devices {
                    let path = device.path().to_string_lossy().to_string();
                    criu.set_external_mount(path.clone(), path);
                }
            }
        }

        // For rootfs itself
        let rootfs_str = rootfs.to_string_lossy().to_string();
        criu.set_external_mount("/".to_string(), rootfs_str);

        Ok(())
    }

    /// Get the rootfs path and spec from the bundle.
    fn get_rootfs_and_spec(
        &self,
        bundle: &Path,
    ) -> Result<(std::path::PathBuf, Spec), LibcontainerError> {
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

        // If the rootfs path is absolute, use it directly
        // If relative, join with bundle path
        let rootfs_path = if root_path.is_absolute() {
            root_path.to_path_buf()
        } else {
            bundle.join(root_path)
        };

        // Verify the rootfs exists (required for CRIU restore)
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

        let rootfs = std::fs::canonicalize(&rootfs_path).map_err(|err| {
            tracing::error!(?rootfs_path, ?err, "failed to canonicalize rootfs path");
            LibcontainerError::OtherIO(err)
        })?;

        Ok((rootfs, spec))
    }
}
