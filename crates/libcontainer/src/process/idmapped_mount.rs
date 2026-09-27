//! Parent-side service that creates idmapped mount file descriptors on
//! behalf of the container init process.
//!
//! `mount_setattr(MOUNT_ATTR_IDMAP)` requires privileges the init process no
//! longer has once it has joined the container namespaces, so rootfs setup
//! asks the main process for the mount fd with `AskMountFd`. Mirrors runc's
//! `goCreateMountSources` in `libcontainer/process_linux.go`.

use std::fs::File;
use std::io::ErrorKind;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::Path;
use std::sync::mpsc;
use std::{fs, mem, thread};

use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sched::CloneFlags;
use nix::sys::wait::waitpid;
use nix::unistd::{ForkResult, Pid, fork, pipe2, read, write};
use oci_spec::runtime::{LinuxIdMapping, Spec};

use crate::container::mount_validation::mount_requests_idmap;
use crate::process::args::ContainerType;
use crate::process::message::{MountIdMapUsernsSource, MountMsg};
use crate::syscall::syscall::SyscallType;
use crate::syscall::{Syscall, SyscallError, linux};

#[derive(Debug, thiserror::Error)]
pub enum IdmappedMountError {
    #[error("failed to join init mount namespace: {0}")]
    JoinMountNamespace(String),
    #[error("failed to create user namespace for mount id-mappings: {0}")]
    CreateUserNamespace(String),
    #[error("invalid idmapped mount request: {0}")]
    InvalidRequest(String),
    #[error("idmapped mounts require open_tree/mount_setattr support (Linux 5.12+)")]
    NotSupported(#[source] SyscallError),
    #[error("failed to attach id-mapping, the source filesystem may not support idmapped mounts")]
    FilesystemNotSupported(#[source] SyscallError),
    #[error("failed syscall for idmapped mount")]
    Syscall(#[source] SyscallError),
    #[error("mount fd worker is unavailable: {0}")]
    WorkerUnavailable(String),
}

type Result<T> = std::result::Result<T, IdmappedMountError>;

pub(crate) fn spec_has_idmapped_mounts(spec: &Spec) -> bool {
    spec.mounts()
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .any(mount_requests_idmap)
}

pub(crate) fn mount_fd_service_required(container_type: ContainerType, spec: &Spec) -> bool {
    // Only an init container prepares the rootfs, so only it can ask for mount fds.
    matches!(container_type, ContainerType::InitContainer) && spec_has_idmapped_mounts(spec)
}

#[derive(Debug)]
pub(crate) struct MountFdService {
    request_tx: mpsc::Sender<MountMsg>,
    reply_rx: mpsc::Receiver<Result<OwnedFd>>,
}

impl MountFdService {
    /// Blocks until the worker has detached its filesystem state, so a broken
    /// setup fails the container start rather than the first mount request.
    ///
    /// The mount namespace join is deferred to the first request: init enters
    /// that namespace only after the main process learns its pid, but is
    /// guaranteed to be inside by the time rootfs setup sends `AskMountFd`.
    pub(crate) fn start(init_pid: Pid, syscall: SyscallType) -> Result<Self> {
        let (request_tx, request_rx) = mpsc::channel::<MountMsg>();
        let (reply_tx, reply_rx) = mpsc::channel::<Result<OwnedFd>>();
        let (setup_tx, setup_rx) = mpsc::channel::<Result<()>>();
        thread::spawn(move || {
            let syscall = syscall.create_syscall();
            // setns(CLONE_NEWNS) fails on a thread that shares filesystem
            // state with the rest of the process.
            if let Err(err) = syscall.unshare(CloneFlags::CLONE_FS) {
                let _ = setup_tx.send(Err(IdmappedMountError::JoinMountNamespace(format!(
                    "unshare(CLONE_FS): {err}"
                ))));
                return;
            }
            let _ = setup_tx.send(Ok(()));

            let mut mntns_joined: Option<std::result::Result<(), String>> = None;
            for msg in request_rx {
                let joined = mntns_joined.get_or_insert_with(|| {
                    join_init_mount_namespace(syscall.as_ref(), init_pid)
                        .map_err(|err| err.to_string())
                });
                let reply = match joined {
                    Ok(()) => create_idmapped_mount_fd(syscall.as_ref(), &msg, init_pid),
                    Err(err) => Err(IdmappedMountError::JoinMountNamespace(err.clone())),
                };
                let _ = reply_tx.send(reply);
            }
        });

        match setup_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                request_tx,
                reply_rx,
            }),
            Ok(Err(err)) => Err(err),
            Err(err) => Err(IdmappedMountError::WorkerUnavailable(err.to_string())),
        }
    }

    pub(crate) fn request_mount_fd(&self, msg: MountMsg) -> Result<OwnedFd> {
        self.request_tx
            .send(msg)
            .map_err(|err| IdmappedMountError::WorkerUnavailable(err.to_string()))?;
        self.reply_rx
            .recv()
            .map_err(|err| IdmappedMountError::WorkerUnavailable(err.to_string()))?
    }
}

/// Resolves mount sources the way the init process sees them. Requires the
/// calling thread to have run unshare(CLONE_FS) first.
fn join_init_mount_namespace(syscall: &dyn Syscall, init_pid: Pid) -> Result<()> {
    let mntns_path = format!("/proc/{}/ns/mnt", init_pid.as_raw());
    let mntns = File::open(&mntns_path).map_err(|err| {
        IdmappedMountError::JoinMountNamespace(format!("open {mntns_path}: {err}"))
    })?;
    syscall
        .set_ns(mntns.as_raw_fd(), CloneFlags::CLONE_NEWNS)
        .map_err(|err| IdmappedMountError::JoinMountNamespace(format!("setns: {err}")))?;
    Ok(())
}

/// The mount must be detached: mount_setattr(2) rejects MOUNT_ATTR_IDMAP on a
/// mount that has ever been visible in a mount namespace. The returned fd is
/// ready to be installed with move_mount(2).
fn create_idmapped_mount_fd(
    syscall: &dyn Syscall,
    msg: &MountMsg,
    init_pid: Pid,
) -> Result<OwnedFd> {
    let idmap = msg.idmap.as_ref().ok_or_else(|| {
        IdmappedMountError::InvalidRequest("mount fd request without id-mappings".to_string())
    })?;
    let userns_fd = match &idmap.userns_source {
        MountIdMapUsernsSource::Mappings {
            uid_mappings,
            gid_mappings,
        } => create_userns_fd(uid_mappings, gid_mappings)?,
        MountIdMapUsernsSource::ContainerUserns => open_user_namespace(init_pid)?,
    };

    let source = msg.source.to_str().ok_or_else(|| {
        IdmappedMountError::InvalidRequest(format!(
            "mount source is not valid UTF-8: {:?}",
            msg.source
        ))
    })?;
    let mut open_flags = linux::OPEN_TREE_CLONE | linux::OPEN_TREE_CLOEXEC;
    if msg.clone_mount_tree_recursively {
        open_flags |= linux::AT_RECURSIVE;
    }
    let mount_fd = syscall
        .open_tree(libc::AT_FDCWD, Some(source), open_flags)
        .map_err(syscall_error)?;

    let mut setattr_flags = linux::AT_EMPTY_PATH;
    if idmap.apply_idmap_recursively {
        setattr_flags |= linux::AT_RECURSIVE;
    }
    let mount_attr = linux::MountAttr {
        attr_set: linux::MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd: userns_fd.as_raw_fd() as u64,
    };
    syscall
        .mount_setattr(
            mount_fd.as_fd(),
            Path::new(""),
            setattr_flags,
            &mount_attr,
            mem::size_of::<linux::MountAttr>(),
        )
        .map_err(|err| match err {
            // Usually means the source filesystem has no idmapped mount support.
            SyscallError::Nix(Errno::EINVAL) => IdmappedMountError::FilesystemNotSupported(err),
            err => syscall_error(err),
        })?;
    Ok(mount_fd)
}

fn syscall_error(err: SyscallError) -> IdmappedMountError {
    match err {
        SyscallError::Nix(Errno::ENOSYS) => IdmappedMountError::NotSupported(err),
        _ => IdmappedMountError::Syscall(err),
    }
}

/// `mount_setattr` takes the id-mapping as a user namespace, so one has to be
/// materialized to carry it. Nothing ever runs in it: a child process only
/// exists to give the id-map files a pid, and dies once the fd keeps the
/// namespace alive. The worker cannot unshare it itself without losing the
/// host privileges that mount_setattr(2) then needs.
fn create_userns_fd(
    uid_mappings: &[LinuxIdMapping],
    gid_mappings: &[LinuxIdMapping],
) -> Result<OwnedFd> {
    for (file_name, mappings) in [("uid_map", uid_mappings), ("gid_map", gid_mappings)] {
        if mappings.is_empty() {
            return Err(IdmappedMountError::InvalidRequest(format!(
                "{file_name} mappings are empty"
            )));
        }
    }

    // O_CLOEXEC so a concurrent exec elsewhere in the process cannot inherit
    // the write ends and keep the release pipe from ever reaching EOF.
    let (ready_read, ready_write) = pipe2(OFlag::O_CLOEXEC).map_err(|err| {
        IdmappedMountError::CreateUserNamespace(format!("create ready pipe: {err}"))
    })?;
    let (release_read, release_write) = pipe2(OFlag::O_CLOEXEC).map_err(|err| {
        IdmappedMountError::CreateUserNamespace(format!("create release pipe: {err}"))
    })?;

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Forked from a multi-threaded process: async-signal-safe calls
            // only, so failures are reported through the exit code.
            drop(ready_read);
            drop(release_write);
            if nix::sched::unshare(CloneFlags::CLONE_NEWUSER).is_ok() {
                let _ = write(&ready_write, &[1]);
                let mut buf = [0u8; 1];
                // Exiting early would take /proc/<pid>/{uid,gid}_map with it
                // before the parent has written them.
                while let Err(Errno::EINTR) = read(&release_read, &mut buf) {}
                unsafe { libc::_exit(0) }
            }
            unsafe { libc::_exit(1) }
        }
        Ok(ForkResult::Parent { child }) => {
            drop(ready_write);
            drop(release_read);
            let mut buf = [0u8; 1];
            let ready = loop {
                match read(&ready_read, &mut buf) {
                    Err(Errno::EINTR) => continue,
                    other => break other,
                }
            };
            let result = match ready {
                Ok(1) => write_userns_mappings(child, uid_mappings, gid_mappings)
                    .and_then(|()| open_user_namespace(child)),
                _ => Err(IdmappedMountError::CreateUserNamespace(
                    "user namespace helper process failed to unshare".to_string(),
                )),
            };
            // The child must outlive the id-map writes above: its /proc entries
            // vanish when it exits.
            drop(release_write);
            while let Err(Errno::EINTR) = waitpid(child, None) {}
            result
        }
        Err(err) => Err(IdmappedMountError::CreateUserNamespace(format!(
            "fork user namespace helper process: {err}"
        ))),
    }
}

fn write_userns_mappings(
    pid: Pid,
    uid_mappings: &[LinuxIdMapping],
    gid_mappings: &[LinuxIdMapping],
) -> Result<()> {
    // Required before an unprivileged process may write the gid map, see
    // user_namespaces(7). ENOENT means the kernel predates the file.
    let setgroups_path = format!("/proc/{}/setgroups", pid.as_raw());
    if let Err(err) = fs::write(&setgroups_path, "deny") {
        if err.kind() != ErrorKind::NotFound {
            return Err(IdmappedMountError::CreateUserNamespace(format!(
                "write deny to {setgroups_path}: {err}"
            )));
        }
    }

    write_id_mapping_file(pid, "uid_map", uid_mappings)?;
    write_id_mapping_file(pid, "gid_map", gid_mappings)
}

fn write_id_mapping_file(pid: Pid, file_name: &str, mappings: &[LinuxIdMapping]) -> Result<()> {
    use std::fmt::Write;
    let mut content = String::new();
    for mapping in mappings {
        let _ = writeln!(
            content,
            "{} {} {}",
            mapping.container_id(),
            mapping.host_id(),
            mapping.size()
        );
    }
    let path = format!("/proc/{}/{}", pid.as_raw(), file_name);
    fs::write(&path, content)
        .map_err(|err| IdmappedMountError::CreateUserNamespace(format!("write {path}: {err}")))
}

fn open_user_namespace(pid: Pid) -> Result<OwnedFd> {
    let path = format!("/proc/{}/ns/user", pid.as_raw());
    let file = File::open(&path)
        .map_err(|err| IdmappedMountError::CreateUserNamespace(format!("open {path}: {err}")))?;
    Ok(file.into())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Result;
    use nix::unistd::{getgid, getuid};
    use oci_spec::runtime::{LinuxIdMappingBuilder, MountBuilder, SpecBuilder};
    use serial_test::serial;

    use super::*;
    use crate::process::message::MountIdMap;
    use crate::syscall::syscall::create_syscall;
    use crate::syscall::test::{ArgName, TestHelperSyscall};

    fn container_userns_request(recursive: bool) -> MountMsg {
        MountMsg {
            source: PathBuf::from("/src"),
            idmap: Some(MountIdMap {
                userns_source: MountIdMapUsernsSource::ContainerUserns,
                apply_idmap_recursively: recursive,
            }),
            clone_mount_tree_recursively: recursive,
        }
    }

    fn mock_syscall(syscall: &dyn Syscall) -> &TestHelperSyscall {
        syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
    }

    fn own_id_mappings() -> (LinuxIdMapping, LinuxIdMapping) {
        let uid_mapping = LinuxIdMappingBuilder::default()
            .container_id(0u32)
            .host_id(getuid())
            .size(1u32)
            .build()
            .unwrap();
        let gid_mapping = LinuxIdMappingBuilder::default()
            .container_id(0u32)
            .host_id(getgid())
            .size(1u32)
            .build()
            .unwrap();
        (uid_mapping, gid_mapping)
    }

    #[test]
    fn mount_fd_service_only_runs_for_init_containers_with_idmapped_mounts() {
        let plain = MountBuilder::default()
            .destination(PathBuf::from("/mnt"))
            .typ("tmpfs")
            .source(PathBuf::from("tmpfs"))
            .build()
            .unwrap();
        let idmapped = MountBuilder::default()
            .destination(PathBuf::from("/mnt"))
            .typ("bind")
            .source(PathBuf::from("/src"))
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .build()
            .unwrap();

        let spec = SpecBuilder::default()
            .mounts(vec![plain.clone()])
            .build()
            .unwrap();
        assert!(!mount_fd_service_required(
            ContainerType::InitContainer,
            &spec
        ));

        let spec = SpecBuilder::default()
            .mounts(vec![plain, idmapped])
            .build()
            .unwrap();
        assert!(mount_fd_service_required(
            ContainerType::InitContainer,
            &spec
        ));
        assert!(!mount_fd_service_required(
            ContainerType::TenantContainer { exec_notify_fd: -1 },
            &spec
        ));
    }

    #[test]
    fn create_idmapped_mount_fd_sets_idmap_attr() -> Result<()> {
        let syscall = create_syscall();
        let msg = container_userns_request(false);

        let _fd = create_idmapped_mount_fd(syscall.as_ref(), &msg, Pid::this())?;

        let mock = mock_syscall(syscall.as_ref());
        let open_tree_args = mock.get_open_tree_args();
        assert_eq!(open_tree_args.len(), 1);
        assert_eq!(open_tree_args[0].dirfd, libc::AT_FDCWD);
        assert_eq!(open_tree_args[0].path.as_deref(), Some("/src"));
        assert_eq!(
            open_tree_args[0].flags,
            linux::OPEN_TREE_CLONE | linux::OPEN_TREE_CLOEXEC
        );
        let setattr_args = mock.get_mount_setattr_args();
        assert_eq!(setattr_args.len(), 1);
        assert_eq!(setattr_args[0].flags, linux::AT_EMPTY_PATH);
        assert_eq!(setattr_args[0].attr_set, linux::MOUNT_ATTR_IDMAP);
        assert_eq!(setattr_args[0].attr_clr, 0);
        assert_eq!(setattr_args[0].propagation, 0);
        assert_ne!(setattr_args[0].userns_fd, 0);
        Ok(())
    }

    #[test]
    fn create_idmapped_mount_fd_recursive_flags() -> Result<()> {
        let syscall = create_syscall();
        let msg = container_userns_request(true);

        let _fd = create_idmapped_mount_fd(syscall.as_ref(), &msg, Pid::this())?;

        let mock = mock_syscall(syscall.as_ref());
        assert_eq!(
            mock.get_open_tree_args()[0].flags,
            linux::OPEN_TREE_CLONE | linux::OPEN_TREE_CLOEXEC | linux::AT_RECURSIVE
        );
        assert_eq!(
            mock.get_mount_setattr_args()[0].flags,
            linux::AT_EMPTY_PATH | linux::AT_RECURSIVE
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn create_idmapped_mount_fd_uses_mount_level_mappings() -> Result<()> {
        let (uid_mapping, gid_mapping) = own_id_mappings();
        let syscall = create_syscall();
        let msg = MountMsg {
            source: PathBuf::from("/src"),
            idmap: Some(MountIdMap {
                userns_source: MountIdMapUsernsSource::Mappings {
                    uid_mappings: vec![uid_mapping],
                    gid_mappings: vec![gid_mapping],
                },
                apply_idmap_recursively: false,
            }),
            clone_mount_tree_recursively: false,
        };

        let _fd = create_idmapped_mount_fd(syscall.as_ref(), &msg, Pid::this())?;

        let setattr_args = mock_syscall(syscall.as_ref()).get_mount_setattr_args();
        assert_eq!(setattr_args.len(), 1);
        assert_eq!(setattr_args[0].attr_set, linux::MOUNT_ATTR_IDMAP);
        assert_ne!(setattr_args[0].userns_fd, 0);
        Ok(())
    }

    #[test]
    fn create_idmapped_mount_fd_reports_missing_kernel_support() {
        let syscall = create_syscall();
        mock_syscall(syscall.as_ref())
            .set_ret_err(ArgName::OpenTree, || Err(SyscallError::Nix(Errno::ENOSYS)));

        let err = create_idmapped_mount_fd(
            syscall.as_ref(),
            &container_userns_request(false),
            Pid::this(),
        )
        .unwrap_err();
        assert!(matches!(err, IdmappedMountError::NotSupported(_)));
        assert_eq!(
            err.to_string(),
            "idmapped mounts require open_tree/mount_setattr support (Linux 5.12+)"
        );
    }

    #[test]
    fn create_idmapped_mount_fd_reports_missing_filesystem_support() {
        let syscall = create_syscall();
        mock_syscall(syscall.as_ref()).set_ret_err(ArgName::MountSetattr, || {
            Err(SyscallError::Nix(Errno::EINVAL))
        });

        let err = create_idmapped_mount_fd(
            syscall.as_ref(),
            &container_userns_request(false),
            Pid::this(),
        )
        .unwrap_err();
        assert!(matches!(err, IdmappedMountError::FilesystemNotSupported(_)));
    }

    #[test]
    fn create_userns_fd_rejects_empty_mappings() {
        let (uid_mapping, gid_mapping) = own_id_mappings();

        // Rejected before the fork, so no #[serial] needed.
        let err = create_userns_fd(&[], &[gid_mapping]).unwrap_err();
        assert!(
            matches!(err, IdmappedMountError::InvalidRequest(msg) if msg == "uid_map mappings are empty")
        );
        let err = create_userns_fd(&[uid_mapping], &[]).unwrap_err();
        assert!(
            matches!(err, IdmappedMountError::InvalidRequest(msg) if msg == "gid_map mappings are empty")
        );
    }

    #[test]
    #[serial]
    fn create_userns_fd_returns_user_namespace() -> Result<()> {
        let (uid_mapping, gid_mapping) = own_id_mappings();

        let userns_fd = create_userns_fd(&[uid_mapping], &[gid_mapping])?;

        let link = fs::read_link(format!("/proc/self/fd/{}", userns_fd.as_raw_fd()))?;
        assert!(
            link.to_string_lossy().starts_with("user:["),
            "expected a user namespace fd, got {link:?}"
        );
        Ok(())
    }

    #[test]
    fn mount_fd_service_joins_mount_namespace_lazily() {
        let service = MountFdService::start(Pid::from_raw(-1), SyscallType::Test)
            .expect("service startup must not join the init mount namespace");

        let err = service
            .request_mount_fd(container_userns_request(false))
            .unwrap_err();
        assert!(matches!(err, IdmappedMountError::JoinMountNamespace(_)));
    }
}
