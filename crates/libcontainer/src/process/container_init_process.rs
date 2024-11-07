use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::{env, fs, mem};

use nc;
use nix::mount::{MntFlags, MsFlags};
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use nix::unistd::{self, setsid, Gid, Uid};
use oci_spec::runtime::{
    IOPriorityClass, LinuxIOPriority, LinuxNamespaceType, LinuxSchedulerFlag, LinuxSchedulerPolicy,
    Scheduler, Spec, User,
};

use super::args::{ContainerArgs, ContainerType};
use crate::error::MissingSpecError;
use crate::namespaces::{NamespaceError, Namespaces};
use crate::process::channel;
use crate::rootfs::RootFS;
#[cfg(feature = "libseccomp")]
use crate::seccomp;
use crate::syscall::{Syscall, SyscallError};
use crate::user_ns::UserNamespaceConfig;
use crate::{apparmor, capabilities, hooks, notify_socket, rootfs, tty, utils, workload};

#[derive(Debug, thiserror::Error)]
pub enum InitProcessError {
    #[error("failed to set sysctl")]
    Sysctl(#[source] std::io::Error),
    #[error("failed to mount path as readonly")]
    MountPathReadonly(#[source] SyscallError),
    #[error("failed to mount path as masked")]
    MountPathMasked(#[source] SyscallError),
    #[error(transparent)]
    Namespaces(#[from] NamespaceError),
    #[error("failed to set hostname")]
    SetHostname(#[source] SyscallError),
    #[error("failed to set domainname")]
    SetDomainname(#[source] SyscallError),
    #[error("failed to reopen /dev/null")]
    ReopenDevNull(#[source] std::io::Error),
    #[error("failed to unix syscall")]
    NixOther(#[source] nix::Error),
    #[error(transparent)]
    MissingSpec(#[from] crate::error::MissingSpecError),
    #[error("failed to setup tty")]
    Tty(#[source] tty::TTYError),
    #[error("failed to run hooks")]
    Hooks(#[from] hooks::HookError),
    #[error("failed to prepare rootfs")]
    RootFS(#[source] rootfs::RootfsError),
    #[error("failed syscall")]
    SyscallOther(#[source] SyscallError),
    #[error("failed apparmor")]
    AppArmor(#[source] apparmor::AppArmorError),
    #[error("invalid umask")]
    InvalidUmask(u32),
    #[error(transparent)]
    #[cfg(feature = "libseccomp")]
    Seccomp(#[from] seccomp::SeccompError),
    #[error("invalid executable: {0}")]
    InvalidExecutable(String),
    #[error("io error")]
    Io(#[source] std::io::Error),
    #[error(transparent)]
    Channel(#[from] channel::ChannelError),
    #[error("setgroup is disabled")]
    SetGroupDisabled,
    #[error(transparent)]
    NotifyListener(#[from] notify_socket::NotifyListenerError),
    #[error(transparent)]
    Workload(#[from] workload::ExecutorError),
    #[error(transparent)]
    WorkloadValidation(#[from] workload::ExecutorValidationError),
    #[error(transparent)]
    WorkloadSetEnvs(#[from] workload::ExecutorSetEnvsError),
    #[error("invalid io priority class: {0}")]
    IoPriorityClass(String),
    #[error("call exec sched_setattr error: {0}")]
    SchedSetattr(String),
    #[error("failed to verify if current working directory is safe")]
    InvalidCwd(#[source] nix::Error),
}

type Result<T> = std::result::Result<T, InitProcessError>;

fn sysctl(kernel_params: &HashMap<String, String>) -> Result<()> {
    let sys = PathBuf::from("/proc/sys");
    for (kernel_param, value) in kernel_params {
        let path = sys.join(kernel_param.replace('.', "/"));
        tracing::debug!(
            "apply value {} to kernel parameter {}.",
            value,
            kernel_param
        );
        fs::write(path, value.as_bytes()).map_err(|err| {
            tracing::error!("failed to set sysctl {kernel_param}={value}: {err}");
            InitProcessError::Sysctl(err)
        })?;
    }

    Ok(())
}

// make a read only path
// The first time we bind mount, other flags are ignored,
// so we need to mount it once and then remount it with the necessary flags specified.
// https://man7.org/linux/man-pages/man2/mount.2.html
fn readonly_path(path: &Path, syscall: &dyn Syscall) -> Result<()> {
    if let Err(err) = syscall.mount(
        Some(path),
        path,
        None,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None,
    ) {
        if let SyscallError::Nix(errno) = err {
            // ignore error if path is not exist.
            if matches!(errno, nix::errno::Errno::ENOENT) {
                return Ok(());
            }
        }

        tracing::error!(?path, ?err, "failed to mount path as readonly");
        return Err(InitProcessError::MountPathReadonly(err));
    }

    syscall
        .mount(
            Some(path),
            path,
            None,
            MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV
                | MsFlags::MS_NOEXEC
                | MsFlags::MS_BIND
                | MsFlags::MS_REMOUNT
                | MsFlags::MS_RDONLY,
            None,
        )
        .map_err(|err| {
            tracing::error!(?path, ?err, "failed to remount path as readonly");
            InitProcessError::MountPathReadonly(err)
        })?;

    tracing::debug!("readonly path {:?} mounted", path);
    Ok(())
}

// For files, bind mounts /dev/null over the top of the specified path.
// For directories, mounts read-only tmpfs over the top of the specified path.
fn masked_path(path: &Path, mount_label: &Option<String>, syscall: &dyn Syscall) -> Result<()> {
    if let Err(err) = syscall.mount(
        Some(Path::new("/dev/null")),
        path,
        None,
        MsFlags::MS_BIND,
        None,
    ) {
        match err {
            SyscallError::Nix(nix::errno::Errno::ENOENT) => {
                // ignore error if path is not exist.
            }
            SyscallError::Nix(nix::errno::Errno::ENOTDIR) => {
                let label = match mount_label {
                    Some(l) => format!("context=\"{l}\""),
                    None => "".to_string(),
                };
                syscall
                    .mount(
                        Some(Path::new("tmpfs")),
                        path,
                        Some("tmpfs"),
                        MsFlags::MS_RDONLY,
                        Some(label.as_str()),
                    )
                    .map_err(|err| {
                        tracing::error!(?path, ?err, "failed to mount path as masked using tempfs");
                        InitProcessError::MountPathMasked(err)
                    })?;
            }
            _ => {
                tracing::error!(
                    ?path,
                    ?err,
                    "failed to mount path as masked using /dev/null"
                );
                return Err(InitProcessError::MountPathMasked(err));
            }
        }
    }

    Ok(())
}

// Enter into rest of namespace. Note, we already entered into user and pid
// namespace. We also have to enter into mount namespace last since
// namespace may be bind to /proc path. The /proc path will need to be
// accessed before pivot_root.
fn apply_rest_namespaces(
    namespaces: &Namespaces,
    spec: &Spec,
    syscall: &dyn Syscall,
) -> Result<()> {
    namespaces
        .apply_namespaces(|ns_type| -> bool {
            ns_type != CloneFlags::CLONE_NEWUSER && ns_type != CloneFlags::CLONE_NEWPID
        })
        .map_err(|err| {
            tracing::error!(
                ?err,
                "failed to apply rest of the namespaces (exclude user and pid)"
            );
            InitProcessError::Namespaces(err)
        })?;

    // Only set the host name if entering into a new uts namespace
    if let Some(uts_namespace) = namespaces.get(LinuxNamespaceType::Uts)? {
        if uts_namespace.path().is_none() {
            if let Some(hostname) = spec.hostname() {
                syscall.set_hostname(hostname).map_err(|err| {
                    tracing::error!(?err, ?hostname, "failed to set hostname");
                    InitProcessError::SetHostname(err)
                })?;
            }

            if let Some(domainname) = spec.domainname() {
                syscall.set_domainname(domainname).map_err(|err| {
                    tracing::error!(?err, ?domainname, "failed to set domainname");
                    InitProcessError::SetDomainname(err)
                })?;
            }
        }
    }
    Ok(())
}

fn reopen_dev_null() -> Result<()> {
    // At this point we should be inside of the container and now
    // we can re-open /dev/null if it is in use to the /dev/null
    // in the container.

    let dev_null = fs::File::open("/dev/null").map_err(|err| {
        tracing::error!(?err, "failed to open /dev/null inside the container");
        InitProcessError::ReopenDevNull(err)
    })?;
    let dev_null_fstat_info = nix::sys::stat::fstat(dev_null.as_raw_fd()).map_err(|err| {
        tracing::error!(?err, "failed to fstat /dev/null inside the container");
        InitProcessError::NixOther(err)
    })?;

    // Check if stdin, stdout or stderr point to /dev/null
    for fd in 0..3 {
        let fstat_info = nix::sys::stat::fstat(fd).map_err(|err| {
            tracing::error!(?err, "failed to fstat stdio fd {}", fd);
            InitProcessError::NixOther(err)
        })?;

        if dev_null_fstat_info.st_rdev == fstat_info.st_rdev {
            // This FD points to /dev/null outside of the container.
            // Let's point to /dev/null inside of the container.
            nix::unistd::dup2(dev_null.as_raw_fd(), fd).map_err(|err| {
                tracing::error!(?err, "failed to dup2 fd {} to /dev/null", fd);
                InitProcessError::NixOther(err)
            })?;
        }
    }

    Ok(())
}

// umount or hide the target path. If the target path is mounted
// try to unmount it first if the unmount operation fails with EINVAL
// then mount a tmpfs with size 0k to hide the target path.
fn unmount_or_hide(syscall: &dyn Syscall, target: impl AsRef<Path>) -> Result<()> {
    let target_path = target.as_ref();
    match syscall.umount2(target_path, MntFlags::MNT_DETACH) {
        Ok(_) => Ok(()),
        Err(SyscallError::Nix(nix::errno::Errno::EINVAL)) => syscall
            .mount(
                None,
                target_path,
                Some("tmpfs"),
                MsFlags::MS_RDONLY,
                Some("size=0k"),
            )
            .map_err(InitProcessError::SyscallOther),
        Err(err) => Err(InitProcessError::SyscallOther(err)),
    }
}

fn move_root(syscall: &dyn Syscall, rootfs: &Path) -> Result<()> {
    unistd::chdir(rootfs).map_err(InitProcessError::NixOther)?;
    // umount /sys and /proc if they are mounted, the purpose is to
    // unmount or hide the /sys and /proc filesystems before the process changes its
    // root to the new rootfs. thus ensure that the /sys and /proc filesystems are not
    // accessible in the new rootfs. the logic is borrowed from crun
    // https://github.com/containers/crun/blob/53cd1c1c697d7351d0cad23708d29bf4a7980a3a/src/libcrun/linux.c#L2780
    unmount_or_hide(syscall, "/sys")?;
    unmount_or_hide(syscall, "/proc")?;
    syscall
        .mount(Some(rootfs), Path::new("/"), None, MsFlags::MS_MOVE, None)
        .map_err(|err| {
            tracing::error!(?err, ?rootfs, "failed to mount ms_move");
            InitProcessError::SyscallOther(err)
        })?;

    syscall.chroot(Path::new(".")).map_err(|err| {
        tracing::error!(?err, ?rootfs, "failed to chroot");
        InitProcessError::SyscallOther(err)
    })?;

    unistd::chdir("/").map_err(InitProcessError::NixOther)?;

    Ok(())
}

fn do_pivot_root(
    syscall: &dyn Syscall,
    namespaces: &Namespaces,
    no_pivot: bool,
    rootfs: impl AsRef<Path>,
) -> Result<()> {
    let rootfs_path = rootfs.as_ref();

    let handle_error = |err: SyscallError, msg: &str| -> InitProcessError {
        tracing::error!(?err, ?rootfs_path, msg);
        InitProcessError::SyscallOther(err)
    };

    match namespaces.get(LinuxNamespaceType::Mount)? {
        Some(_) if no_pivot => move_root(syscall, rootfs_path),
        Some(_) => syscall
            .pivot_rootfs(rootfs.as_ref())
            .map_err(|err| handle_error(err, "failed to pivot root")),
        None => syscall
            .chroot(rootfs_path)
            .map_err(|err| handle_error(err, "failed to chroot")),
    }
}

// Some variables are unused in the case where libseccomp feature is not enabled.
#[allow(unused_variables)]
pub fn container_init_process(
    args: &ContainerArgs,
    main_sender: &mut channel::MainSender,
    init_receiver: &mut channel::InitReceiver,
) -> Result<()> {
    let syscall = args.syscall.create_syscall();
    let spec = &args.spec;
    let linux = spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;
    let proc = spec.process().as_ref().ok_or(MissingSpecError::Process)?;
    let mut envs: HashMap<String, String> =
        utils::parse_env(proc.env().as_ref().unwrap_or(&vec![]));
    let rootfs_path = &args.rootfs;
    let hooks = spec.hooks().as_ref();
    let container = args.container.as_ref();
    let namespaces = Namespaces::try_from(linux.namespaces().as_ref())?;
    let notify_listener = &args.notify_listener;

    setsid().map_err(|err| {
        tracing::error!(?err, "failed to setsid to create a session");
        InitProcessError::NixOther(err)
    })?;

    set_io_priority(syscall.as_ref(), proc.io_priority())?;

    setup_scheduler(proc.scheduler())?;

    // set up tty if specified
    if let Some(csocketfd) = args.console_socket {
        tty::setup_console(csocketfd).map_err(|err| {
            tracing::error!(?err, "failed to set up tty");
            InitProcessError::Tty(err)
        })?;
    }

    apply_rest_namespaces(&namespaces, spec, syscall.as_ref())?;

    if let Some(true) = proc.no_new_privileges() {
        let _ = prctl::set_no_new_privileges(true);
    }

    if matches!(args.container_type, ContainerType::InitContainer) {
        // create_container hook needs to be called after the namespace setup, but
        // before pivot_root is called. This runs in the container namespaces.
        if let Some(hooks) = hooks {
            hooks::run_hooks(hooks.create_container().as_ref(), container, None).map_err(
                |err| {
                    tracing::error!(?err, "failed to run create container hooks");
                    InitProcessError::Hooks(err)
                },
            )?;
        }

        let in_user_ns = utils::is_in_new_userns().map_err(InitProcessError::Io)?;
        let bind_service = namespaces.get(LinuxNamespaceType::User)?.is_some() || in_user_ns;
        let rootfs = RootFS::new();
        rootfs
            .prepare_rootfs(
                spec,
                rootfs_path,
                bind_service,
                namespaces.get(LinuxNamespaceType::Cgroup)?.is_some(),
            )
            .map_err(|err| {
                tracing::error!(?err, "failed to prepare rootfs");
                InitProcessError::RootFS(err)
            })?;

        // Entering into the rootfs jail. If mount namespace is specified, then
        // we use pivot_root, but if we are on the host mount namespace, we will
        // use simple chroot. Scary things will happen if you try to pivot_root
        // in the host mount namespace...
        do_pivot_root(syscall.as_ref(), &namespaces, args.no_pivot, rootfs_path)?;

        // As we have changed the root mount, from here on
        // logs are no longer visible in journalctl
        // so make sure that you bubble up any errors
        // and do not call unwrap() as any panics would not be correctly logged

        rootfs.adjust_root_mount_propagation(linux).map_err(|err| {
            tracing::error!(?err, "failed to adjust root mount propagation");
            InitProcessError::RootFS(err)
        })?;

        reopen_dev_null().map_err(|err| {
            tracing::error!(?err, "failed to reopen /dev/null");
            err
        })?;

        if let Some(kernel_params) = linux.sysctl() {
            sysctl(kernel_params)?;
        }
    }

    if let Some(profile) = proc.apparmor_profile() {
        apparmor::apply_profile(profile).map_err(|err| {
            tracing::error!(?err, "failed to apply apparmor profile");
            InitProcessError::AppArmor(err)
        })?;
    }

    if let Some(true) = spec.root().as_ref().map(|r| r.readonly().unwrap_or(false)) {
        syscall
            .mount(
                None,
                Path::new("/"),
                None,
                MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT | MsFlags::MS_BIND,
                None,
            )
            .map_err(|err| {
                tracing::error!(?err, "failed to remount root `/` as readonly");
                InitProcessError::SyscallOther(err)
            })?;
    }

    if let Some(umask) = proc.user().umask() {
        match Mode::from_bits(umask) {
            Some(mode) => {
                nix::sys::stat::umask(mode);
            }
            None => {
                return Err(InitProcessError::InvalidUmask(umask));
            }
        }
    }

    if let Some(paths) = linux.readonly_paths() {
        // mount readonly path
        for path in paths {
            readonly_path(Path::new(path), syscall.as_ref()).map_err(|err| {
                tracing::error!(?err, ?path, "failed to set readonly path");
                err
            })?;
        }
    }

    if let Some(paths) = linux.masked_paths() {
        // mount masked path
        for path in paths {
            masked_path(Path::new(path), linux.mount_label(), syscall.as_ref()).map_err(|err| {
                tracing::error!(?err, ?path, "failed to set masked path");
                err
            })?;
        }
    }

    let cwd = format!("{}", proc.cwd().display());
    let do_chdir = if cwd.is_empty() {
        false
    } else {
        // This chdir must run before setting up the user.
        // This may allow the user running youki to access directories
        // that the container user cannot access.
        match unistd::chdir(proc.cwd()) {
            std::result::Result::Ok(_) => false,
            Err(nix::Error::EPERM) => true,
            Err(e) => {
                tracing::error!(?e, "failed to chdir");
                return Err(InitProcessError::NixOther(e));
            }
        }
    };

    set_supplementary_gids(proc.user(), &args.user_ns_config, syscall.as_ref()).map_err(|err| {
        tracing::error!(?err, "failed to set supplementary gids");
        err
    })?;

    syscall
        .set_id(
            Uid::from_raw(proc.user().uid()),
            Gid::from_raw(proc.user().gid()),
        )
        .map_err(|err| {
            let uid = proc.user().uid();
            let gid = proc.user().gid();
            tracing::error!(?err, ?uid, ?gid, "failed to set uid and gid");
            InitProcessError::SyscallOther(err)
        })?;

    // Take care of LISTEN_FDS used for systemd-active-socket. If the value is
    // not 0, then we have to preserve those fds as well, and set up the correct
    // environment variables.
    let preserve_fds: i32 = match env::var("LISTEN_FDS") {
        std::result::Result::Ok(listen_fds_str) => {
            let listen_fds = match listen_fds_str.parse::<i32>() {
                std::result::Result::Ok(v) => v,
                Err(error) => {
                    tracing::warn!(
                        "LISTEN_FDS entered is not a fd. Ignore the value. {:?}",
                        error
                    );

                    0
                }
            };

            // The LISTEN_FDS will have to be passed to container init process.
            // The LISTEN_PID will be set to PID 1. Based on the spec, if
            // LISTEN_FDS is 0, the variable should be unset, so we just ignore
            // it here, if it is 0.
            if listen_fds > 0 {
                envs.insert("LISTEN_FDS".to_owned(), listen_fds.to_string());
                envs.insert("LISTEN_PID".to_owned(), 1.to_string());
            }

            args.preserve_fds + listen_fds
        }
        Err(env::VarError::NotPresent) => args.preserve_fds,
        Err(env::VarError::NotUnicode(value)) => {
            tracing::warn!(
                "LISTEN_FDS entered is malformed: {:?}. Ignore the value.",
                &value
            );
            args.preserve_fds
        }
    };

    // Cleanup any extra file descriptors, so the new container process will not
    // leak a file descriptor from before execve gets executed. The first 3 fd will
    // stay open: stdio, stdout, and stderr. We would further preserve the next
    // "preserve_fds" number of fds. Set the rest of fd with CLOEXEC flag, so they
    // will be closed after execve into the container payload. We can't close the
    // fds immediately since we at least still need it for the pipe used to wait on
    // starting the container.
    syscall.close_range(preserve_fds).map_err(|err| {
        tracing::error!(?err, "failed to cleanup extra fds");
        InitProcessError::SyscallOther(err)
    })?;

    // Without no new privileges, seccomp is a privileged operation. We have to
    // do this before dropping capabilities. Otherwise, we should do it later,
    // as close to exec as possible.
    #[cfg(feature = "libseccomp")]
    if let Some(seccomp) = linux.seccomp() {
        if proc.no_new_privileges().is_none() {
            let notify_fd = seccomp::initialize_seccomp(seccomp).map_err(|err| {
                tracing::error!(?err, "failed to initialize seccomp");
                err
            })?;
            sync_seccomp(notify_fd, main_sender, init_receiver).map_err(|err| {
                tracing::error!(?err, "failed to sync seccomp");
                err
            })?;
        }
    }
    #[cfg(not(feature = "libseccomp"))]
    if proc.no_new_privileges().is_none() {
        tracing::warn!("seccomp not available, unable to enforce no_new_privileges!")
    }

    capabilities::reset_effective(syscall.as_ref()).map_err(|err| {
        tracing::error!(?err, "failed to reset effective capabilities");
        InitProcessError::SyscallOther(err)
    })?;
    if let Some(caps) = proc.capabilities() {
        capabilities::drop_privileges(caps, syscall.as_ref()).map_err(|err| {
            tracing::error!(?err, "failed to drop capabilities");
            InitProcessError::SyscallOther(err)
        })?;
    }

    // Change directory to process.cwd if process.cwd is not empty
    if do_chdir {
        unistd::chdir(proc.cwd()).map_err(|err| {
            let cwd = proc.cwd();
            tracing::error!(?err, ?cwd, "failed to chdir to cwd");
            InitProcessError::NixOther(err)
        })?;
    }

    // Ensure that the current working directory is actually inside the container.
    verify_cwd().map_err(|err| {
        tracing::error!(?err, "failed to verify cwd");
        err
    })?;

    // Initialize seccomp profile right before we are ready to execute the
    // payload so as few syscalls will happen between here and payload exec. The
    // notify socket will still need network related syscalls.
    #[cfg(feature = "libseccomp")]
    if let Some(seccomp) = linux.seccomp() {
        if proc.no_new_privileges().is_some() {
            let notify_fd = seccomp::initialize_seccomp(seccomp).map_err(|err| {
                tracing::error!(?err, "failed to initialize seccomp");
                err
            })?;
            sync_seccomp(notify_fd, main_sender, init_receiver).map_err(|err| {
                tracing::error!(?err, "failed to sync seccomp");
                err
            })?;
        }
    }
    #[cfg(not(feature = "libseccomp"))]
    if proc.no_new_privileges().is_some() {
        tracing::warn!("seccomp not available, unable to set seccomp privileges!")
    }

    // add HOME into envs if not exists
    if !envs.contains_key("HOME") {
        if let Some(dir_home) = utils::get_user_home(proc.user().uid()) {
            envs.insert("HOME".to_owned(), dir_home.to_string_lossy().to_string());
        }
    }

    args.executor.validate(spec)?;
    args.executor.setup_envs(envs)?;

    // Notify main process that the init process is ready to execute the
    // payload.  Note, because we are already inside the pid namespace, the pid
    // outside the pid namespace should be recorded by the intermediate process
    // already.
    main_sender.init_ready().map_err(|err| {
        tracing::error!(
            ?err,
            "failed to notify main process that init process is ready"
        );
        InitProcessError::Channel(err)
    })?;
    main_sender.close().map_err(|err| {
        tracing::error!(?err, "failed to close down main sender in init process");
        InitProcessError::Channel(err)
    })?;

    // listing on the notify socket for container start command
    notify_listener.wait_for_container_start().map_err(|err| {
        tracing::error!(?err, "failed to wait for container start");
        err
    })?;
    notify_listener.close().map_err(|err| {
        tracing::error!(?err, "failed to close notify socket");
        err
    })?;

    // create_container hook needs to be called after the namespace setup, but
    // before pivot_root is called. This runs in the container namespaces.
    if matches!(args.container_type, ContainerType::InitContainer) {
        if let Some(hooks) = hooks {
            hooks::run_hooks(hooks.start_container().as_ref(), container, None).map_err(|err| {
                tracing::error!(?err, "failed to run start container hooks");
                err
            })?;
        }
    }

    if proc.args().is_none() {
        tracing::error!("on non-Windows, at least one process arg entry is required");
        Err(MissingSpecError::Args)?;
    }

    args.executor.exec(spec).map_err(|err| {
        tracing::error!(?err, "failed to execute payload");
        err
    })?;

    // Once the executor is executed without error, it should not return. For
    // example, the default executor is expected to call `exec` and replace the
    // current process.
    unreachable!("the executor should not return if it is successful.");
}

// Before 3.19 it was possible for an unprivileged user to enter an user namespace,
// become root and then call setgroups in order to drop membership in supplementary
// groups. This allowed access to files which blocked access based on being a member
// of these groups (see CVE-2014-8989)
//
// This leaves us with three scenarios:
//
// Unprivileged user starting a rootless container: The main process is running as an
// unprivileged user and therefore cannot write the mapping until "deny" has been written
// to /proc/{pid}/setgroups. Once written /proc/{pid}/setgroups cannot be reset and the
// setgroups system call will be disabled for all processes in this user namespace. This
// also means that we should detect if the user is unprivileged and additional gids have
// been specified and bail out early as this can never work. This is not handled here,
// but during the validation for rootless containers.
//
// Privileged user starting a rootless container: It is not necessary to write "deny" to
// /proc/setgroups in order to create the gid mapping and therefore we don't. This means
// that setgroups could be used to drop groups, but this is fine as the user is privileged
// and could do so anyway.
// We already have checked during validation if the specified supplemental groups fall into
// the range that are specified in the gid mapping and bail out early if they do not.
//
// Privileged user starting a normal container: Just add the supplementary groups.
//
fn set_supplementary_gids(
    user: &User,
    user_ns_config: &Option<UserNamespaceConfig>,
    syscall: &dyn Syscall,
) -> Result<()> {
    if let Some(additional_gids) = user.additional_gids() {
        if additional_gids.is_empty() {
            return Ok(());
        }

        let setgroups = fs::read_to_string("/proc/self/setgroups").map_err(|err| {
            tracing::error!(?err, "failed to read setgroups");
            InitProcessError::Io(err)
        })?;
        if setgroups.trim() == "deny" {
            tracing::error!("cannot set supplementary gids, setgroup is disabled");
            return Err(InitProcessError::SetGroupDisabled);
        }

        let gids: Vec<Gid> = additional_gids
            .iter()
            .map(|gid| Gid::from_raw(*gid))
            .collect();

        match user_ns_config {
            Some(r) if r.privileged => {
                syscall.set_groups(&gids).map_err(|err| {
                    tracing::error!(?err, ?gids, "failed to set privileged supplementary gids");
                    InitProcessError::SyscallOther(err)
                })?;
            }
            None => {
                syscall.set_groups(&gids).map_err(|err| {
                    tracing::error!(?err, ?gids, "failed to set unprivileged supplementary gids");
                    InitProcessError::SyscallOther(err)
                })?;
            }
            // this should have been detected during validation
            _ => unreachable!(
                "unprivileged users cannot set supplementary gids in containers with new user namespace"
            ),
        }
    }

    Ok(())
}

/// set_io_priority set io priority
fn set_io_priority(syscall: &dyn Syscall, io_priority_op: &Option<LinuxIOPriority>) -> Result<()> {
    match io_priority_op {
        Some(io_priority) => {
            let io_prio_class_mapping: HashMap<_, _> = [
                (IOPriorityClass::IoprioClassRt, 1i64),
                (IOPriorityClass::IoprioClassBe, 2i64),
                (IOPriorityClass::IoprioClassIdle, 3i64),
            ]
            .iter()
            .filter_map(|(class, num)| match serde_json::to_string(&class) {
                Ok(class_str) => Some((class_str, *num)),
                Err(err) => {
                    tracing::error!(?err, "failed to parse io priority class");
                    None
                }
            })
            .collect();

            let iop_class = serde_json::to_string(&io_priority.class())
                .map_err(|err| InitProcessError::IoPriorityClass(err.to_string()))?;

            match io_prio_class_mapping.get(&iop_class) {
                Some(value) => {
                    syscall
                        .set_io_priority(*value, io_priority.priority())
                        .map_err(|err| {
                            tracing::error!(?err, ?io_priority, "failed to set io_priority");
                            InitProcessError::SyscallOther(err)
                        })?;
                }
                None => {
                    return Err(InitProcessError::IoPriorityClass(iop_class));
                }
            }
        }
        None => {}
    }
    Ok(())
}

/// Set the RT priority of a thread
fn setup_scheduler(sc_op: &Option<Scheduler>) -> Result<()> {
    if let Some(sc) = sc_op {
        let policy: u32 = match *sc.policy() {
            LinuxSchedulerPolicy::SchedOther => 0,
            LinuxSchedulerPolicy::SchedFifo => 1,
            LinuxSchedulerPolicy::SchedRr => 2,
            LinuxSchedulerPolicy::SchedBatch => 3,
            LinuxSchedulerPolicy::SchedIso => 4,
            LinuxSchedulerPolicy::SchedIdle => 5,
            LinuxSchedulerPolicy::SchedDeadline => 6,
        };
        let mut flags_value: u64 = 0;
        if let Some(flags) = sc.flags() {
            for flag in flags {
                match *flag {
                    LinuxSchedulerFlag::SchedResetOnFork => flags_value |= 0x01,
                    LinuxSchedulerFlag::SchedFlagReclaim => flags_value |= 0x02,
                    LinuxSchedulerFlag::SchedFlagDLOverrun => flags_value |= 0x04,
                    LinuxSchedulerFlag::SchedFlagKeepPolicy => flags_value |= 0x08,
                    LinuxSchedulerFlag::SchedFlagKeepParams => flags_value |= 0x10,
                    LinuxSchedulerFlag::SchedFlagUtilClampMin => flags_value |= 0x20,
                    LinuxSchedulerFlag::SchedFlagUtilClampMax => flags_value |= 0x40,
                }
            }
        }
        let a = nc::sched_attr_t {
            // size of the structure should always be within u32 bounds,
            // so this unwrap should never fail
            size: mem::size_of::<nc::sched_attr_t>().try_into().unwrap(),
            sched_policy: policy,
            sched_flags: flags_value,
            sched_nice: sc.nice().unwrap_or(0),
            sched_priority: sc.priority().unwrap_or(0) as u32,
            sched_runtime: sc.runtime().unwrap_or(0),
            sched_deadline: sc.deadline().unwrap_or(0),
            sched_period: sc.period().unwrap_or(0),
            sched_util_min: 0,
            sched_util_max: 0,
        };
        // TODO when nix or libc support this function, replace nx crates.
        unsafe {
            let result = nc::sched_setattr(0, &a, 0);
            match result {
                Ok(_) => {}
                Err(err) => {
                    tracing::error!(?err, "error setting scheduler");
                    Err(InitProcessError::SchedSetattr(err.to_string()))?;
                }
            }
        };
    }
    Ok(())
}

#[cfg(feature = "libseccomp")]
fn sync_seccomp(
    fd: Option<i32>,
    main_sender: &mut channel::MainSender,
    init_receiver: &mut channel::InitReceiver,
) -> Result<()> {
    if let Some(fd) = fd {
        tracing::debug!("init process sync seccomp, notify fd: {}", fd);
        main_sender.seccomp_notify_request(fd).map_err(|err| {
            tracing::error!(?err, "failed to send seccomp notify request");
            InitProcessError::Channel(err)
        })?;
        init_receiver
            .wait_for_seccomp_request_done()
            .map_err(|err| {
                tracing::error!(?err, "failed to wait for seccomp request done");
                InitProcessError::Channel(err)
            })?;
        // Once we are sure the seccomp notify fd is sent, we can safely close
        // it. The fd is now duplicated to the main process and sent to seccomp
        // listener.
        let _ = unistd::close(fd);
    }

    Ok(())
}

// verifyCwd ensures that the current directory is actually inside the mount
// namespace root of the current process.
// Please refer to https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv for more details.
fn verify_cwd() -> Result<()> {
    let cwd = unistd::getcwd().map_err(|err| {
        if let nix::errno::Errno::ENOENT = err {
            // https://man7.org/linux/man-pages/man2/getcwd.2.html
            // ENOENT The current working directory has been unlinked.
            InitProcessError::InvalidCwd(err)
        } else {
            InitProcessError::NixOther(err)
        }
    })?;

    if !cwd.is_absolute() {
        // This should never happen, but just in case.
        return Err(InitProcessError::InvalidCwd(nix::errno::Errno::ENOENT));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    #[cfg(feature = "libseccomp")]
    use nix::unistd;
    use oci_spec::runtime::{LinuxNamespaceBuilder, SpecBuilder, UserBuilder};
    #[cfg(feature = "libseccomp")]
    use serial_test::serial;

    use super::*;
    use crate::syscall::syscall::create_syscall;
    use crate::syscall::test::{ArgName, IoPriorityArgs, MountArgs, TestHelperSyscall};

    #[test]
    fn test_readonly_path() -> Result<()> {
        let syscall = create_syscall();
        readonly_path(Path::new("/proc/sys"), syscall.as_ref())?;

        let want = vec![
            MountArgs {
                source: Some(PathBuf::from("/proc/sys")),
                target: PathBuf::from("/proc/sys"),
                fstype: None,
                flags: MsFlags::MS_BIND | MsFlags::MS_REC,
                data: None,
            },
            MountArgs {
                source: Some(PathBuf::from("/proc/sys")),
                target: PathBuf::from("/proc/sys"),
                fstype: None,
                flags: MsFlags::MS_NOSUID
                    | MsFlags::MS_NODEV
                    | MsFlags::MS_NOEXEC
                    | MsFlags::MS_BIND
                    | MsFlags::MS_REMOUNT
                    | MsFlags::MS_RDONLY,
                data: None,
            },
        ];
        let got = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_mount_args();

        assert_eq!(want, *got);
        assert_eq!(got.len(), 2);
        Ok(())
    }

    #[test]
    fn test_apply_rest_namespaces() -> Result<()> {
        let syscall = create_syscall();
        let spec = SpecBuilder::default().build()?;
        let linux_spaces = vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Uts)
                .build()?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Pid)
                .build()?,
        ];
        let namespaces = Namespaces::try_from(Some(&linux_spaces))?;

        apply_rest_namespaces(&namespaces, &spec, syscall.as_ref())?;

        let got_hostnames = syscall
            .as_ref()
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_hostname_args();
        assert_eq!(1, got_hostnames.len());
        assert_eq!("youki".to_string(), got_hostnames[0]);

        let got_domainnames = syscall
            .as_ref()
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_domainname_args();
        assert_eq!(0, got_domainnames.len());
        Ok(())
    }

    #[test]
    fn test_set_supplementary_gids() -> Result<()> {
        // gids additional gids is empty case
        let user = UserBuilder::default().build().unwrap();
        assert!(set_supplementary_gids(&user, &None, create_syscall().as_ref()).is_ok());

        let tests = vec![
            (
                UserBuilder::default()
                    .additional_gids(vec![33, 34])
                    .build()?,
                None::<UserNamespaceConfig>,
                vec![vec![Gid::from_raw(33), Gid::from_raw(34)]],
            ),
            // unreachable case
            (
                UserBuilder::default().build()?,
                Some(UserNamespaceConfig::default()),
                vec![],
            ),
            (
                UserBuilder::default()
                    .additional_gids(vec![37, 38])
                    .build()?,
                Some(UserNamespaceConfig {
                    privileged: true,
                    gid_mappings: None,
                    newgidmap: None,
                    newuidmap: None,
                    uid_mappings: None,
                    user_namespace: None,
                    ..Default::default()
                }),
                vec![vec![Gid::from_raw(37), Gid::from_raw(38)]],
            ),
        ];
        for (user, ns_config, want) in tests.into_iter() {
            let syscall = create_syscall();
            let result = set_supplementary_gids(&user, &ns_config, syscall.as_ref());
            match fs::read_to_string("/proc/self/setgroups")?.trim() {
                "deny" => {
                    assert!(result.is_err());
                }
                "allow" => {
                    assert!(result.is_ok());
                    let got = syscall
                        .as_any()
                        .downcast_ref::<TestHelperSyscall>()
                        .unwrap()
                        .get_groups_args();
                    assert_eq!(want, got);
                }
                _ => unreachable!("setgroups value unknown"),
            }
        }
        Ok(())
    }

    #[test]
    #[serial]
    #[cfg(feature = "libseccomp")]
    fn test_sync_seccomp() -> Result<()> {
        use std::os::unix::io::IntoRawFd;
        use std::thread;

        let tmp_file = tempfile::tempfile()?;

        let (mut main_sender, mut main_receiver) = channel::main_channel()?;
        let (mut init_sender, mut init_receiver) = channel::init_channel()?;

        let fd = tmp_file.into_raw_fd();
        let th = thread::spawn(move || {
            assert!(main_receiver.wait_for_seccomp_request().is_ok());
            assert!(init_sender.seccomp_notify_done().is_ok());
        });

        // sync_seccomp close the fd,
        sync_seccomp(Some(fd), &mut main_sender, &mut init_receiver)?;
        // so expecting close the same fd again will causing EBADF error.
        assert_eq!(nix::errno::Errno::EBADF, unistd::close(fd).unwrap_err());
        assert!(th.join().is_ok());
        Ok(())
    }

    #[test]
    fn test_masked_path_does_not_exist() {
        let syscall = create_syscall();
        let mocks = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap();
        mocks.set_ret_err(ArgName::Mount, || {
            Err(SyscallError::Nix(nix::errno::Errno::ENOENT))
        });

        assert!(masked_path(Path::new("/proc/self"), &None, syscall.as_ref()).is_ok());
        let got = mocks.get_mount_args();
        assert_eq!(0, got.len());
    }

    #[test]
    fn test_masked_path_is_file_with_no_label() {
        let syscall = create_syscall();
        let mocks = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap();
        mocks.set_ret_err(ArgName::Mount, || {
            Err(SyscallError::Nix(nix::errno::Errno::ENOTDIR))
        });

        assert!(masked_path(Path::new("/proc/self"), &None, syscall.as_ref()).is_ok());

        let got = mocks.get_mount_args();
        let want = MountArgs {
            source: Some(PathBuf::from("tmpfs")),
            target: PathBuf::from("/proc/self"),
            fstype: Some("tmpfs".to_string()),
            flags: MsFlags::MS_RDONLY,
            data: Some("".to_string()),
        };
        assert_eq!(1, got.len());
        assert_eq!(want, got[0]);
    }

    #[test]
    fn test_masked_path_is_file_with_label() {
        let syscall = create_syscall();
        let mocks = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap();
        mocks.set_ret_err(ArgName::Mount, || {
            Err(SyscallError::Nix(nix::errno::Errno::ENOTDIR))
        });

        assert!(masked_path(
            Path::new("/proc/self"),
            &Some("default".to_string()),
            syscall.as_ref()
        )
        .is_ok());

        let got = mocks.get_mount_args();
        let want = MountArgs {
            source: Some(PathBuf::from("tmpfs")),
            target: PathBuf::from("/proc/self"),
            fstype: Some("tmpfs".to_string()),
            flags: MsFlags::MS_RDONLY,
            data: Some("context=\"default\"".to_string()),
        };
        assert_eq!(1, got.len());
        assert_eq!(want, got[0]);
    }

    #[test]
    fn test_masked_path_with_unknown_error() {
        let syscall = create_syscall();
        let mocks = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap();
        mocks.set_ret_err(ArgName::Mount, || {
            Err(SyscallError::Nix(nix::errno::Errno::UnknownErrno))
        });

        assert!(masked_path(Path::new("/proc/self"), &None, syscall.as_ref()).is_err());
        let got = mocks.get_mount_args();
        assert_eq!(0, got.len());
    }

    #[test]
    fn test_set_io_priority() {
        let test_command = TestHelperSyscall::default();
        let io_priority_op = None;
        assert!(set_io_priority(&test_command, &io_priority_op).is_ok());

        let data = "{\"class\":\"IOPRIO_CLASS_RT\",\"priority\":1}";
        let iop: LinuxIOPriority = serde_json::from_str(data).unwrap();
        let io_priority_op = Some(iop);
        assert!(set_io_priority(&test_command, &io_priority_op).is_ok());

        let want_io_priority = IoPriorityArgs {
            class: 1,
            priority: 1,
        };
        let set_io_prioritys = test_command.get_io_priority_args();
        assert_eq!(set_io_prioritys[0], want_io_priority);
    }
}
