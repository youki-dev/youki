//! Implements Command trait for Linux systems
use std::any::Any;
use std::ffi::{CStr, CString, OsStr};
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::{fs, mem, ptr};

use caps::{CapSet, CapsHashSet};
use libc::{c_char, setdomainname, uid_t};
use nix::fcntl;
use nix::fcntl::{open, OFlag};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::stat::{mknod, Mode, SFlag};
use nix::unistd::{chown, chroot, fchdir, pivot_root, sethostname, Gid, Uid};
use oci_spec::runtime::PosixRlimit;

use super::{Result, Syscall, SyscallError};
use crate::{capabilities, utils};

// Flags used in mount_setattr(2).
// see https://man7.org/linux/man-pages/man2/mount_setattr.2.html.
pub const AT_RECURSIVE: u32 = 0x00008000; // Change the mount properties of the entire mount tree.
#[allow(non_upper_case_globals)]
pub const MOUNT_ATTR__ATIME: u64 = 0x00000070; // Setting on how atime should be updated.
const MOUNT_ATTR_RDONLY: u64 = 0x00000001;
const MOUNT_ATTR_NOSUID: u64 = 0x00000002;
const MOUNT_ATTR_NODEV: u64 = 0x00000004;
const MOUNT_ATTR_NOEXEC: u64 = 0x00000008;
const MOUNT_ATTR_RELATIME: u64 = 0x00000000;
const MOUNT_ATTR_NOATIME: u64 = 0x00000010;
const MOUNT_ATTR_STRICTATIME: u64 = 0x00000020;
const MOUNT_ATTR_NODIRATIME: u64 = 0x00000080;
const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x00200000;

/// Constants used by mount(2).
pub enum MountOption {
    Defaults(bool, MsFlags),
    Ro(bool, MsFlags),
    Rw(bool, MsFlags),
    Suid(bool, MsFlags),
    Nosuid(bool, MsFlags),
    Dev(bool, MsFlags),
    Nodev(bool, MsFlags),
    Exec(bool, MsFlags),
    Noexec(bool, MsFlags),
    Sync(bool, MsFlags),
    Async(bool, MsFlags),
    Dirsync(bool, MsFlags),
    Remount(bool, MsFlags),
    Mand(bool, MsFlags),
    Nomand(bool, MsFlags),
    Atime(bool, MsFlags),
    Noatime(bool, MsFlags),
    Diratime(bool, MsFlags),
    Nodiratime(bool, MsFlags),
    Bind(bool, MsFlags),
    Rbind(bool, MsFlags),
    Unbindable(bool, MsFlags),
    Runbindable(bool, MsFlags),
    Private(bool, MsFlags),
    Rprivate(bool, MsFlags),
    Shared(bool, MsFlags),
    Rshared(bool, MsFlags),
    Slave(bool, MsFlags),
    Rslave(bool, MsFlags),
    Relatime(bool, MsFlags),
    Norelatime(bool, MsFlags),
    Strictatime(bool, MsFlags),
    Nostrictatime(bool, MsFlags),
}

impl FromStr for MountOption {
    type Err = String;

    fn from_str(option: &str) -> std::result::Result<Self, Self::Err> {
        match option {
            "defaults" => Ok(MountOption::Defaults(false, MsFlags::empty())),
            "ro" => Ok(MountOption::Ro(false, MsFlags::MS_RDONLY)),
            "rw" => Ok(MountOption::Rw(true, MsFlags::MS_RDONLY)),
            "suid" => Ok(MountOption::Suid(true, MsFlags::MS_NOSUID)),
            "nosuid" => Ok(MountOption::Nosuid(false, MsFlags::MS_NOSUID)),
            "dev" => Ok(MountOption::Dev(true, MsFlags::MS_NODEV)),
            "nodev" => Ok(MountOption::Nodev(false, MsFlags::MS_NODEV)),
            "exec" => Ok(MountOption::Exec(true, MsFlags::MS_NOEXEC)),
            "noexec" => Ok(MountOption::Noexec(false, MsFlags::MS_NOEXEC)),
            "sync" => Ok(MountOption::Sync(false, MsFlags::MS_SYNCHRONOUS)),
            "async" => Ok(MountOption::Async(true, MsFlags::MS_SYNCHRONOUS)),
            "dirsync" => Ok(MountOption::Dirsync(false, MsFlags::MS_DIRSYNC)),
            "remount" => Ok(MountOption::Remount(false, MsFlags::MS_REMOUNT)),
            "mand" => Ok(MountOption::Mand(false, MsFlags::MS_MANDLOCK)),
            "nomand" => Ok(MountOption::Nomand(true, MsFlags::MS_MANDLOCK)),
            "atime" => Ok(MountOption::Atime(true, MsFlags::MS_NOATIME)),
            "noatime" => Ok(MountOption::Noatime(false, MsFlags::MS_NOATIME)),
            "diratime" => Ok(MountOption::Diratime(true, MsFlags::MS_NODIRATIME)),
            "nodiratime" => Ok(MountOption::Nodiratime(false, MsFlags::MS_NODIRATIME)),
            "bind" => Ok(MountOption::Bind(false, MsFlags::MS_BIND)),
            "rbind" => Ok(MountOption::Rbind(
                false,
                MsFlags::MS_BIND | MsFlags::MS_REC,
            )),
            "unbindable" => Ok(MountOption::Unbindable(false, MsFlags::MS_UNBINDABLE)),
            "runbindable" => Ok(MountOption::Runbindable(
                false,
                MsFlags::MS_UNBINDABLE | MsFlags::MS_REC,
            )),
            "private" => Ok(MountOption::Private(true, MsFlags::MS_PRIVATE)),
            "rprivate" => Ok(MountOption::Rprivate(
                true,
                MsFlags::MS_PRIVATE | MsFlags::MS_REC,
            )),
            "shared" => Ok(MountOption::Shared(true, MsFlags::MS_SHARED)),
            "rshared" => Ok(MountOption::Rshared(
                true,
                MsFlags::MS_SHARED | MsFlags::MS_REC,
            )),
            "slave" => Ok(MountOption::Slave(true, MsFlags::MS_SLAVE)),
            "rslave" => Ok(MountOption::Rslave(
                true,
                MsFlags::MS_SLAVE | MsFlags::MS_REC,
            )),
            "relatime" => Ok(MountOption::Relatime(false, MsFlags::MS_RELATIME)),
            "norelatime" => Ok(MountOption::Norelatime(true, MsFlags::MS_RELATIME)),
            "strictatime" => Ok(MountOption::Strictatime(false, MsFlags::MS_STRICTATIME)),
            "nostrictatime" => Ok(MountOption::Nostrictatime(true, MsFlags::MS_STRICTATIME)),
            _ => Err(option.to_string()),
        }
    }
}

/// Constants used by mount_setattr(2).
pub enum MountRecursive {
    /// Mount read-only.
    Rdonly(bool, u64),

    /// Ignore suid and sgid bits.
    Nosuid(bool, u64),

    /// Disallow access to device special files.
    Nodev(bool, u64),

    /// Disallow program execution.
    Noexec(bool, u64),

    /// Setting on how atime should be updated.
    Atime(bool, u64),

    /// Update atime relative to mtime/ctime.
    Relatime(bool, u64),

    /// Do not update access times.
    Noatime(bool, u64),

    /// Always perform atime updates.
    StrictAtime(bool, u64),

    /// Do not update directory access times.
    NoDiratime(bool, u64),

    /// Prevents following symbolic links.
    Nosymfollow(bool, u64),
}

impl FromStr for MountRecursive {
    type Err = SyscallError;

    fn from_str(option: &str) -> std::result::Result<Self, Self::Err> {
        match option {
            "rro" => Ok(MountRecursive::Rdonly(false, MOUNT_ATTR_RDONLY)),
            "rrw" => Ok(MountRecursive::Rdonly(true, MOUNT_ATTR_RDONLY)),
            "rnosuid" => Ok(MountRecursive::Nosuid(false, MOUNT_ATTR_NOSUID)),
            "rsuid" => Ok(MountRecursive::Nosuid(true, MOUNT_ATTR_NOSUID)),
            "rnodev" => Ok(MountRecursive::Nodev(false, MOUNT_ATTR_NODEV)),
            "rdev" => Ok(MountRecursive::Nodev(true, MOUNT_ATTR_NODEV)),
            "rnoexec" => Ok(MountRecursive::Noexec(false, MOUNT_ATTR_NOEXEC)),
            "rexec" => Ok(MountRecursive::Noexec(true, MOUNT_ATTR_NOEXEC)),
            "rnodiratime" => Ok(MountRecursive::NoDiratime(false, MOUNT_ATTR_NODIRATIME)),
            "rdiratime" => Ok(MountRecursive::NoDiratime(true, MOUNT_ATTR_NODIRATIME)),
            "rrelatime" => Ok(MountRecursive::Relatime(false, MOUNT_ATTR_RELATIME)),
            "rnorelatime" => Ok(MountRecursive::Relatime(true, MOUNT_ATTR_RELATIME)),
            "rnoatime" => Ok(MountRecursive::Noatime(false, MOUNT_ATTR_NOATIME)),
            "ratime" => Ok(MountRecursive::Noatime(true, MOUNT_ATTR_NOATIME)),
            "rstrictatime" => Ok(MountRecursive::StrictAtime(false, MOUNT_ATTR_STRICTATIME)),
            "rnostrictatime" => Ok(MountRecursive::StrictAtime(true, MOUNT_ATTR_STRICTATIME)),
            "rnosymfollow" => Ok(MountRecursive::Nosymfollow(false, MOUNT_ATTR_NOSYMFOLLOW)),
            "rsymfollow" => Ok(MountRecursive::Nosymfollow(true, MOUNT_ATTR_NOSYMFOLLOW)),
            // No support for MOUNT_ATTR_IDMAP yet (needs UserNS FD)
            _ => Err(SyscallError::UnexpectedMountRecursiveOption(
                option.to_string(),
            )),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
/// A structure used as te third argument of mount_setattr(2).
pub struct MountAttr {
    /// Mount properties to set.
    pub attr_set: u64,

    /// Mount properties to clear.
    pub attr_clr: u64,

    /// Mount propagation type.
    pub propagation: u64,

    /// User namespace file descriptor.
    pub userns_fd: u64,
}

impl MountAttr {
    /// Return MountAttr with the flag raised.
    /// This function is used in test code.
    pub fn all() -> Self {
        MountAttr {
            attr_set: MOUNT_ATTR_RDONLY
                | MOUNT_ATTR_NOSUID
                | MOUNT_ATTR_NODEV
                | MOUNT_ATTR_NOEXEC
                | MOUNT_ATTR_NODIRATIME
                | MOUNT_ATTR_RELATIME
                | MOUNT_ATTR_NOATIME
                | MOUNT_ATTR_STRICTATIME
                | MOUNT_ATTR_NOSYMFOLLOW,
            attr_clr: MOUNT_ATTR_RDONLY
                | MOUNT_ATTR_NOSUID
                | MOUNT_ATTR_NODEV
                | MOUNT_ATTR_NOEXEC
                | MOUNT_ATTR_NODIRATIME
                | MOUNT_ATTR_RELATIME
                | MOUNT_ATTR_NOATIME
                | MOUNT_ATTR_STRICTATIME
                | MOUNT_ATTR_NOSYMFOLLOW
                | MOUNT_ATTR__ATIME,
            propagation: 0,
            userns_fd: 0,
        }
    }
}

/// Empty structure to implement Command trait for
#[derive(Clone)]
pub struct LinuxSyscall;

impl LinuxSyscall {
    unsafe fn from_raw_buf<'a, T>(p: *const c_char) -> T
    where
        T: From<&'a OsStr>,
    {
        T::from(OsStr::from_bytes(CStr::from_ptr(p).to_bytes()))
    }

    /// Reads data from the `c_passwd` and returns it as a `User`.
    unsafe fn passwd_to_user(passwd: libc::passwd) -> Arc<OsStr> {
        let name: Arc<OsStr> = Self::from_raw_buf(passwd.pw_name);
        name
    }

    fn emulate_close_range(preserve_fds: i32) -> Result<()> {
        let open_fds = Self::get_open_fds()?;
        // Include stdin, stdout, and stderr for fd 0, 1, and 2 respectively.
        let min_fd = preserve_fds + 3;
        let to_be_cleaned_up_fds: Vec<i32> = open_fds
            .iter()
            .filter_map(|&fd| if fd >= min_fd { Some(fd) } else { None })
            .collect();

        to_be_cleaned_up_fds.iter().for_each(|&fd| {
            // Intentionally ignore errors here -- the cases where this might fail
            // are basically file descriptors that have already been closed.
            let _ = fcntl::fcntl(fd, fcntl::F_SETFD(fcntl::FdFlag::FD_CLOEXEC));
        });

        Ok(())
    }

    // Get a list of open fds for the calling process.
    fn get_open_fds() -> Result<Vec<i32>> {
        const PROCFS_FD_PATH: &str = "/proc/self/fd";
        utils::ensure_procfs(Path::new(PROCFS_FD_PATH)).map_err(|err| {
            tracing::error!(?err, "failed to ensure /proc is mounted");
            match err {
                utils::EnsureProcfsError::Nix(err) => SyscallError::Nix(err),
                utils::EnsureProcfsError::IO(err) => SyscallError::IO(err),
            }
        })?;

        let fds: Vec<i32> = fs::read_dir(PROCFS_FD_PATH)
            .map_err(|err| {
                tracing::error!(?err, "failed to read /proc/self/fd");
                err
            })?
            .filter_map(|entry| match entry {
                Ok(entry) => Some(entry.path()),
                Err(_) => None,
            })
            .filter_map(|path| path.file_name().map(|file_name| file_name.to_owned()))
            .filter_map(|file_name| file_name.to_str().map(String::from))
            .filter_map(|file_name| -> Option<i32> {
                // Convert the file name from string into i32. Since we are looking
                // at /proc/<pid>/fd, anything that's not a number (i32) can be
                // ignored. We are only interested in opened fds.
                match file_name.parse() {
                    Ok(fd) => Some(fd),
                    Err(_) => None,
                }
            })
            .collect();

        Ok(fds)
    }
}

impl Syscall for LinuxSyscall {
    /// To enable dynamic typing,
    /// see <https://doc.rust-lang.org/std/any/index.html> for more information
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Function to set given path as root path inside process
    fn pivot_rootfs(&self, path: &Path) -> Result<()> {
        // open the path as directory and read only
        let newroot =
            open(path, OFlag::O_DIRECTORY | OFlag::O_RDONLY, Mode::empty()).map_err(|errno| {
                tracing::error!(?errno, ?path, "failed to open the new root for pivot root");
                errno
            })?;

        // make the given path as the root directory for the container
        // see https://man7.org/linux/man-pages/man2/pivot_root.2.html, specially the notes
        // pivot root usually changes the root directory to first argument, and then mounts the original root
        // directory at second argument. Giving same path for both stacks mapping of the original root directory
        // above the new directory at the same path, then the call to umount unmounts the original root directory from
        // this path. This is done, as otherwise, we will need to create a separate temporary directory under the new root path
        // so we can move the original root there, and then unmount that. This way saves the creation of the temporary
        // directory to put original root directory.
        pivot_root(path, path).map_err(|errno| {
            tracing::error!(?errno, ?path, "failed to pivot root to");
            errno
        })?;

        // Make the original root directory rslave to avoid propagating unmount event to the host mount namespace.
        // We should use MS_SLAVE not MS_PRIVATE according to https://github.com/opencontainers/runc/pull/1500.
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_SLAVE | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|errno| {
            tracing::error!(?errno, "failed to make original root directory rslave");
            errno
        })?;

        // Unmount the original root directory which was stacked on top of new root directory
        // MNT_DETACH makes the mount point unavailable to new accesses, but waits till the original mount point
        // to be free of activity to actually unmount
        // see https://man7.org/linux/man-pages/man2/umount2.2.html for more information
        umount2("/", MntFlags::MNT_DETACH).map_err(|errno| {
            tracing::error!(?errno, "failed to unmount old root directory");
            errno
        })?;
        // Change directory to the new root
        fchdir(newroot).map_err(|errno| {
            tracing::error!(?errno, ?newroot, "failed to change directory to new root");
            errno
        })?;

        Ok(())
    }

    /// Set namespace for process
    fn set_ns(&self, rawfd: i32, nstype: CloneFlags) -> Result<()> {
        let fd = unsafe { BorrowedFd::borrow_raw(rawfd) };
        nix::sched::setns(fd, nstype)?;
        Ok(())
    }

    /// set uid and gid for process
    fn set_id(&self, uid: Uid, gid: Gid) -> Result<()> {
        prctl::set_keep_capabilities(true).map_err(|errno| {
            tracing::error!(?errno, "failed to set keep capabilities to true");
            nix::errno::Errno::from_raw(errno)
        })?;
        // args : real *id, effective *id, saved set *id respectively

        // This is safe because at this point we have only
        // one thread in the process
        if unsafe { libc::syscall(libc::SYS_setresgid, gid, gid, gid) } == -1 {
            let err = nix::errno::Errno::last();
            tracing::error!(
                ?err,
                ?gid,
                "failed to set real, effective and saved set gid"
            );
            return Err(err.into());
        }

        // This is safe because at this point we have only
        // one thread in the process
        if unsafe { libc::syscall(libc::SYS_setresuid, uid, uid, uid) } == -1 {
            let err = nix::errno::Errno::last();
            tracing::error!(
                ?err,
                ?uid,
                "failed to set real, effective and saved set uid"
            );
            return Err(err.into());
        }

        // if not the root user, reset capabilities to effective capabilities,
        // which are used by kernel to perform checks
        // see https://man7.org/linux/man-pages/man7/capabilities.7.html for more information
        if uid != Uid::from_raw(0) {
            capabilities::reset_effective(self)?;
        }
        prctl::set_keep_capabilities(false).map_err(|errno| {
            tracing::error!(?errno, "failed to set keep capabilities to false");
            nix::errno::Errno::from_raw(errno)
        })?;
        Ok(())
    }

    /// Disassociate parts of execution context
    // see https://man7.org/linux/man-pages/man2/unshare.2.html for more information
    fn unshare(&self, flags: CloneFlags) -> Result<()> {
        unshare(flags)?;

        Ok(())
    }
    /// Set capabilities for container process
    fn set_capability(&self, cset: CapSet, value: &CapsHashSet) -> Result<()> {
        match cset {
            // caps::set cannot set capabilities in bounding set,
            // so we do it differently
            CapSet::Bounding => {
                // get all capabilities
                let all = caps::read(None, CapSet::Bounding)?;
                // the difference will give capabilities
                // which are to be unset
                // for each such =, drop that capability
                // after this, only those which are to be set will remain set
                for c in all.difference(value) {
                    caps::drop(None, CapSet::Bounding, *c)?
                }
            }
            _ => {
                caps::set(None, cset, value)?;
            }
        }
        Ok(())
    }

    /// Sets hostname for process
    fn set_hostname(&self, hostname: &str) -> Result<()> {
        sethostname(hostname)?;
        Ok(())
    }

    /// Sets domainname for process (see
    /// [setdomainname(2)](https://man7.org/linux/man-pages/man2/setdomainname.2.html)).
    fn set_domainname(&self, domainname: &str) -> Result<()> {
        let ptr = domainname.as_bytes().as_ptr() as *const c_char;
        let len = domainname.len();
        match unsafe { setdomainname(ptr, len) } {
            0 => Ok(()),
            -1 => Err(nix::Error::last()),

            _ => Err(nix::Error::UnknownErrno),
        }?;

        Ok(())
    }

    /// Sets resource limit for process
    fn set_rlimit(&self, rlimit: &PosixRlimit) -> Result<()> {
        let rlim = &libc::rlimit {
            rlim_cur: rlimit.soft(),
            rlim_max: rlimit.hard(),
        };

        // Change for musl libc based on seccomp needs
        #[cfg(not(target_env = "musl"))]
        let res = unsafe { libc::setrlimit(rlimit.typ() as u32, rlim) };
        #[cfg(target_env = "musl")]
        let res = unsafe { libc::setrlimit(rlimit.typ() as i32, rlim) };

        match res {
            0 => Ok(()),
            -1 => Err(SyscallError::Nix(nix::Error::last())),
            _ => Err(SyscallError::Nix(nix::Error::UnknownErrno)),
        }?;

        Ok(())
    }

    // taken from https://crates.io/crates/users
    fn get_pwuid(&self, uid: uid_t) -> Option<Arc<OsStr>> {
        let mut passwd = unsafe { mem::zeroed::<libc::passwd>() };
        let mut buf = vec![0; 2048];
        let mut result = ptr::null_mut::<libc::passwd>();

        loop {
            let r = unsafe {
                libc::getpwuid_r(uid, &mut passwd, buf.as_mut_ptr(), buf.len(), &mut result)
            };

            if r != libc::ERANGE {
                break;
            }

            let newsize = buf.len().checked_mul(2)?;
            buf.resize(newsize, 0);
        }

        if result.is_null() {
            // There is no such user, or an error has occurred.
            // errno gets set if there’s an error.
            return None;
        }

        if result != &mut passwd {
            // The result of getpwuid_r should be its input passwd.
            return None;
        }

        let user = unsafe { Self::passwd_to_user(result.read()) };
        Some(user)
    }

    fn chroot(&self, path: &Path) -> Result<()> {
        chroot(path)?;

        Ok(())
    }

    fn mount(
        &self,
        source: Option<&Path>,
        target: &Path,
        fstype: Option<&str>,
        flags: MsFlags,
        data: Option<&str>,
    ) -> Result<()> {
        mount(source, target, fstype, flags, data)?;
        Ok(())
    }

    fn symlink(&self, original: &Path, link: &Path) -> Result<()> {
        symlink(original, link)?;

        Ok(())
    }

    fn mknod(&self, path: &Path, kind: SFlag, perm: Mode, dev: u64) -> Result<()> {
        mknod(path, kind, perm, dev)?;

        Ok(())
    }

    fn chown(&self, path: &Path, owner: Option<Uid>, group: Option<Gid>) -> Result<()> {
        chown(path, owner, group)?;

        Ok(())
    }

    fn set_groups(&self, groups: &[Gid]) -> Result<()> {
        let n_groups = groups.len() as libc::size_t;
        let groups_ptr = groups.as_ptr() as *const libc::gid_t;

        // This is safe because at this point we have only
        // one thread in the process
        if unsafe { libc::syscall(libc::SYS_setgroups, n_groups, groups_ptr) } == -1 {
            let err = nix::errno::Errno::last();
            tracing::error!(?err, ?groups, "failed to set groups");
            return Err(err.into());
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn close_range(&self, preserve_fds: i32) -> Result<()> {
        match unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3 + preserve_fds,
                libc::c_int::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        } {
            0 => Ok(()),
            -1 => {
                match nix::errno::Errno::last() {
                    nix::errno::Errno::ENOSYS | nix::errno::Errno::EINVAL => {
                        // close_range was introduced in kernel 5.9 and CLOSEEXEC was introduced in
                        // kernel 5.11. If the kernel is older we emulate close_range in userspace.
                        Self::emulate_close_range(preserve_fds)
                    }
                    e => Err(SyscallError::Nix(e)),
                }
            }
            _ => Err(SyscallError::Nix(nix::errno::Errno::UnknownErrno)),
        }?;

        Ok(())
    }

    fn mount_setattr(
        &self,
        dirfd: RawFd,
        pathname: &Path,
        flags: u32,
        mount_attr: &MountAttr,
        size: libc::size_t,
    ) -> Result<()> {
        let path_c_string = pathname
            .to_path_buf()
            .to_str()
            .map(CString::new)
            .ok_or_else(|| {
                tracing::error!(path = ?pathname, "failed to convert path to string");
                nix::Error::EINVAL
            })?
            .map_err(|err| {
                tracing::error!(path = ?pathname, ?err, "failed to convert path to string");
                nix::Error::EINVAL
            })?;

        match unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                dirfd,
                path_c_string.as_ptr(),
                flags,
                mount_attr as *const MountAttr,
                size,
            )
        } {
            0 => Ok(()),
            -1 => Err(nix::Error::last()),
            _ => Err(nix::Error::UnknownErrno),
        }?;
        Ok(())
    }

    fn set_io_priority(&self, class: i64, priority: i64) -> Result<()> {
        let ioprio_who_progress: libc::c_int = 1;
        let ioprio_who_pid = 0;
        let iop = (class << 13) | priority;
        match unsafe {
            libc::syscall(
                libc::SYS_ioprio_set,
                ioprio_who_progress,
                ioprio_who_pid,
                iop as libc::c_ulong,
            )
        } {
            0 => Ok(()),
            -1 => Err(nix::Error::last()),
            _ => Err(nix::Error::UnknownErrno),
        }?;
        Ok(())
    }

    fn umount2(&self, target: &Path, flags: MntFlags) -> Result<()> {
        umount2(target, flags)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Note: We have to run these tests here as serial. The main issue is that
    // these tests has a dependency on the system state. The
    // cleanup_file_descriptors test is especially evil when running with other
    // tests because it would ran around close down different fds.

    use std::fs;
    use std::os::unix::prelude::AsRawFd;

    use anyhow::{bail, Context, Result};
    use nix::{fcntl, sys, unistd};
    use serial_test::serial;

    use super::LinuxSyscall;
    use crate::syscall::Syscall;

    #[test]
    #[serial]
    fn test_get_open_fds() -> Result<()> {
        let file = fs::File::open("/dev/null")?;
        let fd = file.as_raw_fd();
        let open_fds = LinuxSyscall::get_open_fds()?;

        if !open_fds.iter().any(|&v| v == fd) {
            bail!("failed to find the opened dev null fds: {:?}", open_fds);
        }

        // explicitly close the file before the test case returns.
        drop(file);

        // The stdio fds should also be contained in the list of opened fds.
        if ![0, 1, 2]
            .iter()
            .all(|&stdio_fd| open_fds.iter().any(|&open_fd| open_fd == stdio_fd))
        {
            bail!("failed to find the stdio fds: {:?}", open_fds);
        }

        Ok(())
    }

    #[test]
    #[serial]
    fn test_close_range_userspace() -> Result<()> {
        // Open a fd without the CLOEXEC flag. Rust automatically adds the flag,
        // so we use fcntl::open here for more control.
        let fd = fcntl::open("/dev/null", fcntl::OFlag::O_RDWR, sys::stat::Mode::empty())?;
        LinuxSyscall::emulate_close_range(0).context("failed to clean up the fds")?;

        let fd_flag = fcntl::fcntl(fd, fcntl::F_GETFD)?;
        if (fd_flag & fcntl::FdFlag::FD_CLOEXEC.bits()) == 0 {
            bail!("CLOEXEC flag is not set correctly");
        }

        unistd::close(fd)?;
        Ok(())
    }

    #[test]
    #[serial]
    fn test_close_range_native() -> Result<()> {
        let fd = fcntl::open("/dev/null", fcntl::OFlag::O_RDWR, sys::stat::Mode::empty())?;
        let syscall = LinuxSyscall {};
        syscall
            .close_range(0)
            .context("failed to clean up the fds")?;

        let fd_flag = fcntl::fcntl(fd, fcntl::F_GETFD)?;
        if (fd_flag & fcntl::FdFlag::FD_CLOEXEC.bits()) == 0 {
            bail!("CLOEXEC flag is not set correctly");
        }

        unistd::close(fd)?;
        Ok(())
    }
}
