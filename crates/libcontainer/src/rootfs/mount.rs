use std::fs::{Permissions, canonicalize};
use std::io::{BufRead, BufReader, ErrorKind};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
#[cfg(feature = "v1")]
use std::{borrow::Cow, collections::HashMap};
use std::{fs, mem};

use libcgroups::common::CgroupSetup::{Hybrid, Legacy, Unified};
#[cfg(feature = "v1")]
use libcgroups::common::DEFAULT_CGROUP_ROOT;
use nix::NixPath;
use nix::errno::Errno;
use nix::mount::MsFlags;
use nix::sys::statfs::{PROC_SUPER_MAGIC, statfs};
use oci_spec::runtime::{Mount as SpecMount, MountBuilder as SpecMountBuilder};
use pathrs::Root;
use pathrs::flags::OpenFlags;
use pathrs::procfs::{ProcfsBase, ProcfsHandle};
#[cfg(feature = "v1")]
use procfs::process::Process;
use procfs::process::{MountInfo, MountOptFields};
use procfs::{FromRead, ProcessCGroups};

#[cfg(feature = "v1")]
use super::symlink::Symlink;
use super::symlink::SymlinkError;
use super::utils::{MountOptionConfig, parse_mount};
use crate::syscall::syscall::create_syscall;
use crate::syscall::{Syscall, SyscallError, linux};
use crate::utils::{PathBufExt, retry};

const MAX_EBUSY_MOUNT_ATTEMPTS: u32 = 3;
// runc has a retry interval of 100ms. We are following this.
// https://github.com/opencontainers/runc/blob/v1.3.0/libcontainer/rootfs_linux.go#L1235
#[cfg(not(test))]
const MOUNT_RETRY_DELAY_MS: u64 = 100;
// In tests, there is no need to delay, so set it to 0ms.
#[cfg(test)]
const MOUNT_RETRY_DELAY_MS: u64 = 0;

#[derive(Debug, thiserror::Error)]
pub enum MountError {
    #[error("no source in mount spec")]
    NoSource,
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("syscall")]
    Syscall(#[from] crate::syscall::SyscallError),
    #[error("nix error")]
    Nix(#[from] nix::Error),
    #[error("failed to build oci spec")]
    SpecBuild(#[from] oci_spec::OciSpecError),
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
    #[error("{0}")]
    Custom(String),
    #[error("symlink")]
    Symlink(#[from] SymlinkError),
    #[error("procfs failed")]
    Procfs(#[from] procfs::ProcError),
    #[error("unknown mount option: {0}")]
    UnsupportedMountOption(String),
    #[error(transparent)]
    Pathrs(#[from] pathrs::error::Error),
}

type Result<T> = std::result::Result<T, MountError>;

pub trait MountInfoProvider {
    fn mountinfo(&self) -> Result<Vec<MountInfo>>;
}

/// Default provider that reads mountinfo from /proc via procfs.
pub struct ProcMountInfoProvider;

impl ProcMountInfoProvider {
    pub fn new() -> Self {
        ProcMountInfoProvider
    }
}

impl MountInfoProvider for ProcMountInfoProvider {
    fn mountinfo(&self) -> Result<Vec<MountInfo>> {
        let reader = BufReader::new(ProcfsHandle::new()?.open(
            ProcfsBase::ProcSelf,
            "mountinfo",
            OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC,
        )?);

        let mount_infos: Vec<MountInfo> = reader
            .lines()
            .map(|lr| {
                lr.map_err(MountError::from)
                    .and_then(|s| MountInfo::from_line(&s).map_err(MountError::from))
            })
            .collect::<Result<_>>()?;
        Ok(mount_infos)
    }
}

#[derive(Debug)]
pub struct MountOptions<'a> {
    pub root: &'a Path,
    pub label: Option<&'a str>,
    #[allow(dead_code)]
    pub cgroup_ns: bool,
}

pub struct Mount {
    syscall: Box<dyn Syscall>,
    mountinfo_provider: Box<dyn MountInfoProvider>,
}

impl Default for Mount {
    fn default() -> Self {
        Self::new()
    }
}

impl Mount {
    pub fn new() -> Mount {
        Mount {
            syscall: create_syscall(),
            mountinfo_provider: Box::new(ProcMountInfoProvider::new()),
        }
    }

    pub fn with_mountinfo_provider<P: MountInfoProvider + 'static>(mut self, provider: P) -> Self {
        self.mountinfo_provider = Box::new(provider);
        self
    }

    pub fn setup_mount(&self, mount: &SpecMount, options: &MountOptions) -> Result<()> {
        tracing::debug!("mounting {:?}", mount);
        let mut mount_option_config = parse_mount(mount)?;

        match mount.typ().as_deref() {
            Some("cgroup") => {
                let cgroup_setup = libcgroups::common::get_cgroup_setup().map_err(|err| {
                    tracing::error!("failed to determine cgroup setup: {}", err);
                    MountError::Other(err.into())
                })?;
                match cgroup_setup {
                    Legacy | Hybrid => {
                        #[cfg(not(feature = "v1"))]
                        panic!(
                            "libcontainer can't run in a Legacy or Hybrid cgroup setup without the v1 feature"
                        );
                        #[cfg(feature = "v1")]
                        self.mount_cgroup_v1(mount, options).map_err(|err| {
                            tracing::error!("failed to mount cgroup v1: {}", err);
                            err
                        })?
                    }
                    Unified => {
                        #[cfg(not(feature = "v2"))]
                        panic!(
                            "libcontainer can't run in a Unified cgroup setup without the v2 feature"
                        );
                        #[cfg(feature = "v2")]
                        self.mount_cgroup_v2(mount, options, &mount_option_config)
                            .map_err(|err| {
                                tracing::error!("failed to mount cgroup v2: {}", err);
                                err
                            })?
                    }
                }
            }
            // procfs and sysfs are special because we need to ensure they are actually
            // mounted on a specific path in a container without any funny business.
            // Ref: https://github.com/opencontainers/runc/security/advisories/GHSA-fh74-hm69-rqjw
            Some(typ @ ("proc" | "sysfs")) => {
                let dest_path = options
                    .root
                    .join_safely(Path::new(mount.destination()).normalize())
                    .map_err(|err| {
                        tracing::error!(
                            "could not join rootfs path with mount destination {:?}: {}",
                            mount.destination(),
                            err
                        );
                        MountError::Other(err.into())
                    })?;

                match fs::symlink_metadata(&dest_path) {
                    Ok(m) if !m.is_dir() => {
                        return Err(MountError::Other(
                            format!("filesystem {} must be mounted on ordinary directory", typ)
                                .into(),
                        ));
                    }
                    Err(e) if e.kind() != ErrorKind::NotFound => {
                        return Err(MountError::Other(
                            format!("symlink_metadata failed for {}: {}", dest_path.display(), e)
                                .into(),
                        ));
                    }
                    _ => {}
                }

                self.check_proc_mount(options.root, mount)?;

                self.mount_into_container(mount, options.root, &mount_option_config, options.label)
                    .map_err(|err| {
                        tracing::error!("failed to mount {:?}: {}", mount, err);
                        err
                    })?;
            }
            _ => {
                if *mount.destination() == PathBuf::from("/dev") {
                    mount_option_config.flags &= !MsFlags::MS_RDONLY;
                    self.mount_into_container(
                        mount,
                        options.root,
                        &mount_option_config,
                        options.label,
                    )
                    .map_err(|err| {
                        tracing::error!("failed to mount /dev: {}", err);
                        err
                    })?;
                } else {
                    self.mount_into_container(
                        mount,
                        options.root,
                        &mount_option_config,
                        options.label,
                    )
                    .map_err(|err| {
                        tracing::error!("failed to mount {:?}: {}", mount, err);
                        err
                    })?;
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "v1")]
    fn mount_cgroup_v1(&self, cgroup_mount: &SpecMount, options: &MountOptions) -> Result<()> {
        tracing::debug!("mounting cgroup v1 filesystem");
        // create tmpfs into which the cgroup subsystems will be mounted
        let tmpfs = SpecMountBuilder::default()
            .source("tmpfs")
            .typ("tmpfs")
            .destination(cgroup_mount.destination())
            .options(
                ["noexec", "nosuid", "nodev", "mode=755"]
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<String>>(),
            )
            .build()
            .map_err(|err| {
                tracing::error!("failed to build tmpfs for cgroup: {}", err);
                err
            })?;

        self.setup_mount(&tmpfs, options).map_err(|err| {
            tracing::error!("failed to mount tmpfs for cgroup: {}", err);
            err
        })?;

        // get all cgroup mounts on the host system
        let host_mounts: Vec<PathBuf> = libcgroups::v1::util::list_subsystem_mount_points()
            .map_err(|err| {
                tracing::error!("failed to get subsystem mount points: {}", err);
                MountError::Other(err.into())
            })?
            .into_iter()
            .filter(|p| p.as_path().starts_with(DEFAULT_CGROUP_ROOT))
            .collect();
        tracing::debug!("cgroup mounts: {:?}", host_mounts);

        // get process cgroups
        let ppid = std::os::unix::process::parent_id();
        // The non-zero ppid means that the PID Namespace is not separated.
        let ppid = if ppid == 0 { std::process::id() } else { ppid };
        let root_cgroups = Process::new(ppid as i32)?.cgroups()?.0;
        let process_cgroups: HashMap<String, String> =
            ProcessCGroups::from_read(ProcfsHandle::new()?.open(
                ProcfsBase::ProcSelf,
                "cgroup",
                OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC,
            )?)?
            .into_iter()
            .map(|c| {
                let hierarchy = c.hierarchy;
                // When youki itself is running inside a container, the cgroup path
                // will include the path of pid-1, which needs to be stripped before
                // mounting.
                let root_pathname = root_cgroups
                    .iter()
                    .find(|c| c.hierarchy == hierarchy)
                    .map(|c| c.pathname.as_ref())
                    .unwrap_or("");
                let path = c
                    .pathname
                    .strip_prefix(root_pathname)
                    .unwrap_or(&c.pathname);
                (c.controllers.join(","), path.to_owned())
            })
            .collect();
        tracing::debug!("Process cgroups: {:?}", process_cgroups);

        let cgroup_root = options
            .root
            .join_safely(cgroup_mount.destination())
            .map_err(|err| {
                tracing::error!(
                    "could not join rootfs path with cgroup mount destination: {}",
                    err
                );
                MountError::Other(err.into())
            })?;
        tracing::debug!("cgroup root: {:?}", cgroup_root);

        let symlink = Symlink::new();

        // setup cgroup mounts for container
        for host_mount in &host_mounts {
            if let Some(subsystem_name) = host_mount.file_name().and_then(|n| n.to_str()) {
                if options.cgroup_ns {
                    self.setup_namespaced_subsystem(
                        cgroup_mount,
                        options,
                        subsystem_name,
                        subsystem_name == "systemd",
                    )?;
                } else {
                    self.setup_emulated_subsystem(
                        cgroup_mount,
                        options,
                        subsystem_name,
                        subsystem_name == "systemd",
                        host_mount,
                        &process_cgroups,
                    )?;
                }

                symlink.setup_comount_symlinks(&cgroup_root, subsystem_name)?;
            } else {
                tracing::warn!("could not get subsystem name from {:?}", host_mount);
            }
        }

        Ok(())
    }

    // On some distros cgroup subsystems are comounted e.g. cpu,cpuacct or net_cls,net_prio. These systems
    // have to be comounted in the container as well as the kernel will reject trying to mount them separately.
    #[cfg(feature = "v1")]
    fn setup_namespaced_subsystem(
        &self,
        cgroup_mount: &SpecMount,
        options: &MountOptions,
        subsystem_name: &str,
        named: bool,
    ) -> Result<()> {
        tracing::debug!(
            "Mounting (namespaced) {:?} cgroup subsystem",
            subsystem_name
        );
        let subsystem_mount = SpecMountBuilder::default()
            .source("cgroup")
            .typ("cgroup")
            .destination(cgroup_mount.destination().join(subsystem_name))
            .options(
                ["noexec", "nosuid", "nodev"]
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<String>>(),
            )
            .build()
            .map_err(|err| {
                tracing::error!("failed to build {subsystem_name} mount: {err}");
                err
            })?;

        let data: Cow<str> = if named {
            format!("name={subsystem_name}").into()
        } else {
            subsystem_name.into()
        };

        let mount_options_config = MountOptionConfig {
            flags: MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            data: vec![data.into_owned()],
            rec_attr: None,
        };

        self.mount_into_container(
            &subsystem_mount,
            options.root,
            &mount_options_config,
            options.label,
        )
        .map_err(|err| {
            tracing::error!("failed to mount {subsystem_mount:?}: {err}");
            err
        })
    }

    #[cfg(feature = "v1")]
    fn setup_emulated_subsystem(
        &self,
        cgroup_mount: &SpecMount,
        options: &MountOptions,
        subsystem_name: &str,
        named: bool,
        host_mount: &Path,
        process_cgroups: &HashMap<String, String>,
    ) -> Result<()> {
        tracing::debug!("Mounting (emulated) {:?} cgroup subsystem", subsystem_name);
        let named_hierarchy: Cow<str> = if named {
            format!("name={subsystem_name}").into()
        } else {
            subsystem_name.into()
        };

        if let Some(proc_path) = process_cgroups.get(named_hierarchy.as_ref()) {
            let emulated = SpecMountBuilder::default()
                .source(
                    host_mount
                        .join_safely(proc_path.as_str())
                        .map_err(|err| {
                            tracing::error!(
                                "failed to join mount source for {subsystem_name} subsystem: {}",
                                err
                            );
                            MountError::Other(err.into())
                        })?,
                )
                .destination(
                    cgroup_mount
                        .destination()
                        .join_safely(subsystem_name)
                        .map_err(|err| {
                            tracing::error!(
                                "failed to join mount destination for {subsystem_name} subsystem: {}",
                                err
                            );
                            MountError::Other(err.into())
                        })?,
                )
                .typ("bind")
                .options(
                    ["rw", "rbind"]
                        .iter()
                        .map(|o| o.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?;
            tracing::debug!("Mounting emulated cgroup subsystem: {:?}", emulated);

            self.setup_mount(&emulated, options).map_err(|err| {
                tracing::error!("failed to mount {subsystem_name} cgroup hierarchy: {}", err);
                err
            })?;
        } else {
            tracing::warn!("Could not mount {:?} cgroup subsystem", subsystem_name);
        }

        Ok(())
    }

    #[cfg(feature = "v2")]
    fn mount_cgroup_v2(
        &self,
        cgroup_mount: &SpecMount,
        options: &MountOptions,
        mount_option_config: &MountOptionConfig,
    ) -> Result<()> {
        tracing::debug!("Mounting cgroup v2 filesystem");

        let cgroup_mount = SpecMountBuilder::default()
            .typ("cgroup2")
            .source("cgroup")
            .destination(cgroup_mount.destination())
            .options(Vec::new())
            .build()?;
        tracing::debug!("{:?}", cgroup_mount);

        if self
            .mount_into_container(
                &cgroup_mount,
                options.root,
                mount_option_config,
                options.label,
            )
            .is_err()
        {
            let host_mount = libcgroups::v2::util::get_unified_mount_point().map_err(|err| {
                tracing::error!("failed to get unified mount point: {}", err);
                MountError::Other(err.into())
            })?;

            let process_cgroup = ProcessCGroups::from_read(ProcfsHandle::new()?.open(
                ProcfsBase::ProcSelf,
                "cgroup",
                OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC,
            )?)?
            .into_iter()
            .find(|c| c.hierarchy == 0)
            .map(|c| PathBuf::from(c.pathname))
            .ok_or_else(|| MountError::Custom("failed to find unified process cgroup".into()))?;

            let bind_mount = SpecMountBuilder::default()
                .typ("bind")
                .source(host_mount.join_safely(process_cgroup).map_err(|err| {
                    tracing::error!("failed to join host mount for cgroup hierarchy: {}", err);
                    MountError::Other(err.into())
                })?)
                .destination(cgroup_mount.destination())
                .options(Vec::new())
                .build()
                .map_err(|err| {
                    tracing::error!("failed to build cgroup bind mount: {}", err);
                    err
                })?;
            tracing::debug!("{:?}", bind_mount);

            let mut mount_option_config = (*mount_option_config).clone();
            mount_option_config.flags |= MsFlags::MS_BIND;
            self.mount_into_container(
                &bind_mount,
                options.root,
                &mount_option_config,
                options.label,
            )
            .map_err(|err| {
                tracing::error!("failed to bind mount cgroup hierarchy: {}", err);
                err
            })?;
        }

        Ok(())
    }

    /// Make parent mount of rootfs private if it was shared, which is required by pivot_root.
    /// It also makes sure following bind mount does not propagate in other namespaces.
    pub fn make_parent_mount_private(&self, rootfs: &Path) -> Result<MountInfo> {
        let mount_infos = self.mountinfo_provider.mountinfo()?;
        let parent_mount = find_parent_mount(rootfs, mount_infos)?;

        // check parent mount has 'shared' propagation type
        if parent_mount
            .opt_fields
            .iter()
            .any(|field| matches!(field, MountOptFields::Shared(_)))
        {
            self.syscall.mount(
                None,
                &parent_mount.mount_point,
                None,
                MsFlags::MS_PRIVATE,
                None,
            )?;
        }
        Ok(parent_mount)
    }

    fn mount_into_container(
        &self,
        m: &SpecMount,
        rootfs: &Path,
        mount_option_config: &MountOptionConfig,
        label: Option<&str>,
    ) -> Result<()> {
        let typ = m.typ().as_deref();
        let mut data_options = mount_option_config.data.clone();

        if let Some(l) = label {
            if typ != Some("proc") && typ != Some("sysfs") {
                if Path::new("/sys/fs/selinux").exists() {
                    data_options.push(format!("context={}", l));
                } else {
                    tracing::debug!("ignoring mount label because SELinux is disabled");
                }
            }
        }

        let root = Root::open(rootfs)?;
        let container_dest = m.destination();

        let source = m.source().as_ref().ok_or(MountError::NoSource)?;
        let dir_perm = Permissions::from_mode(0o755);
        let src = if typ == Some("bind") {
            let src = canonicalize(source).map_err(|err| {
                tracing::error!("failed to canonicalize {:?}: {}", source, err);
                err
            })?;

            if src.is_file() {
                let parent = container_dest
                    .parent()
                    .ok_or(MountError::Custom("destination has no parent".to_string()))?;
                root.mkdir_all(parent, &dir_perm)?;

                match root.create_file(
                    container_dest,
                    OpenFlags::O_EXCL
                        | OpenFlags::O_CREAT
                        | OpenFlags::O_NOFOLLOW
                        | OpenFlags::O_CLOEXEC,
                    &Permissions::from_mode(0o644),
                ) {
                    Ok(_) => Ok(()),
                    // If we get here, the file is already present, so continue.
                    Err(create_err) => root
                        .resolve(container_dest)
                        .map(|_| ())
                        .map_err(|_| create_err),
                }?;
            } else {
                root.mkdir_all(container_dest, &dir_perm)?;
            };

            src
        } else {
            root.mkdir_all(container_dest, &dir_perm)?;
            PathBuf::from(source)
        };

        let dest: OwnedFd = root.resolve(container_dest)?.into();
        let dest_fd = dest.as_fd();

        let is_bind = typ == Some("bind")
            || m.options()
                .as_deref()
                .is_some_and(|ops| ops.iter().any(|o| o == "bind" || o == "rbind"));

        // fd-based mount flow:
        // - bind: open_tree -> mount_setattr -> move_mount
        // - nonbind: fsopen -> fsconfig -> fsmount -> mount_setattr -> move_mount
        if is_bind {
            let recursive = m
                .options()
                .as_ref()
                .map(|v| v.iter().any(|o| o == "rbind"))
                .unwrap_or(false);
            let mut open_tree_flags: libc::c_uint = (libc::OPEN_TREE_CLOEXEC as libc::c_uint)
                | (libc::OPEN_TREE_CLONE as libc::c_uint)
                | (libc::AT_EMPTY_PATH as libc::c_uint);
            if recursive {
                open_tree_flags |= libc::AT_RECURSIVE as libc::c_uint;
            };

            let src_str = src.to_str().ok_or(SyscallError::Nix(Errno::EINVAL))?;
            let mount_fd_owned =
                self.syscall
                    .open_tree(libc::AT_FDCWD, Some(src_str), open_tree_flags)?;
            let mount_fd = mount_fd_owned.as_fd();

            // mount_setattr
            let attr_set_from_flags = self.mount_flag_to_attr(&mount_option_config.flags);
            let mut mount_attr = mount_option_config
                .rec_attr
                .clone()
                .unwrap_or(linux::MountAttr {
                    attr_set: 0,
                    attr_clr: 0,
                    propagation: 0,
                    userns_fd: 0,
                });
            mount_attr.attr_set |= attr_set_from_flags;

            let mut at_flags = linux::AT_EMPTY_PATH;
            if recursive {
                at_flags |= linux::AT_RECURSIVE;
            }

            self.apply_atime_from_msflags(
                &mut mount_attr,
                attr_set_from_flags,
                mount_option_config.flags,
            );

            self.syscall.mount_setattr(
                mount_fd,
                Path::new(""),
                at_flags,
                &mount_attr,
                mem::size_of::<linux::MountAttr>(),
            )?;

            // move_mount
            self.syscall.move_mount(
                mount_fd,
                None,
                dest_fd,
                None,
                linux::MOVE_MOUNT_T_EMPTY_PATH | linux::MOVE_MOUNT_F_EMPTY_PATH,
            )?;
        } else {
            let mount_fn = || -> std::result::Result<(), SyscallError> {
                // fsopen
                let fsfd_owned = self.syscall.fsopen(typ, 0)?;
                let fsfd = fsfd_owned.as_fd();

                // fsconfig
                let src_str = src
                    .as_os_str()
                    .to_str()
                    .ok_or(SyscallError::Nix(Errno::EINVAL))?;
                self.syscall.fsconfig(
                    fsfd,
                    linux::FSCONFIG_SET_STRING as u32,
                    Some("source"),
                    Some(src_str),
                    0,
                )?;

                for opt in data_options.iter().filter(|s| !s.is_empty()) {
                    if let Some((k, v)) = opt.split_once('=') {
                        self.syscall.fsconfig(
                            fsfd,
                            linux::FSCONFIG_SET_STRING as u32,
                            Some(k),
                            Some(v),
                            0,
                        )?;
                    } else {
                        self.syscall.fsconfig(
                            fsfd,
                            linux::FSCONFIG_SET_FLAG as u32,
                            Some(opt),
                            None,
                            0,
                        )?;
                    };
                }

                self.syscall
                    .fsconfig(fsfd, linux::FSCONFIG_CMD_CREATE as u32, None, None, 0)?;

                // fsmount
                let mount_fd_owned = self.syscall.fsmount(fsfd, 0, None)?;
                let mount_fd = mount_fd_owned.as_fd();

                // mount_setattr
                let attr_set_from_flags = self.mount_flag_to_attr(&mount_option_config.flags);
                let mut mount_attr =
                    mount_option_config
                        .rec_attr
                        .clone()
                        .unwrap_or(linux::MountAttr {
                            attr_set: 0,
                            attr_clr: 0,
                            propagation: 0,
                            userns_fd: 0,
                        });
                mount_attr.attr_set |= attr_set_from_flags;

                self.apply_atime_from_msflags(
                    &mut mount_attr,
                    attr_set_from_flags,
                    mount_option_config.flags,
                );

                self.syscall.mount_setattr(
                    mount_fd,
                    Path::new(""),
                    linux::AT_EMPTY_PATH | linux::AT_RECURSIVE,
                    &mount_attr,
                    mem::size_of::<linux::MountAttr>(),
                )?;

                // move_mount
                self.syscall.move_mount(
                    mount_fd,
                    None,
                    dest_fd,
                    None,
                    linux::MOVE_MOUNT_T_EMPTY_PATH | linux::MOVE_MOUNT_F_EMPTY_PATH,
                )?;
                Ok(())
            };

            match mount_fn() {
                Ok(()) => {}
                Err(SyscallError::Nix(nix::Error::EINVAL)) => {
                    mount_fn()?;
                }
                Err(SyscallError::Nix(nix::Error::EBUSY)) => {
                    let delay = Duration::from_millis(MOUNT_RETRY_DELAY_MS);
                    let retry_policy =
                        |err: &SyscallError| matches!(err, SyscallError::Nix(Errno::EBUSY));
                    retry(mount_fn, MAX_EBUSY_MOUNT_ATTEMPTS - 1, delay, retry_policy)?;
                }
                Err(e) => return Err(e.into()),
            }
        }

        Ok(())
    }

    // https://man7.org/linux/man-pages/man2/mount_setattr.2.html
    // To apply MsFlags via mount_setattr, we set the corresponding bits in attr_set
    fn mount_flag_to_attr(&self, flags: &MsFlags) -> u64 {
        const MAP_SET: &[(MsFlags, u64)] = &[
            (MsFlags::MS_RDONLY, linux::MOUNT_ATTR_RDONLY),
            (MsFlags::MS_NOSUID, linux::MOUNT_ATTR_NOSUID),
            (MsFlags::MS_NODEV, linux::MOUNT_ATTR_NODEV),
            (MsFlags::MS_NOEXEC, linux::MOUNT_ATTR_NOEXEC),
            (MsFlags::MS_NOATIME, linux::MOUNT_ATTR_NOATIME),
            (MsFlags::MS_NODIRATIME, linux::MOUNT_ATTR_NODIRATIME),
            (MsFlags::MS_RELATIME, linux::MOUNT_ATTR_RELATIME),
            (MsFlags::MS_STRICTATIME, linux::MOUNT_ATTR_STRICTATIME),
        ];

        let mut set = 0;
        for (ms, attr) in MAP_SET {
            if flags.intersects(*ms) {
                set |= *attr;
            }
        }
        set
    }

    // Apply atime-related configuration.
    // https://man7.org/linux/man-pages/man2/mount_setattr.2.html
    // ref: MOUNT_ATTR__ATIME
    fn apply_atime_from_msflags(
        &self,
        mount_attr: &mut linux::MountAttr,
        attr_set_from_flags: u64,
        msflags: MsFlags,
    ) {
        let atime_bits =
            linux::MOUNT_ATTR_NOATIME | linux::MOUNT_ATTR_STRICTATIME | linux::MOUNT_ATTR_RELATIME;

        let noatime = msflags.contains(MsFlags::MS_NOATIME);
        let strictatime = msflags.contains(MsFlags::MS_STRICTATIME);
        let relatime = msflags.contains(MsFlags::MS_RELATIME);

        let atime = if strictatime {
            linux::MOUNT_ATTR_STRICTATIME
        } else if noatime {
            linux::MOUNT_ATTR_NOATIME
        } else if relatime {
            linux::MOUNT_ATTR_RELATIME
        } else {
            0
        };

        let non_atime = attr_set_from_flags & !atime_bits;

        if atime != 0 {
            mount_attr.attr_clr |= linux::MOUNT_ATTR__ATIME;
            mount_attr.attr_set |= non_atime | atime;
        } else {
            mount_attr.attr_set |= non_atime;
        }
    }

    /// check_proc_mount checks to ensure that the mount destination is not over the top of /proc.
    /// dest is required to be an abs path and have any symlinks resolved before calling this function.
    /// # Example  (a valid case where `/proc` is mounted with `proc` type.)
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use oci_spec::runtime::MountBuilder as SpecMountBuilder;
    /// use libcontainer::rootfs::Mount;
    ///
    /// let mounter = Mount::new();
    ///
    /// let rootfs = PathBuf::from("/var/lib/my-runtime/containers/abcd1234/rootfs");
    /// let destination = PathBuf::from("/proc");
    /// let source = PathBuf::from("proc");
    /// let typ = "proc";
    ///
    /// let mount = SpecMountBuilder::default()
    ///     .destination(destination)
    ///     .typ(typ)
    ///     .source(source)
    ///     .build()
    ///     .expect("failed to build SpecMount");
    ///
    /// assert!(mounter.check_proc_mount(rootfs.as_path(), &mount).is_ok());
    /// ```
    /// # Example (bind mount to `/proc` that should fail)
    /// ```
    /// use std::path::PathBuf;
    /// use oci_spec::runtime::MountBuilder as SpecMountBuilder;
    /// use libcontainer::rootfs::Mount;
    ///
    /// let mounter = Mount::new();
    ///
    /// let rootfs = PathBuf::from("/var/lib/my-runtime/containers/abcd1234/rootfs");
    /// let destination = PathBuf::from("/proc");
    /// let source = PathBuf::from("/tmp");
    /// let typ = "bind";
    ///
    /// let mount = SpecMountBuilder::default()
    ///     .destination(destination)
    ///     .typ(typ)
    ///     .source(source)
    ///     .build()
    ///     .expect("failed to build SpecMount");
    ///
    /// assert!(mounter.check_proc_mount(rootfs.as_path(), &mount).is_err());
    /// ```
    pub fn check_proc_mount(&self, rootfs: &Path, mount: &SpecMount) -> Result<()> {
        const PROC_ROOT_INO: u64 = 1;
        const VALID_PROC_MOUNTS: &[&str] = &[
            "/proc/cpuinfo",
            "/proc/diskstats",
            "/proc/meminfo",
            "/proc/stat",
            "/proc/swaps",
            "/proc/uptime",
            "/proc/loadavg",
            "/proc/slabinfo",
            "/proc/sys/kernel/ns_last_pid",
            "/proc/sys/crypto/fips_enabled",
        ];

        let dest = mount.destination();

        let container_proc_path = rootfs.join("proc");
        let dest_path = rootfs.join_safely(dest).map_err(|err| {
            tracing::error!(
                "could not join rootfs path with mount destination {:?}: {}",
                dest,
                err
            );
            MountError::Other(err.into())
        })?;

        // If path is Ok, it means dest_path is under /proc.
        // - Ok(p) with p.is_empty(): mount target is exactly /proc.
        //   In this case, check if the mount source is procfs.
        // - Ok(p) with !p.is_empty(): mount target is under /proc.
        //   Only allow if it matches a specific whitelist of proc entries.
        // - Err: not under /proc, so no further checks are needed
        let path = dest_path.strip_prefix(&container_proc_path);

        match path {
            Err(_) => Ok(()),
            Ok(p) if p.as_os_str().is_empty() => {
                if mount.typ().as_deref() == Some("proc") {
                    return Ok(());
                }

                if mount.typ().as_deref() == Some("bind") {
                    if let Some(source) = mount.source() {
                        let stat = statfs(source).map_err(MountError::from)?;
                        if stat.filesystem_type() == PROC_SUPER_MAGIC {
                            let meta = fs::metadata(source).map_err(MountError::from)?;
                            // Follow the behavior of runc's checkProcMount function.
                            if meta.ino() != PROC_ROOT_INO {
                                tracing::warn!(
                                    "bind-mount {} (source {:?}) is of type procfs but not the root (inode {}). \
                                    Future versions may reject this.",
                                    dest.display(),
                                    mount.source(),
                                    meta.ino()
                                );
                            }
                            return Ok(());
                        }
                    }
                }

                Err(MountError::Custom(format!(
                    "{} cannot be mounted because it is not type proc",
                    dest.display()
                )))
            }
            Ok(_) => {
                // Here dest is definitely under /proc. Do not allow those,
                // except for a few specific entries emulated by lxcfs.
                let is_allowed = VALID_PROC_MOUNTS.iter().any(|allowed_path| {
                    let container_allowed_path = rootfs.join(allowed_path.trim_start_matches('/'));
                    dest_path == container_allowed_path
                });

                if is_allowed {
                    Ok(())
                } else {
                    Err(MountError::Other(
                        format!("{} is not a valid mount under /proc", dest.display()).into(),
                    ))
                }
            }
        }
    }
}

/// Find parent mount of rootfs in given mount infos
pub fn find_parent_mount(
    rootfs: &Path,
    mount_infos: Vec<MountInfo>,
) -> std::result::Result<MountInfo, MountError> {
    // find the longest mount point
    let parent_mount_info = mount_infos
        .into_iter()
        .filter(|mi| rootfs.starts_with(&mi.mount_point))
        .max_by(|mi1, mi2| mi1.mount_point.len().cmp(&mi2.mount_point.len()))
        .ok_or_else(|| {
            MountError::Custom(format!("can't find the parent mount of {:?}", rootfs))
        })?;
    Ok(parent_mount_info)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "v1")]
    use std::fs;
    use std::fs::OpenOptions;
    use std::os::unix::fs::symlink;
    use std::str::FromStr;

    use anyhow::{Context, Ok, Result};

    use super::*;
    use crate::syscall::test::{ArgName, MountArgs, TestHelperSyscall};

    #[test]
    #[ignore] // TODO: fix fd-based test
    fn test_mount_into_container() -> Result<()> {
        let tmp_dir = tempfile::tempdir()?;
        {
            let m = Mount::new();
            let mount = &SpecMountBuilder::default()
                .destination(PathBuf::from("/dev/pts"))
                .typ("devpts")
                .source(PathBuf::from("devpts"))
                .options(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "newinstance".to_string(),
                    "ptmxmode=0666".to_string(),
                    "mode=0620".to_string(),
                    "gid=5".to_string(),
                ])
                .build()?;
            let mount_option_config = parse_mount(mount)?;

            assert!(
                m.mount_into_container(
                    mount,
                    tmp_dir.path(),
                    &mount_option_config,
                    Some("defaults")
                )
                .is_ok()
            );

            let want = vec![MountArgs {
                source: Some(PathBuf::from("devpts")),
                target: tmp_dir.path().join("dev/pts"),
                fstype: Some("devpts".to_string()),
                flags: MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                data: Some(
                    "newinstance,ptmxmode=0666,mode=0620,gid=5,context=\"defaults\"".to_string(),
                ),
            }];
            let got = &m
                .syscall
                .as_any()
                .downcast_ref::<TestHelperSyscall>()
                .unwrap()
                .get_mount_args();
            assert_eq!(want, *got);
            assert_eq!(got.len(), 1);
        }
        {
            let m = Mount::new();
            let mount = &SpecMountBuilder::default()
                .destination(PathBuf::from("/dev/null"))
                .typ("bind")
                .source(tmp_dir.path().join("null"))
                .options(vec!["ro".to_string()])
                .build()?;
            let mount_option_config = parse_mount(mount)?;
            OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(tmp_dir.path().join("null"))?;

            assert!(
                m.mount_into_container(mount, tmp_dir.path(), &mount_option_config, None)
                    .is_ok()
            );

            let want = vec![
                MountArgs {
                    source: Some(tmp_dir.path().join("null")),
                    target: tmp_dir.path().join("dev/null"),
                    fstype: Some("bind".to_string()),
                    flags: MsFlags::MS_RDONLY,
                    data: Some("".to_string()),
                },
                // remount one
                MountArgs {
                    source: None,
                    target: tmp_dir.path().join("dev/null"),
                    fstype: None,
                    flags: MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT,
                    data: None,
                },
            ];
            let got = &m
                .syscall
                .as_any()
                .downcast_ref::<TestHelperSyscall>()
                .unwrap()
                .get_mount_args();
            assert_eq!(want, *got);
            assert_eq!(got.len(), 2);
        }
        {
            let m = Mount::new();
            let mount = &SpecMountBuilder::default()
                .destination(PathBuf::from("/tmp/retry"))
                .typ("tmpfs")
                .source(PathBuf::from("tmpfs"))
                .build()?;
            let mount_option_config = parse_mount(mount)?;

            let syscall = m
                .syscall
                .as_any()
                .downcast_ref::<TestHelperSyscall>()
                .unwrap();
            syscall.set_ret_err(ArgName::Mount, || {
                Err(crate::syscall::SyscallError::Nix(nix::errno::Errno::EINVAL))
            });
            syscall.set_ret_err_times(ArgName::Mount, 1);

            assert!(
                m.mount_into_container(mount, tmp_dir.path(), &mount_option_config, None)
                    .is_ok()
            );
            assert_eq!(syscall.get_mount_args().len(), 1);
        }
        {
            let m = Mount::new();
            let mount = &SpecMountBuilder::default()
                .destination(PathBuf::from("/tmp/retry"))
                .typ("tmpfs")
                .source(PathBuf::from("tmpfs"))
                .build()?;
            let mount_option_config = parse_mount(mount)?;

            let syscall = m
                .syscall
                .as_any()
                .downcast_ref::<TestHelperSyscall>()
                .unwrap();
            syscall.set_ret_err(ArgName::Mount, || {
                Err(crate::syscall::SyscallError::Nix(nix::errno::Errno::EINVAL))
            });
            syscall.set_ret_err_times(ArgName::Mount, 2);

            assert!(
                m.mount_into_container(mount, tmp_dir.path(), &mount_option_config, None)
                    .is_err()
            );
            assert_eq!(syscall.get_mount_args().len(), 0);
        }
        {
            let m = Mount::new();
            let mount = &SpecMountBuilder::default()
                .destination(PathBuf::from("/tmp/retry"))
                .typ("tmpfs")
                .source(PathBuf::from("tmpfs"))
                .build()?;
            let mount_option_config = parse_mount(mount)?;

            let syscall = m
                .syscall
                .as_any()
                .downcast_ref::<TestHelperSyscall>()
                .unwrap();
            syscall.set_ret_err(ArgName::Mount, || {
                Err(crate::syscall::SyscallError::Nix(nix::errno::Errno::EBUSY))
            });
            syscall.set_ret_err_times(ArgName::Mount, MAX_EBUSY_MOUNT_ATTEMPTS as usize - 1);

            assert!(
                m.mount_into_container(mount, tmp_dir.path(), &mount_option_config, None)
                    .is_ok()
            );
            assert_eq!(syscall.get_mount_args().len(), 1);
        }
        {
            let m = Mount::new();
            let mount = &SpecMountBuilder::default()
                .destination(PathBuf::from("/tmp/retry"))
                .typ("tmpfs")
                .source(PathBuf::from("tmpfs"))
                .build()?;
            let mount_option_config = parse_mount(mount)?;

            let syscall = m
                .syscall
                .as_any()
                .downcast_ref::<TestHelperSyscall>()
                .unwrap();
            syscall.set_ret_err(ArgName::Mount, || {
                Err(crate::syscall::SyscallError::Nix(nix::errno::Errno::EBUSY))
            });
            syscall.set_ret_err_times(ArgName::Mount, MAX_EBUSY_MOUNT_ATTEMPTS as usize);

            assert!(
                m.mount_into_container(mount, tmp_dir.path(), &mount_option_config, None)
                    .is_err()
            );
            assert_eq!(syscall.get_mount_args().len(), 0);
        }

        Ok(())
    }

    struct FakeMountInfo {
        entries: Vec<MountInfo>,
    }
    impl MountInfoProvider for FakeMountInfo {
        fn mountinfo(&self) -> std::result::Result<Vec<MountInfo>, MountError> {
            std::result::Result::Ok(self.entries.clone())
        }
    }

    #[test]
    fn test_make_parent_mount_private() -> Result<()> {
        let tmp_dir = PathBuf::from_str("/tmp/mydir")?;

        let parent = tmp_dir.as_path().parent().unwrap().to_path_buf();
        let fake = FakeMountInfo {
            entries: vec![MountInfo {
                mnt_id: 1,
                pid: 0,
                majmin: "".to_string(),
                root: "/".to_string(),
                mount_point: parent.clone(),
                mount_options: Default::default(),
                opt_fields: vec![MountOptFields::Shared(1)],
                fs_type: "tmpfs".to_string(),
                mount_source: None,
                super_options: Default::default(),
            }],
        };

        let m = Mount::new().with_mountinfo_provider(fake);
        m.make_parent_mount_private(tmp_dir.as_path())?;

        let set = m
            .syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_mount_args();

        assert_eq!(set.len(), 1);

        let got = &set[0];
        assert_eq!(got.source, None);
        assert_eq!(got.fstype, None);
        assert_eq!(got.flags, MsFlags::MS_PRIVATE);
        assert_eq!(got.data, None);

        assert_eq!(got.target, parent);

        Ok(())
    }

    #[test]
    fn test_not_make_parent_mount_private_if_already_private() -> Result<()> {
        let tmp_dir = PathBuf::from_str("/tmp/mydir")?;

        let parent = tmp_dir.as_path().parent().unwrap().to_path_buf();
        let fake = FakeMountInfo {
            entries: vec![MountInfo {
                mnt_id: 1,
                pid: 0,
                majmin: "".to_string(),
                root: "/".to_string(),
                mount_point: parent.clone(),
                mount_options: Default::default(),
                opt_fields: vec![],
                fs_type: "tmpfs".to_string(),
                mount_source: None,
                super_options: Default::default(),
            }],
        };

        let m = Mount::new().with_mountinfo_provider(fake);
        m.make_parent_mount_private(tmp_dir.as_path())?;

        let set = m
            .syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_mount_args();

        assert_eq!(set.len(), 0);

        Ok(())
    }

    #[test]
    #[cfg(feature = "v1")]
    #[ignore] // TODO: fix fd-based test
    fn test_namespaced_subsystem_success() -> Result<()> {
        let tmp = tempfile::tempdir().unwrap();
        let container_cgroup = Path::new("/container_cgroup");

        let mounter = Mount::new();

        let spec_cgroup_mount = SpecMountBuilder::default()
            .destination(container_cgroup)
            .source("cgroup")
            .typ("cgroup")
            .build()
            .context("failed to build cgroup mount")?;

        let mount_opts = MountOptions {
            root: tmp.path(),
            label: None,
            cgroup_ns: true,
        };

        let subsystem_name = "cpu";

        mounter
            .setup_namespaced_subsystem(&spec_cgroup_mount, &mount_opts, subsystem_name, false)
            .context("failed to setup namespaced subsystem")?;

        let expected = MountArgs {
            source: Some(PathBuf::from("cgroup")),
            target: tmp
                .path()
                .join_safely(container_cgroup)?
                .join(subsystem_name),
            fstype: Some("cgroup".to_owned()),
            flags: MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            data: Some("cpu".to_owned()),
        };

        let got = mounter
            .syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_mount_args();

        assert_eq!(got.len(), 1);
        assert_eq!(expected, got[0]);

        Ok(())
    }

    #[test]
    #[cfg(feature = "v1")]
    #[ignore] // TODO: fix fd-based test
    fn test_emulated_subsystem_success() -> Result<()> {
        // arrange
        let tmp = tempfile::tempdir().unwrap();
        let host_cgroup_mount = tmp.path().join("host_cgroup");
        let host_cgroup = host_cgroup_mount.join("cpu/container1");
        fs::create_dir_all(&host_cgroup)?;

        let container_cgroup = Path::new("/container_cgroup");
        let mounter = Mount::new();

        let spec_cgroup_mount = SpecMountBuilder::default()
            .destination(container_cgroup)
            .source("cgroup")
            .typ("cgroup")
            .build()
            .context("failed to build cgroup mount")?;

        let mount_opts = MountOptions {
            root: tmp.path(),
            label: None,
            cgroup_ns: false,
        };

        let subsystem_name = "cpu";
        let mut process_cgroups = HashMap::new();
        process_cgroups.insert("cpu".to_owned(), "container1".to_owned());

        // act
        mounter
            .setup_emulated_subsystem(
                &spec_cgroup_mount,
                &mount_opts,
                subsystem_name,
                false,
                &host_cgroup_mount.join(subsystem_name),
                &process_cgroups,
            )
            .context("failed to setup emulated subsystem")?;

        // assert
        let expected = MountArgs {
            source: Some(host_cgroup),
            target: tmp
                .path()
                .join_safely(container_cgroup)?
                .join(subsystem_name),
            fstype: Some("bind".to_owned()),
            flags: MsFlags::MS_BIND | MsFlags::MS_REC,
            data: Some("".to_owned()),
        };

        let got = mounter
            .syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_mount_args();

        assert_eq!(got.len(), 1);
        assert_eq!(expected, got[0]);

        Ok(())
    }

    #[test]
    #[cfg(feature = "v1")]
    #[ignore] // TODO: fix fd-based test
    fn test_mount_cgroup_v1() -> Result<()> {
        // arrange
        let tmp = tempfile::tempdir()?;
        let container_cgroup = PathBuf::from("/sys/fs/cgroup");

        let spec_cgroup_mount = SpecMountBuilder::default()
            .destination(&container_cgroup)
            .source("cgroup")
            .typ("cgroup")
            .build()
            .context("failed to build cgroup mount")?;

        let mount_opts = MountOptions {
            root: tmp.path(),
            label: None,
            cgroup_ns: true,
        };

        let mounter = Mount::new();

        // act
        mounter
            .mount_cgroup_v1(&spec_cgroup_mount, &mount_opts)
            .context("failed to mount cgroup v1")?;

        // assert
        let mut got = mounter
            .syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_mount_args()
            .into_iter();

        let host_mounts = libcgroups::v1::util::list_subsystem_mount_points()?;
        assert_eq!(got.len(), host_mounts.len() + 1);

        let expected = MountArgs {
            source: Some(PathBuf::from("tmpfs".to_owned())),
            target: tmp.path().join_safely(&container_cgroup)?,
            fstype: Some("tmpfs".to_owned()),
            flags: MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            data: Some("mode=755".to_owned()),
        };
        assert_eq!(expected, got.next().unwrap());

        for (host_mount, act) in host_mounts.iter().zip(got) {
            let subsystem_name = host_mount.file_name().and_then(|f| f.to_str()).unwrap();
            let expected = MountArgs {
                source: Some(PathBuf::from("cgroup".to_owned())),
                target: tmp
                    .path()
                    .join_safely(&container_cgroup)?
                    .join(subsystem_name),
                fstype: Some("cgroup".to_owned()),
                flags: MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                data: Some(
                    if subsystem_name == "systemd" {
                        format!("name={subsystem_name}")
                    } else {
                        subsystem_name.to_string()
                    }
                    .to_owned(),
                ),
            };
            assert_eq!(expected, act);
        }

        Ok(())
    }

    #[test]
    #[cfg(feature = "v2")]
    #[ignore] // TODO: fix fd-based test
    fn test_mount_cgroup_v2() -> Result<()> {
        // arrange
        let tmp = tempfile::tempdir().unwrap();
        let container_cgroup = PathBuf::from("/sys/fs/cgroup");

        let spec_cgroup_mount = SpecMountBuilder::default()
            .destination(&container_cgroup)
            .source("cgroup")
            .typ("cgroup")
            .build()
            .context("failed to build cgroup mount")?;

        let mount_opts = MountOptions {
            root: tmp.path(),
            label: None,
            cgroup_ns: true,
        };

        let mounter = Mount::new();
        let flags = MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV;

        // act
        let mount_option_config = MountOptionConfig {
            flags,
            data: vec![],
            rec_attr: None,
        };
        mounter
            .mount_cgroup_v2(&spec_cgroup_mount, &mount_opts, &mount_option_config)
            .context("failed to mount cgroup v2")?;

        // assert
        let expected = MountArgs {
            source: Some(PathBuf::from("cgroup".to_owned())),
            target: tmp.path().join_safely(container_cgroup)?,
            fstype: Some("cgroup2".to_owned()),
            flags: MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            data: Some("".to_owned()),
        };

        let got = mounter
            .syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_mount_args();

        assert_eq!(got.len(), 1);
        assert_eq!(expected, got[0]);

        Ok(())
    }

    #[test]
    fn test_find_parent_mount() -> anyhow::Result<()> {
        let mount_infos = vec![
            MountInfo {
                mnt_id: 11,
                pid: 10,
                majmin: "".to_string(),
                root: "/".to_string(),
                mount_point: PathBuf::from("/"),
                mount_options: Default::default(),
                opt_fields: vec![],
                fs_type: "ext4".to_string(),
                mount_source: Some("/dev/sda1".to_string()),
                super_options: Default::default(),
            },
            MountInfo {
                mnt_id: 12,
                pid: 11,
                majmin: "".to_string(),
                root: "/".to_string(),
                mount_point: PathBuf::from("/proc"),
                mount_options: Default::default(),
                opt_fields: vec![],
                fs_type: "proc".to_string(),
                mount_source: Some("proc".to_string()),
                super_options: Default::default(),
            },
        ];

        let res = find_parent_mount(Path::new("/path/to/rootfs"), mount_infos)
            .context("failed to get parent mount")?;
        assert_eq!(res.mnt_id, 11);
        Ok(())
    }

    #[test]
    fn test_find_parent_mount_with_empty_mount_infos() {
        let mount_infos = vec![];
        let res = find_parent_mount(Path::new("/path/to/rootfs"), mount_infos);
        assert!(res.is_err());
    }

    #[test]
    fn test_check_proc_mount_proc_ok() -> Result<()> {
        let rootfs = tempfile::tempdir()?;
        let mounter = Mount::new();

        let mount = SpecMountBuilder::default()
            .destination(PathBuf::from("/proc"))
            .typ("proc".to_string())
            .source(PathBuf::from("proc"))
            .build()?;

        assert!(mounter.check_proc_mount(rootfs.path(), &mount).is_ok());
        Ok(())
    }

    #[test]
    fn test_check_proc_mount_allowed_subpath() -> Result<()> {
        let rootfs = tempfile::tempdir()?;
        let uptime = rootfs.path().join("proc/uptime");
        std::fs::create_dir_all(uptime.parent().unwrap())?;

        let mounter = Mount::new();
        let mount = SpecMountBuilder::default()
            .destination(PathBuf::from("/proc/uptime"))
            .typ("bind".to_string())
            .source(uptime)
            .build()?;

        assert!(mounter.check_proc_mount(rootfs.path(), &mount).is_ok());
        Ok(())
    }

    #[test]
    fn test_check_proc_mount_denied_subpath() -> Result<()> {
        let rootfs = tempfile::tempdir()?;
        let custom = rootfs.path().join("proc/custom");
        std::fs::create_dir_all(custom.parent().unwrap())?;

        let mounter = Mount::new();
        let mount = SpecMountBuilder::default()
            .destination(PathBuf::from("/proc/custom"))
            .typ("bind".to_string())
            .source(custom)
            .build()?;

        assert!(mounter.check_proc_mount(rootfs.path(), &mount).is_err());
        Ok(())
    }

    #[test]
    fn setup_mount_proc_fails_if_destination_is_symlink() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let rootfs = tmp.path();

        let symlink_path = rootfs.join("symlink");
        fs::create_dir_all(&symlink_path)?;
        let proc_path = rootfs.join("proc");

        symlink(&symlink_path, &proc_path)?;

        let mount = SpecMountBuilder::default()
            .destination(PathBuf::from("/proc"))
            .typ("proc")
            .source(proc_path)
            .build()?;

        let options = MountOptions {
            root: rootfs,
            label: None,
            cgroup_ns: true,
        };

        let m = Mount::new();

        let res = m.setup_mount(&mount, &options);

        // proc destination symlink should be rejected
        assert!(res.is_err());
        let err = format!("{:?}", res.err().unwrap());
        assert!(err.contains("must be mounted on ordinary directory"));

        Ok(())
    }

    #[test]
    fn setup_mount_sys_fails_if_destination_is_symlink() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let rootfs = tmp.path();

        let symlink_path = rootfs.join("symlink");
        fs::create_dir_all(&symlink_path)?;
        let sys_path = rootfs.join("sys");

        symlink(&symlink_path, &sys_path)?;

        let mount = SpecMountBuilder::default()
            .destination(PathBuf::from("/sys"))
            .typ("sysfs")
            .source(sys_path)
            .build()?;

        let options = MountOptions {
            root: rootfs,
            label: None,
            cgroup_ns: true,
        };

        let m = Mount::new();

        let res = m.setup_mount(&mount, &options);

        // sys destination symlink should be rejected
        assert!(res.is_err());
        let err = format!("{:?}", res.err().unwrap());
        assert!(err.contains("must be mounted on ordinary directory"));

        Ok(())
    }
}
