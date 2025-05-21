use std::fs::{canonicalize, create_dir_all, OpenOptions};
use std::mem;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;
#[cfg(feature = "v1")]
use std::{borrow::Cow, collections::HashMap};

use libcgroups::common::CgroupSetup::{Hybrid, Legacy, Unified};
#[cfg(feature = "v1")]
use libcgroups::common::DEFAULT_CGROUP_ROOT;
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::mount::MsFlags;
use nix::sys::stat::Mode;
use nix::NixPath;
use oci_spec::runtime::{Mount as SpecMount, MountBuilder as SpecMountBuilder};
use procfs::process::{MountInfo, MountOptFields, Process};
use safe_path;

#[cfg(feature = "v1")]
use super::symlink::Symlink;
use super::symlink::SymlinkError;
use super::utils::{parse_mount, MountOptionConfig};
use crate::syscall::syscall::create_syscall;
use crate::syscall::{linux, Syscall, SyscallError};
use crate::utils::{retry, PathBufExt};

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
}

type Result<T> = std::result::Result<T, MountError>;

#[derive(Debug)]
pub struct MountOptions<'a> {
    pub root: &'a Path,
    pub label: Option<&'a str>,
    #[allow(dead_code)]
    pub cgroup_ns: bool,
}

pub struct Mount {
    syscall: Box<dyn Syscall>,
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
        }
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
                        panic!("libcontainer can't run in a Legacy or Hybrid cgroup setup without the v1 feature");
                        #[cfg(feature = "v1")]
                        self.mount_cgroup_v1(mount, options).map_err(|err| {
                            tracing::error!("failed to mount cgroup v1: {}", err);
                            err
                        })?
                    }
                    Unified => {
                        #[cfg(not(feature = "v2"))]
                        panic!("libcontainer can't run in a Unified cgroup setup without the v2 feature");
                        #[cfg(feature = "v2")]
                        self.mount_cgroup_v2(mount, options, &mount_option_config)
                            .map_err(|err| {
                                tracing::error!("failed to mount cgroup v2: {}", err);
                                err
                            })?
                    }
                }
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
        let process_cgroups: HashMap<String, String> = Process::myself()?
            .cgroups()?
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
            data: data.to_string(),
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

            let process_cgroup = Process::myself()
                .map_err(|err| {
                    tracing::error!("failed to get /proc/self: {}", err);
                    MountError::Other(err.into())
                })?
                .cgroups()
                .map_err(|err| {
                    tracing::error!("failed to get process cgroups: {}", err);
                    MountError::Other(err.into())
                })?
                .into_iter()
                .find(|c| c.hierarchy == 0)
                .map(|c| PathBuf::from(c.pathname))
                .ok_or_else(|| {
                    MountError::Custom("failed to find unified process cgroup".into())
                })?;
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
    pub fn make_parent_mount_private(&self, rootfs: &Path) -> Result<Option<MountInfo>> {
        let mount_infos = Process::myself()
            .map_err(|err| {
                tracing::error!("failed to get /proc/self: {}", err);
                MountError::Other(err.into())
            })?
            .mountinfo()
            .map_err(|err| {
                tracing::error!("failed to get mount info: {}", err);
                MountError::Other(err.into())
            })?;
        let parent_mount = find_parent_mount(rootfs, mount_infos.0)?;

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
            Ok(Some(parent_mount))
        } else {
            Ok(None)
        }
    }

    fn mount_into_container(
        &self,
        m: &SpecMount,
        rootfs: &Path,
        mount_option_config: &MountOptionConfig,
        label: Option<&str>,
    ) -> Result<()> {
        let typ = m.typ().as_deref();
        let mut d = mount_option_config.data.to_string();

        if let Some(l) = label {
            if typ != Some("proc") && typ != Some("sysfs") {
                match mount_option_config.data.is_empty() {
                    true => d = format!("context=\"{l}\""),
                    false => d = format!("{},context=\"{}\"", mount_option_config.data, l),
                }
            }
        }

        let dest_for_host = safe_path::scoped_join(rootfs, m.destination()).map_err(|err| {
            tracing::error!(
                "failed to join rootfs {:?} with mount destination {:?}: {}",
                rootfs,
                m.destination(),
                err
            );
            MountError::Other(err.into())
        })?;

        let dest = Path::new(&dest_for_host);
        let source = m.source().as_ref().ok_or(MountError::NoSource)?;
        let src = if typ == Some("bind") {
            let src = canonicalize(source).map_err(|err| {
                tracing::error!("failed to canonicalize {:?}: {}", source, err);
                err
            })?;
            let dir = if src.is_file() {
                Path::new(&dest).parent().unwrap()
            } else {
                Path::new(&dest)
            };

            create_dir_all(dir).map_err(|err| {
                tracing::error!("failed to create dir for bind mount {:?}: {}", dir, err);
                err
            })?;

            if src.is_file() && !dest.exists() {
                OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(dest)
                    .map_err(|err| {
                        tracing::error!("failed to create file for bind mount {:?}: {}", src, err);
                        err
                    })?;
            }

            src
        } else {
            create_dir_all(dest).map_err(|err| {
                tracing::error!("failed to create device: {:?}", dest);
                err
            })?;

            PathBuf::from(source)
        };

        if let Err(err) =
            self.syscall
                .mount(Some(&*src), dest, typ, mount_option_config.flags, Some(&*d))
        {
            if let SyscallError::Nix(errno) = err {
                if matches!(errno, Errno::EINVAL) {
                    self.syscall.mount(
                        Some(&*src),
                        dest,
                        typ,
                        mount_option_config.flags,
                        Some(&mount_option_config.data),
                    )?;
                } else if matches!(errno, Errno::EBUSY) {
                    let mount_op = || -> std::result::Result<(), SyscallError> {
                        self.syscall.mount(
                            Some(&*src),
                            dest,
                            typ,
                            mount_option_config.flags,
                            Some(&*d),
                        )
                    };
                    let delay = Duration::from_millis(MOUNT_RETRY_DELAY_MS);
                    let retry_policy = |err: &SyscallError| -> bool {
                        matches!(err, SyscallError::Nix(Errno::EBUSY))
                    };
                    retry(mount_op, MAX_EBUSY_MOUNT_ATTEMPTS - 1, delay, retry_policy)?;
                } else {
                    return Err(err.into());
                }
            } else {
                return Err(err.into());
            }
        }

        if typ == Some("bind")
            && mount_option_config.flags.intersects(
                !(MsFlags::MS_REC
                    | MsFlags::MS_REMOUNT
                    | MsFlags::MS_BIND
                    | MsFlags::MS_PRIVATE
                    | MsFlags::MS_SHARED
                    | MsFlags::MS_SLAVE),
            )
        {
            self.syscall
                .mount(
                    Some(dest),
                    dest,
                    None,
                    mount_option_config.flags | MsFlags::MS_REMOUNT,
                    None,
                )
                .map_err(|err| {
                    tracing::error!("failed to remount {:?}: {}", dest, err);
                    err
                })?;
        }

        if let Some(mount_attr) = &mount_option_config.rec_attr {
            let open_dir = Dir::open(dest, OFlag::O_DIRECTORY, Mode::empty())?;
            let dir_fd_pathbuf = PathBuf::from(format!("/proc/self/fd/{}", open_dir.as_raw_fd()));
            self.syscall.mount_setattr(
                -1,
                &dir_fd_pathbuf,
                linux::AT_RECURSIVE,
                mount_attr,
                mem::size_of::<linux::MountAttr>(),
            )?;
        }

        Ok(())
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

    use anyhow::{Context, Ok, Result};

    use super::*;
    use crate::syscall::test::{ArgName, MountArgs, TestHelperSyscall};

    #[test]
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

            assert!(m
                .mount_into_container(
                    mount,
                    tmp_dir.path(),
                    &mount_option_config,
                    Some("defaults")
                )
                .is_ok());

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

            assert!(m
                .mount_into_container(mount, tmp_dir.path(), &mount_option_config, None)
                .is_ok());

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
                    source: Some(tmp_dir.path().join("dev/null")),
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

            assert!(m
                .mount_into_container(mount, tmp_dir.path(), &mount_option_config, None)
                .is_ok());
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

            assert!(m
                .mount_into_container(mount, tmp_dir.path(), &mount_option_config, None)
                .is_err());
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

            assert!(m
                .mount_into_container(mount, tmp_dir.path(), &mount_option_config, None)
                .is_ok());
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

            assert!(m
                .mount_into_container(mount, tmp_dir.path(), &mount_option_config, None)
                .is_err());
            assert_eq!(syscall.get_mount_args().len(), 0);
        }

        Ok(())
    }

    #[test]
    fn test_make_parent_mount_private() -> Result<()> {
        let tmp_dir = tempfile::tempdir()?;
        let m = Mount::new();
        let result = m.make_parent_mount_private(tmp_dir.path())?;
        assert!(result.is_some());

        if result.is_some() {
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

            // This can be either depending on the system, some systems mount tmpfs at /tmp others it's
            // a plain directory. See https://github.com/containers/youki/issues/471
            assert!(got.target == PathBuf::from("/") || got.target == PathBuf::from("/tmp"));
        }

        Ok(())
    }

    #[test]
    #[cfg(feature = "v1")]
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
            data: String::new(),
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
}
