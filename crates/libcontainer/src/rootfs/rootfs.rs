use std::collections::HashSet;
use std::path::Path;

use nix::mount::MsFlags;
use oci_spec::runtime::{Linux, Spec};

use super::device::Device;
use super::mount::{Mount, MountOptions};
use super::symlink::Symlink;
use super::utils::default_devices;
use super::{Result, RootfsError};
use crate::error::MissingSpecError;
use crate::syscall::Syscall;
use crate::syscall::syscall::create_syscall;

/// Holds information about rootfs
pub struct RootFS {
    syscall: Box<dyn Syscall>,
}

impl Default for RootFS {
    fn default() -> Self {
        Self::new()
    }
}

impl RootFS {
    pub fn new() -> RootFS {
        RootFS {
            syscall: create_syscall(),
        }
    }

    #[cfg(test)]
    pub fn new_with_syscall(syscall: Box<dyn Syscall>) -> RootFS {
        RootFS { syscall }
    }

    pub fn mount_to_rootfs(
        &self,
        linux: &Linux,
        spec: &Spec,
        rootfs: &Path,
        cgroup_ns: bool,
    ) -> Result<()> {
        let mut flags = MsFlags::MS_REC;
        match linux.rootfs_propagation().as_deref() {
            Some("shared") => flags |= MsFlags::MS_SHARED,
            Some("private") => flags |= MsFlags::MS_PRIVATE,
            Some("slave" | "unbindable") | None => flags |= MsFlags::MS_SLAVE,
            Some(unknown) => {
                return Err(RootfsError::UnknownRootfsPropagation(unknown.to_string()));
            }
        }

        self.syscall
            .mount(None, Path::new("/"), None, flags, None)
            .map_err(|err| {
                tracing::error!(
                    ?err,
                    ?flags,
                    "failed to change the mount propagation type of the root"
                );

                err
            })?;

        let mounter = Mount::new();

        mounter.make_parent_mount_private(rootfs)?;

        tracing::debug!("mount root fs {:?}", rootfs);
        self.syscall
            .mount(
                Some(rootfs),
                rootfs,
                None,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None,
            )
            .map_err(|err| {
                tracing::error!(?rootfs, ?err, "failed to bind mount rootfs");
                err
            })?;

        let global_options = MountOptions {
            root: rootfs,
            label: linux.mount_label().as_deref(),
            cgroup_ns,
        };

        if let Some(mounts) = spec.mounts() {
            for mount in mounts {
                mounter.setup_mount(mount, &global_options)?;
            }
        }
        Ok(())
    }

    pub fn prepare_rootfs(
        &self,
        spec: &Spec,
        rootfs: &Path,
        bind_devices: bool,
        cgroup_ns: bool,
    ) -> Result<()> {
        tracing::debug!(?rootfs, "prepare rootfs");
        let linux = spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;

        self.mount_to_rootfs(linux, spec, rootfs, cgroup_ns)?;

        let symlinker = Symlink::new();
        symlinker.setup_kcore_symlink(rootfs)?;
        symlinker.setup_default_symlinks(rootfs)?;

        let devicer = Device::new();
        if let Some(added_devices) = linux.devices() {
            let mut path_set = HashSet::new();
            let devices = default_devices();
            added_devices.iter().for_each(|d| {
                path_set.insert(d.path());
            });
            let default = devices.iter().filter(|d| !path_set.contains(d.path()));
            devicer.create_devices(rootfs, added_devices.iter().chain(default), bind_devices)
        } else {
            devicer.create_devices(rootfs, &default_devices(), bind_devices)
        }?;

        symlinker.setup_ptmx(rootfs)?;
        Ok(())
    }

    /// Change propagation type of rootfs as specified in spec.
    pub fn adjust_root_mount_propagation(&self, linux: &Linux) -> Result<()> {
        let rootfs_propagation = linux.rootfs_propagation().as_deref();
        let flags = match rootfs_propagation {
            Some("shared") => Some(MsFlags::MS_SHARED),
            Some("unbindable") => Some(MsFlags::MS_UNBINDABLE),
            _ => None,
        };

        if let Some(flags) = flags {
            self.syscall
                .mount(None, Path::new("/"), None, flags, None)
                .map_err(|err| {
                    tracing::error!(
                        ?err,
                        ?flags,
                        "failed to adjust the mount propagation type of the root"
                    );
                    err
                })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use anyhow::Result;
    use nix::mount::MsFlags;
    use oci_spec::runtime::LinuxBuilder;

    use crate::rootfs::RootFS;
    use crate::syscall::test::{MountArgs, TestHelperSyscall};

    // helper function for adjust_root_mount_propagation unit tests
    fn assert_root_mount_propagation(
        propagation_option: Option<&str>,
        expected_flags: Option<MsFlags>,
    ) -> Result<()> {
        // Create OCI Spec with propagation option
        let mut linux_builder = LinuxBuilder::default();
        if let Some(propagation) = propagation_option {
            linux_builder = linux_builder.rootfs_propagation(propagation);
        }
        let linux_spec = linux_builder.build()?;

        // Build mock rootfs
        let rootfs = RootFS::new_with_syscall(Box::<TestHelperSyscall>::default());
        rootfs.adjust_root_mount_propagation(&linux_spec)?;

        // Get mount calls from mock
        let helper = rootfs
            .syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .expect("RootFS should contain TestHelperSyscall");
        let mount_args = helper.get_mount_args();

        if let Some(flag) = expected_flags {
            assert_eq!(
                mount_args,
                vec![MountArgs {
                    source: None,
                    target: PathBuf::from("/"),
                    fstype: None,
                    flags: flag,
                    data: None,
                }]
            );
        } else {
            assert!(
                mount_args.is_empty(),
                "expected no mount calls, but mount was called with {mount_args:?}"
            )
        }
        Ok(())
    }

    #[test]
    fn test_shared_root_mount_propagation() -> Result<()> {
        assert_root_mount_propagation(Some("shared"), Some(MsFlags::MS_SHARED))
    }

    #[test]
    fn test_unbindable_root_mount_propagation() -> Result<()> {
        assert_root_mount_propagation(Some("unbindable"), Some(MsFlags::MS_UNBINDABLE))
    }

    #[test]
    fn test_ignore_slave_root_mount_propagation() -> Result<()> {
        assert_root_mount_propagation(Some("slave"), None)
    }

    #[test]
    fn test_ignore_none_inputs_on_root_mount_propagation() -> Result<()> {
        assert_root_mount_propagation(None, None)
    }
}
