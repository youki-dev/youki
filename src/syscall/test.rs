use std::{any::Any, cell::RefCell, ffi::OsStr, path::PathBuf, sync::Arc};

use caps::{errors::CapsError, CapSet, CapsHashSet};
use nix::sched::CloneFlags;
use oci_spec::runtime::LinuxRlimit;

use super::Syscall;

#[derive(Clone)]
pub struct TestHelperSyscall {
    set_ns_args: RefCell<Vec<(i32, CloneFlags)>>,
    unshare_args: RefCell<Vec<CloneFlags>>,
    set_capability_args: RefCell<Vec<(CapSet, CapsHashSet)>>,
    mount_args: RefCell<
        Vec<(
            Option<std::path::PathBuf>,
            std::path::PathBuf,
            Option<String>,
            nix::mount::MsFlags,
            Option<String>,
        )>,
    >,
    symlink_args: RefCell<Vec<(PathBuf, PathBuf)>>,
}

impl Default for TestHelperSyscall {
    fn default() -> Self {
        TestHelperSyscall {
            set_ns_args: RefCell::new(vec![]),
            unshare_args: RefCell::new(vec![]),
            set_capability_args: RefCell::new(vec![]),
            mount_args: RefCell::new(vec![]),
            symlink_args: RefCell::new(vec![]),
        }
    }
}

impl Syscall for TestHelperSyscall {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn pivot_rootfs(&self, _path: &std::path::Path) -> anyhow::Result<()> {
        unimplemented!()
    }

    fn set_ns(&self, rawfd: i32, nstype: CloneFlags) -> anyhow::Result<()> {
        let args = (rawfd, nstype);
        self.set_ns_args.borrow_mut().push(args);
        Ok(())
    }

    fn set_id(&self, _uid: nix::unistd::Uid, _gid: nix::unistd::Gid) -> anyhow::Result<()> {
        unimplemented!()
    }

    fn unshare(&self, flags: CloneFlags) -> anyhow::Result<()> {
        self.unshare_args.borrow_mut().push(flags);
        Ok(())
    }

    fn set_capability(&self, cset: CapSet, value: &CapsHashSet) -> Result<(), CapsError> {
        let args = (cset, value.clone());
        self.set_capability_args.borrow_mut().push(args);
        Ok(())
    }

    fn set_hostname(&self, _hostname: &str) -> anyhow::Result<()> {
        todo!()
    }

    fn set_rlimit(&self, _rlimit: &LinuxRlimit) -> anyhow::Result<()> {
        todo!()
    }

    fn get_pwuid(&self, _: u32) -> Option<Arc<OsStr>> {
        todo!()
    }

    fn chroot(&self, _: &std::path::Path) -> anyhow::Result<()> {
        todo!()
    }

    fn mount(
        &self,
        source: Option<&std::path::Path>,
        target: &std::path::Path,
        fstype: Option<&str>,
        flags: nix::mount::MsFlags,
        data: Option<&str>,
    ) -> anyhow::Result<()> {
        self.mount_args.borrow_mut().push((
            source.map(|x| x.to_owned()),
            target.to_owned(),
            fstype.map(|x| x.to_owned()),
            flags,
            data.map(|x| x.to_owned()),
        ));
        Ok(())
    }

    fn symlink(&self, original: &std::path::Path, link: &std::path::Path) -> anyhow::Result<()> {
        self.symlink_args
            .borrow_mut()
            .push((original.to_path_buf(), link.to_path_buf()));
        Ok(())
    }
}

impl TestHelperSyscall {
    pub fn get_setns_args(&self) -> Vec<(i32, CloneFlags)> {
        self.set_ns_args.borrow_mut().clone()
    }

    pub fn get_unshare_args(&self) -> Vec<CloneFlags> {
        self.unshare_args.borrow_mut().clone()
    }

    pub fn get_set_capability_args(&self) -> Vec<(CapSet, CapsHashSet)> {
        self.set_capability_args.borrow_mut().clone()
    }

    pub fn get_mount_args(
        &self,
    ) -> Vec<(
        Option<std::path::PathBuf>,
        std::path::PathBuf,
        Option<String>,
        nix::mount::MsFlags,
        Option<String>,
    )> {
        self.mount_args.borrow_mut().clone()
    }

    pub fn get_symlink_args(&self) -> Vec<(PathBuf, PathBuf)> {
        self.symlink_args.borrow_mut().clone()
    }
}
