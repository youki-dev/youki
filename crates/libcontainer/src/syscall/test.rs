use std::any::Any;
use std::cell::{Ref, RefCell, RefMut};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use caps::{CapSet, CapsHashSet};
use nix::mount::{MntFlags, MsFlags};
use nix::sched::CloneFlags;
use nix::sys::stat::{Mode, SFlag};
use nix::unistd::{Gid, Uid};
use oci_spec::runtime::PosixRlimit;

use super::{linux, Result, Syscall};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MountArgs {
    pub source: Option<PathBuf>,
    pub target: PathBuf,
    pub fstype: Option<String>,
    pub flags: MsFlags,
    pub data: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MknodArgs {
    pub path: PathBuf,
    pub kind: SFlag,
    pub perm: Mode,
    pub dev: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChownArgs {
    pub path: PathBuf,
    pub owner: Option<Uid>,
    pub group: Option<Gid>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IoPriorityArgs {
    pub class: i64,
    pub priority: i64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UMount2Args {
    pub target: PathBuf,
    pub flags: MntFlags,
}

#[derive(Default)]
struct Mock {
    values: Vec<Box<dyn Any>>,
    ret_err: Option<fn() -> Result<()>>,
    ret_err_times: usize,
}

#[derive(PartialEq, Eq, Hash, Copy, Clone)]
pub enum ArgName {
    Namespace,
    Unshare,
    Mount,
    Symlink,
    Mknod,
    Chown,
    Hostname,
    Domainname,
    Groups,
    Capability,
    IoPriority,
    UMount2,
}

impl ArgName {
    fn iterator() -> impl Iterator<Item = ArgName> {
        [
            ArgName::Namespace,
            ArgName::Unshare,
            ArgName::Mount,
            ArgName::Symlink,
            ArgName::Mknod,
            ArgName::Chown,
            ArgName::Hostname,
            ArgName::Domainname,
            ArgName::Groups,
            ArgName::Capability,
            ArgName::IoPriority,
        ]
        .iter()
        .copied()
    }
}

struct MockCalls {
    args: HashMap<ArgName, RefCell<Mock>>,
}

impl Default for MockCalls {
    fn default() -> Self {
        let mut m = MockCalls {
            args: HashMap::new(),
        };

        for name in ArgName::iterator() {
            m.args.insert(name, RefCell::new(Mock::default()));
        }

        m
    }
}

impl MockCalls {
    fn act(&self, name: ArgName, value: Box<dyn Any>) -> Result<()> {
        if self.args.get(&name).unwrap().borrow().ret_err_times > 0 {
            self.args.get(&name).unwrap().borrow_mut().ret_err_times -= 1;
            if let Some(e) = &self.args.get(&name).unwrap().borrow().ret_err {
                return e();
            }
        }

        self.args
            .get(&name)
            .unwrap()
            .borrow_mut()
            .values
            .push(value);
        Ok(())
    }

    fn fetch(&self, name: ArgName) -> Ref<Mock> {
        self.args.get(&name).unwrap().borrow()
    }

    fn fetch_mut(&self, name: ArgName) -> RefMut<Mock> {
        self.args.get(&name).unwrap().borrow_mut()
    }
}

#[derive(Default)]
pub struct TestHelperSyscall {
    mocks: MockCalls,
}

impl Syscall for TestHelperSyscall {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn pivot_rootfs(&self, _path: &Path) -> Result<()> {
        unimplemented!()
    }

    fn set_ns(&self, rawfd: i32, nstype: CloneFlags) -> Result<()> {
        self.mocks
            .act(ArgName::Namespace, Box::new((rawfd, nstype)))
    }

    fn set_id(&self, _uid: Uid, _gid: Gid) -> Result<()> {
        unimplemented!()
    }

    fn unshare(&self, flags: CloneFlags) -> Result<()> {
        self.mocks.act(ArgName::Unshare, Box::new(flags))
    }

    fn set_capability(&self, cset: CapSet, value: &CapsHashSet) -> Result<()> {
        self.mocks
            .act(ArgName::Capability, Box::new((cset, value.clone())))
    }

    fn set_hostname(&self, hostname: &str) -> Result<()> {
        self.mocks
            .act(ArgName::Hostname, Box::new(hostname.to_owned()))
    }

    fn set_domainname(&self, domainname: &str) -> Result<()> {
        self.mocks
            .act(ArgName::Domainname, Box::new(domainname.to_owned()))
    }

    fn set_rlimit(&self, _rlimit: &PosixRlimit) -> Result<()> {
        todo!()
    }

    fn get_pwuid(&self, _: u32) -> Option<Arc<OsStr>> {
        Some(OsString::from("youki").into())
    }

    fn chroot(&self, _: &Path) -> Result<()> {
        todo!()
    }

    fn mount(
        &self,
        source: Option<&Path>,
        target: &Path,
        fstype: Option<&str>,
        flags: MsFlags,
        data: Option<&str>,
    ) -> Result<()> {
        self.mocks.act(
            ArgName::Mount,
            Box::new(MountArgs {
                source: source.map(|x| x.to_owned()),
                target: target.to_owned(),
                fstype: fstype.map(|x| x.to_owned()),
                flags,
                data: data.map(|x| x.to_owned()),
            }),
        )
    }

    fn symlink(&self, original: &Path, link: &Path) -> Result<()> {
        self.mocks.act(
            ArgName::Symlink,
            Box::new((original.to_path_buf(), link.to_path_buf())),
        )
    }

    fn mknod(&self, path: &Path, kind: SFlag, perm: Mode, dev: u64) -> Result<()> {
        self.mocks.act(
            ArgName::Mknod,
            Box::new(MknodArgs {
                path: path.to_path_buf(),
                kind,
                perm,
                dev,
            }),
        )
    }
    fn chown(&self, path: &Path, owner: Option<Uid>, group: Option<Gid>) -> Result<()> {
        self.mocks.act(
            ArgName::Chown,
            Box::new(ChownArgs {
                path: path.to_path_buf(),
                owner,
                group,
            }),
        )
    }

    fn set_groups(&self, groups: &[Gid]) -> Result<()> {
        self.mocks.act(ArgName::Groups, Box::new(groups.to_vec()))
    }

    fn close_range(&self, _: i32) -> Result<()> {
        todo!()
    }

    fn mount_setattr(
        &self,
        _: i32,
        _: &Path,
        _: u32,
        _: &linux::MountAttr,
        _: libc::size_t,
    ) -> Result<()> {
        todo!()
    }

    fn set_io_priority(&self, class: i64, priority: i64) -> Result<()> {
        self.mocks.act(
            ArgName::IoPriority,
            Box::new(IoPriorityArgs { class, priority }),
        )
    }

    fn umount2(&self, target: &Path, flags: MntFlags) -> Result<()> {
        self.mocks.act(
            ArgName::UMount2,
            Box::new(UMount2Args {
                target: target.to_owned(),
                flags,
            }),
        )
    }
}

impl TestHelperSyscall {
    pub fn set_ret_err(&self, name: ArgName, err: fn() -> Result<()>) {
        self.mocks.fetch_mut(name).ret_err = Some(err);
        self.set_ret_err_times(name, 1);
    }

    pub fn set_ret_err_times(&self, name: ArgName, times: usize) {
        self.mocks.fetch_mut(name).ret_err_times = times;
    }

    pub fn get_setns_args(&self) -> Vec<(i32, CloneFlags)> {
        self.mocks
            .fetch(ArgName::Namespace)
            .values
            .iter()
            .map(|x| *x.downcast_ref::<(i32, CloneFlags)>().unwrap())
            .collect::<Vec<(i32, CloneFlags)>>()
    }

    pub fn get_unshare_args(&self) -> Vec<CloneFlags> {
        self.mocks
            .fetch(ArgName::Unshare)
            .values
            .iter()
            .map(|x| *x.downcast_ref::<CloneFlags>().unwrap())
            .collect::<Vec<CloneFlags>>()
    }

    pub fn get_set_capability_args(&self) -> Vec<(CapSet, CapsHashSet)> {
        self.mocks
            .fetch(ArgName::Capability)
            .values
            .iter()
            .map(|x| x.downcast_ref::<(CapSet, CapsHashSet)>().unwrap().clone())
            .collect::<Vec<(CapSet, CapsHashSet)>>()
    }

    pub fn get_mount_args(&self) -> Vec<MountArgs> {
        self.mocks
            .fetch(ArgName::Mount)
            .values
            .iter()
            .map(|x| x.downcast_ref::<MountArgs>().unwrap().clone())
            .collect::<Vec<MountArgs>>()
    }

    pub fn get_symlink_args(&self) -> Vec<(PathBuf, PathBuf)> {
        self.mocks
            .fetch(ArgName::Symlink)
            .values
            .iter()
            .map(|x| x.downcast_ref::<(PathBuf, PathBuf)>().unwrap().clone())
            .collect::<Vec<(PathBuf, PathBuf)>>()
    }

    pub fn get_mknod_args(&self) -> Vec<MknodArgs> {
        self.mocks
            .fetch(ArgName::Mknod)
            .values
            .iter()
            .map(|x| x.downcast_ref::<MknodArgs>().unwrap().clone())
            .collect::<Vec<MknodArgs>>()
    }

    pub fn get_chown_args(&self) -> Vec<ChownArgs> {
        self.mocks
            .fetch(ArgName::Chown)
            .values
            .iter()
            .map(|x| x.downcast_ref::<ChownArgs>().unwrap().clone())
            .collect::<Vec<ChownArgs>>()
    }

    pub fn get_hostname_args(&self) -> Vec<String> {
        self.mocks
            .fetch(ArgName::Hostname)
            .values
            .iter()
            .map(|x| x.downcast_ref::<String>().unwrap().clone())
            .collect::<Vec<String>>()
    }

    pub fn get_domainname_args(&self) -> Vec<String> {
        self.mocks
            .fetch(ArgName::Domainname)
            .values
            .iter()
            .map(|x| x.downcast_ref::<String>().unwrap().clone())
            .collect::<Vec<String>>()
    }

    pub fn get_groups_args(&self) -> Vec<Gid> {
        self.mocks
            .fetch(ArgName::Groups)
            .values
            .iter()
            .flat_map(|x| x.downcast_ref::<Vec<Gid>>().unwrap().clone())
            .collect::<Vec<Gid>>()
    }

    pub fn get_io_priority_args(&self) -> Vec<IoPriorityArgs> {
        self.mocks
            .fetch(ArgName::IoPriority)
            .values
            .iter()
            .map(|x| x.downcast_ref::<IoPriorityArgs>().unwrap().clone())
            .collect::<Vec<IoPriorityArgs>>()
    }

    pub fn get_umount_args(&self) -> Vec<UMount2Args> {
        self.mocks
            .fetch(ArgName::UMount2)
            .values
            .iter()
            .map(|x| x.downcast_ref::<UMount2Args>().unwrap().clone())
            .collect::<Vec<UMount2Args>>()
    }
}
