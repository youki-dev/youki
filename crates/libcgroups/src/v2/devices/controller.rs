use std::os::unix::io::AsRawFd;
use std::path::Path;

#[cfg(test)]
use bpf::mock_prog as bpf_prog;
#[cfg(not(test))]
use bpf::prog as bpf_prog;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use oci_spec::runtime::LinuxDeviceCgroup;

use super::bpf::BpfError;
use super::program::ProgramError;
use super::*;
use crate::common::{ControllerOpt, default_allow_devices, default_devices};
use crate::v2::controller::Controller;

const LICENSE: &str = "Apache";

pub struct Devices {}

#[derive(thiserror::Error, Debug)]
pub enum DevicesControllerError {
    #[error("bpf error: {0}")]
    Bpf(#[from] BpfError),
    #[error("nix error: {0}")]
    Nix(#[from] nix::Error),
    #[error("program error: {0}")]
    Program(#[from] ProgramError),
}

impl Controller for Devices {
    type Error = DevicesControllerError;
    type Resource = Vec<LinuxDeviceCgroup>;

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        controller_opt.resources.devices().as_ref()
    }

    fn apply(
        controller_opt: &ControllerOpt,
        cgroup_root: &Path,
    ) -> Result<(), DevicesControllerError> {
        #[cfg(not(feature = "cgroupsv2_devices"))]
        return Ok(());

        #[cfg(feature = "cgroupsv2_devices")]
        {
            if controller_opt.skip_devices {
                return Ok(());
            }
            Self::apply_devices(cgroup_root, controller_opt.resources.devices())
        }
    }
}

impl Devices {
    pub fn apply_devices(
        cgroup_root: &Path,
        linux_devices: &Option<Vec<LinuxDeviceCgroup>>,
    ) -> Result<(), DevicesControllerError> {
        tracing::debug!("Apply Devices cgroup config");

        // FIXME: should we start as "deny all"?
        let mut emulator = emulator::Emulator::with_default_allow(false);

        // FIXME: apply user-defined and default rules in which order?
        if let Some(devices) = linux_devices {
            for d in devices {
                tracing::debug!("apply user defined rule: {:?}", d);
                emulator.add_rule(d);
            }
        }

        for d in [
            default_devices().iter().map(|d| d.into()).collect(),
            default_allow_devices(),
        ]
        .concat()
        {
            tracing::debug!("apply default rule: {:?}", d);
            emulator.add_rule(&d);
        }

        let prog = program::Program::from_rules(&emulator.rules, emulator.default_allow)?;

        // Increase `ulimit -l` limit to avoid BPF_PROG_LOAD error (#2167).
        // This limit is not inherited into the container.
        bpf_prog::bump_memlock_rlimit()?;
        let prog_fd = bpf_prog::load(LICENSE, prog.bytecodes())?;

        // FIXME: simple way to attach BPF program
        //  1. get list of existing attached programs
        //  2. attach this program (not use BPF_F_REPLACE, see below)
        //  3. detach all programs of 1
        //
        // runc will use BPF_F_REPLACE to replace currently attached program if:
        //   1. BPF_F_REPLACE is supported by kernel
        //   2. there is exactly one attached program
        // https://github.com/opencontainers/runc/blob/8e6871a3b14bb74e0ef358aca3b9f8f9cb80f041/libcontainer/cgroups/ebpf/ebpf_linux.go#L165
        //
        // IMHO, this is too complicated, and in most cases, we just attach program once without
        // already attached programs.

        // get the fd of the cgroup root
        let fd = nix::dir::Dir::open(
            cgroup_root.as_os_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            Mode::from_bits(0o600).unwrap(),
        )?;

        // collect the programs attached to this cgroup
        let old_progs = bpf_prog::query(fd.as_raw_fd())?;
        // attach our new program
        bpf_prog::attach(prog_fd, fd.as_raw_fd())?;
        // detach all previous programs
        for old_prog in old_progs {
            bpf_prog::detach2(old_prog.fd, fd.as_raw_fd())?;
        }

        Ok(())
    }

    /// Ids of the programs attached directly to `cgroup_root`.
    pub fn attached_program_ids(cgroup_root: &Path) -> Result<Vec<u32>, DevicesControllerError> {
        let fd = nix::dir::Dir::open(
            cgroup_root.as_os_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            Mode::from_bits(0o600).unwrap(),
        )?;

        // Only the ids: a program that cannot be opened must still count as attached
        // before the update, or the detach below would treat it as new.
        Ok(bpf_prog::query_ids(fd.as_raw_fd())?)
    }

    /// Detaches the programs attached directly to `cgroup_root` whose ids are not in
    /// `before`, and returns the ids detached. The systemd manager calls this right
    /// after set_unit_properties on a skipped update: systemd attaches its own device
    /// filter there. Anything else attached between the two queries is detached too.
    pub fn detach_programs_added(
        cgroup_root: &Path,
        before: &[u32],
    ) -> Result<Vec<u32>, DevicesControllerError> {
        let fd = nix::dir::Dir::open(
            cgroup_root.as_os_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            Mode::from_bits(0o600).unwrap(),
        )?;

        let mut detached = Vec::new();
        for id in bpf_prog::query_ids(fd.as_raw_fd())? {
            if before.contains(&id) {
                continue;
            }
            // A new program that cannot be opened cannot be detached, so this is an
            // error rather than a silent success. ENOENT means it is already gone.
            // Like apply_devices, the fd is left to the process exit.
            let prog_fd = match bpf_prog::get_fd_by_id(id) {
                Ok(prog_fd) => prog_fd,
                Err(BpfError::Errno(errno)) if errno.0 == libc::ENOENT => continue,
                Err(err) => return Err(err.into()),
            };
            bpf_prog::detach2(prog_fd, fd.as_raw_fd())?;
            detached.push(id);
        }

        Ok(detached)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::RawFd;

    use bpf::mock_prog;
    use oci_spec::runtime::{
        LinuxDeviceCgroupBuilder, LinuxDeviceType, LinuxResources, LinuxResourcesBuilder,
    };
    use serial_test::serial;

    use super::*;
    use crate::test::setup;

    fn opt(resources: &LinuxResources) -> ControllerOpt<'_> {
        ControllerOpt {
            resources,
            freezer_state: None,
            oom_score_adj: None,
            disable_oom_killer: false,
            skip_devices: false,
        }
    }

    #[test]
    #[serial(bpf)] // mock contexts are shared
    fn test_apply_devices() {
        // arrange
        let (tmp, _) = setup("some.value");
        let a_type = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::A)
            .build()
            .unwrap();
        let resources = LinuxResourcesBuilder::default()
            .devices(vec![a_type])
            .build()
            .unwrap();
        let file_descriptor: RawFd = 6;

        // expect
        let bump_memlock_rlimit = mock_prog::bump_memlock_rlimit_context();
        let load = mock_prog::load_context();
        let query = mock_prog::query_context();
        let attach = mock_prog::attach_context();
        let detach2 = mock_prog::detach2_context();
        bump_memlock_rlimit.expect().once().returning(|| Ok(()));
        load.expect()
            .once()
            .returning(move |_, _| Ok(file_descriptor));
        query.expect().once().returning(|_| Ok(vec![]));
        attach.expect().once().returning(|_, _| Ok(()));
        detach2.expect().never();

        // act
        // Through apply with skip_devices false, so an always-skip change fails here.
        Devices::apply(&opt(&resources), tmp.path()).expect("Could not apply devices");
    }

    #[test]
    #[serial(bpf)] // mock contexts are shared
    fn test_existing_programs() {
        // arrange
        let (tmp, _) = setup("some.value");
        let a_type = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::A)
            .build()
            .unwrap();
        let resources = LinuxResourcesBuilder::default()
            .devices(vec![a_type])
            .build()
            .unwrap();
        let file_descriptor: RawFd = 6;
        let existing_program_1 = bpf::ProgramInfo {
            id: u32::default(),
            fd: i32::default(),
        };

        // expect
        let bump_memlock_rlimit = mock_prog::bump_memlock_rlimit_context();
        let load = mock_prog::load_context();
        let query = mock_prog::query_context();
        let attach = mock_prog::attach_context();
        let detach2 = mock_prog::detach2_context();
        bump_memlock_rlimit.expect().once().returning(|| Ok(()));
        load.expect()
            .once()
            .returning(move |_, _| Ok(file_descriptor));
        query
            .expect()
            .once()
            .returning(move |_| Ok(vec![existing_program_1.clone()]));
        attach.expect().once().returning(|_, _| Ok(()));
        detach2.expect().once().returning(|_, _| Ok(()));

        // act
        Devices::apply_devices(tmp.path(), resources.devices()).expect("Could not apply devices");
    }

    #[test]
    #[serial(bpf)] // mock contexts are shared
    fn test_skip_devices_keeps_the_attached_program() {
        // arrange
        let (tmp, _) = setup("some.value");
        let a_type = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::A)
            .build()
            .unwrap();
        let resources = LinuxResourcesBuilder::default()
            .devices(vec![a_type])
            .build()
            .unwrap();
        let mut controller_opt = opt(&resources);
        controller_opt.skip_devices = true;

        // expect: no bpf interaction at all
        let bump_memlock_rlimit = mock_prog::bump_memlock_rlimit_context();
        let load = mock_prog::load_context();
        let query = mock_prog::query_context();
        let attach = mock_prog::attach_context();
        let detach2 = mock_prog::detach2_context();
        bump_memlock_rlimit.expect().never();
        load.expect().never();
        query.expect().never();
        attach.expect().never();
        detach2.expect().never();

        // act
        Devices::apply(&controller_opt, tmp.path()).expect("Could not apply devices");
    }

    #[test]
    #[serial(bpf)] // mock contexts are shared
    fn test_detach_programs_added_detaches_only_new_programs() {
        let (tmp, _) = setup("some.value");

        let query_ids = mock_prog::query_ids_context();
        let get_fd_by_id = mock_prog::get_fd_by_id_context();
        let detach2 = mock_prog::detach2_context();
        query_ids.expect().once().returning(|_| Ok(vec![1, 2]));
        get_fd_by_id
            .expect()
            .once()
            .with(mockall::predicate::eq(2))
            .returning(|_| Ok(11));
        detach2
            .expect()
            .once()
            .with(mockall::predicate::eq(11), mockall::predicate::always())
            .returning(|_, _| Ok(()));

        let detached =
            Devices::detach_programs_added(tmp.path(), &[1]).expect("detach added programs");
        assert_eq!(detached, vec![2]);
    }

    #[test]
    #[serial(bpf)] // mock contexts are shared
    fn test_detach_programs_added_fails_when_a_new_program_cannot_be_opened() {
        let (tmp, _) = setup("some.value");

        let query_ids = mock_prog::query_ids_context();
        let get_fd_by_id = mock_prog::get_fd_by_id_context();
        let detach2 = mock_prog::detach2_context();
        query_ids.expect().once().returning(|_| Ok(vec![1, 2]));
        get_fd_by_id
            .expect()
            .once()
            .returning(|_| Err(BpfError::Errno(errno::Errno(libc::EMFILE))));
        detach2.expect().never();

        assert!(Devices::detach_programs_added(tmp.path(), &[1]).is_err());
    }

    #[test]
    #[serial(bpf)] // mock contexts are shared
    fn test_attached_program_ids_counts_programs_without_opening_them() {
        let (tmp, _) = setup("some.value");

        let query_ids = mock_prog::query_ids_context();
        let get_fd_by_id = mock_prog::get_fd_by_id_context();
        query_ids.expect().once().returning(|_| Ok(vec![1, 2]));
        get_fd_by_id.expect().never();

        let ids = Devices::attached_program_ids(tmp.path()).expect("list programs");
        assert_eq!(ids, vec![1, 2]);
    }
}
