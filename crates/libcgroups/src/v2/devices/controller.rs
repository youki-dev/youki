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

    fn apply(
        controller_opt: &ControllerOpt,
        cgroup_root: &Path,
    ) -> Result<(), DevicesControllerError> {
        #[cfg(not(feature = "cgroupsv2_devices"))]
        return Ok(());

        #[cfg(feature = "cgroupsv2_devices")]
        return Self::apply_devices(cgroup_root, controller_opt.resources.devices());
    }
}

/// Whether the process sits in a user namespace, told apart the way runc's
/// userns.RunningInUserNS() does: only the initial namespace maps the whole uid range.
/// An unreadable map leaves no reason to assume otherwise.
fn in_user_namespace() -> bool {
    match std::fs::read_to_string("/proc/self/uid_map") {
        Ok(content) => !content.contains("4294967295"),
        Err(_) => false,
    }
}

fn grants_full_access(rule: &LinuxDeviceCgroup) -> bool {
    rule.allow()
        && rule
            .access()
            .as_deref()
            .is_some_and(|access| ['r', 'w', 'm'].iter().all(|flag| access.contains(*flag)))
}

/// Whether a filter that would not load can be left off.
///
/// bpf(2) is not available in a user namespace, and a container there cannot mknod a device
/// node or reach a host one anyway, so the missing filter is not what keeps it away from
/// devices. Outside one the filter is the only thing holding the rules up, so the error
/// stands unless every rule grants full access and the filter would take nothing away.
/// Mirrors runc's canSkipEBPFError() (devices/v2.go).
fn can_skip_ebpf_error(linux_devices: &Option<Vec<LinuxDeviceCgroup>>) -> bool {
    in_user_namespace()
        || linux_devices
            .as_deref()
            .unwrap_or_default()
            .iter()
            .all(grants_full_access)
}

impl Devices {
    pub fn apply_devices(
        cgroup_root: &Path,
        linux_devices: &Option<Vec<LinuxDeviceCgroup>>,
    ) -> Result<(), DevicesControllerError> {
        match Self::attach_device_filter(cgroup_root, linux_devices) {
            Err(err) if can_skip_ebpf_error(linux_devices) => {
                tracing::warn!("leaving the device filter off, it could not be attached: {err}");
                Ok(())
            }
            result => result,
        }
    }

    fn attach_device_filter(
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
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::RawFd;

    use bpf::mock_prog;
    use oci_spec::runtime::{LinuxDeviceCgroupBuilder, LinuxDeviceType};
    use serial_test::serial;

    use super::*;
    use crate::test::setup;

    #[test]
    #[serial(bpf)] // mock contexts are shared
    fn test_apply_devices() {
        // arrange
        let (tmp, _) = setup("some.value");
        let a_type = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::A)
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
        Devices::apply_devices(tmp.path(), &Some(vec![a_type])).expect("Could not apply devices");
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
        Devices::apply_devices(tmp.path(), &Some(vec![a_type])).expect("Could not apply devices");
    }
}

#[cfg(test)]
mod skip_tests {
    use oci_spec::runtime::{LinuxDeviceCgroupBuilder, LinuxDeviceType};

    use super::*;

    fn rule(allow: bool, access: &str) -> LinuxDeviceCgroup {
        LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .allow(allow)
            .access(access)
            .build()
            .unwrap()
    }

    #[test]
    fn test_rules_that_take_nothing_away_can_skip() {
        assert!(grants_full_access(&rule(true, "rwm")));
        assert!(!grants_full_access(&rule(true, "rw")));
        assert!(!grants_full_access(&rule(false, "rwm")));
    }

    #[test]
    fn test_a_rule_the_filter_has_to_enforce_cannot_skip() {
        // Only meaningful outside a user namespace, where the filter is the enforcement.
        if in_user_namespace() {
            return;
        }

        assert!(can_skip_ebpf_error(&None));
        assert!(can_skip_ebpf_error(&Some(vec![rule(true, "rwm")])));
        assert!(!can_skip_ebpf_error(&Some(vec![rule(false, "rwm")])));
        assert!(!can_skip_ebpf_error(&Some(vec![
            rule(true, "rwm"),
            rule(true, "r")
        ])));
    }
}
