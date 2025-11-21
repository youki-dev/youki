//! Handles Management of Capabilities
use caps::{Capability as CapsCapability, *};
use oci_spec::runtime::{Capabilities, Capability as SpecCapability, LinuxCapabilities};

use crate::syscall::{Syscall, SyscallError};

/// Converts a list of capability types to capabilities has set
fn to_set(caps: &Capabilities) -> CapsHashSet {
    let mut capabilities = CapsHashSet::new();

    for c in caps {
        let cap = c.to_cap();
        capabilities.insert(cap);
    }
    capabilities
}

pub trait CapabilityExt {
    /// Convert self to caps::Capability
    fn to_cap(&self) -> caps::Capability;
    /// Convert caps::Capability to self
    fn from_cap(c: CapsCapability) -> Self;
}

impl CapabilityExt for SpecCapability {
    /// Convert oci::runtime::Capability to caps::Capability
    fn to_cap(&self) -> caps::Capability {
        match self {
            SpecCapability::AuditControl => CapsCapability::CAP_AUDIT_CONTROL,
            SpecCapability::AuditRead => CapsCapability::CAP_AUDIT_READ,
            SpecCapability::AuditWrite => CapsCapability::CAP_AUDIT_WRITE,
            SpecCapability::BlockSuspend => CapsCapability::CAP_BLOCK_SUSPEND,
            SpecCapability::Bpf => CapsCapability::CAP_BPF,
            SpecCapability::CheckpointRestore => CapsCapability::CAP_CHECKPOINT_RESTORE,
            SpecCapability::Chown => CapsCapability::CAP_CHOWN,
            SpecCapability::DacOverride => CapsCapability::CAP_DAC_OVERRIDE,
            SpecCapability::DacReadSearch => CapsCapability::CAP_DAC_READ_SEARCH,
            SpecCapability::Fowner => CapsCapability::CAP_FOWNER,
            SpecCapability::Fsetid => CapsCapability::CAP_FSETID,
            SpecCapability::IpcLock => CapsCapability::CAP_IPC_LOCK,
            SpecCapability::IpcOwner => CapsCapability::CAP_IPC_OWNER,
            SpecCapability::Kill => CapsCapability::CAP_KILL,
            SpecCapability::Lease => CapsCapability::CAP_LEASE,
            SpecCapability::LinuxImmutable => CapsCapability::CAP_LINUX_IMMUTABLE,
            SpecCapability::MacAdmin => CapsCapability::CAP_MAC_ADMIN,
            SpecCapability::MacOverride => CapsCapability::CAP_MAC_OVERRIDE,
            SpecCapability::Mknod => CapsCapability::CAP_MKNOD,
            SpecCapability::NetAdmin => CapsCapability::CAP_NET_ADMIN,
            SpecCapability::NetBindService => CapsCapability::CAP_NET_BIND_SERVICE,
            SpecCapability::NetBroadcast => CapsCapability::CAP_NET_BROADCAST,
            SpecCapability::NetRaw => CapsCapability::CAP_NET_RAW,
            SpecCapability::Perfmon => CapsCapability::CAP_PERFMON,
            SpecCapability::Setgid => CapsCapability::CAP_SETGID,
            SpecCapability::Setfcap => CapsCapability::CAP_SETFCAP,
            SpecCapability::Setpcap => CapsCapability::CAP_SETPCAP,
            SpecCapability::Setuid => CapsCapability::CAP_SETUID,
            SpecCapability::SysAdmin => CapsCapability::CAP_SYS_ADMIN,
            SpecCapability::SysBoot => CapsCapability::CAP_SYS_BOOT,
            SpecCapability::SysChroot => CapsCapability::CAP_SYS_CHROOT,
            SpecCapability::SysModule => CapsCapability::CAP_SYS_MODULE,
            SpecCapability::SysNice => CapsCapability::CAP_SYS_NICE,
            SpecCapability::SysPacct => CapsCapability::CAP_SYS_PACCT,
            SpecCapability::SysPtrace => CapsCapability::CAP_SYS_PTRACE,
            SpecCapability::SysRawio => CapsCapability::CAP_SYS_RAWIO,
            SpecCapability::SysResource => CapsCapability::CAP_SYS_RESOURCE,
            SpecCapability::SysTime => CapsCapability::CAP_SYS_TIME,
            SpecCapability::SysTtyConfig => CapsCapability::CAP_SYS_TTY_CONFIG,
            SpecCapability::Syslog => CapsCapability::CAP_SYSLOG,
            SpecCapability::WakeAlarm => CapsCapability::CAP_WAKE_ALARM,
        }
    }

    /// Convert caps::Capability to oci::runtime::Capability
    fn from_cap(c: CapsCapability) -> SpecCapability {
        match c {
            CapsCapability::CAP_AUDIT_CONTROL => SpecCapability::AuditControl,
            CapsCapability::CAP_AUDIT_READ => SpecCapability::AuditRead,
            CapsCapability::CAP_AUDIT_WRITE => SpecCapability::AuditWrite,
            CapsCapability::CAP_BLOCK_SUSPEND => SpecCapability::BlockSuspend,
            CapsCapability::CAP_BPF => SpecCapability::Bpf,
            CapsCapability::CAP_CHECKPOINT_RESTORE => SpecCapability::CheckpointRestore,
            CapsCapability::CAP_CHOWN => SpecCapability::Chown,
            CapsCapability::CAP_DAC_OVERRIDE => SpecCapability::DacOverride,
            CapsCapability::CAP_DAC_READ_SEARCH => SpecCapability::DacReadSearch,
            CapsCapability::CAP_FOWNER => SpecCapability::Fowner,
            CapsCapability::CAP_FSETID => SpecCapability::Fsetid,
            CapsCapability::CAP_IPC_LOCK => SpecCapability::IpcLock,
            CapsCapability::CAP_IPC_OWNER => SpecCapability::IpcOwner,
            CapsCapability::CAP_KILL => SpecCapability::Kill,
            CapsCapability::CAP_LEASE => SpecCapability::Lease,
            CapsCapability::CAP_LINUX_IMMUTABLE => SpecCapability::LinuxImmutable,
            CapsCapability::CAP_MAC_ADMIN => SpecCapability::MacAdmin,
            CapsCapability::CAP_MAC_OVERRIDE => SpecCapability::MacOverride,
            CapsCapability::CAP_MKNOD => SpecCapability::Mknod,
            CapsCapability::CAP_NET_ADMIN => SpecCapability::NetAdmin,
            CapsCapability::CAP_NET_BIND_SERVICE => SpecCapability::NetBindService,
            CapsCapability::CAP_NET_BROADCAST => SpecCapability::NetBroadcast,
            CapsCapability::CAP_NET_RAW => SpecCapability::NetRaw,
            CapsCapability::CAP_PERFMON => SpecCapability::Perfmon,
            CapsCapability::CAP_SETGID => SpecCapability::Setgid,
            CapsCapability::CAP_SETFCAP => SpecCapability::Setfcap,
            CapsCapability::CAP_SETPCAP => SpecCapability::Setpcap,
            CapsCapability::CAP_SETUID => SpecCapability::Setuid,
            CapsCapability::CAP_SYS_ADMIN => SpecCapability::SysAdmin,
            CapsCapability::CAP_SYS_BOOT => SpecCapability::SysBoot,
            CapsCapability::CAP_SYS_CHROOT => SpecCapability::SysChroot,
            CapsCapability::CAP_SYS_MODULE => SpecCapability::SysModule,
            CapsCapability::CAP_SYS_NICE => SpecCapability::SysNice,
            CapsCapability::CAP_SYS_PACCT => SpecCapability::SysPacct,
            CapsCapability::CAP_SYS_PTRACE => SpecCapability::SysPtrace,
            CapsCapability::CAP_SYS_RAWIO => SpecCapability::SysRawio,
            CapsCapability::CAP_SYS_RESOURCE => SpecCapability::SysResource,
            CapsCapability::CAP_SYS_TIME => SpecCapability::SysTime,
            CapsCapability::CAP_SYS_TTY_CONFIG => SpecCapability::SysTtyConfig,
            CapsCapability::CAP_SYSLOG => SpecCapability::Syslog,
            CapsCapability::CAP_WAKE_ALARM => SpecCapability::WakeAlarm,
            CapsCapability::__Nonexhaustive => unreachable!("invalid capability"),
        }
    }
}

/// reset capabilities of process calling this to effective capabilities
/// effective capability set is set of capabilities used by kernel to perform checks
/// see <https://man7.org/linux/man-pages/man7/capabilities.7.html> for more information
pub fn reset_effective<S: Syscall + ?Sized>(syscall: &S) -> Result<(), SyscallError> {
    tracing::debug!("reset all caps");
    // permitted capabilities are all the capabilities that we are allowed to acquire
    let permitted = caps::read(None, CapSet::Permitted)?;
    syscall.set_capability(CapSet::Effective, &permitted)?;
    Ok(())
}

/// Drop any extra granted capabilities, and reset to defaults which are in oci specification
pub fn drop_privileges<S: Syscall + ?Sized>(
    cs: &LinuxCapabilities,
    syscall: &S,
) -> Result<(), SyscallError> {
    tracing::debug!("dropping bounding capabilities to {:?}", cs.bounding());
    if let Some(bounding) = cs.bounding() {
        syscall.set_capability(CapSet::Bounding, &to_set(bounding))?;
    }

    if let Some(effective) = cs.effective() {
        syscall.set_capability(CapSet::Effective, &to_set(effective))?;
    }

    if let Some(permitted) = cs.permitted() {
        syscall.set_capability(CapSet::Permitted, &to_set(permitted))?;
    }

    if let Some(inheritable) = cs.inheritable() {
        syscall.set_capability(CapSet::Inheritable, &to_set(inheritable))?;
    }

    if let Some(ambient) = cs.ambient() {
        syscall.set_capability(CapSet::Ambient, &to_set(ambient))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use oci_spec::runtime::LinuxCapabilitiesBuilder;

    use super::*;
    use crate::syscall::test::TestHelperSyscall;

    #[test]
    fn test_reset_effective() {
        let test_command = TestHelperSyscall::default();
        let permitted_caps = caps::read(None, CapSet::Permitted).unwrap();
        assert!(reset_effective(&test_command).is_ok());
        let set_capability_args: Vec<_> = test_command
            .get_set_capability_args()
            .into_iter()
            .map(|(_capset, caps)| caps)
            .collect();
        assert_eq!(set_capability_args, vec![permitted_caps]);
    }

    #[test]
    fn test_convert_oci_spec_to_caps_type() {
        struct Testcase {
            input: SpecCapability,
            want: CapsCapability,
        }

        let tests = vec![
            Testcase {
                input: SpecCapability::AuditControl,
                want: CapsCapability::CAP_AUDIT_CONTROL,
            },
            Testcase {
                input: SpecCapability::AuditRead,
                want: CapsCapability::CAP_AUDIT_READ,
            },
            Testcase {
                input: SpecCapability::AuditWrite,
                want: CapsCapability::CAP_AUDIT_WRITE,
            },
            Testcase {
                input: SpecCapability::BlockSuspend,
                want: CapsCapability::CAP_BLOCK_SUSPEND,
            },
            Testcase {
                input: SpecCapability::Bpf,
                want: CapsCapability::CAP_BPF,
            },
            Testcase {
                input: SpecCapability::CheckpointRestore,
                want: CapsCapability::CAP_CHECKPOINT_RESTORE,
            },
            Testcase {
                input: SpecCapability::Chown,
                want: Capability::CAP_CHOWN,
            },
            Testcase {
                input: SpecCapability::DacOverride,
                want: CapsCapability::CAP_DAC_OVERRIDE,
            },
            Testcase {
                input: SpecCapability::DacReadSearch,
                want: CapsCapability::CAP_DAC_READ_SEARCH,
            },
            Testcase {
                input: SpecCapability::Fowner,
                want: CapsCapability::CAP_FOWNER,
            },
            Testcase {
                input: SpecCapability::Fsetid,
                want: CapsCapability::CAP_FSETID,
            },
            Testcase {
                input: SpecCapability::IpcLock,
                want: CapsCapability::CAP_IPC_LOCK,
            },
            Testcase {
                input: SpecCapability::IpcOwner,
                want: CapsCapability::CAP_IPC_OWNER,
            },
            Testcase {
                input: SpecCapability::Kill,
                want: CapsCapability::CAP_KILL,
            },
            Testcase {
                input: SpecCapability::Lease,
                want: CapsCapability::CAP_LEASE,
            },
            Testcase {
                input: SpecCapability::LinuxImmutable,
                want: CapsCapability::CAP_LINUX_IMMUTABLE,
            },
            Testcase {
                input: SpecCapability::MacAdmin,
                want: CapsCapability::CAP_MAC_ADMIN,
            },
            Testcase {
                input: SpecCapability::MacOverride,
                want: CapsCapability::CAP_MAC_OVERRIDE,
            },
            Testcase {
                input: SpecCapability::Mknod,
                want: CapsCapability::CAP_MKNOD,
            },
            Testcase {
                input: SpecCapability::NetAdmin,
                want: CapsCapability::CAP_NET_ADMIN,
            },
            Testcase {
                input: SpecCapability::NetBindService,
                want: CapsCapability::CAP_NET_BIND_SERVICE,
            },
            Testcase {
                input: SpecCapability::NetBroadcast,
                want: CapsCapability::CAP_NET_BROADCAST,
            },
            Testcase {
                input: SpecCapability::NetRaw,
                want: CapsCapability::CAP_NET_RAW,
            },
            Testcase {
                input: SpecCapability::Perfmon,
                want: CapsCapability::CAP_PERFMON,
            },
            Testcase {
                input: SpecCapability::Setgid,
                want: CapsCapability::CAP_SETGID,
            },
            Testcase {
                input: SpecCapability::Setfcap,
                want: CapsCapability::CAP_SETFCAP,
            },
            Testcase {
                input: SpecCapability::Setpcap,
                want: CapsCapability::CAP_SETPCAP,
            },
            Testcase {
                input: SpecCapability::Setuid,
                want: CapsCapability::CAP_SETUID,
            },
            Testcase {
                input: SpecCapability::SysAdmin,
                want: CapsCapability::CAP_SYS_ADMIN,
            },
            Testcase {
                input: SpecCapability::SysBoot,
                want: CapsCapability::CAP_SYS_BOOT,
            },
            Testcase {
                input: SpecCapability::SysChroot,
                want: CapsCapability::CAP_SYS_CHROOT,
            },
            Testcase {
                input: SpecCapability::SysModule,
                want: CapsCapability::CAP_SYS_MODULE,
            },
            Testcase {
                input: SpecCapability::SysNice,
                want: CapsCapability::CAP_SYS_NICE,
            },
            Testcase {
                input: SpecCapability::SysPacct,
                want: CapsCapability::CAP_SYS_PACCT,
            },
            Testcase {
                input: SpecCapability::SysPtrace,
                want: CapsCapability::CAP_SYS_PTRACE,
            },
            Testcase {
                input: SpecCapability::SysRawio,
                want: CapsCapability::CAP_SYS_RAWIO,
            },
            Testcase {
                input: SpecCapability::SysResource,
                want: CapsCapability::CAP_SYS_RESOURCE,
            },
            Testcase {
                input: SpecCapability::SysTime,
                want: CapsCapability::CAP_SYS_TIME,
            },
            Testcase {
                input: SpecCapability::SysTtyConfig,
                want: CapsCapability::CAP_SYS_TTY_CONFIG,
            },
            Testcase {
                input: SpecCapability::Syslog,
                want: CapsCapability::CAP_SYSLOG,
            },
            Testcase {
                input: SpecCapability::WakeAlarm,
                want: CapsCapability::CAP_WAKE_ALARM,
            },
        ];

        for test in tests {
            let got = test.input.to_cap();
            assert_eq!(got, test.want);
        }
    }

    #[test]
    fn test_convert_caps_type_to_oci_spec() {
        struct Testcase {
            input: CapsCapability,
            want: SpecCapability,
        }

        let tests = vec![
            Testcase {
                input: CapsCapability::CAP_AUDIT_CONTROL,
                want: SpecCapability::AuditControl,
            },
            Testcase {
                input: CapsCapability::CAP_AUDIT_READ,
                want: SpecCapability::AuditRead,
            },
            Testcase {
                input: CapsCapability::CAP_AUDIT_WRITE,
                want: SpecCapability::AuditWrite,
            },
            Testcase {
                input: CapsCapability::CAP_BLOCK_SUSPEND,
                want: SpecCapability::BlockSuspend,
            },
            Testcase {
                input: CapsCapability::CAP_BPF,
                want: SpecCapability::Bpf,
            },
            Testcase {
                input: CapsCapability::CAP_CHECKPOINT_RESTORE,
                want: SpecCapability::CheckpointRestore,
            },
            Testcase {
                input: CapsCapability::CAP_CHOWN,
                want: SpecCapability::Chown,
            },
            Testcase {
                input: CapsCapability::CAP_DAC_OVERRIDE,
                want: SpecCapability::DacOverride,
            },
            Testcase {
                input: CapsCapability::CAP_DAC_READ_SEARCH,
                want: SpecCapability::DacReadSearch,
            },
            Testcase {
                input: CapsCapability::CAP_FOWNER,
                want: SpecCapability::Fowner,
            },
            Testcase {
                input: CapsCapability::CAP_FSETID,
                want: SpecCapability::Fsetid,
            },
            Testcase {
                input: CapsCapability::CAP_IPC_LOCK,
                want: SpecCapability::IpcLock,
            },
            Testcase {
                input: CapsCapability::CAP_IPC_OWNER,
                want: SpecCapability::IpcOwner,
            },
            Testcase {
                input: CapsCapability::CAP_KILL,
                want: SpecCapability::Kill,
            },
            Testcase {
                input: CapsCapability::CAP_LEASE,
                want: SpecCapability::Lease,
            },
            Testcase {
                input: CapsCapability::CAP_LINUX_IMMUTABLE,
                want: SpecCapability::LinuxImmutable,
            },
            Testcase {
                input: CapsCapability::CAP_MAC_ADMIN,
                want: SpecCapability::MacAdmin,
            },
            Testcase {
                input: CapsCapability::CAP_MAC_OVERRIDE,
                want: SpecCapability::MacOverride,
            },
            Testcase {
                input: CapsCapability::CAP_MKNOD,
                want: SpecCapability::Mknod,
            },
            Testcase {
                input: CapsCapability::CAP_NET_ADMIN,
                want: SpecCapability::NetAdmin,
            },
            Testcase {
                input: CapsCapability::CAP_NET_BIND_SERVICE,
                want: SpecCapability::NetBindService,
            },
            Testcase {
                input: CapsCapability::CAP_NET_BROADCAST,
                want: SpecCapability::NetBroadcast,
            },
            Testcase {
                input: CapsCapability::CAP_NET_RAW,
                want: SpecCapability::NetRaw,
            },
            Testcase {
                input: CapsCapability::CAP_PERFMON,
                want: SpecCapability::Perfmon,
            },
            Testcase {
                input: CapsCapability::CAP_SETGID,
                want: SpecCapability::Setgid,
            },
            Testcase {
                input: CapsCapability::CAP_SETFCAP,
                want: SpecCapability::Setfcap,
            },
            Testcase {
                input: CapsCapability::CAP_SETPCAP,
                want: SpecCapability::Setpcap,
            },
            Testcase {
                input: CapsCapability::CAP_SETUID,
                want: SpecCapability::Setuid,
            },
            Testcase {
                input: CapsCapability::CAP_SYS_ADMIN,
                want: SpecCapability::SysAdmin,
            },
            Testcase {
                input: CapsCapability::CAP_SYS_BOOT,
                want: SpecCapability::SysBoot,
            },
            Testcase {
                input: CapsCapability::CAP_SYS_CHROOT,
                want: SpecCapability::SysChroot,
            },
            Testcase {
                input: CapsCapability::CAP_SYS_MODULE,
                want: SpecCapability::SysModule,
            },
            Testcase {
                input: CapsCapability::CAP_SYS_NICE,
                want: SpecCapability::SysNice,
            },
            Testcase {
                input: CapsCapability::CAP_SYS_PACCT,
                want: SpecCapability::SysPacct,
            },
            Testcase {
                input: CapsCapability::CAP_SYS_PTRACE,
                want: SpecCapability::SysPtrace,
            },
            Testcase {
                input: CapsCapability::CAP_SYS_RAWIO,
                want: SpecCapability::SysRawio,
            },
            Testcase {
                input: CapsCapability::CAP_SYS_RESOURCE,
                want: SpecCapability::SysResource,
            },
            Testcase {
                input: CapsCapability::CAP_SYS_TIME,
                want: SpecCapability::SysTime,
            },
            Testcase {
                input: CapsCapability::CAP_SYS_TTY_CONFIG,
                want: SpecCapability::SysTtyConfig,
            },
            Testcase {
                input: CapsCapability::CAP_SYSLOG,
                want: SpecCapability::Syslog,
            },
            Testcase {
                input: CapsCapability::CAP_WAKE_ALARM,
                want: SpecCapability::WakeAlarm,
            },
        ];

        for test in tests {
            let got = SpecCapability::from_cap(test.input);
            assert_eq!(got, test.want);
        }
    }

    #[test]
    fn test_drop_privileges() {
        struct Testcase {
            name: String,
            input: LinuxCapabilities,
            // be aware that the calling sequence in the drop_privileges function
            // will affect the output sequence from test_command.get_set_capability_args()
            want: Vec<(CapSet, Vec<SpecCapability>)>,
        }

        let cps = vec![
            SpecCapability::AuditWrite,
            SpecCapability::Kill,
            SpecCapability::NetBindService,
        ];

        let tests = vec![
            Testcase {
                name: format!("all LinuxCapabilities fields with caps: {cps:?}"),
                input: LinuxCapabilitiesBuilder::default()
                    .bounding(cps.clone().into_iter().collect::<Capabilities>())
                    .effective(cps.clone().into_iter().collect::<Capabilities>())
                    .inheritable(cps.clone().into_iter().collect::<Capabilities>())
                    .permitted(cps.clone().into_iter().collect::<Capabilities>())
                    .ambient(cps.clone().into_iter().collect::<Capabilities>())
                    .build()
                    .unwrap(),
                want: vec![
                    (CapSet::Bounding, cps.clone()),
                    (CapSet::Effective, cps.clone()),
                    (CapSet::Permitted, cps.clone()),
                    (CapSet::Inheritable, cps.clone()),
                    (CapSet::Ambient, cps.clone()),
                ],
            },
            Testcase {
                name: format!("partial LinuxCapabilities fields with caps: {cps:?}"),
                input: LinuxCapabilitiesBuilder::default()
                    .bounding(cps.clone().into_iter().collect::<Capabilities>())
                    .effective(cps.clone().into_iter().collect::<Capabilities>())
                    .permitted(cps.clone().into_iter().collect::<Capabilities>())
                    .build()
                    .unwrap(),
                want: vec![
                    (CapSet::Bounding, cps.clone()),
                    (CapSet::Effective, cps.clone()),
                    (CapSet::Permitted, cps.clone()),
                    (CapSet::Inheritable, cps.clone()),
                    (CapSet::Ambient, cps.clone()),
                ],
            },
            Testcase {
                name: format!("empty LinuxCapabilities fields with caps: {cps:?}"),
                input: LinuxCapabilitiesBuilder::default()
                    .bounding(HashSet::new())
                    .effective(HashSet::new())
                    .inheritable(HashSet::new())
                    .permitted(HashSet::new())
                    .ambient(HashSet::new())
                    .build()
                    .unwrap(),
                want: vec![
                    (CapSet::Bounding, cps.clone()),
                    (CapSet::Effective, cps.clone()),
                    (CapSet::Permitted, cps.clone()),
                    (CapSet::Inheritable, cps.clone()),
                    (CapSet::Ambient, cps),
                ],
            },
        ];

        for test in tests {
            let test_command = TestHelperSyscall::default();
            assert!(
                drop_privileges(&test.input, &test_command).is_ok(),
                "{}, drop_privileges is not ok",
                test.name
            );

            let got: Vec<(CapSet, Vec<_>)> = test_command
                .get_set_capability_args()
                .into_iter()
                .map(|(capset, caps)| {
                    (
                        capset,
                        caps.into_iter().map(SpecCapability::from_cap).collect(),
                    )
                })
                .collect();
            assert_eq!(
                got.len(),
                test.want.len(),
                "{}, len of got:{}, want:{}",
                test.name,
                got.len(),
                test.want.len(),
            );

            for (i, want) in test.want.iter().enumerate().take(test.want.len()) {
                // because CapSet has no Eq, PartialEq attributes,
                // so using String to do the comparison.
                let want_cap_set = format!("{:?}", want.0);
                let got_cap_set = format!("{:?}", got[i].0);
                let want_caps = &want.1;
                let got_caps = &got[i].1;

                assert_eq!(
                    got_cap_set, want_cap_set,
                    "{}, capset of got:{}, want:{}",
                    test.name, got_cap_set, want_cap_set,
                );
                // because get_set_capability_args returns a HasSet of capabilities,
                // so the ordering is randomized.
                assert!(
                    got_caps.iter().all(|cap| want_caps.contains(cap)),
                    "{}, caps of got:{:?}, want:{:?}",
                    test.name,
                    got_caps,
                    want_caps
                );
            }
        }
    }
}
