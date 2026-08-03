use std::collections::HashSet;
use std::path::Path;

use libc::IFNAMSIZ;
use nix::sys::stat::stat;
use oci_spec::runtime::{LinuxNamespaceType, LinuxSchedulerPolicy, Spec};

use crate::error::ErrInvalidSpec;
use crate::utils::is_in_new_userns;

pub struct Validator;

impl Validator {
    pub fn validate_spec(spec: &Spec, is_rootless: bool) -> Result<(), ErrInvalidSpec> {
        Self::validate_spec_for_uts_namespace(spec)?;
        Self::validate_spec_for_mnt_namespace(spec)?;
        Self::validate_spec_for_sysctl(spec)?;
        Self::validate_spec_for_scheduler(spec)?;
        Self::validate_spec_for_io_priority(spec)?;
        Self::validate_spec_for_intel_rdt(spec)?;
        Self::validate_spec_for_time_namespace(spec)?;
        if let Some(mounts) = spec.mounts() {
            Self::validate_spec_for_mount_options(mounts)?;
        }
        Self::validate_spec_for_net_devices(spec, is_rootless)?;
        Self::validate_spec_for_new_user_ns(spec, is_rootless)?;

        Ok(())
    }

    // https://elixir.bootlin.com/linux/v6.12/source/net/core/dev.c#L1066
    fn dev_valid_name(name: &str) -> bool {
        if name.is_empty() || name.len() >= IFNAMSIZ {
            return false;
        }
        if name.eq(".") || name.eq("..") {
            return false;
        }

        for c in name.chars() {
            if c == '/' || c == ':' || c.is_whitespace() {
                return false;
            }
        }

        true
    }

    // check if given spec is valid for netDevices
    fn validate_spec_for_net_devices(spec: &Spec, is_rootless: bool) -> Result<(), ErrInvalidSpec> {
        let Some(devices) = spec.linux().as_ref().and_then(|l| l.net_devices().as_ref()) else {
            return Ok(());
        };

        if devices.is_empty() {
            return Ok(());
        }

        let has_net_namespace = spec
            .linux()
            .as_ref()
            .and_then(|l| l.namespaces().as_ref())
            .is_some_and(|namespaces| {
                namespaces
                    .iter()
                    .any(|ns| ns.typ() == LinuxNamespaceType::Network)
            });

        if !has_net_namespace {
            return Err(ErrInvalidSpec::NetDevicesNoNetNamespace);
        }

        if is_rootless {
            return Err(ErrInvalidSpec::NetDevicesRootlessNotSupported);
        }

        for (name, net_dev) in devices {
            if !Validator::dev_valid_name(name) {
                return Err(ErrInvalidSpec::NetDevicesInvalidDeviceName(
                    name.to_string(),
                ));
            }
            if let Some(dev_name) = net_dev.name() {
                if !Validator::dev_valid_name(dev_name) {
                    return Err(ErrInvalidSpec::NetDevicesInvalidDeviceName(
                        dev_name.to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    // Validates mount destinations and warns about deprecated relative paths.
    // Follows the OCI Runtime Spec requirement that mount destinations SHOULD be absolute.
    // Relative paths are deprecated but still accepted for backward compatibility.
    fn validate_spec_for_mount_options(
        mounts: &[oci_spec::runtime::Mount],
    ) -> Result<(), ErrInvalidSpec> {
        mounts
        .iter()
        .filter(|mount| !mount.destination().is_absolute())
        .for_each(|mount| {
            tracing::warn!(
                "mount destination {:?} is not absolute. \
                Relative paths are deprecated in OCI Runtime Spec and may not be supported in future versions. \
                The path will be interpreted as relative to '/'.",
                mount.destination()
            );
        });
        Ok(())
    }

    fn validate_spec_for_uts_namespace(spec: &Spec) -> Result<(), ErrInvalidSpec> {
        let has_uts_namespace = spec
            .linux()
            .as_ref()
            .and_then(|l| l.namespaces().as_ref())
            .is_some_and(|namespaces| {
                namespaces
                    .iter()
                    .any(|ns| ns.typ() == LinuxNamespaceType::Uts)
            });

        if !has_uts_namespace {
            if spec.hostname().is_some() {
                return Err(ErrInvalidSpec::HostnameWithoutUTS);
            }

            if spec.domainname().is_some() {
                return Err(ErrInvalidSpec::DomainnameWithoutUTS);
            }
        }

        Ok(())
    }

    // checks if given spec is valid for current user namespace setup
    fn validate_spec_for_new_user_ns(spec: &Spec, is_rootless: bool) -> Result<(), ErrInvalidSpec> {
        let has_user_namespace = spec
            .linux()
            .as_ref()
            .and_then(|l| l.namespaces().as_ref())
            .is_some_and(|namespaces| {
                namespaces
                    .iter()
                    .any(|ns| ns.typ() == LinuxNamespaceType::User)
            });

        if !has_user_namespace {
            let has_uid_mappings = spec
                .linux()
                .as_ref()
                .is_some_and(|l| l.uid_mappings().as_ref().is_some_and(|m| !m.is_empty()));
            let has_gid_mappings = spec
                .linux()
                .as_ref()
                .is_some_and(|l| l.gid_mappings().as_ref().is_some_and(|m| !m.is_empty()));

            if has_uid_mappings || has_gid_mappings {
                return Err(ErrInvalidSpec::UserMappingsWithoutNamespace);
            }
        }

        let in_user_ns = is_in_new_userns().map_err(ErrInvalidSpec::IO)?;
        // In case of rootless, there are 2 possible cases :
        // we have a new user ns specified in the spec
        // or the youki is launched in a new user ns (this is how podman does it)
        // So here, we check if rootless is required,
        // but we are neither in a new user ns nor a new user ns is specified in spec
        // then it is an error
        if is_rootless && !in_user_ns && !has_user_namespace {
            return Err(ErrInvalidSpec::NoUserNamespace);
        }

        Ok(())
    }

    fn validate_spec_for_mnt_namespace(spec: &Spec) -> Result<(), ErrInvalidSpec> {
        let has_mnt_namespace = spec
            .linux()
            .as_ref()
            .and_then(|l| l.namespaces().as_ref())
            .is_some_and(|namespaces| {
                namespaces
                    .iter()
                    .any(|ns| ns.typ() == LinuxNamespaceType::Mount)
            });

        if !has_mnt_namespace {
            let has_masked_paths = spec
                .linux()
                .as_ref()
                .is_some_and(|l| l.masked_paths().as_ref().is_some_and(|m| !m.is_empty()));
            let has_readonly_paths = spec
                .linux()
                .as_ref()
                .is_some_and(|l| l.readonly_paths().as_ref().is_some_and(|m| !m.is_empty()));

            if has_masked_paths || has_readonly_paths {
                return Err(ErrInvalidSpec::SysEntriesWithoutMntNamespace);
            }
        }

        Ok(())
    }

    fn validate_spec_for_sysctl(spec: &Spec) -> Result<(), ErrInvalidSpec> {
        fn is_host_net_ns(path: &Path) -> Result<bool, nix::Error> {
            let current_netns = "/proc/self/ns/net";

            let host_stat = stat(current_netns)?;
            let target_stat = stat(path)?;

            Ok(host_stat.st_dev == target_stat.st_dev && host_stat.st_ino == target_stat.st_ino)
        }

        if let Some(linux) = spec.linux() {
            if let Some(sysctls) = linux.sysctl() {
                let has_ipc = linux
                    .namespaces()
                    .as_ref()
                    .is_some_and(|ns| ns.iter().any(|n| n.typ() == LinuxNamespaceType::Ipc));
                let has_uts = linux
                    .namespaces()
                    .as_ref()
                    .is_some_and(|ns| ns.iter().any(|n| n.typ() == LinuxNamespaceType::Uts));
                let has_user = linux
                    .namespaces()
                    .as_ref()
                    .is_some_and(|ns| ns.iter().any(|n| n.typ() == LinuxNamespaceType::User));

                let mut valid_ipc_sysctls = HashSet::with_capacity(8);
                valid_ipc_sysctls.insert("kernel.msgmax");
                valid_ipc_sysctls.insert("kernel.msgmnb");
                valid_ipc_sysctls.insert("kernel.msgmni");
                valid_ipc_sysctls.insert("kernel.sem");
                valid_ipc_sysctls.insert("kernel.shmall");
                valid_ipc_sysctls.insert("kernel.shmmax");
                valid_ipc_sysctls.insert("kernel.shmmni");
                valid_ipc_sysctls.insert("kernel.shm_rmid_forced");

                let mut is_host_net_cache: Option<bool> = None;
                let namespaces = linux.namespaces().as_ref();

                for key in sysctls.keys() {
                    let s = key.replace('/', ".");
                    if valid_ipc_sysctls.contains(&s.as_str()) || s.starts_with("fs.mqueue.") {
                        if !has_ipc {
                            return Err(ErrInvalidSpec::SysctlNotAllowedInHostIpc(s));
                        }
                        continue;
                    }

                    if s.starts_with("net.") {
                        let is_host_net = if let Some(cached_result) = is_host_net_cache {
                            cached_result
                        } else {
                            let computed_result = match namespaces.and_then(|ns| {
                                ns.iter().find(|n| n.typ() == LinuxNamespaceType::Network)
                            }) {
                                // No NEWNET namespace means it uses the host's
                                None => true,
                                Some(ns) => match ns.path() {
                                    // No path means a completely fresh, isolated namespace is being created
                                    None => false,
                                    // Empty string is effectively the same as None
                                    Some(path) if path.as_os_str().is_empty() => false,
                                    // A path is provided; we must verify it isn't the host's network namespace
                                    Some(path) => is_host_net_ns(path).map_err(|e| {
                                        ErrInvalidSpec::InvalidNetNsPath(e.to_string())
                                    })?,
                                },
                            };
                            is_host_net_cache = Some(computed_result);
                            computed_result
                        };

                        if is_host_net {
                            return Err(ErrInvalidSpec::SysctlNotAllowedInHostNet(s));
                        }
                        continue;
                    }

                    if has_uts {
                        match s.as_str() {
                            "kernel.domainname" => continue,
                            "kernel.hostname" => {
                                // hostname is supported via an explicit OCI field, so it is denied here
                                return Err(ErrInvalidSpec::SysctlConflictsWithOci(
                                    s,
                                    "hostname".to_string(),
                                ));
                            }
                            _ => {}
                        }
                    }

                    if s.starts_with("user.") {
                        if !has_user {
                            return Err(ErrInvalidSpec::SysctlNotAllowedInHostUser(s));
                        }
                        continue;
                    }

                    return Err(ErrInvalidSpec::SysctlNotInSeparateNamespace(s));
                }
            }
        }

        Ok(())
    }

    fn validate_spec_for_scheduler(spec: &Spec) -> Result<(), ErrInvalidSpec> {
        // https://man7.org/linux/man-pages/man2/sched_setattr.2.html#top_of_page
        if let Some(process) = spec.process() {
            if let Some(scheduler) = process.scheduler() {
                let policy = scheduler.policy();

                if *policy == LinuxSchedulerPolicy::SchedOther
                    || *policy == LinuxSchedulerPolicy::SchedBatch
                {
                    if let Some(nice) = scheduler.nice() {
                        if !(-20..=19).contains(nice) {
                            return Err(ErrInvalidSpec::Scheduler(format!(
                                "invalid scheduler.nice: '{}', must be within -20 to 19",
                                nice
                            )));
                        }
                    }
                }

                if let Some(priority) = scheduler.priority() {
                    if *priority != 0
                        && *policy != LinuxSchedulerPolicy::SchedFifo
                        && *policy != LinuxSchedulerPolicy::SchedRr
                    {
                        return Err(ErrInvalidSpec::Scheduler(
                                "scheduler.priority can only be specified for SchedFIFO or SchedRR policy".to_string(),
                            ));
                    }
                }

                if *policy != LinuxSchedulerPolicy::SchedDeadline
                    && (scheduler.runtime().is_some_and(|r| r != 0)
                        || scheduler.deadline().is_some_and(|d| d != 0)
                        || scheduler.period().is_some_and(|p| p != 0))
                {
                    {
                        return Err(ErrInvalidSpec::Scheduler(
                            "scheduler runtime/deadline/period can only be specified for SchedDeadline policy"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_spec_for_io_priority(spec: &Spec) -> Result<(), ErrInvalidSpec> {
        if let Some(process) = spec.process() {
            if let Some(io_priority) = process.io_priority() {
                let priority = io_priority.priority();

                if !(0..=7).contains(&priority) {
                    return Err(ErrInvalidSpec::IoPriority);
                }
            }
        }

        Ok(())
    }

    fn validate_spec_for_intel_rdt(spec: &Spec) -> Result<(), ErrInvalidSpec> {
        if let Some(linux) = spec.linux() {
            if let Some(intel_rdt) = linux.intel_rdt() {
                if let Some(clos_id) = intel_rdt.clos_id() {
                    if clos_id == "."
                        || clos_id == ".."
                        || (clos_id.len() > 1 && clos_id.contains('/'))
                    {
                        return Err(ErrInvalidSpec::InvalidIntelRdtClosId);
                    }
                }
            }
        }

        Ok(())
    }

    // Validates time namespace configuration. Rejects two invalid combinations
    // when time_offsets is set:
    //   (1) no time namespace in the spec -- nothing for the offsets to apply to
    //   (2) time namespace has a path -- joining an existing NS, whose offsets are
    //       already fixed and cannot be rewritten
    fn validate_spec_for_time_namespace(spec: &Spec) -> Result<(), ErrInvalidSpec> {
        if let Some(linux) = spec.linux()
            && linux.time_offsets().is_some()
        {
            let time_ns = linux
                .namespaces()
                .as_ref()
                .and_then(|nss| nss.iter().find(|ns| ns.typ() == LinuxNamespaceType::Time))
                .ok_or(ErrInvalidSpec::TimeNamespace)?;
            if time_ns.path().is_some() {
                return Err(ErrInvalidSpec::TimeOffsetsWithPath);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use nix::unistd::{Gid, Uid};
    use oci_spec::runtime::{
        IOPriorityClass, LinuxBuilder, LinuxIOPriorityBuilder, LinuxIdMappingBuilder,
        LinuxIntelRdtBuilder, LinuxNamespaceBuilder, LinuxNetDevice, ProcessBuilder,
        SchedulerBuilder, SpecBuilder,
    };
    use serial_test::serial;

    use super::*;
    use crate::syscall::syscall::create_syscall;
    use crate::test_utils;
    use crate::utils::rootless_required;

    #[test]
    fn test_validate_spec_for_uts_namespace() {
        let spec_no_uts_with_hostname = SpecBuilder::default()
            .hostname("some-host")
            .linux(LinuxBuilder::default().namespaces(vec![]).build().unwrap())
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_uts_namespace(&spec_no_uts_with_hostname).unwrap_err(),
            ErrInvalidSpec::HostnameWithoutUTS
        ));

        let mut spec_no_uts_with_domainname = SpecBuilder::default()
            .domainname("some-domain")
            .linux(LinuxBuilder::default().namespaces(vec![]).build().unwrap())
            .build()
            .unwrap();
        spec_no_uts_with_domainname.set_hostname(None);
        assert!(matches!(
            Validator::validate_spec_for_uts_namespace(&spec_no_uts_with_domainname).unwrap_err(),
            ErrInvalidSpec::DomainnameWithoutUTS
        ));

        let spec_with_uts_and_host_domain_names = SpecBuilder::default()
            .hostname("my-host")
            .domainname("my-domain")
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Uts)
                            .build()
                            .unwrap(),
                    ])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(
            Validator::validate_spec_for_uts_namespace(&spec_with_uts_and_host_domain_names)
                .is_ok()
        );

        let spec_no_uts_no_host_domain_names = SpecBuilder::default()
            .linux(LinuxBuilder::default().build().unwrap())
            .build()
            .unwrap();
        assert!(
            Validator::validate_spec_for_uts_namespace(&spec_no_uts_no_host_domain_names).is_ok()
        );
    }

    #[test]
    fn test_validate_user_ns_mappings() {
        let spec_with_mappings_no_ns = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![])
                    .uid_mappings(vec![
                        LinuxIdMappingBuilder::default()
                            .container_id(0_u32)
                            .host_id(1000_u32)
                            .size(1_u32)
                            .build()
                            .unwrap(),
                    ])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let syscall = create_syscall();
        assert!(matches!(
            Validator::validate_spec_for_new_user_ns(
                &spec_with_mappings_no_ns,
                rootless_required(&*syscall).unwrap(),
            )
            .unwrap_err(),
            ErrInvalidSpec::UserMappingsWithoutNamespace
        ));
    }

    // the following test is marked as serial because
    // we are doing unshare of user ns and fork, so better to run in serial,
    #[test]
    #[serial]
    fn test_userns_spec_validation() -> Result<(), test_utils::TestError> {
        use nix::sched::{CloneFlags, unshare};
        let syscall = create_syscall();
        // default rootful spec
        let rootful_spec = Spec::default();
        // as we are not in a user ns, and spec does not have user ns
        // we should get error here
        assert!(
            Validator::validate_spec_for_new_user_ns(
                &rootful_spec,
                rootless_required(&*syscall).unwrap(),
            )
            .is_err()
        );

        let rootless_spec = Spec::rootless(1000, 1000);
        // because the spec contains user ns info, we should not get error
        assert!(
            Validator::validate_spec_for_new_user_ns(
                &rootless_spec,
                rootless_required(&*syscall).unwrap(),
            )
            .is_ok()
        );

        test_utils::test_in_child_process(|| {
            unshare(CloneFlags::CLONE_NEWUSER).unwrap();
            // here we are in a new user namespace
            let rootful_spec = Spec::default();
            let syscall = create_syscall();
            // because we are already in a new user ns, it is fine if spec
            // does not have user ns, and because the test is running as
            // non root
            assert!(
                Validator::validate_spec_for_new_user_ns(
                    &rootful_spec,
                    rootless_required(&*syscall).unwrap(),
                )
                .is_ok()
            );

            let rootless_spec = Spec::rootless(1000, 1000);
            // following should succeed irrespective if we're in user ns or not
            assert!(
                Validator::validate_spec_for_new_user_ns(
                    &rootless_spec,
                    rootless_required(&*syscall).unwrap(),
                )
                .is_ok()
            );
            Ok(())
        })
    }

    #[test]
    fn test_validate_spec_for_mnt_namespace() {
        let spec_no_mnt_with_masked = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![])
                    .masked_paths(vec!["/proc/keys".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_mnt_namespace(&spec_no_mnt_with_masked).unwrap_err(),
            ErrInvalidSpec::SysEntriesWithoutMntNamespace
        ));

        let spec_no_mnt_with_readonly = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![])
                    .readonly_paths(vec!["/proc/sys".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_mnt_namespace(&spec_no_mnt_with_readonly).unwrap_err(),
            ErrInvalidSpec::SysEntriesWithoutMntNamespace
        ));

        let spec_with_mnt_and_masked = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Mount)
                            .build()
                            .unwrap(),
                    ])
                    .masked_paths(vec!["/proc/keys".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(Validator::validate_spec_for_mnt_namespace(&spec_with_mnt_and_masked).is_ok());

        let spec_with_mnt_and_readonly = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Mount)
                            .build()
                            .unwrap(),
                    ])
                    .readonly_paths(vec!["/proc/sys".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(Validator::validate_spec_for_mnt_namespace(&spec_with_mnt_and_readonly).is_ok());
    }

    #[test]
    fn test_validate_spec_for_sysctl() {
        use std::collections::HashMap;

        let mut sysctl_ipc = HashMap::new();
        sysctl_ipc.insert("fs.mqueue.msg_max".to_string(), "10".to_string());

        let spec_no_ipc = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![])
                    .sysctl(sysctl_ipc)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        assert!(matches!(
            Validator::validate_spec_for_sysctl(&spec_no_ipc).unwrap_err(),
            ErrInvalidSpec::SysctlNotAllowedInHostIpc(_)
        ));

        let mut sysctl_net = HashMap::new();
        sysctl_net.insert("net.ipv4.ip_forward".to_string(), "1".to_string());

        let spec_no_net = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![])
                    .sysctl(sysctl_net)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        assert!(matches!(
            Validator::validate_spec_for_sysctl(&spec_no_net).unwrap_err(),
            ErrInvalidSpec::SysctlNotAllowedInHostNet(_)
        ));

        let mut sysctl_uts_conflict = HashMap::new();
        sysctl_uts_conflict.insert("kernel.hostname".to_string(), "bad-host".to_string());

        let spec_uts_conflict = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Uts)
                            .build()
                            .unwrap(),
                    ])
                    .sysctl(sysctl_uts_conflict)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        assert!(matches!(
            Validator::validate_spec_for_sysctl(&spec_uts_conflict).unwrap_err(),
            ErrInvalidSpec::SysctlConflictsWithOci(_, _)
        ));
    }

    #[test]
    fn test_validate_spec_for_scheduler() {
        let build_spec = |scheduler| {
            SpecBuilder::default()
                .process(
                    ProcessBuilder::default()
                        .scheduler(scheduler)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap()
        };

        // Valid: SchedOther with Nice 0
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedOther)
                .nice(0)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_ok());

        // Valid: SchedBatch with Nice 19
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedBatch)
                .nice(19)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_ok());

        // Invalid: SchedOther with Nice 20 (out of bounds)
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedOther)
                .nice(20)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_err());

        // Invalid: SchedBatch with Nice -21 (out of bounds)
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedBatch)
                .nice(-21)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_err());

        // Valid: SchedFifo with Priority 99
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedFifo)
                .priority(99)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_ok());

        // Valid: SchedRr with Priority 1
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedRr)
                .priority(1)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_ok());

        // Valid: SchedOther with Priority 0 (0 is allowed for anything)
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedOther)
                .priority(0)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_ok());

        // Invalid: SchedOther with Priority 1
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedOther)
                .priority(1)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_err());

        // Invalid: SchedIso with Priority 10
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedIso)
                .priority(10)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_err());

        // Valid: SchedDeadline with runtime/deadline/period
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedDeadline)
                .runtime(100_u64)
                .deadline(200_u64)
                .period(300_u64)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_ok());

        // Valid: SchedOther with runtime 0 (0 is allowed for anything)
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedOther)
                .runtime(0_u64)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_ok());

        // Invalid: SchedFifo with runtime 100
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedFifo)
                .runtime(100_u64)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_err());

        // Invalid: SchedOther with deadline 200
        let spec = build_spec(
            SchedulerBuilder::default()
                .policy(LinuxSchedulerPolicy::SchedOther)
                .deadline(200_u64)
                .build()
                .unwrap(),
        );
        assert!(Validator::validate_spec_for_scheduler(&spec).is_err());
    }

    #[test]
    fn test_validate_spec_for_io_priority() {
        let valid_io = LinuxIOPriorityBuilder::default()
            .class(IOPriorityClass::IoprioClassBe)
            .priority(4)
            .build()
            .unwrap();
        let valid_spec = SpecBuilder::default()
            .process(
                ProcessBuilder::default()
                    .io_priority(valid_io)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(Validator::validate_spec_for_io_priority(&valid_spec).is_ok());

        let invalid_io_high = LinuxIOPriorityBuilder::default()
            .class(IOPriorityClass::IoprioClassRt)
            .priority(8)
            .build()
            .unwrap();
        let invalid_spec_high = SpecBuilder::default()
            .process(
                ProcessBuilder::default()
                    .io_priority(invalid_io_high)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_io_priority(&invalid_spec_high).unwrap_err(),
            ErrInvalidSpec::IoPriority
        ));

        let valid_io_low = LinuxIOPriorityBuilder::default()
            .class(IOPriorityClass::IoprioClassIdle)
            .priority(0)
            .build()
            .unwrap();
        let valid_spec_low = SpecBuilder::default()
            .process(
                ProcessBuilder::default()
                    .io_priority(valid_io_low)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(Validator::validate_spec_for_io_priority(&valid_spec_low).is_ok());

        let valid_io_edge = LinuxIOPriorityBuilder::default()
            .class(IOPriorityClass::IoprioClassRt)
            .priority(7)
            .build()
            .unwrap();
        let valid_spec_edge = SpecBuilder::default()
            .process(
                ProcessBuilder::default()
                    .io_priority(valid_io_edge)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(Validator::validate_spec_for_io_priority(&valid_spec_edge).is_ok());
    }

    #[test]
    fn test_validate_spec_for_intel_rdt() {
        let intel_rdt_traversal_dotdot = LinuxIntelRdtBuilder::default()
            .clos_id("../escape")
            .build()
            .unwrap();
        let spec_traversal_dotdot = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .intel_rdt(intel_rdt_traversal_dotdot)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_intel_rdt(&spec_traversal_dotdot).unwrap_err(),
            ErrInvalidSpec::InvalidIntelRdtClosId
        ));

        let intel_rdt_traversal_slash = LinuxIntelRdtBuilder::default()
            .clos_id("/absolute/path")
            .build()
            .unwrap();
        let spec_traversal_slash = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .intel_rdt(intel_rdt_traversal_slash)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_intel_rdt(&spec_traversal_slash).unwrap_err(),
            ErrInvalidSpec::InvalidIntelRdtClosId
        ));

        let intel_rdt_valid_id = LinuxIntelRdtBuilder::default()
            .clos_id("valid-clos-id-123")
            .build()
            .unwrap();
        let spec_valid_id = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .intel_rdt(intel_rdt_valid_id)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(Validator::validate_spec_for_intel_rdt(&spec_valid_id).is_ok());

        let intel_rdt_traversal_dot = LinuxIntelRdtBuilder::default()
            .clos_id(".")
            .build()
            .unwrap();
        let spec_traversal_dot = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .intel_rdt(intel_rdt_traversal_dot)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_intel_rdt(&spec_traversal_dot).unwrap_err(),
            ErrInvalidSpec::InvalidIntelRdtClosId
        ));

        let intel_rdt_traversal_nested = LinuxIntelRdtBuilder::default()
            .clos_id("some/path")
            .build()
            .unwrap();
        let spec_traversal_nested = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .intel_rdt(intel_rdt_traversal_nested)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_intel_rdt(&spec_traversal_nested).unwrap_err(),
            ErrInvalidSpec::InvalidIntelRdtClosId
        ));

        let intel_rdt_traversal_trailing = LinuxIntelRdtBuilder::default()
            .clos_id("clos_id/")
            .build()
            .unwrap();
        let spec_traversal_trailing = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .intel_rdt(intel_rdt_traversal_trailing)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_intel_rdt(&spec_traversal_trailing).unwrap_err(),
            ErrInvalidSpec::InvalidIntelRdtClosId
        ));
    }

    fn timens_offsets() -> std::collections::HashMap<String, oci_spec::runtime::LinuxTimeOffset> {
        [(
            "monotonic".to_string(),
            oci_spec::runtime::LinuxTimeOffset::default(),
        )]
        .into_iter()
        .collect()
    }

    #[test]
    fn test_validate_spec_for_time_namespace_error() {
        let offsets = timens_offsets();

        // offsets set but no time namespace -> TimeNamespace
        let spec_offsets_without_ns = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![])
                    .time_offsets(offsets.clone())
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_time_namespace(&spec_offsets_without_ns).unwrap_err(),
            ErrInvalidSpec::TimeNamespace
        ));

        // offsets set and the time namespace joins an existing one (has a path) -> TimeOffsetsWithPath
        let spec_offsets_with_path = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Time)
                            .path("/proc/1/ns/time")
                            .build()
                            .unwrap(),
                    ])
                    .time_offsets(offsets)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_time_namespace(&spec_offsets_with_path).unwrap_err(),
            ErrInvalidSpec::TimeOffsetsWithPath
        ));
    }

    #[test]
    fn test_validate_spec_for_time_namespace_success() {
        let offsets = timens_offsets();

        // offsets set with a new time namespace (no path) -> Ok
        let spec_valid = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Time)
                            .build()
                            .unwrap(),
                    ])
                    .time_offsets(offsets)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(Validator::validate_spec_for_time_namespace(&spec_valid).is_ok());

        // no offsets at all -> Ok (nothing to validate)
        let spec_no_offsets = SpecBuilder::default()
            .linux(LinuxBuilder::default().namespaces(vec![]).build().unwrap())
            .build()
            .unwrap();
        assert!(Validator::validate_spec_for_time_namespace(&spec_no_offsets).is_ok());
    }

    #[test]
    fn test_dev_valid_name() {
        assert!(!Validator::dev_valid_name(""));

        let long_name = "a".repeat(IFNAMSIZ + 1);
        assert!(!Validator::dev_valid_name(&long_name));

        // The kernel rejects interface names whose length is >= IFNAMSIZ (16 bytes),
        // therefore valid names must be at most IFNAMSIZ - 1 (15 bytes).
        // https://elixir.bootlin.com/linux/v6.12/source/net/core/dev.c#L1066
        let over_length_name = "a".repeat(IFNAMSIZ);
        assert!(!Validator::dev_valid_name(&over_length_name));

        let valid_name = "a".repeat(IFNAMSIZ - 1);
        assert!(Validator::dev_valid_name(&valid_name));

        assert!(!Validator::dev_valid_name("."));
        assert!(!Validator::dev_valid_name(".."));

        assert!(!Validator::dev_valid_name("/: "));
        assert!(!Validator::dev_valid_name("eth0/: "));

        assert!(Validator::dev_valid_name("eth0"));
        assert!(Validator::dev_valid_name("veth123"));
        assert!(Validator::dev_valid_name("abc.def"));
    }

    #[test]
    fn test_net_devices_none() {
        let spec = Spec::default();
        let syscall = create_syscall();
        syscall.set_id(Uid::from_raw(0), Gid::from_raw(0)).unwrap();
        let result =
            Validator::validate_spec_for_net_devices(&spec, rootless_required(&*syscall).unwrap());
        assert!(result.is_ok());
    }

    fn build_spec_with_ns_and_devices(include_net_ns: bool, devices: Vec<(&str, &str)>) -> Spec {
        let mut namespaces = vec![];
        if include_net_ns {
            namespaces.push(
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Network)
                    .path(PathBuf::from("/dev/net"))
                    .build()
                    .unwrap(),
            );
        }

        let net_devices: HashMap<String, LinuxNetDevice> = devices
            .into_iter()
            .map(|(key, val)| {
                (
                    key.into(),
                    LinuxNetDevice::default().set_name(Some(val.into())).clone(),
                )
            })
            .collect();
        let linux = LinuxBuilder::default()
            .namespaces(namespaces)
            .net_devices(net_devices)
            .build()
            .unwrap();

        SpecBuilder::default().linux(linux).build().unwrap()
    }

    #[test]
    fn test_missing_net_namespace() {
        let spec = build_spec_with_ns_and_devices(false, vec![("eth0", "eth0_container")]);
        let syscall = create_syscall();
        let err =
            Validator::validate_spec_for_net_devices(&spec, rootless_required(&*syscall).unwrap())
                .unwrap_err();
        assert!(matches!(err, ErrInvalidSpec::NetDevicesNoNetNamespace));
    }

    #[test]
    fn test_invalid_device_name() {
        let spec = build_spec_with_ns_and_devices(true, vec![("eth0", "/:invalid")]);
        let syscall = create_syscall();
        syscall.set_id(Uid::from_raw(0), Gid::from_raw(0)).unwrap();
        let err =
            Validator::validate_spec_for_net_devices(&spec, rootless_required(&*syscall).unwrap())
                .unwrap_err();
        if let ErrInvalidSpec::NetDevicesInvalidDeviceName(name) = err {
            assert_eq!(name, "/:invalid");
        } else {
            panic!("Expected InvalidDeviceName error");
        }
    }

    #[test]
    fn test_valid_config() {
        let spec = build_spec_with_ns_and_devices(true, vec![("eth0", "eth0_container")]);
        let syscall = create_syscall();
        syscall.set_id(Uid::from_raw(0), Gid::from_raw(0)).unwrap();
        let result =
            Validator::validate_spec_for_net_devices(&spec, rootless_required(&*syscall).unwrap());
        assert!(result.is_ok());
    }
}
