use std::collections::HashSet;
use std::num::TryFromIntError;
use std::os::unix::io;

use libseccomp::{
    ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall,
};
use oci_spec::runtime::{
    Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompFilterFlag, LinuxSeccompOperator,
};

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("failed to translate trace action due to failed to convert errno {errno} into i16")]
    TraceAction { source: TryFromIntError, errno: i32 },
    #[error("SCMP_ACT_NOTIFY cannot be used as default action")]
    NotifyAsDefaultAction,
    #[error("SCMP_ACT_NOTIFY cannot be used for the write syscall")]
    NotifyWriteSyscall,
    #[error("failed to add arch to seccomp")]
    AddArch {
        source: libseccomp::error::SeccompError,
        arch: Arch,
    },
    #[error("failed to load seccomp context")]
    LoadContext {
        source: libseccomp::error::SeccompError,
    },
    #[error("failed to get seccomp notify id")]
    GetNotifyId {
        source: libseccomp::error::SeccompError,
    },
    #[error("failed to add rule to seccomp")]
    AddRule {
        source: libseccomp::error::SeccompError,
    },
    #[error("failed to create new seccomp filter")]
    NewFilter {
        source: libseccomp::error::SeccompError,
        default: LinuxSeccompAction,
    },
    #[error("failed to set filter flag")]
    SetFilterFlag {
        source: libseccomp::error::SeccompError,
        flag: LinuxSeccompFilterFlag,
    },
    #[error("failed to set SCMP_FLTATR_CTL_NNP")]
    SetCtlNnp {
        source: libseccomp::error::SeccompError,
    },
    #[error("seccomp program is too long: {len} instructions")]
    ProgramTooLong { len: usize },
    #[error("failed to load seccomp program")]
    LoadProgram { source: std::io::Error },
}

type Result<T> = std::result::Result<T, SeccompError>;

fn translate_arch(arch: Arch) -> ScmpArch {
    match arch {
        Arch::ScmpArchNative => ScmpArch::Native,
        Arch::ScmpArchX86 => ScmpArch::X86,
        Arch::ScmpArchX86_64 => ScmpArch::X8664,
        Arch::ScmpArchX32 => ScmpArch::X32,
        Arch::ScmpArchArm => ScmpArch::Arm,
        Arch::ScmpArchAarch64 => ScmpArch::Aarch64,
        Arch::ScmpArchMips => ScmpArch::Mips,
        Arch::ScmpArchMips64 => ScmpArch::Mips64,
        Arch::ScmpArchMips64n32 => ScmpArch::Mips64N32,
        Arch::ScmpArchMipsel => ScmpArch::Mipsel,
        Arch::ScmpArchMipsel64 => ScmpArch::Mipsel64,
        Arch::ScmpArchMipsel64n32 => ScmpArch::Mipsel64N32,
        Arch::ScmpArchPpc => ScmpArch::Ppc,
        Arch::ScmpArchPpc64 => ScmpArch::Ppc64,
        Arch::ScmpArchPpc64le => ScmpArch::Ppc64Le,
        Arch::ScmpArchS390 => ScmpArch::S390,
        Arch::ScmpArchS390x => ScmpArch::S390X,
        Arch::ScmpArchRiscv64 => ScmpArch::Riscv64,
        Arch::ScmpArchParisc => ScmpArch::Parisc,
        Arch::ScmpArchParisc64 => ScmpArch::Parisc64,
        Arch::ScmpArchLoongarch64 => ScmpArch::Loongarch64,
        Arch::ScmpArchM68k => ScmpArch::M68k,
        Arch::ScmpArchSh => ScmpArch::Sh,
        Arch::ScmpArchSheb => ScmpArch::Sheb,
    }
}

fn translate_action(action: LinuxSeccompAction, errno: Option<u32>) -> Result<ScmpAction> {
    tracing::trace!(?action, ?errno, "translating action");
    let errno = errno.map(|e| e as i32).unwrap_or(libc::EPERM);
    let action = match action {
        LinuxSeccompAction::ScmpActKill => ScmpAction::KillThread,
        LinuxSeccompAction::ScmpActTrap => ScmpAction::Trap,
        LinuxSeccompAction::ScmpActErrno => ScmpAction::Errno(errno),
        LinuxSeccompAction::ScmpActTrace => ScmpAction::Trace(
            errno
                .try_into()
                .map_err(|err| SeccompError::TraceAction { source: err, errno })?,
        ),
        LinuxSeccompAction::ScmpActAllow => ScmpAction::Allow,
        LinuxSeccompAction::ScmpActKillProcess => ScmpAction::KillProcess,
        LinuxSeccompAction::ScmpActNotify => ScmpAction::Notify,
        LinuxSeccompAction::ScmpActLog => ScmpAction::Log,
        LinuxSeccompAction::ScmpActKillThread => ScmpAction::KillThread,
    };

    tracing::trace!(?action, "translated action");
    Ok(action)
}

fn translate_op(op: LinuxSeccompOperator, datum_b: Option<u64>) -> ScmpCompareOp {
    match op {
        LinuxSeccompOperator::ScmpCmpNe => ScmpCompareOp::NotEqual,
        LinuxSeccompOperator::ScmpCmpLt => ScmpCompareOp::Less,
        LinuxSeccompOperator::ScmpCmpLe => ScmpCompareOp::LessOrEqual,
        LinuxSeccompOperator::ScmpCmpEq => ScmpCompareOp::Equal,
        LinuxSeccompOperator::ScmpCmpGe => ScmpCompareOp::GreaterEqual,
        LinuxSeccompOperator::ScmpCmpGt => ScmpCompareOp::Greater,
        LinuxSeccompOperator::ScmpCmpMaskedEq => ScmpCompareOp::MaskedEqual(datum_b.unwrap_or(0)),
    }
}

fn translate_flags(seccomp: &LinuxSeccomp) -> u32 {
    let mut flags = 0;
    for flag in seccomp.flags().iter().flatten() {
        flags |= match flag {
            LinuxSeccompFilterFlag::SeccompFilterFlagLog => libc::SECCOMP_FILTER_FLAG_LOG,
            LinuxSeccompFilterFlag::SeccompFilterFlagTsync => libc::SECCOMP_FILTER_FLAG_TSYNC,
            LinuxSeccompFilterFlag::SeccompFilterFlagSpecAllow => {
                libc::SECCOMP_FILTER_FLAG_SPEC_ALLOW
            }
            LinuxSeccompFilterFlag::SeccompFilterFlagWaitKillableRecv => {
                libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
            }
        };
    }
    flags as u32
}

fn check_seccomp(seccomp: &LinuxSeccomp) -> Result<()> {
    // We don't support notify as default action. After the seccomp filter is
    // created with notify, the container process will have to communicate the
    // returned fd to another process. Therefore, we need the write syscall or
    // otherwise, the write syscall will be block by the seccomp filter causing
    // the container process to hang. `runc` also disallow notify as default
    // action.
    // Note: read and close syscall are also used, because if we can
    // successfully write fd to another process, the other process can choose to
    // handle read/close syscall and allow read and close to proceed as
    // expected.
    if seccomp.default_action() == LinuxSeccompAction::ScmpActNotify {
        return Err(SeccompError::NotifyAsDefaultAction);
    }

    if let Some(syscalls) = seccomp.syscalls() {
        for syscall in syscalls {
            if syscall.action() == LinuxSeccompAction::ScmpActNotify {
                for name in syscall.names() {
                    if name == "write" {
                        return Err(SeccompError::NotifyWriteSyscall);
                    }
                }
            }
        }
    }

    Ok(())
}

// Same layout as the kernel's struct sock_filter.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[derive(Debug)]
enum Filter {
    Libseccomp(ScmpFilterContext),
    Program(Vec<SockFilter>),
}

#[derive(Debug)]
pub struct CompiledSeccomp {
    pub flags: u32,
    pub wants_listener: bool,
    filter: Filter,
}

impl CompiledSeccomp {
    pub fn from_program(program: Vec<SockFilter>, flags: u32, wants_listener: bool) -> Self {
        Self {
            flags,
            wants_listener,
            filter: Filter::Program(program),
        }
    }
}

pub trait SeccompBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn compile(&self, seccomp: &LinuxSeccomp) -> Result<CompiledSeccomp>;
}

pub struct LibseccompBackend;

impl SeccompBackend for LibseccompBackend {
    fn name(&self) -> &'static str {
        "libseccomp"
    }

    fn compile(&self, seccomp: &LinuxSeccomp) -> Result<CompiledSeccomp> {
        Ok(CompiledSeccomp {
            flags: translate_flags(seccomp),
            wants_listener: is_notify(seccomp),
            filter: Filter::Libseccomp(build_context(seccomp)?),
        })
    }
}

fn build_context(seccomp: &LinuxSeccomp) -> Result<ScmpFilterContext> {
    check_seccomp(seccomp)?;

    tracing::trace!(default_action = ?seccomp.default_action(), errno = ?seccomp.default_errno_ret(), "initializing seccomp");
    let default_action = translate_action(seccomp.default_action(), seccomp.default_errno_ret())?;
    let mut ctx =
        ScmpFilterContext::new(default_action).map_err(|err| SeccompError::NewFilter {
            source: err,
            default: seccomp.default_action(),
        })?;

    if let Some(flags) = seccomp.flags() {
        for flag in flags {
            match flag {
                LinuxSeccompFilterFlag::SeccompFilterFlagLog => ctx.set_ctl_log(true),
                LinuxSeccompFilterFlag::SeccompFilterFlagTsync => ctx.set_ctl_tsync(true),
                LinuxSeccompFilterFlag::SeccompFilterFlagSpecAllow => ctx.set_ctl_ssb(true),
                LinuxSeccompFilterFlag::SeccompFilterFlagWaitKillableRecv => {
                    ctx.set_ctl_waitkill(true)
                }
            }
            .map_err(|err| SeccompError::SetFilterFlag {
                source: err,
                flag: *flag,
            })?;
        }
    }

    if let Some(architectures) = seccomp.architectures() {
        for &arch in architectures {
            tracing::trace!(?arch, "adding architecture");
            ctx.add_arch(translate_arch(arch))
                .map_err(|err| SeccompError::AddArch { source: err, arch })?;
        }
    }

    // The SCMP_FLTATR_CTL_NNP controls if the seccomp load function will set
    // the new privilege bit automatically in prctl. Normally this is a good
    // thing, but for us we need better control. Based on the spec, if OCI
    // runtime spec doesn't set the no new privileges in Process, we should not
    // set it here.  If the seccomp load operation fails without enough
    // privilege, so be it. To prevent this automatic behavior, we unset the
    // value here.
    ctx.set_ctl_nnp(false)
        .map_err(|err| SeccompError::SetCtlNnp { source: err })?;

    if let Some(syscalls) = seccomp.syscalls() {
        for syscall in syscalls {
            let action = translate_action(syscall.action(), syscall.errno_ret())?;
            if action == default_action {
                // When the action is the same as the default action, the rule is redundant. We can
                // skip this here to avoid failing when we add the rules.
                tracing::warn!(
                    "detect a seccomp action that is the same as the default action: {:?}",
                    syscall
                );
                continue;
            }

            for name in syscall.names() {
                let sc = match ScmpSyscall::from_name(name) {
                    Ok(x) => x,
                    Err(_) => {
                        // If we failed to resolve the syscall by name, likely the kernel
                        // doeesn't support this syscall. So it is safe to skip...
                        tracing::warn!(
                            "failed to resolve syscall, likely kernel doesn't support this. {:?}",
                            name
                        );
                        continue;
                    }
                };
                match syscall.args() {
                    // libseccomp allows multiple argument comparisons in a single rule,
                    // but each syscall argument can only be compared once per rule.
                    // When multiple comparisons target the same argument index,
                    // we follow runc's behavior and add each condition as a separate rule.
                    // Ref: libseccomp seccomp_rule_add(3)
                    // https://github.com/seccomp/libseccomp/blob/9d7a3cd937e7841ece62ac19f0f06aafd0fdaaa9/doc/man/man3/seccomp_rule_add.3#L137
                    // Ref: runc seccomp_linux.go
                    // https://github.com/opencontainers/runc/blob/4b97e12fccdfca981a296d9ef82df5f3ae95e288/libcontainer/seccomp/seccomp_linux.go#L327
                    Some(args) => {
                        let mut comparators = Vec::<ScmpArgCompare>::with_capacity(args.len());
                        let mut seen = HashSet::new();
                        let mut has_duplicate_index = false;

                        for arg in args {
                            let index = arg.index() as u32;
                            let comparator = ScmpArgCompare::new(
                                index,
                                translate_op(arg.op(), arg.value_two()),
                                arg.value(),
                            );
                            if !seen.insert(index) {
                                has_duplicate_index = true;
                            }
                            comparators.push(comparator);
                        }

                        if has_duplicate_index {
                            for comparator in &comparators {
                                tracing::trace!(
                                    ?name,
                                    ?action,
                                    ?comparator,
                                    "add seccomp conditional rule separately"
                                );
                                ctx.add_rule_conditional(action, sc, std::slice::from_ref(comparator))
                                    .map_err(|err| {
                                        tracing::error!(
                                            "failed to add seccomp action: {:?}. Comparator: {:?} Syscall: {name}",
                                            &action,
                                            comparator,
                                        );
                                        SeccompError::AddRule { source: err }
                                    })?;
                            }
                        } else {
                            tracing::trace!(
                                ?name,
                                ?action,
                                ?comparators,
                                "add seccomp conditional rule"
                            );
                            ctx.add_rule_conditional(action, sc, &comparators)
                                .map_err(|err| {
                                    tracing::error!(
                                        "failed to add seccomp action: {:?}. Comparators: {:?} Syscall: {name}",
                                        &action,
                                        comparators,
                                    );
                                    SeccompError::AddRule { source: err }
                                })?;
                        }
                    }
                    None => {
                        tracing::trace!(?name, ?action, "add seccomp rule");
                        ctx.add_rule(action, sc).map_err(|err| {
                            tracing::error!(
                                "failed to add seccomp rule: {:?}. Syscall: {name}",
                                &sc
                            );
                            SeccompError::AddRule { source: err }
                        })?;
                    }
                }
            }
        }
    }

    Ok(ctx)
}

#[tracing::instrument(level = "trace", skip(seccomp))]
pub fn initialize_seccomp(seccomp: &LinuxSeccomp) -> Result<Option<io::RawFd>> {
    initialize_seccomp_with(&LibseccompBackend, seccomp)
}

pub fn initialize_seccomp_with(
    backend: &dyn SeccompBackend,
    seccomp: &LinuxSeccomp,
) -> Result<Option<io::RawFd>> {
    tracing::trace!(backend = backend.name(), "compiling seccomp profile");
    let compiled = backend.compile(seccomp)?;
    let ctx = match &compiled.filter {
        Filter::Libseccomp(ctx) => ctx,
        Filter::Program(program) => {
            return load_program(program, compiled.flags, compiled.wants_listener);
        }
    };

    // In order to use the SECCOMP_SET_MODE_FILTER operation, either the calling
    // thread must have the CAP_SYS_ADMIN capability in its user namespace, or
    // the thread must already have the no_new_privs bit set.
    // Ref: https://man7.org/linux/man-pages/man2/seccomp.2.html
    ctx.load()
        .map_err(|err| SeccompError::LoadContext { source: err })?;

    let fd = if is_notify(seccomp) {
        Some(
            ctx.get_notify_fd()
                .map_err(|err| SeccompError::GetNotifyId { source: err })?,
        )
    } else {
        None
    };

    Ok(fd)
}

fn load_program(
    program: &[SockFilter],
    flags: u32,
    wants_listener: bool,
) -> Result<Option<io::RawFd>> {
    let len = u16::try_from(program.len())
        .map_err(|_| SeccompError::ProgramTooLong { len: program.len() })?;
    let prog = libc::sock_fprog {
        len,
        filter: program.as_ptr() as *mut libc::sock_filter,
    };

    let mut flags = libc::c_ulong::from(flags);
    if wants_listener {
        flags |= libc::SECCOMP_FILTER_FLAG_NEW_LISTENER;
        // With TSYNC a failure returns a thread id, which would be taken for
        // the listener fd. TSYNC_ESRCH makes it an error instead.
        if flags & libc::SECCOMP_FILTER_FLAG_TSYNC != 0 {
            flags |= libc::SECCOMP_FILTER_FLAG_TSYNC_ESRCH;
        }
    } else {
        // The kernel only accepts WAIT_KILLABLE_RECV together with a listener.
        flags &= !libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            flags,
            &raw const prog,
        )
    };
    if ret < 0 {
        return Err(SeccompError::LoadProgram {
            source: std::io::Error::last_os_error(),
        });
    }
    if wants_listener {
        return Ok(Some(ret as io::RawFd));
    }
    if ret > 0 {
        return Err(SeccompError::LoadProgram {
            source: std::io::Error::other(format!("failed to sync thread {ret}")),
        });
    }

    Ok(None)
}

pub fn is_notify(seccomp: &LinuxSeccomp) -> bool {
    seccomp
        .syscalls()
        .iter()
        .flatten()
        .any(|syscall| syscall.action() == LinuxSeccompAction::ScmpActNotify)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek};
    use std::path;

    use anyhow::{Context, Result};
    use oci_spec::runtime::{
        Arch, LinuxSeccompArgBuilder, LinuxSeccompBuilder, LinuxSyscallBuilder,
    };
    use serial_test::serial;

    use super::*;
    use crate::test_utils::{self, TestCallbackError};

    // Here, we choose an error that getcwd call would never return on its own, so
    // we can make sure that getcwd failed because of seccomp rule.
    const GETCWD_ERRNO: i32 = libc::EAGAIN;

    fn basic_profile() -> Result<LinuxSeccomp> {
        let syscall = LinuxSyscallBuilder::default()
            .names(vec![String::from("getcwd")])
            .action(LinuxSeccompAction::ScmpActErrno)
            .errno_ret(GETCWD_ERRNO as u32)
            .build()?;
        Ok(LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .architectures(vec![Arch::ScmpArchNative])
            .syscalls(vec![syscall])
            .build()?)
    }

    fn moby_profile() -> Result<LinuxSeccomp> {
        let fixture_path =
            path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/seccomp/fixture/config.json");
        let spec = oci_spec::runtime::Spec::load(fixture_path)
            .context("Failed to load test spec for seccomp")?;

        // We know linux and seccomp exist, so let's just unwrap.
        Ok(spec
            .linux()
            .as_ref()
            .unwrap()
            .seccomp()
            .as_ref()
            .unwrap()
            .clone())
    }

    fn notify_profile() -> Result<LinuxSeccomp> {
        let syscall = LinuxSyscallBuilder::default()
            .names(vec![String::from("getcwd")])
            .action(LinuxSeccompAction::ScmpActNotify)
            .build()?;
        Ok(LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .architectures(vec![Arch::ScmpArchNative])
            .syscalls(vec![syscall])
            .build()?)
    }

    fn multiple_distinct_args_profile() -> Result<LinuxSeccomp> {
        let syscall = LinuxSyscallBuilder::default()
            .names(vec![String::from("socket")])
            .action(LinuxSeccompAction::ScmpActErrno)
            .errno_ret(libc::EAGAIN as u32)
            .args(vec![
                LinuxSeccompArgBuilder::default()
                    .index(0_usize)
                    .value(libc::AF_INET as u64)
                    .op(LinuxSeccompOperator::ScmpCmpEq)
                    .build()?,
                LinuxSeccompArgBuilder::default()
                    .index(1_usize)
                    .value(libc::SOCK_STREAM as u64)
                    .op(LinuxSeccompOperator::ScmpCmpEq)
                    .build()?,
            ])
            .build()?;

        Ok(LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .architectures(vec![Arch::ScmpArchNative])
            .syscalls(vec![syscall])
            .build()?)
    }

    fn duplicate_arg_index_profile() -> Result<LinuxSeccomp> {
        let syscall = LinuxSyscallBuilder::default()
            .names(vec![String::from("socket")])
            .action(LinuxSeccompAction::ScmpActErrno)
            .errno_ret(libc::EAGAIN as u32)
            .args(vec![
                LinuxSeccompArgBuilder::default()
                    .index(0_usize)
                    .value(libc::AF_INET as u64)
                    .op(LinuxSeccompOperator::ScmpCmpEq)
                    .build()?,
                LinuxSeccompArgBuilder::default()
                    .index(0_usize)
                    .value(libc::AF_UNIX as u64)
                    .op(LinuxSeccompOperator::ScmpCmpNe)
                    .build()?,
            ])
            .build()?;

        Ok(LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .architectures(vec![Arch::ScmpArchNative])
            .syscalls(vec![syscall])
            .build()?)
    }

    fn multiple_entries_for_same_name_profile() -> Result<LinuxSeccomp> {
        let rule1 = LinuxSyscallBuilder::default()
            .names(vec!["socket".into()])
            .action(LinuxSeccompAction::ScmpActErrno)
            .errno_ret(libc::EAGAIN as u32)
            .args(vec![
                LinuxSeccompArgBuilder::default()
                    .index(0_usize)
                    .value(libc::AF_NETLINK as u64)
                    .op(LinuxSeccompOperator::ScmpCmpEq)
                    .build()?,
                LinuxSeccompArgBuilder::default()
                    .index(2_usize)
                    .value(libc::NETLINK_AUDIT as u64)
                    .op(LinuxSeccompOperator::ScmpCmpNe)
                    .build()?,
            ])
            .build()?;

        let rule2 = LinuxSyscallBuilder::default()
            .names(vec!["socket".into()])
            .action(LinuxSeccompAction::ScmpActErrno)
            .errno_ret(libc::EAGAIN as u32)
            .args(vec![
                LinuxSeccompArgBuilder::default()
                    .index(0_usize)
                    .value(libc::AF_INET as u64)
                    .op(LinuxSeccompOperator::ScmpCmpNe)
                    .build()?,
            ])
            .build()?;

        Ok(LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .architectures(vec![Arch::ScmpArchNative])
            .syscalls(vec![rule1, rule2])
            .build()?)
    }

    fn expect_getcwd_denied() -> std::result::Result<(), TestCallbackError> {
        let ret = nix::unistd::getcwd();
        if ret.is_ok() {
            Err(TestCallbackError::Custom(
                "getcwd didn't error out as seccomp profile specified".to_string(),
            ))?;
        }

        if let Some(errno) = ret.err() {
            if errno != nix::errno::Errno::from_raw(GETCWD_ERRNO) {
                Err(TestCallbackError::Custom(format!(
                    "getcwd failed but we didn't get the expected error from seccomp profile: {}",
                    errno
                )))?;
            }
        }

        Ok(())
    }

    #[test]
    #[serial]
    fn test_basic() -> Result<()> {
        // Note: seccomp profile is really hard to write unit test for. First,
        // we can't really test default error or kill action, since rust test
        // actually relies on certain syscalls. Second, some of the syscall will
        // not return errorno. These syscalls will just send an abort signal or
        // even just segfaults.  Here we choose to use `getcwd` syscall for
        // testing, since it will correctly return an error under seccomp rule.
        // This is more of a sanity check.
        let seccomp_profile = basic_profile()?;

        test_utils::test_in_child_process(|| {
            let _ = prctl::set_no_new_privileges(true);
            initialize_seccomp(&seccomp_profile).expect("failed to initialize seccomp");
            expect_getcwd_denied()
        })?;

        Ok(())
    }

    #[test]
    #[serial]
    fn test_moby() -> Result<()> {
        let seccomp_profile = moby_profile()?;
        test_utils::test_in_child_process(|| {
            let _ = prctl::set_no_new_privileges(true);
            initialize_seccomp(&seccomp_profile).expect("failed to initialize seccomp");

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    #[serial]
    fn test_seccomp_notify() -> Result<()> {
        let seccomp_profile = notify_profile()?;
        test_utils::test_in_child_process(|| {
            let _ = prctl::set_no_new_privileges(true);
            let fd =
                initialize_seccomp(&seccomp_profile).expect("failed to initialize seccomp profile");
            if fd.is_none() {
                Err(TestCallbackError::Custom(
                    "failed to get a seccomp notify fd with notify seccomp profile".to_string(),
                ))?;
            }

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    #[serial]
    fn test_seccomp_conditional_rule_multiple_distinct_args() -> Result<()> {
        let seccomp_profile = multiple_distinct_args_profile()?;

        test_utils::test_in_child_process(|| {
            let _ = prctl::set_no_new_privileges(true);
            initialize_seccomp(&seccomp_profile).expect("failed to initialize seccomp");
            Ok(())
        })?;

        Ok(())
    }

    #[test]
    #[serial]
    fn test_seccomp_conditional_rule_duplicate_arg_index() -> Result<()> {
        let seccomp_profile = duplicate_arg_index_profile()?;

        test_utils::test_in_child_process(|| {
            let _ = prctl::set_no_new_privileges(true);
            initialize_seccomp(&seccomp_profile).expect("failed to initialize seccomp");
            Ok(())
        })?;

        Ok(())
    }

    #[test]
    #[serial]
    fn test_seccomp_multiple_syscall_entries_for_same_name() -> Result<()> {
        let profile = multiple_entries_for_same_name_profile()?;

        test_utils::test_in_child_process(|| {
            let _ = prctl::set_no_new_privileges(true);
            initialize_seccomp(&profile).expect("failed to initialize seccomp");

            Ok(())
        })?;

        Ok(())
    }

    fn export(ctx: &ScmpFilterContext) -> Result<Vec<SockFilter>> {
        let mut file = tempfile::tempfile()?;
        ctx.export_bpf(&file)?;
        file.rewind()?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes
            .chunks_exact(8)
            .map(|b| SockFilter {
                code: u16::from_ne_bytes([b[0], b[1]]),
                jt: b[2],
                jf: b[3],
                k: u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
            })
            .collect())
    }

    #[test]
    fn test_backend_compiles_same_filter() -> Result<()> {
        let profiles = [
            basic_profile()?,
            moby_profile()?,
            notify_profile()?,
            multiple_distinct_args_profile()?,
            duplicate_arg_index_profile()?,
            multiple_entries_for_same_name_profile()?,
        ];

        for profile in &profiles {
            let expected = export(&build_context(profile)?)?;
            assert!(!expected.is_empty());

            let compiled = LibseccompBackend.compile(profile)?;
            let Filter::Libseccomp(ctx) = &compiled.filter else {
                panic!("libseccomp backend didn't return a libseccomp filter");
            };
            assert_eq!(export(ctx)?, expected);
            assert_eq!(compiled.wants_listener, is_notify(profile));
            assert_eq!(compiled.flags, 0);
        }

        Ok(())
    }

    #[test]
    fn test_compile_flags() -> Result<()> {
        let profile = LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .flags(vec![
                LinuxSeccompFilterFlag::SeccompFilterFlagLog,
                LinuxSeccompFilterFlag::SeccompFilterFlagSpecAllow,
            ])
            .build()?;
        let compiled = LibseccompBackend.compile(&profile)?;
        let expected = libc::SECCOMP_FILTER_FLAG_LOG | libc::SECCOMP_FILTER_FLAG_SPEC_ALLOW;
        assert_eq!(compiled.flags, expected as u32);
        assert!(!compiled.wants_listener);

        Ok(())
    }

    #[test]
    fn test_compile_rejects_notify_as_default_action() -> Result<()> {
        let profile = LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActNotify)
            .build()?;
        assert!(matches!(
            LibseccompBackend.compile(&profile),
            Err(SeccompError::NotifyAsDefaultAction)
        ));

        Ok(())
    }

    // A backend that only has a BPF program.
    struct ProgramBackend(Vec<SockFilter>);

    impl SeccompBackend for ProgramBackend {
        fn name(&self) -> &'static str {
            "program"
        }

        fn compile(&self, seccomp: &LinuxSeccomp) -> super::Result<CompiledSeccomp> {
            Ok(CompiledSeccomp::from_program(
                self.0.clone(),
                translate_flags(seccomp),
                is_notify(seccomp),
            ))
        }
    }

    // Returns `action` for getcwd and allows everything else.
    fn getcwd_program(action: u32) -> Vec<SockFilter> {
        let insn = |code: u32, jt: u8, jf: u8, k: u32| SockFilter {
            code: code as u16,
            jt,
            jf,
            k,
        };
        vec![
            // offset 0 of seccomp_data is the syscall number
            insn(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
            insn(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                0,
                1,
                libc::SYS_getcwd as u32,
            ),
            insn(libc::BPF_RET | libc::BPF_K, 0, 0, action),
            insn(libc::BPF_RET | libc::BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW),
        ]
    }

    #[test]
    #[serial]
    fn test_program_backend() -> Result<()> {
        let backend = ProgramBackend(getcwd_program(
            libc::SECCOMP_RET_ERRNO | GETCWD_ERRNO as u32,
        ));
        let seccomp_profile = basic_profile()?;

        test_utils::test_in_child_process(|| {
            let _ = prctl::set_no_new_privileges(true);
            let fd = initialize_seccomp_with(&backend, &seccomp_profile)
                .expect("failed to initialize seccomp");
            if fd.is_some() {
                Err(TestCallbackError::Custom(
                    "got a seccomp notify fd without a notify seccomp profile".to_string(),
                ))?;
            }
            expect_getcwd_denied()
        })?;

        Ok(())
    }

    #[test]
    #[serial]
    fn test_program_backend_notify() -> Result<()> {
        let backend = ProgramBackend(getcwd_program(libc::SECCOMP_RET_USER_NOTIF));
        let seccomp_profile = notify_profile()?;

        test_utils::test_in_child_process(|| {
            let _ = prctl::set_no_new_privileges(true);
            let fd = initialize_seccomp_with(&backend, &seccomp_profile)
                .expect("failed to initialize seccomp profile");
            if fd.is_none() {
                Err(TestCallbackError::Custom(
                    "failed to get a seccomp notify fd with notify seccomp profile".to_string(),
                ))?;
            }

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    #[serial]
    fn test_program_backend_wait_killable_recv_without_notify() -> Result<()> {
        let backend = ProgramBackend(getcwd_program(
            libc::SECCOMP_RET_ERRNO | GETCWD_ERRNO as u32,
        ));
        let seccomp_profile = LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .flags(vec![
                LinuxSeccompFilterFlag::SeccompFilterFlagWaitKillableRecv,
            ])
            .build()?;

        test_utils::test_in_child_process(|| {
            let _ = prctl::set_no_new_privileges(true);
            initialize_seccomp_with(&backend, &seccomp_profile)
                .expect("failed to initialize seccomp");
            expect_getcwd_denied()
        })?;

        Ok(())
    }

    #[test]
    #[serial]
    fn test_program_backend_with_libseccomp_program() -> Result<()> {
        // The program libseccomp generates for the profile, loaded by us.
        let seccomp_profile = basic_profile()?;
        let backend = ProgramBackend(export(&build_context(&seccomp_profile)?)?);

        test_utils::test_in_child_process(|| {
            let _ = prctl::set_no_new_privileges(true);
            initialize_seccomp_with(&backend, &seccomp_profile)
                .expect("failed to initialize seccomp");
            expect_getcwd_denied()
        })?;

        Ok(())
    }
}
