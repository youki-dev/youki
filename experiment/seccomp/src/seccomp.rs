use core::fmt;
use std::{
    mem::MaybeUninit,
    os::{
        raw::{c_long, c_uint, c_ulong, c_ushort, c_void},
        unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    },
};
use std::os::raw::c_uchar;
use crate::instruction::*;
use crate::instruction::{Arch, Instruction, SECCOMP_IOC_MAGIC};
use anyhow::anyhow;
use anyhow::Result;
use nix::{
    errno::Errno,
    ioctl_readwrite, ioctl_write_ptr, libc,
    libc::{SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_SET_MODE_FILTER},
    unistd,
};
use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompFilterFlag,
    LinuxSeccompOperator,
};
use std::str::FromStr;
use nix::libc::{SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_SPEC_ALLOW, SECCOMP_FILTER_FLAG_TSYNC};
use syscalls::{syscall_args, SyscallArgs};

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("Failed to apply seccomp rules: {0}")]
    Apply(String),
}

pub struct Seccomp {
    pub filters: Vec<Instruction>,
    pub flags: c_ulong,
}

impl Default for Seccomp {
    fn default() -> Self {
        Seccomp::new()
    }
}

impl Seccomp {
    pub fn new() -> Self {
        Seccomp {
            filters: Vec::new(),
            flags: SECCOMP_FILTER_FLAG_NEW_LISTENER,
        }
    }

    pub fn set_flags(&mut self, flags: Vec<c_ulong>) {
        for flag in flags {
            self.flags |= flag;
        }
    }

    // apply applies the seccomp rules to the current process and return a fd for seccomp notify.
    pub fn apply(&self) -> Result<NotifyFd, SeccompError> {
        let mut prog = Filters {
            len: self.filters.len() as _,
            filter: self.filters.as_ptr(),
        };

        // TODO: Address the case where don't use seccomp notify.
        let notify_fd = unsafe {
            seccomp(
                SECCOMP_SET_MODE_FILTER,
                self.flags,
                &mut prog as *mut _ as *mut c_void,
            )
        };

        Errno::result(notify_fd).map_err(|e| SeccompError::Apply(e.to_string()))?;
        Ok(unsafe { NotifyFd::from_raw_fd(notify_fd as RawFd) })
    }
}

#[derive(Debug)]
pub struct NotifyFd {
    fd: RawFd,
}

impl Drop for NotifyFd {
    fn drop(&mut self) {
        unistd::close(self.fd).unwrap()
    }
}

impl FromRawFd for NotifyFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        NotifyFd { fd }
    }
}

impl IntoRawFd for NotifyFd {
    fn into_raw_fd(self) -> RawFd {
        let NotifyFd { fd } = self;
        fd
    }
}

impl AsRawFd for NotifyFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl NotifyFd {
    pub fn success(&self, v: i64, notify_id: u64) -> nix::Result<()> {
        let mut resp = SeccompNotifResp {
            id: notify_id,
            val: v,
            error: 0,
            flags: 0,
        };

        unsafe { seccomp_notif_ioctl_send(self.fd, &mut resp as *mut _)? };

        Ok(())
    }
}

// TODO: Rename
#[repr(C)]
#[derive(Debug)]
pub struct SeccompData {
    pub nr: libc::c_int,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifSizes {
    pub seccomp_notif: u16,
    pub seccomp_notif_resp: u16,
    pub seccomp_data: u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

ioctl_readwrite!(seccomp_notif_ioctl_recv, SECCOMP_IOC_MAGIC, 0, SeccompNotif);
ioctl_readwrite!(
    seccomp_notif_ioctl_send,
    SECCOMP_IOC_MAGIC,
    1,
    SeccompNotifResp
);
ioctl_write_ptr!(seccomp_notif_ioctl_id_valid, SECCOMP_IOC_MAGIC, 2, u64);
ioctl_write_ptr!(
    seccomp_notif_ioctl_addfd,
    SECCOMP_IOC_MAGIC,
    3,
    SeccompNotifAddfd
);

pub struct Notification<'f> {
    pub notif: SeccompNotif,
    pub fd: &'f NotifyFd,
}

impl<'f> fmt::Debug for Notification<'f> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.notif, f)
    }
}

impl NotifyFd {
    pub fn recv(&self) -> nix::Result<Notification> {
        let mut res = MaybeUninit::zeroed();
        let notif = unsafe {
            seccomp_notif_ioctl_recv(self.fd, res.as_mut_ptr())?;
            res.assume_init()
        };

        Ok(Notification { notif, fd: self })
    }
}

unsafe fn seccomp(op: c_uint, flags: c_ulong, args: *mut c_void) -> c_long {
    libc::syscall(libc::SYS_seccomp, op, flags, args)
}

#[repr(C)]
struct Filters {
    pub len: c_ushort,
    pub filter: *const Instruction,
}

fn get_syscall_number(arc: &Arch, name: &str) -> Option<u64> {
    match arc {
        Arch::X86 => match syscalls::x86_64::Sysno::from_str(name) {
            Ok(syscall) => Some(syscall as u64),
            Err(_) => None,
        },
        Arch::AArch64 => match syscalls::aarch64::Sysno::from_str(name) {
            Ok(syscall) => Some(syscall as u64),
            Err(_) => None,
        },
    }
}

// This wrapper type is used to implement the `From` trait while avoiding the orphan rule's restrictions.
pub struct SeccompActionWrapper(pub LinuxSeccompAction);

impl From<SeccompActionWrapper> for u32 {
    fn from(wrapped_action: SeccompActionWrapper) -> Self {
        // Extracts the wrapped LinuxSeccompAction
        let action = wrapped_action.0;
        match action {
            LinuxSeccompAction::ScmpActKill => SECCOMP_RET_KILL_THREAD,
            LinuxSeccompAction::ScmpActTrap => SECCOMP_RET_TRAP,
            LinuxSeccompAction::ScmpActErrno => SECCOMP_RET_ERRNO,
            LinuxSeccompAction::ScmpActTrace => SECCOMP_RET_TRACE,
            LinuxSeccompAction::ScmpActAllow => SECCOMP_RET_ALLOW,
            LinuxSeccompAction::ScmpActKillProcess => SECCOMP_RET_KILL_PROCESS,
            LinuxSeccompAction::ScmpActNotify => SECCOMP_RET_USER_NOTIF,
            LinuxSeccompAction::ScmpActLog => SECCOMP_RET_LOG,
            LinuxSeccompAction::ScmpActKillThread => SECCOMP_RET_KILL_THREAD,
        }
    }
}

impl From<LinuxSeccompOperator> for SeccompCompareOp {
    fn from(op: LinuxSeccompOperator) -> Self {
        match op {
            LinuxSeccompOperator::ScmpCmpNe => SeccompCompareOp::NotEqual,
            LinuxSeccompOperator::ScmpCmpLt => SeccompCompareOp::LessThan,
            LinuxSeccompOperator::ScmpCmpLe => SeccompCompareOp::LessOrEqual,
            LinuxSeccompOperator::ScmpCmpEq => SeccompCompareOp::Equal,
            LinuxSeccompOperator::ScmpCmpGe => SeccompCompareOp::GreaterOrEqual,
            LinuxSeccompOperator::ScmpCmpGt => SeccompCompareOp::GreaterThan,
            LinuxSeccompOperator::ScmpCmpMaskedEq => SeccompCompareOp::MaskedEqual,
        }
    }
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
        // Todo: consider need to porting SeccompError
        return Err(anyhow!("Cant ScmpActNotify to default action"));
    }

    if let Some(syscalls) = seccomp.syscalls() {
        for syscall in syscalls {
            if syscall.action() == LinuxSeccompAction::ScmpActNotify {
                for name in syscall.names() {
                    if name == "write" {
                        return Err(anyhow!("Cant filter to write system call"));
                    }
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug, Default)]
pub struct InstructionData {
    pub arc: Arch,
    pub def_action: u32,
    pub def_errno_ret: u32,
    pub flags: Vec<c_ulong>,
    pub rule: Rule,
}

impl From<InstructionData> for Vec<Instruction> {
    fn from(inst_data: InstructionData) -> Self {
        // let mut bpf_prog = gen_validate(&inst_data.arc);

        let mut bpf_prog = vec![];

        let jump_num = inst_data.rule.syscall.len();
        for syscall in &inst_data.rule.syscall {
            bpf_prog.append(&mut Rule::to_instruction(&inst_data.arc, &inst_data.rule, jump_num, syscall));
        }
        bpf_prog.append(&mut vec![Instruction::stmt(BPF_RET | BPF_K, inst_data.def_action)]);
        bpf_prog.append(&mut vec![Instruction::stmt(BPF_RET | BPF_K, inst_data.rule.action)]);
        bpf_prog
    }
}

impl InstructionData {

    pub fn from_linux_seccomp(seccomp: &LinuxSeccomp) -> Result<Self> {
        let mut data: InstructionData = Default::default();
        // let mut rules: Vec<Rule> = Vec::new();

        check_seccomp(seccomp)?;
        // data.def_action = translate_action(seccomp.default_action());
        data.def_action = u32::from(seccomp.default_action());
        if let Some(ret) = seccomp.default_errno_ret() {
            data.def_errno_ret = ret
        } else {
            data.def_errno_ret = libc::EPERM as u32
        }

        if let Some(flags) = seccomp.flags() {
            for flag in flags {
                match flag {
                    LinuxSeccompFilterFlag::SeccompFilterFlagLog => data.flags.push(SECCOMP_FILTER_FLAG_LOG),
                    LinuxSeccompFilterFlag::SeccompFilterFlagTsync => data.flags.push(SECCOMP_FILTER_FLAG_TSYNC),
                    LinuxSeccompFilterFlag::SeccompFilterFlagSpecAllow => data.flags.push(SECCOMP_FILTER_FLAG_SPEC_ALLOW),
                }
            }
        }

        if let Some(archs) = seccomp.architectures() {
            for &arch in archs {
                // Todo: consider support other Arch
                match arch {
                    OciSpecArch::ScmpArchX86_64 => data.arc = Arch::X86,
                    OciSpecArch::ScmpArchAarch64 => data.arc = Arch::AArch64,
                    _ => {}
                }
            }
        }

        /*
        Todo: how to impl this?
        ctx.set_ctl_nnp(false)
        .map_err(|err| SeccompError::SetCtlNnp { source: err })?;
         */
        if let Some(syscalls) = seccomp.syscalls() {
            for syscall in syscalls {
                // let mut rule: Rule = Default::default();
                data.rule.action = u32::from(syscall.action());
                if data.rule.action == SECCOMP_RET_USER_NOTIF {
                    data.rule.is_notify = true
                } else {
                    data.rule.is_notify = false
                }

                for name in syscall.names() {
                    data.rule.syscall.append(&mut vec![name.to_string()]);
                    match syscall.args() {
                        Some(args) => {
                            for arg in args {
                                data.rule.arg_cnt = Option::from(arg.index() as u8);
                                data.rule.args = Option::from(syscall_args!(arg.value() as usize));
                                if arg.value_two().is_some() {
                                    data.rule.args = Option::from(
                                        syscall_args!(arg.value() as usize, arg.value_two().unwrap() as usize)
                                    );
                                }
                                data.rule.op = Option::from(SeccompCompareOp::from(arg.op()))
                            }
                        }
                        None => {
                            continue
                        }
                    }
                }
            }
        }
        Ok(data)
    }
}

#[derive(Debug, Default)]
pub struct Rule {
    pub syscall: Vec<String>,
    pub action: u32,
    pub arg_cnt: Option<u8>,
    pub args: Option<SyscallArgs>,
    pub op: Option<SeccompCompareOp>,
    pub is_notify: bool,
}

impl Rule {
    pub fn new(syscall: Vec<String>, action: u32, arg_cnt: Option<u8>, args: Option<SyscallArgs>, op: Option<SeccompCompareOp>, is_notify: bool) -> Self {
        Self {
            syscall,
            action,
            arg_cnt,
            args,
            op,
            is_notify,
        }
    }

    pub fn to_instruction(arch: &Arch, rule: &Rule, jump_num: usize, syscall: &String) -> Vec<Instruction> {
        let mut bpf_prog = vec![];
        let mut jump_cnt = jump_num.clone();
        bpf_prog.append(&mut vec![Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, 0)]);
        bpf_prog.append(&mut vec![Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 0, jump_cnt as c_uchar,
                                                    get_syscall_number(arch, syscall).unwrap() as c_uint)]);
        if rule.arg_cnt.is_some() {
            bpf_prog.append(&mut vec![Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, seccomp_data_args_offset().into())]);
            bpf_prog.append(&mut vec![Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, rule.args.unwrap().arg0 as c_uint)]);
        }
        jump_cnt--
        bpf_prog
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscalls::syscall_args;

    #[test]
    fn test_get_syscall_number_x86() {
        let sys_num = get_syscall_number(&Arch::X86, "read");
        assert_eq!(sys_num.unwrap(), 0);
    }

    #[test]
    fn test_get_syscall_number_aarch64() {
        let sys_num = get_syscall_number(&Arch::AArch64, "read");
        assert_eq!(sys_num.unwrap(), 63);
    }

    #[test]
    fn test_to_instruction_x86() {
        let rule = Rule::new(vec!["getcwd".parse().unwrap()], SECCOMP_RET_ALLOW, None, None, None,false);
        let inst = Rule::to_instruction(&Arch::X86, SECCOMP_RET_KILL_PROCESS, &rule);
        let bpf_prog = gen_validate(&Arch::X86);
        assert_eq!(inst[0], bpf_prog[0]);
        assert_eq!(inst[1], bpf_prog[1]);
        assert_eq!(inst[2], bpf_prog[2]);
        assert_eq!(inst[3], Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, 0));
        assert_eq!(inst[4], Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1,
                                              get_syscall_number(&Arch::X86, "getcwd").unwrap() as c_uint));
        assert_eq!(inst[5], Instruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }

    #[test]
    fn test_to_instruction_aarch64() {
        let rule = Rule::new(vec!["getcwd".parse().unwrap()], SECCOMP_RET_ALLOW, None, None, None,false);
        let inst = Rule::to_instruction(&Arch::AArch64, SECCOMP_RET_KILL_PROCESS, &rule);
        let bpf_prog = gen_validate(&Arch::AArch64);
        assert_eq!(inst[0], bpf_prog[0]);
        assert_eq!(inst[1], bpf_prog[1]);
        assert_eq!(inst[2], bpf_prog[2]);
        assert_eq!(inst[3], Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, 0));
        assert_eq!(inst[4], Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1,
                                              get_syscall_number(&Arch::AArch64, "getcwd").unwrap() as c_uint));
        assert_eq!(inst[5], Instruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }
}