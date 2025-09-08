use crate::instruction::*;
use crate::instruction::{Arch, Instruction, SECCOMP_IOC_MAGIC};
use anyhow::anyhow;
use anyhow::Result;
use core::fmt;
use derive_builder::Builder;
use nix::libc::{
    SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_SPEC_ALLOW, SECCOMP_FILTER_FLAG_TSYNC,
};
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
use std::os::raw::c_uchar;
use std::str::FromStr;
use std::{
    mem::MaybeUninit,
    os::{
        raw::{c_long, c_uint, c_ulong, c_ushort, c_void},
        unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    },
};
use syscalls::{syscall_args, SyscallArgs};

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("Failed to apply seccomp rules: {0}")]
    Apply(String),
    #[error("valid indices are 0–5")]
    InvalidArgumentSize,
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

impl TryFrom<InstructionData> for Vec<Instruction> {
    type Error = SeccompError;
    fn try_from(inst_data: InstructionData) -> Result<Self, SeccompError> {
        let mut bpf_prog = vec![];
        let mut jump_num = inst_data.rule.syscall.len();
        if jump_num <= 255 {
            for syscall in &inst_data.rule.syscall {
                bpf_prog.append(&mut Rule::build_instruction(
                    &inst_data.arc,
                    &inst_data.rule,
                    jump_num,
                    false,
                    syscall,
                )?);
                jump_num -= 1;
            }
        } else {
            let mut cnt_ff = 254;
            for syscall in &inst_data.rule.syscall {
                if cnt_ff == 0 {
                    bpf_prog.append(&mut Rule::build_instruction(
                        &inst_data.arc,
                        &inst_data.rule,
                        1,
                        true,
                        syscall,
                    )?);
                    bpf_prog.append(&mut vec![Instruction::stmt(
                        BPF_RET | BPF_K,
                        inst_data.rule.action,
                    )]);
                    cnt_ff = jump_num;
                } else {
                    bpf_prog.append(&mut Rule::build_instruction(
                        &inst_data.arc,
                        &inst_data.rule,
                        cnt_ff,
                        false,
                        syscall,
                    )?);
                    jump_num -= 1;
                }
                cnt_ff -= 1;
            }
        }

        let mut all_bpf_prog = gen_validate(&inst_data.arc, inst_data.def_action, bpf_prog.len());
        all_bpf_prog.append(&mut bpf_prog);
        all_bpf_prog.append(&mut vec![Instruction::stmt(
            BPF_RET | BPF_K,
            inst_data.def_action,
        )]);
        all_bpf_prog.append(&mut vec![Instruction::stmt(
            BPF_RET | BPF_K,
            inst_data.rule.action,
        )]);
        Ok(all_bpf_prog)
    }
}

impl InstructionData {
    pub fn from_linux_seccomp(seccomp: &LinuxSeccomp) -> Result<Self> {
        let mut data: InstructionData = Default::default();

        check_seccomp(seccomp)?;
        data.def_action = u32::from(seccomp.default_action());
        if let Some(ret) = seccomp.default_errno_ret() {
            data.def_errno_ret = ret
        } else {
            data.def_errno_ret = libc::EPERM as u32
        }

        if let Some(flags) = seccomp.flags() {
            for flag in flags {
                match flag {
                    LinuxSeccompFilterFlag::SeccompFilterFlagLog => {
                        data.flags.push(SECCOMP_FILTER_FLAG_LOG)
                    }
                    LinuxSeccompFilterFlag::SeccompFilterFlagTsync => {
                        data.flags.push(SECCOMP_FILTER_FLAG_TSYNC)
                    }
                    LinuxSeccompFilterFlag::SeccompFilterFlagSpecAllow => {
                        data.flags.push(SECCOMP_FILTER_FLAG_SPEC_ALLOW)
                    }
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
                if data.rule.action == 0 {
                    data.rule.action = u32::from(syscall.action());
                }
                data.rule.is_notify = data.rule.action == SECCOMP_RET_USER_NOTIF;

                for name in syscall.names() {
                    data.rule.syscall.append(&mut vec![name.to_string()]);
                    match syscall.args() {
                        Some(args) => {
                            if syscall.args().iter().len() > 6 {
                                return Err(anyhow!(SeccompError::InvalidArgumentSize));
                            }
                            data.rule
                                .check_arg_syscall
                                .append(&mut vec![name.to_string()]);
                            for arg in args {
                                data.rule.arg_cnt = Option::from(arg.index() as u8);
                                data.rule.args = Option::from(syscall_args!(arg.value() as usize));
                                if arg.value_two().is_some() {
                                    data.rule.args = Option::from(syscall_args!(
                                        arg.value() as usize,
                                        arg.value_two().unwrap() as usize
                                    ));
                                }
                                data.rule.op = Option::from(SeccompCompareOp::from(arg.op()))
                            }
                        }
                        None => continue,
                    }
                }
            }
        }
        Ok(data)
    }
}

#[derive(Builder, Debug, Default)]
#[builder(setter(into))]
pub struct Rule {
    pub syscall: Vec<String>,
    pub action: u32,
    #[builder(default)]
    pub check_arg_syscall: Vec<String>,
    #[builder(default)]
    pub arg_cnt: Option<u8>,
    #[builder(default)]
    pub args: Option<SyscallArgs>,
    #[builder(default)]
    pub op: Option<SeccompCompareOp>,
    #[builder(default)]
    pub is_notify: bool,
}

impl Rule {
    pub fn new(
        syscall: Vec<String>,
        action: u32,
        check_arg_syscall: Vec<String>,
        arg_cnt: Option<u8>,
        args: Option<SyscallArgs>,
        op: Option<SeccompCompareOp>,
        is_notify: bool,
    ) -> Self {
        Self {
            syscall,
            action,
            check_arg_syscall,
            arg_cnt,
            args,
            op,
            is_notify,
        }
    }

    fn jump_cnt(rule: &Rule, jump_num: usize) -> c_uchar {
        if rule.arg_cnt.is_none() {
            jump_num as c_uchar
        } else {
            match rule.op.as_ref().unwrap() {
                SeccompCompareOp::Equal
                | SeccompCompareOp::NotEqual
                | SeccompCompareOp::MaskedEqual => (jump_num + 4) as c_uchar,
                SeccompCompareOp::GreaterThan
                | SeccompCompareOp::GreaterOrEqual
                | SeccompCompareOp::LessThan
                | SeccompCompareOp::LessOrEqual => (jump_num + 5) as c_uchar,
            }
        }
    }

    fn build_instruction_with_args(
        arch: &Arch,
        rule: &Rule,
        syscall: &str,
    ) -> Result<Vec<Instruction>, SeccompError> {
        let mut bpf_prog = vec![];
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap())?;
        match rule.op.as_ref().unwrap() {
            SeccompCompareOp::NotEqual => {
                // if system call number is not match, skip args check jf 4 to default action
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    4,
                    get_syscall_number(arch, syscall).unwrap() as c_uint,
                )]);
                // uppper 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    (offset + 4).into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    3,
                    (rule.args.unwrap().arg0 >> 32) as c_uint,
                )]);
                // lower 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    offset.into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    1,
                    rule.args.unwrap().arg0 as c_uint,
                )]);
            }
            SeccompCompareOp::LessThan => {
                // if system call number is not match, skip args check jf 4 to default action
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    5,
                    get_syscall_number(arch, syscall).unwrap() as c_uint,
                )]);
                // uppper 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    (offset + 4).into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JGE | BPF_K,
                    0,
                    4,
                    (rule.args.unwrap().arg0 >> 32) as c_uint,
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    2,
                    (rule.args.unwrap().arg0 >> 32) as c_uint,
                )]);
                // lower 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    offset.into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JGE | BPF_K,
                    0,
                    1,
                    rule.args.unwrap().arg0 as c_uint,
                )]);
            }
            SeccompCompareOp::LessOrEqual => {
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    5,
                    get_syscall_number(arch, syscall).unwrap() as c_uint,
                )]);
                // uppper 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    (offset + 4).into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JGE | BPF_K,
                    0,
                    4,
                    (rule.args.unwrap().arg0 >> 32) as c_uint,
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    2,
                    (rule.args.unwrap().arg0 >> 32) as c_uint,
                )]);
                // lower 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    offset.into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JGT | BPF_K,
                    0,
                    1,
                    rule.args.unwrap().arg0 as c_uint,
                )]);
            }
            SeccompCompareOp::Equal => {
                // if system call number is not match, skip args check jf 4 to default action
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    4,
                    get_syscall_number(arch, syscall).unwrap() as c_uint,
                )]);
                // uppper 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    (offset + 4).into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    2,
                    (rule.args.unwrap().arg0 >> 32) as c_uint,
                )]);
                // lower 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    offset.into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    1,
                    0,
                    rule.args.unwrap().arg0 as c_uint,
                )]);
            }
            SeccompCompareOp::GreaterOrEqual => {
                // if system call number is not match, skip args check jf 4 to default action
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    5,
                    get_syscall_number(arch, syscall).unwrap() as c_uint,
                )]);
                // uppper 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    (offset + 4).into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JGT | BPF_K,
                    4,
                    0,
                    (rule.args.unwrap().arg0 >> 32) as c_uint,
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    2,
                    (rule.args.unwrap().arg0 >> 32) as c_uint,
                )]);
                // lower 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    offset.into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JGE | BPF_K,
                    1,
                    0,
                    rule.args.unwrap().arg0 as c_uint,
                )]);
            }
            SeccompCompareOp::GreaterThan => {
                // if system call number is not match, skip args check jf 4 to default action
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    5,
                    get_syscall_number(arch, syscall).unwrap() as c_uint,
                )]);
                // uppper 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    (offset + 4).into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JGT | BPF_K,
                    4,
                    0,
                    (rule.args.unwrap().arg0 >> 32) as c_uint,
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    2,
                    (rule.args.unwrap().arg0 >> 32) as c_uint,
                )]);
                // lower 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    offset.into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JGE | BPF_K,
                    1,
                    0,
                    rule.args.unwrap().arg0 as c_uint,
                )]);
            }
            SeccompCompareOp::MaskedEqual => {
                // if system call number is not match, skip args check jf 4 to default action
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    4,
                    get_syscall_number(arch, syscall).unwrap() as c_uint,
                )]);

                // uppper 32bit check of args
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    (offset + 4).into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JSET | BPF_K,
                    3,
                    0,
                    (rule.args.unwrap().arg0 >> 32) as c_uint,
                )]);

                // lower 32bit check of
                bpf_prog.append(&mut vec![Instruction::stmt(
                    BPF_LD | BPF_W | BPF_ABS,
                    offset.into(),
                )]);
                bpf_prog.append(&mut vec![Instruction::jump(
                    BPF_JSET | BPF_K,
                    1,
                    0,
                    rule.args.unwrap().arg0 as c_uint,
                )]);
            }
        }
        Ok(bpf_prog)
    }

    pub fn build_instruction(
        arch: &Arch,
        rule: &Rule,
        jump_num: usize,
        zero_jump: bool,
        syscall: &String,
    ) -> Result<Vec<Instruction>, SeccompError> {
        let mut bpf_prog = vec![];
        if rule.arg_cnt.is_some() && rule.check_arg_syscall.contains(syscall) {
            bpf_prog.append(&mut Rule::build_instruction_with_args(arch, rule, syscall)?);
        } else if zero_jump {
            bpf_prog.append(&mut vec![Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                1,
                get_syscall_number(arch, syscall).unwrap() as c_uint,
            )]);
        } else {
            bpf_prog.append(&mut vec![Instruction::jump(
                BPF_JEQ | BPF_K,
                Self::jump_cnt(rule, jump_num),
                0,
                get_syscall_number(arch, syscall).unwrap() as c_uint,
            )]);
        }
        Ok(bpf_prog)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_build_instruction_x86() {
        let rule = RuleBuilder::default()
            .action(SECCOMP_RET_ALLOW)
            .syscall(vec!["getcwd".to_string()])
            .build()
            .expect("failed to build rule");
        let inst =
            Rule::build_instruction(&Arch::X86, &rule, 1, true, &"getcwd".to_string()).unwrap();
        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                1,
                get_syscall_number(&Arch::X86, "getcwd").unwrap() as c_uint
            )
        );
    }

    #[test]
    fn test_build_instruction_aarch64() {
        let rule = RuleBuilder::default()
            .action(SECCOMP_RET_ALLOW)
            .syscall(vec!["getcwd".to_string()])
            .build()
            .expect("failed to build rule");
        let inst =
            Rule::build_instruction(&Arch::AArch64, &rule, 1, true, &"getcwd".to_string()).unwrap();
        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                1,
                get_syscall_number(&Arch::AArch64, "getcwd").unwrap() as c_uint
            )
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_euqal() {
        let personality = "personality";
        let syscall_vec = vec![personality.to_string()];
        let personality_args: SyscallArgs = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(personality_args))
            .op(Option::from(SeccompCompareOp::Equal))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst =
            Rule::build_instruction_with_args(&Arch::X86, &rule, &personality.to_string()).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                4,
                get_syscall_number(&Arch::X86, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                2,
                (rule.args.unwrap().arg0 >> 32) as c_uint
            )
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, rule.args.unwrap().arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_equal() {
        let personality = "personality";
        let syscall_vec = vec![personality.to_string()];
        let personality_args: SyscallArgs = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(personality_args))
            .op(Option::from(SeccompCompareOp::Equal))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst =
            Rule::build_instruction_with_args(&Arch::AArch64, &rule, &personality.to_string())
                .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                4,
                get_syscall_number(&Arch::AArch64, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                2,
                (rule.args.unwrap().arg0 >> 32) as c_uint
            )
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, rule.args.unwrap().arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_not_equal() {
        let syscall_vec = vec!["personality".to_string()];
        let args = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(args))
            .op(Option::from(SeccompCompareOp::NotEqual))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst = Rule::build_instruction_with_args(&Arch::X86, &rule, &"personality".to_string())
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                4,
                get_syscall_number(&Arch::X86, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 3, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 1, args.arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_not_equal() {
        let syscall_vec = vec!["personality".to_string()];
        let args = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(args))
            .op(Option::from(SeccompCompareOp::NotEqual))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst =
            Rule::build_instruction_with_args(&Arch::AArch64, &rule, &"personality".to_string())
                .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                4,
                get_syscall_number(&Arch::AArch64, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 3, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 1, args.arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_less_than() {
        let syscall_vec = vec!["personality".to_string()];
        let args = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(args))
            .op(Option::from(SeccompCompareOp::LessThan))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst = Rule::build_instruction_with_args(&Arch::X86, &rule, &"personality".to_string())
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                5,
                get_syscall_number(&Arch::X86, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGE | BPF_K, 0, 4, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 0, 1, args.arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_less_than() {
        let syscall_vec = vec!["personality".to_string()];
        let args = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(args))
            .op(Option::from(SeccompCompareOp::LessThan))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst =
            Rule::build_instruction_with_args(&Arch::AArch64, &rule, &"personality".to_string())
                .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                5,
                get_syscall_number(&Arch::AArch64, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGE | BPF_K, 0, 4, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 0, 1, args.arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_less_or_equal() {
        let syscall_vec = vec!["personality".to_string()];
        let args = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(args))
            .op(Option::from(SeccompCompareOp::LessOrEqual))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst = Rule::build_instruction_with_args(&Arch::X86, &rule, &"personality".to_string())
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                5,
                get_syscall_number(&Arch::X86, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGE | BPF_K, 0, 4, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGT | BPF_K, 0, 1, args.arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_less_or_equal() {
        let syscall_vec = vec!["personality".to_string()];
        let args = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(args))
            .op(Option::from(SeccompCompareOp::LessOrEqual))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst =
            Rule::build_instruction_with_args(&Arch::AArch64, &rule, &"personality".to_string())
                .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                5,
                get_syscall_number(&Arch::AArch64, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGE | BPF_K, 0, 4, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGT | BPF_K, 0, 1, args.arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_greater_or_equal() {
        let syscall_vec = vec!["personality".to_string()];
        let args = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(args))
            .op(Option::from(SeccompCompareOp::GreaterOrEqual))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst = Rule::build_instruction_with_args(&Arch::X86, &rule, &"personality".to_string())
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                5,
                get_syscall_number(&Arch::X86, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGT | BPF_K, 4, 0, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 1, 0, args.arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_greater_or_equal() {
        let syscall_vec = vec!["personality".to_string()];
        let args = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(args))
            .op(Option::from(SeccompCompareOp::GreaterOrEqual))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst =
            Rule::build_instruction_with_args(&Arch::AArch64, &rule, &"personality".to_string())
                .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                5,
                get_syscall_number(&Arch::AArch64, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGT | BPF_K, 4, 0, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 1, 0, args.arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_greater_than() {
        let syscall_vec = vec!["personality".to_string()];
        let args = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(args))
            .op(Option::from(SeccompCompareOp::GreaterThan))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst = Rule::build_instruction_with_args(&Arch::X86, &rule, &"personality".to_string())
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                5,
                get_syscall_number(&Arch::X86, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGT | BPF_K, 4, 0, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 1, 0, args.arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_greater_than() {
        let syscall_vec = vec!["personality".to_string()];
        let args = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(args))
            .op(Option::from(SeccompCompareOp::GreaterThan))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst =
            Rule::build_instruction_with_args(&Arch::AArch64, &rule, &"personality".to_string())
                .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                5,
                get_syscall_number(&Arch::AArch64, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGT | BPF_K, 4, 0, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 1, 0, args.arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_masked_equal() {
        let syscall_vec = vec!["personality".to_string()];
        let args = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(args))
            .op(Option::from(SeccompCompareOp::MaskedEqual))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst = Rule::build_instruction_with_args(&Arch::X86, &rule, &"personality".to_string())
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                4,
                get_syscall_number(&Arch::X86, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JSET | BPF_K, 3, 0, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JSET | BPF_K, 1, 0, args.arg0 as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_masked_equal() {
        let syscall_vec = vec!["personality".to_string()];
        let args = SyscallArgs {
            arg0: 8,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let rule = RuleBuilder::default()
            .syscall(syscall_vec.clone())
            .action(SECCOMP_RET_ALLOW)
            .check_arg_syscall(syscall_vec.clone())
            .arg_cnt(1)
            .args(Option::from(args))
            .op(Option::from(SeccompCompareOp::MaskedEqual))
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.arg_cnt.unwrap()).unwrap();
        let inst =
            Rule::build_instruction_with_args(&Arch::AArch64, &rule, &"personality".to_string())
                .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                4,
                get_syscall_number(&Arch::AArch64, "personality").unwrap() as c_uint
            )
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JSET | BPF_K, 3, 0, (args.arg0 >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JSET | BPF_K, 1, 0, args.arg0 as c_uint)
        );
    }
}
