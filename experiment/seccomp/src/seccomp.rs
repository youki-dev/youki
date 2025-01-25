use core::fmt;
use std::{
    mem::MaybeUninit,
    os::{
        raw::{c_long, c_uint, c_ulong, c_ushort, c_void},
        unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    },
};

use std::str::FromStr;
use nix::{
    errno::Errno,
    ioctl_readwrite, ioctl_write_ptr, libc,
    libc::{SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_SET_MODE_FILTER},
    unistd,
};
use syscalls::{SyscallArgs};
use crate::instruction::{*};
use crate::instruction::{Arch, Instruction, SECCOMP_IOC_MAGIC};

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("Failed to apply seccomp rules: {0}")]
    Apply(String),
}

pub struct Seccomp {
    pub filters: Vec<Instruction>,
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
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
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
        Arch::X86 => {
            match syscalls::x86_64::Sysno::from_str(name) {
                Ok(syscall) => Some(syscall as u64),
                Err(_) => None,
            }
        },
        Arch::AArch64 => {
            match syscalls::aarch64::Sysno::from_str(name) {
                Ok(syscall) => Some(syscall as u64),
                Err(_) => None,
            }
        }
    }
}

#[derive(Debug)]
pub struct InstructionData {
    pub arc: Arch,
    pub def_action: u32,
    pub rule_arr: Vec<Rule>
}

impl From<InstructionData> for Vec<Instruction> {
    fn from(inst_data: InstructionData) -> Self {
        let mut bpf_prog = gen_validate(&inst_data.arc);

        for rule in &inst_data.rule_arr {
            bpf_prog.append(&mut Rule::to_instruction(&inst_data.arc, inst_data.def_action, rule));
        }

        bpf_prog.append(&mut vec![Instruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)]);
        bpf_prog
    }
}

#[derive(Debug)]
pub struct Rule {
    pub syscall: String,
    pub arg_cnt: u8,
    pub args: SyscallArgs,
    pub is_notify: bool
}

impl Rule {
    pub fn new(syscall: String, arg_cnt: u8, args: SyscallArgs, is_notify: bool) -> Self {
        Self {
            syscall,
            arg_cnt,
            args,
            is_notify,
        }
    }

    pub fn to_instruction(arch: &Arch, action: u32, rule: &Rule) -> Vec<Instruction> {
        let mut bpf_prog = gen_validate(arch);
        bpf_prog.append(&mut vec![Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, 0)]);
        bpf_prog.append(&mut vec![Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1,
                                                    get_syscall_number(arch, &rule.syscall).unwrap() as c_uint)]);
        if rule.arg_cnt != 0 {
            bpf_prog.append(&mut vec![Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, seccomp_data_args_offset().into())]);
            bpf_prog.append(&mut vec![Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, rule.args.arg0 as c_uint)]);
        }

        if rule.is_notify {
            bpf_prog.append(&mut vec![Instruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)]);
        } else {
            bpf_prog.append(&mut vec![Instruction::stmt(BPF_RET | BPF_K, action)]);
        }
        bpf_prog
    }
}

#[cfg(test)]
mod tests {
    use syscalls::syscall_args;
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
    fn test_to_instruction_x86() {
        let rule = Rule::new("getcwd".parse().unwrap(), 0, syscall_args!(), false);
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
        let rule = Rule::new("getcwd".parse().unwrap(), 0, syscall_args!(), false);
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