use std::{mem::offset_of, os::raw::c_int};

// BPF Instruction classes.
// See /usr/include/linux/bpf_common.h .
// Load operation.
pub const BPF_LD: u16 = 0x00;
// ALU operation.
pub const BPF_ALU: u16 = 0x04;
// Jump operation.
pub const BPF_JMP: u16 = 0x05;
// Return operation.
pub const BPF_RET: u16 = 0x06;

// BPF ld/ldx fields.
// See /usr/include/linux/bpf_common.h .
// Operand size is a word.
pub const BPF_W: u16 = 0x00;
// Load from data area (where `seccomp_data` is).
pub const BPF_ABS: u16 = 0x20;

// BPF alu fields.
// See /usr/include/linux/bpf_common.h .
pub const BPF_AND: u16 = 0x50;

// BPF jmp fields.
// See /usr/include/linux/bpf_common.h .
// Unconditional jump.
pub const BPF_JA: u16 = 0x00;
// Jump with comparisons.
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
// Test against the value in the K register.
pub const BPF_K: u16 = 0x00;

// Return codes for BPF programs.
// See /usr/include/linux/seccomp.h .
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
pub const SECCOMP_RET_MASK: u32 = 0x0000_ffff;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;

// Architecture identifiers.
// See /usr/include/linux/audit.h .
pub const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;
pub const AUDIT_ARCH_AARCH64: u32 = 183 | 0x8000_0000 | 0x4000_0000;

// ```c
// struct seccomp_data {
//     int nr;
//     __u32 arch;
//     __u64 instruction_pointer;
//     __u64 args[6];
// };
// ```

#[repr(C)]
struct SeccompData {
    nr: c_int,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

pub const fn seccomp_data_arch_offset() -> u8 {
    offset_of!(SeccompData, arch) as u8
}

pub const fn seccomp_data_arg_size() -> u8 {
    8
}

pub const fn seccomp_data_args_offset() -> u8 {
    offset_of!(SeccompData, args) as u8
}

pub const SECCOMP_IOC_MAGIC: u8 = b'!';

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_data_arch_offset() {
        if cfg!(target_arch = "x86_64") {
            assert_eq!(seccomp_data_arch_offset(), 4);
        }
    }

    #[test]
    fn test_seccomp_data_arg_size_offset() {
        if cfg!(target_arch = "x86_64") {
            assert_eq!(seccomp_data_arg_size(), 8);
        }
    }

    #[test]
    fn test_seccomp_data_args_offset() {
        if cfg!(target_arch = "x86_64") {
            assert_eq!(seccomp_data_args_offset(), 16);
        }
    }
}
