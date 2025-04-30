use std::os::raw::c_uchar;
use nix::errno::Errno::ENOSYS;
use crate::instruction::Instruction;
use crate::instruction::*;

#[derive(PartialEq, Debug, Default)]
pub enum Arch {
    #[default]
    X86,
    AArch64,
}

pub fn gen_validate(arc: &Arch, jump_num: usize) -> Vec<Instruction> {
    let arch = match arc {
        Arch::X86 => AUDIT_ARCH_X86_64,
        Arch::AArch64 => AUDIT_ARCH_AARCH64,
    };

    vec![
        //  load offset architecture
        Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, seccomp_data_arch_offset() as u32),
        // if not match architecture, jump to default action
        Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 0, (jump_num + 3) as c_uchar, arch),
        // load offset system call number
        Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, seccomp_data_nr_offset() as u32),
        // check system call is not using 32bit ABI
        // see https://github.com/elastic/go-seccomp-bpf/blob/main/filter.go#L231
        Instruction::jump(BPF_JMP | BPF_JGE | BPF_K, 0, 1, X32_SYSCALL_BIT),
        Instruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS as u32),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_validate_x86() {
        let bpf_prog = gen_validate(&Arch::X86);
        assert_eq!(
            bpf_prog[0],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, seccomp_data_arch_offset() as u32)
        );
        assert_eq!(
            bpf_prog[1],
            Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_X86_64)
        );
        assert_eq!(
            bpf_prog[2],
            Instruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
        );
    }

    #[test]
    fn test_gen_validate_aarch64() {
        let bpf_prog = gen_validate(&Arch::AArch64);
        assert_eq!(
            bpf_prog[0],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, seccomp_data_arch_offset() as u32)
        );
        assert_eq!(
            bpf_prog[1],
            Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_AARCH64)
        );
        assert_eq!(
            bpf_prog[2],
            Instruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
        );
    }
}
