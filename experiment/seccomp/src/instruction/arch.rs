use crate::instruction::Instruction;
use crate::instruction::*;

#[derive(PartialEq, Debug)]
pub enum Arch {
    X86,AArch64
}

pub fn gen_validate(arc: &Arch) -> Vec<Instruction> {
    let arch = match arc {
        Arch::X86 => AUDIT_ARCH_X86_64,
        Arch::AArch64 => AUDIT_ARCH_AARCH64
    };

    vec![
        Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, seccomp_data_arch_offset() as u32),
        Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, arch),
        Instruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_validate_x86() {
        let bpf_prog = gen_validate(&Arch::X86);
        assert_eq!(bpf_prog[0], Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, seccomp_data_arch_offset() as u32));
        assert_eq!(bpf_prog[1], Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_X86_64));
        assert_eq!(bpf_prog[2], Instruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }

    #[test]
    fn test_gen_validate_aarch64() {
        let bpf_prog = gen_validate(&Arch::AArch64);
        assert_eq!(bpf_prog[0], Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, seccomp_data_arch_offset() as u32));
        assert_eq!(bpf_prog[1], Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_AARCH64));
        assert_eq!(bpf_prog[2], Instruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }
}