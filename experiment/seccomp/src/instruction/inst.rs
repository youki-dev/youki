use std::os::raw::{c_uchar, c_uint, c_ushort};
use crate::instruction::BPF_JMP;

// https://docs.kernel.org/networking/filter.html#structure
// <linux/filter.h>: sock_filter
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub code: c_ushort,
    pub offset_jump_true: c_uchar,
    pub offset_jump_false: c_uchar,
    pub multiuse_field: c_uint,
}

impl Instruction {
    fn new(
        code: c_ushort,
        jump_true: c_uchar,
        jump_false: c_uchar,
        multiuse_field: c_uint,
    ) -> Self {
        Instruction {
            code,
            offset_jump_true: jump_true,
            offset_jump_false: jump_false,
            multiuse_field,
        }
    }

    pub fn jump(
        code: c_ushort,
        jump_true: c_uchar,
        jump_false: c_uchar,
        multiuse_field: c_uint,
    ) -> Self {
        Self::new(code, jump_true, jump_false, multiuse_field)
    }

    pub fn stmt(code: c_ushort, k: c_uint) -> Self {
        Self::new(code, 0, 0, k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::*;

    #[test]
    fn test_bpf_instructions() {
        assert_eq!(
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, 16),
            Instruction {
                code: 0x20,
                offset_jump_true: 0,
                offset_jump_false: 0,
                multiuse_field: 16,
            }
        );
        assert_eq!(
            Instruction::jump(BPF_JMP | BPF_JEQ | BPF_K, 10, 2, 5),
            Instruction {
                code: 0x15,
                offset_jump_true: 10,
                offset_jump_false: 2,
                multiuse_field: 5,
            }
        );
    }
}
