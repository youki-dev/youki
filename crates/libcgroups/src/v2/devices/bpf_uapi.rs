//! The part of the kernel's `bpf(2)` ABI that the device controller uses.
//!
//! Values and layouts are copied from `include/uapi/linux/bpf.h`. Only the leading fields of each
//! command's `union bpf_attr` member that this crate sets are declared: the kernel accepts an
//! attribute shorter than its own and reads the missing tail as zeroes, so each command is passed
//! `size_of` of the struct below. The `const` assertions pin every field to its kernel offset.
//! Defining these here keeps the crate free of a bindings dependency (the generated ones need a
//! newer Rust than libcgroups supports).

use std::mem::{offset_of, size_of};

// `enum bpf_cmd`
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_PROG_ATTACH: u32 = 8;
pub const BPF_PROG_DETACH: u32 = 9;
pub const BPF_PROG_GET_FD_BY_ID: u32 = 13;
pub const BPF_PROG_QUERY: u32 = 16;

// `enum bpf_prog_type`
pub const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;

// `enum bpf_attach_type`
pub const BPF_CGROUP_DEVICE: u32 = 6;

/// Allows several programs on one cgroup (`BPF_F_ALLOW_MULTI`).
pub const BPF_F_ALLOW_MULTI: u32 = 1 << 1;

// Device types and access bits of `struct bpf_cgroup_dev_ctx` (`BPF_DEVCG_*`).
pub const BPF_DEVCG_ACC_MKNOD: u32 = 1 << 0;
pub const BPF_DEVCG_ACC_READ: u32 = 1 << 1;
pub const BPF_DEVCG_ACC_WRITE: u32 = 1 << 2;
pub const BPF_DEVCG_DEV_BLOCK: u32 = 1 << 0;
pub const BPF_DEVCG_DEV_CHAR: u32 = 1 << 1;

/// `struct bpf_insn`. The kernel declares `dst_reg:4, src_reg:4` as bitfields sharing `regs`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BpfInsn {
    pub code: u8,
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

/// The `BPF_PROG_LOAD` member of `union bpf_attr`, up to `license`.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProgLoadAttr {
    pub prog_type: u32,
    pub insn_cnt: u32,
    /// `__aligned_u64 insns`
    pub insns: u64,
    /// `__aligned_u64 license`
    pub license: u64,
}

/// The `BPF_PROG_ATTACH` / `BPF_PROG_DETACH` member of `union bpf_attr`, up to `replace_bpf_fd`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProgAttachAttr {
    pub target_fd: u32,
    pub attach_bpf_fd: u32,
    pub attach_type: u32,
    pub attach_flags: u32,
    pub replace_bpf_fd: u32,
}

/// The `BPF_PROG_QUERY` member of `union bpf_attr`, up to `prog_cnt`.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProgQueryAttr {
    pub target_fd: u32,
    pub attach_type: u32,
    pub query_flags: u32,
    pub attach_flags: u32,
    /// `__aligned_u64 prog_ids`
    pub prog_ids: u64,
    pub prog_cnt: u32,
    /// The kernel's unnamed `__u32 :32` before `prog_attach_flags`.
    pub _pad: u32,
}

/// The `BPF_PROG_GET_FD_BY_ID` member of `union bpf_attr`, up to `open_flags`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProgGetFdByIdAttr {
    pub prog_id: u32,
    pub next_id: u32,
    pub open_flags: u32,
}

const _: () = {
    assert!(size_of::<BpfInsn>() == 8);
    assert!(offset_of!(BpfInsn, code) == 0);
    assert!(offset_of!(BpfInsn, regs) == 1);
    assert!(offset_of!(BpfInsn, off) == 2);
    assert!(offset_of!(BpfInsn, imm) == 4);

    assert!(size_of::<ProgLoadAttr>() == 24);
    assert!(offset_of!(ProgLoadAttr, prog_type) == 0);
    assert!(offset_of!(ProgLoadAttr, insn_cnt) == 4);
    assert!(offset_of!(ProgLoadAttr, insns) == 8);
    assert!(offset_of!(ProgLoadAttr, license) == 16);

    assert!(size_of::<ProgAttachAttr>() == 20);
    assert!(offset_of!(ProgAttachAttr, target_fd) == 0);
    assert!(offset_of!(ProgAttachAttr, attach_bpf_fd) == 4);
    assert!(offset_of!(ProgAttachAttr, attach_type) == 8);
    assert!(offset_of!(ProgAttachAttr, attach_flags) == 12);
    assert!(offset_of!(ProgAttachAttr, replace_bpf_fd) == 16);

    assert!(size_of::<ProgQueryAttr>() == 32);
    assert!(offset_of!(ProgQueryAttr, target_fd) == 0);
    assert!(offset_of!(ProgQueryAttr, attach_type) == 4);
    assert!(offset_of!(ProgQueryAttr, query_flags) == 8);
    assert!(offset_of!(ProgQueryAttr, attach_flags) == 12);
    assert!(offset_of!(ProgQueryAttr, prog_ids) == 16);
    assert!(offset_of!(ProgQueryAttr, prog_cnt) == 24);

    assert!(size_of::<ProgGetFdByIdAttr>() == 12);
    assert!(offset_of!(ProgGetFdByIdAttr, prog_id) == 0);
    assert!(offset_of!(ProgGetFdByIdAttr, next_id) == 4);
    assert!(offset_of!(ProgGetFdByIdAttr, open_flags) == 8);
};
