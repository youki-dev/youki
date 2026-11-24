//! The `bpf(2)` commands the device controller uses, issued directly with `libc::syscall`.
//!
//! The kernel ABI types come from `aya-obj` (pure Rust bindings generated from the kernel
//! headers), so no C library (libbpf) is built or linked. Each function follows the libbpf
//! function of the same name: it returns a negative value and leaves `errno` set on failure.

use std::ffi::CStr;
use std::mem;
use std::os::raw::{c_int, c_uint};

use aya_obj::generated::{bpf_attach_type, bpf_attr, bpf_cmd, bpf_insn, bpf_prog_type};

/// Attempts at `BPF_PROG_LOAD` while the verifier answers `EAGAIN` (a signal was pending), as in
/// libbpf.
const PROG_LOAD_ATTEMPTS: usize = 5;

/// # Safety
/// Every pointer stored in `attr` must be valid for the command for the duration of the call.
unsafe fn sys_bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> c_int {
    // SAFETY: `attr` is a fully initialised `bpf_attr` of the size the kernel is told; the
    // caller guarantees the pointers inside it.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as c_int,
            attr as *mut bpf_attr,
            mem::size_of::<bpf_attr>(),
        )
    };
    // The command results used here (0 or a file descriptor) fit in a c_int.
    ret as c_int
}

fn zeroed_attr() -> bpf_attr {
    // SAFETY: `bpf_attr` is a plain C union of integers and arrays; all zeroes is the value the
    // kernel expects for every field that is not set.
    unsafe { mem::zeroed() }
}

/// Loads a program of `prog_type` from `insns_cnt` instructions; returns its file descriptor.
///
/// # Safety
/// `insns` must point to `insns_cnt` valid instructions.
pub unsafe fn bpf_prog_load(
    prog_type: bpf_prog_type,
    license: &CStr,
    insns: *const bpf_insn,
    insns_cnt: usize,
) -> c_int {
    let Ok(insns_cnt) = u32::try_from(insns_cnt) else {
        errno::set_errno(errno::Errno(libc::E2BIG));
        return -1;
    };
    let mut attr = zeroed_attr();
    // SAFETY: writing plain integer fields of the union variant this command reads.
    unsafe {
        let load = &mut attr.__bindgen_anon_3;
        load.prog_type = prog_type as u32;
        load.insns = insns as u64;
        load.insn_cnt = insns_cnt;
        load.license = license.as_ptr() as u64;
    }
    for _ in 1..PROG_LOAD_ATTEMPTS {
        // SAFETY: `insns` and `license` outlive the call (caller contract and borrow).
        let fd = unsafe { sys_bpf(bpf_cmd::BPF_PROG_LOAD, &mut attr) };
        if fd >= 0 || errno::errno().0 != libc::EAGAIN {
            return fd;
        }
    }
    // SAFETY: as above.
    unsafe { sys_bpf(bpf_cmd::BPF_PROG_LOAD, &mut attr) }
}

/// Lists the programs of `attach_type` attached to `target_fd`.
///
/// On entry `*prog_cnt` is the capacity of `prog_ids`; on return it is the number of attached
/// programs, also when the call fails with `ENOSPC` because the buffer is too small.
///
/// # Safety
/// `prog_ids` must be valid for `*prog_cnt` writes; `attach_flags` and `prog_cnt` must be valid.
pub unsafe fn bpf_prog_query(
    target_fd: c_int,
    attach_type: bpf_attach_type,
    query_flags: u32,
    attach_flags: *mut u32,
    prog_ids: *mut u32,
    prog_cnt: *mut u32,
) -> c_int {
    let mut attr = zeroed_attr();
    // SAFETY: plain integer fields of the variant this command reads; `prog_cnt` is valid.
    unsafe {
        let query = &mut attr.query;
        query.__bindgen_anon_1.target_fd = target_fd as u32;
        query.attach_type = attach_type as u32;
        query.query_flags = query_flags;
        query.__bindgen_anon_2.prog_cnt = *prog_cnt;
        query.prog_ids = prog_ids as u64;
    }
    // SAFETY: `prog_ids` is valid for the announced count (caller contract).
    let ret = unsafe { sys_bpf(bpf_cmd::BPF_PROG_QUERY, &mut attr) };
    // SAFETY: the kernel wrote back the count and flags; the out pointers are valid.
    unsafe {
        *prog_cnt = attr.query.__bindgen_anon_2.prog_cnt;
        *attach_flags = attr.query.attach_flags;
    }
    ret
}

/// Opens a new file descriptor for the program with ID `id`.
pub fn bpf_prog_get_fd_by_id(id: u32) -> c_int {
    let mut attr = zeroed_attr();
    attr.__bindgen_anon_6.__bindgen_anon_1.prog_id = id;
    // SAFETY: the command reads only the program ID.
    unsafe { sys_bpf(bpf_cmd::BPF_PROG_GET_FD_BY_ID, &mut attr) }
}

fn prog_attach_attr(
    prog_fd: c_int,
    attachable_fd: c_int,
    attach_type: bpf_attach_type,
    flags: c_uint,
) -> bpf_attr {
    let mut attr = zeroed_attr();
    // SAFETY: writing plain integer fields of the union variant these commands read.
    unsafe {
        let attach = &mut attr.__bindgen_anon_5;
        attach.__bindgen_anon_1.target_fd = attachable_fd as u32;
        attach.attach_bpf_fd = prog_fd as u32;
        attach.attach_type = attach_type as u32;
        attach.attach_flags = flags;
    }
    attr
}

/// Detaches program `prog_fd` of `attach_type` from `attachable_fd`.
pub fn bpf_prog_detach2(
    prog_fd: c_int,
    attachable_fd: c_int,
    attach_type: bpf_attach_type,
) -> c_int {
    let mut attr = prog_attach_attr(prog_fd, attachable_fd, attach_type, 0);
    // SAFETY: the command reads only file descriptors and integers.
    unsafe { sys_bpf(bpf_cmd::BPF_PROG_DETACH, &mut attr) }
}

/// Attaches program `prog_fd` to `attachable_fd` as `attach_type`, with `flags`.
///
/// The attachment is not tied to a file descriptor of this process (unlike a BPF link), so it
/// stays after the runtime exits, as the device filter of a container must.
pub fn bpf_prog_attach(
    prog_fd: c_int,
    attachable_fd: c_int,
    attach_type: bpf_attach_type,
    flags: c_uint,
) -> c_int {
    let mut attr = prog_attach_attr(prog_fd, attachable_fd, attach_type, flags);
    // SAFETY: the command reads only file descriptors and integers.
    unsafe { sys_bpf(bpf_cmd::BPF_PROG_ATTACH, &mut attr) }
}
