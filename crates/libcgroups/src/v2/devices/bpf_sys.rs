//! The `bpf(2)` commands the device controller uses, issued directly with `libc::syscall`.
//!
//! The kernel ABI types are declared in `bpf_uapi`, so no C library (libbpf) is built or linked.
//! Each function follows the libbpf function of the same name: it returns a negative value and
//! leaves `errno` set on failure.

use std::ffi::CStr;
use std::mem;
use std::os::raw::{c_int, c_uint};

use super::bpf_uapi::{
    ATTR_BUF_SIZE, AttrBuf, BPF_PROG_ATTACH, BPF_PROG_DETACH, BPF_PROG_GET_FD_BY_ID, BPF_PROG_LOAD,
    BPF_PROG_QUERY, BpfInsn, ProgAttachAttr, ProgGetFdByIdAttr, ProgLoadAttr, ProgQueryAttr,
};

/// Attempts at `BPF_PROG_LOAD` while the verifier answers `EAGAIN` (a signal was pending), as in
/// libbpf.
const PROG_LOAD_ATTEMPTS: usize = 5;

/// What the kernel is asked: the command and the attribute bytes, `size_of` the attr struct.
#[cfg(test)]
type SyscallHook = Box<dyn FnMut(u32, &mut [u8]) -> c_int>;

#[cfg(test)]
thread_local! {
    /// Replaces the raw syscall in test builds, per thread.
    static SYSCALL_HOOK: std::cell::RefCell<Option<SyscallHook>> =
        std::cell::RefCell::new(None);
}

/// # Safety
/// `attr` must be valid for the command, including every pointer stored in it, for the duration
/// of the call.
#[cfg(not(test))]
unsafe fn raw_bpf(cmd: u32, attr: *mut u8, size: usize) -> c_int {
    // SAFETY: the caller guarantees `attr` and the pointers inside it.
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd as c_int, attr, size) };
    // The command results used here (0 or a file descriptor) fit in a c_int.
    ret as c_int
}

#[cfg(test)]
unsafe fn raw_bpf(cmd: u32, attr: *mut u8, size: usize) -> c_int {
    // SAFETY: `attr` points to a live attr struct of `size` bytes.
    let bytes = unsafe { std::slice::from_raw_parts_mut(attr, size) };
    SYSCALL_HOOK.with(|hook| {
        let mut hook = hook.borrow_mut();
        let hook = hook.as_mut().expect("no syscall hook installed");
        hook(cmd, bytes)
    })
}

/// Issues `cmd` from a zeroed `ATTR_BUF_SIZE` buffer holding `attr` at its start, then copies the
/// struct's part of the buffer back into `attr`.
///
/// The kernel writes results back through the pointer whatever size it is given (see
/// `bpf_uapi`), so the buffer, not the caller's struct, is what it gets to write into.
///
/// # Safety
/// `T` must be a `repr(C)` struct of plain integers, and every pointer stored in `attr` must be
/// valid for the command for the duration of the call.
unsafe fn sys_bpf<T: Copy>(cmd: u32, attr: &mut T) -> c_int {
    const { assert!(mem::size_of::<T>() <= ATTR_BUF_SIZE) };
    let mut buf = AttrBuf([0; ATTR_BUF_SIZE]);
    // SAFETY: `T` fits in the buffer (asserted above), which is zeroed and 8-byte aligned.
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::from_ref(attr).cast::<u8>(),
            buf.0.as_mut_ptr(),
            mem::size_of::<T>(),
        );
    }
    // SAFETY: `buf` is `ATTR_BUF_SIZE` bytes; the caller guarantees the pointers inside it.
    let ret = unsafe { raw_bpf(cmd, buf.0.as_mut_ptr(), ATTR_BUF_SIZE) };
    // SAFETY: as above; the kernel's results for the fields of `T` are plain integers.
    unsafe {
        std::ptr::copy_nonoverlapping(
            buf.0.as_ptr(),
            std::ptr::from_mut(attr).cast::<u8>(),
            mem::size_of::<T>(),
        );
    }
    ret
}

/// Loads a program of `prog_type` from `insns_cnt` instructions; returns its file descriptor.
///
/// # Safety
/// `insns` must point to `insns_cnt` valid instructions.
pub unsafe fn bpf_prog_load(
    prog_type: u32,
    license: &CStr,
    insns: *const BpfInsn,
    insns_cnt: usize,
) -> c_int {
    let Ok(insns_cnt) = u32::try_from(insns_cnt) else {
        errno::set_errno(errno::Errno(libc::E2BIG));
        return -1;
    };
    let mut attr = ProgLoadAttr {
        prog_type,
        insn_cnt: insns_cnt,
        insns: insns as u64,
        license: license.as_ptr() as u64,
    };
    for _ in 1..PROG_LOAD_ATTEMPTS {
        // SAFETY: `insns` and `license` outlive the call (caller contract and borrow).
        let fd = unsafe { sys_bpf(BPF_PROG_LOAD, &mut attr) };
        if fd >= 0 || errno::errno().0 != libc::EAGAIN {
            return fd;
        }
    }
    // SAFETY: as above.
    unsafe { sys_bpf(BPF_PROG_LOAD, &mut attr) }
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
    attach_type: u32,
    query_flags: u32,
    attach_flags: *mut u32,
    prog_ids: *mut u32,
    prog_cnt: *mut u32,
) -> c_int {
    let mut attr = ProgQueryAttr {
        target_fd: target_fd as u32,
        attach_type,
        query_flags,
        // SAFETY: `prog_cnt` is valid (caller contract).
        prog_cnt: unsafe { *prog_cnt },
        prog_ids: prog_ids as u64,
        ..ProgQueryAttr::default()
    };
    // SAFETY: `prog_ids` is valid for the announced count (caller contract).
    let ret = unsafe { sys_bpf(BPF_PROG_QUERY, &mut attr) };
    // SAFETY: the kernel wrote back the count and flags; the out pointers are valid.
    unsafe {
        *prog_cnt = attr.prog_cnt;
        *attach_flags = attr.attach_flags;
    }
    ret
}

/// Opens a new file descriptor for the program with ID `id`.
pub fn bpf_prog_get_fd_by_id(id: u32) -> c_int {
    let mut attr = ProgGetFdByIdAttr {
        prog_id: id,
        ..ProgGetFdByIdAttr::default()
    };
    // SAFETY: the command reads only the program ID.
    unsafe { sys_bpf(BPF_PROG_GET_FD_BY_ID, &mut attr) }
}

fn prog_attach_attr(
    prog_fd: c_int,
    attachable_fd: c_int,
    attach_type: u32,
    flags: c_uint,
) -> ProgAttachAttr {
    ProgAttachAttr {
        target_fd: attachable_fd as u32,
        attach_bpf_fd: prog_fd as u32,
        attach_type,
        attach_flags: flags,
        replace_bpf_fd: 0,
    }
}

/// Detaches program `prog_fd` of `attach_type` from `attachable_fd`.
pub fn bpf_prog_detach2(prog_fd: c_int, attachable_fd: c_int, attach_type: u32) -> c_int {
    let mut attr = prog_attach_attr(prog_fd, attachable_fd, attach_type, 0);
    // SAFETY: the command reads only file descriptors and integers.
    unsafe { sys_bpf(BPF_PROG_DETACH, &mut attr) }
}

/// Attaches program `prog_fd` to `attachable_fd` as `attach_type`, with `flags`.
///
/// The attachment is not tied to a file descriptor of this process (unlike a BPF link), so it
/// stays after the runtime exits, as the device filter of a container must.
pub fn bpf_prog_attach(
    prog_fd: c_int,
    attachable_fd: c_int,
    attach_type: u32,
    flags: c_uint,
) -> c_int {
    let mut attr = prog_attach_attr(prog_fd, attachable_fd, attach_type, flags);
    // SAFETY: the command reads only file descriptors and integers.
    unsafe { sys_bpf(BPF_PROG_ATTACH, &mut attr) }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::ptr;
    use std::rc::Rc;

    use super::*;
    use crate::v2::devices::bpf_uapi::{BPF_CGROUP_DEVICE, BPF_F_ALLOW_MULTI};

    fn install(hook: impl FnMut(u32, &mut [u8]) -> c_int + 'static) {
        SYSCALL_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    fn fail(errno_value: c_int) -> c_int {
        errno::set_errno(errno::Errno(errno_value));
        -1
    }

    /// Reads the attr bytes back as the struct the command was sent with.
    fn decode<T: Copy>(bytes: &[u8]) -> T {
        assert_eq!(
            bytes.len(),
            ATTR_BUF_SIZE,
            "the kernel is given the full buffer"
        );
        assert!(bytes[mem::size_of::<T>()..].iter().all(|b| *b == 0));
        // SAFETY: the length was checked; the structs are plain integers.
        unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
    }

    fn encode<T: Copy>(value: &T, bytes: &mut [u8]) {
        assert!(bytes.len() >= mem::size_of::<T>());
        // SAFETY: the length was checked; the structs are plain integers.
        unsafe { ptr::write_unaligned(bytes.as_mut_ptr().cast::<T>(), *value) }
    }

    #[test]
    fn prog_load_encodes_the_attr() {
        let insns = [BpfInsn::default(); 3];
        let license = c"GPL";
        let seen = Rc::new(RefCell::new(None));
        let sink = seen.clone();
        install(move |cmd, bytes| {
            *sink.borrow_mut() = Some((cmd, decode::<ProgLoadAttr>(bytes)));
            7
        });

        let fd = unsafe { bpf_prog_load(15, license, insns.as_ptr(), insns.len()) };

        assert_eq!(fd, 7);
        let (cmd, attr) = seen.borrow().unwrap();
        assert_eq!(cmd, BPF_PROG_LOAD);
        assert_eq!(attr.prog_type, 15);
        assert_eq!(attr.insn_cnt, 3);
        assert_eq!(attr.insns, insns.as_ptr() as u64);
        assert_eq!(attr.license, license.as_ptr() as u64);
    }

    #[test]
    fn prog_load_rejects_too_many_instructions() {
        install(|_, _| panic!("must not reach the kernel"));
        let fd = unsafe { bpf_prog_load(15, c"GPL", ptr::null(), u32::MAX as usize + 1) };
        assert_eq!(fd, -1);
        assert_eq!(errno::errno().0, libc::E2BIG);
    }

    #[test]
    fn prog_load_succeeds_after_eagain() {
        let calls = Rc::new(Cell::new(0));
        let counter = calls.clone();
        install(move |_, _| {
            counter.set(counter.get() + 1);
            if counter.get() < 3 {
                fail(libc::EAGAIN)
            } else {
                9
            }
        });

        let fd = unsafe { bpf_prog_load(15, c"GPL", ptr::null(), 0) };

        assert_eq!(fd, 9);
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn prog_load_returns_other_errors_at_once() {
        let calls = Rc::new(Cell::new(0));
        let counter = calls.clone();
        install(move |_, _| {
            counter.set(counter.get() + 1);
            fail(libc::EPERM)
        });

        let fd = unsafe { bpf_prog_load(15, c"GPL", ptr::null(), 0) };

        assert_eq!(fd, -1);
        assert_eq!(errno::errno().0, libc::EPERM);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn prog_load_gives_up_after_five_eagain() {
        let calls = Rc::new(Cell::new(0));
        let counter = calls.clone();
        install(move |_, _| {
            counter.set(counter.get() + 1);
            fail(libc::EAGAIN)
        });

        let fd = unsafe { bpf_prog_load(15, c"GPL", ptr::null(), 0) };

        assert_eq!(fd, -1);
        assert_eq!(errno::errno().0, libc::EAGAIN);
        assert_eq!(calls.get(), PROG_LOAD_ATTEMPTS);
    }

    #[test]
    fn attach_and_detach_encode_the_attr() {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let sink = seen.clone();
        install(move |cmd, bytes| {
            sink.borrow_mut()
                .push((cmd, decode::<ProgAttachAttr>(bytes)));
            0
        });

        assert_eq!(
            bpf_prog_attach(11, 12, BPF_CGROUP_DEVICE, BPF_F_ALLOW_MULTI),
            0
        );
        assert_eq!(bpf_prog_detach2(11, 12, BPF_CGROUP_DEVICE), 0);

        let seen = seen.borrow();
        let (cmd, attach) = seen[0];
        assert_eq!(cmd, BPF_PROG_ATTACH);
        assert_eq!(attach.target_fd, 12);
        assert_eq!(attach.attach_bpf_fd, 11);
        assert_eq!(attach.attach_type, BPF_CGROUP_DEVICE);
        assert_eq!(attach.attach_flags, BPF_F_ALLOW_MULTI);
        assert_eq!(attach.replace_bpf_fd, 0);
        let (cmd, detach) = seen[1];
        assert_eq!(cmd, BPF_PROG_DETACH);
        assert_eq!(detach.target_fd, 12);
        assert_eq!(detach.attach_bpf_fd, 11);
        assert_eq!(detach.attach_type, BPF_CGROUP_DEVICE);
        assert_eq!(detach.attach_flags, 0);
    }

    #[test]
    fn get_fd_by_id_encodes_the_attr() {
        let seen = Rc::new(RefCell::new(None));
        let sink = seen.clone();
        install(move |cmd, bytes| {
            *sink.borrow_mut() = Some((cmd, decode::<ProgGetFdByIdAttr>(bytes)));
            21
        });

        assert_eq!(bpf_prog_get_fd_by_id(42), 21);

        let (cmd, attr) = seen.borrow().unwrap();
        assert_eq!(cmd, BPF_PROG_GET_FD_BY_ID);
        assert_eq!(attr.prog_id, 42);
        assert_eq!(attr.next_id, 0);
        assert_eq!(attr.open_flags, 0);
    }

    #[test]
    fn query_encodes_the_attr_and_writes_back_results() {
        let seen = Rc::new(RefCell::new(None));
        let sink = seen.clone();
        install(move |cmd, bytes| {
            let mut attr = decode::<ProgQueryAttr>(bytes);
            *sink.borrow_mut() = Some((cmd, attr));
            attr.prog_cnt = 2;
            attr.attach_flags = BPF_F_ALLOW_MULTI;
            encode(&attr, bytes);
            // Recent kernels also store `revision` at offset 56.
            bytes[56..64].copy_from_slice(&7_u64.to_ne_bytes());
            0
        });
        let mut ids = [0_u32; 4];
        let mut cnt = ids.len() as u32;
        let mut flags = 0_u32;

        let ret = unsafe {
            bpf_prog_query(
                5,
                BPF_CGROUP_DEVICE,
                0,
                &mut flags,
                ids.as_mut_ptr(),
                &mut cnt,
            )
        };

        assert_eq!(ret, 0);
        let (cmd, attr) = seen.borrow().unwrap();
        assert_eq!(cmd, BPF_PROG_QUERY);
        assert_eq!(attr.target_fd, 5);
        assert_eq!(attr.attach_type, BPF_CGROUP_DEVICE);
        assert_eq!(attr.query_flags, 0);
        assert_eq!(attr.prog_cnt, 4);
        assert_eq!(attr.prog_ids, ids.as_ptr() as u64);
        assert_eq!(cnt, 2);
        assert_eq!(flags, BPF_F_ALLOW_MULTI);
    }

    #[test]
    fn query_reports_the_needed_count_on_enospc() {
        install(|_, bytes| {
            let mut attr = decode::<ProgQueryAttr>(bytes);
            attr.prog_cnt = 70;
            attr.attach_flags = BPF_F_ALLOW_MULTI;
            encode(&attr, bytes);
            bytes[56..64].copy_from_slice(&7_u64.to_ne_bytes());
            fail(libc::ENOSPC)
        });
        let mut ids = [0_u32; 1];
        let mut cnt = 1_u32;
        let mut flags = 0_u32;

        let ret = unsafe {
            bpf_prog_query(
                5,
                BPF_CGROUP_DEVICE,
                0,
                &mut flags,
                ids.as_mut_ptr(),
                &mut cnt,
            )
        };

        assert_eq!(ret, -1);
        assert_eq!(errno::errno().0, libc::ENOSPC);
        assert_eq!(cnt, 70);
        assert_eq!(flags, BPF_F_ALLOW_MULTI);
    }

    #[test]
    fn kernel_writes_never_leave_the_buffer() {
        // The fake kernel scribbles over everything it is given; the bytes next to the
        // caller's struct must survive, and only the struct's own fields are read back.
        #[repr(C)]
        struct Guarded {
            attr: ProgQueryAttr,
            guard: [u8; 64],
        }
        install(|_, bytes| {
            bytes.fill(0xFF);
            0
        });
        let mut guarded = Guarded {
            attr: ProgQueryAttr::default(),
            guard: [0xA5; 64],
        };

        let ret = unsafe { sys_bpf(BPF_PROG_QUERY, &mut guarded.attr) };

        assert_eq!(ret, 0);
        assert_eq!(guarded.guard, [0xA5; 64]);
        assert_eq!(guarded.attr.revision, u64::MAX);
    }
}
