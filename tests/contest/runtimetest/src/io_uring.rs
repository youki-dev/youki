//! Checks the io_uring policy set by the contest `io_uring` test group:
//! NOP, READ and SOCKET allowed, sockets limited to AF_INET. A denied
//! operation completes with -EACCES. Whether an operation is allowed must not
//! depend on its SQE flags.

use std::os::fd::AsRawFd;

use io_uring::{IoUring, opcode, squeue, types};
use nix::libc;

/// Submits one SQE and returns its CQE result.
fn submit(ring: &mut IoUring, entry: squeue::Entry) -> std::io::Result<i32> {
    // SAFETY: the entry references no buffers that outlive this call; reads
    // are zero-length or take a provided buffer from the kernel.
    unsafe { ring.submission().push(&entry) }.map_err(std::io::Error::other)?;
    ring.submit_and_wait(1)?;
    Ok(ring
        .completion()
        .next()
        .ok_or_else(|| std::io::Error::other("no completion"))?
        .result())
}

pub fn validate_io_uring() {
    let mut ring = match IoUring::new(4) {
        Ok(ring) => ring,
        Err(e) => return eprintln!("io_uring_setup failed: {e}"),
    };
    // A regular file, so that a read with buffer selection fails at once
    // (no buffers: -ENOBUFS) instead of waiting for data.
    let file = match std::fs::File::open("/proc/self/exe") {
        Ok(file) => file,
        Err(e) => return eprintln!("open /proc/self/exe failed: {e}"),
    };

    let checks: Vec<(&str, squeue::Entry, bool)> = vec![
        ("nop", opcode::Nop::new().build(), true),
        (
            "read",
            opcode::Read::new(types::Fd(0), std::ptr::null_mut(), 0).build(),
            true,
        ),
        (
            "read with IOSQE_BUFFER_SELECT",
            opcode::Read::new(types::Fd(file.as_raw_fd()), std::ptr::null_mut(), 64)
                .buf_group(0)
                .build()
                .flags(squeue::Flags::BUFFER_SELECT),
            true,
        ),
        (
            "socket AF_INET",
            opcode::Socket::new(libc::AF_INET, libc::SOCK_STREAM, 0).build(),
            true,
        ),
        (
            "socket AF_UNIX",
            opcode::Socket::new(libc::AF_UNIX, libc::SOCK_STREAM, 0).build(),
            false,
        ),
        (
            "write",
            opcode::Write::new(types::Fd(1), std::ptr::null(), 0).build(),
            false,
        ),
    ];

    for (name, entry, allowed) in checks {
        let res = match submit(&mut ring, entry) {
            Ok(res) => res,
            Err(e) => return eprintln!("io_uring {name}: submit failed: {e}"),
        };
        let denied = res == -libc::EACCES;
        if allowed && denied {
            eprintln!("io_uring {name} was denied, expected it to be allowed");
        } else if !allowed && !denied {
            eprintln!("io_uring {name} returned {res}, expected -EACCES");
        }
        if res > 2 && name.starts_with("socket") {
            // SAFETY: a socket fd the kernel just returned to us.
            unsafe { libc::close(res) };
        }
    }
}
