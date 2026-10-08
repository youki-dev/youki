//! Checks the io_uring policy set by the contest `io_uring` test group:
//! NOP, READ and SOCKET allowed, sockets limited to AF_INET, provided-buffer
//! selection denied. A denied operation completes with -EACCES.

use io_uring::{IoUring, opcode, squeue, types};
use nix::libc;

/// Submits one SQE and returns its CQE result.
fn submit(ring: &mut IoUring, entry: squeue::Entry) -> std::io::Result<i32> {
    // SAFETY: the entry references no buffers that outlive this call; reads
    // are zero-length or use buffer selection.
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

    let checks: Vec<(&str, squeue::Entry, bool)> = vec![
        ("nop", opcode::Nop::new().build(), true),
        (
            "read",
            opcode::Read::new(types::Fd(0), std::ptr::null_mut(), 0).build(),
            true,
        ),
        (
            "read with IOSQE_BUFFER_SELECT",
            opcode::Read::new(types::Fd(0), std::ptr::null_mut(), 64)
                .buf_group(0)
                .build()
                .flags(squeue::Flags::BUFFER_SELECT),
            false,
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
