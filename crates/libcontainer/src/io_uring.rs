//! Experimental: restrict which io_uring operations a container may run.
//!
//! seccomp can't see io_uring operations: they are submitted through a ring
//! in shared memory, not as syscalls. That is why container runtimes block
//! io_uring entirely. Linux 7.0 added task-level io_uring restrictions with
//! classic BPF filters per opcode, which are inherited across fork and exec
//! and can only be tightened, like seccomp. This module applies such a policy
//! to the container's init process before it execs the workload.
//!
//! The kernel must have bc0e8faf90e7 ("io_uring: preserve task restrictions
//! across exec"): mainline 7.2, or a 7.0/7.1 kernel with the backport. Without
//! it, a task that has used io_uring loses its restrictions when it execs, so
//! the workload can drop the policy. [`supported`] doesn't detect this: the
//! fix is backported without a version change (Ubuntu 26.04: 7.0.0-39), and a
//! reliable check would have to exec a helper program.
//!
//! Until the OCI runtime spec has a field for this, the policy is read from
//! the `dev.youki.io_uring` annotation as JSON, in the shape proposed for
//! `linux.ioUring` (opencontainers/runtime-spec#1323):
//!
//! ```json
//! {
//!   "ops": ["IORING_OP_READ", "IORING_OP_WRITE", "IORING_OP_SOCKET"],
//!   "socketFamilies": ["AF_UNIX", "AF_INET", "AF_INET6"]
//! }
//! ```
//!
//! - `ops` are the allowed opcodes; every other opcode is denied. An allowed
//!   opcode that the kernel doesn't know is skipped: it can't be submitted
//!   anyway.
//! - `socketFamilies`, when present, limits `IORING_OP_SOCKET` to these
//!   address families. It can't be empty, and `ops` must allow
//!   `IORING_OP_SOCKET`.
//!
//! Names youki doesn't know are ignored with a warning: what they would
//! allow stays denied, and a policy written for a newer youki still works.
//!
//! The policy is built only from BPF filters, never from the one-shot opcode
//! allowlist (`IORING_REGISTER_RESTRICTIONS`). That keeps the SQE flags
//! unrestricted and lets the workload add its own, tighter io_uring filters.

use std::collections::BTreeSet;
use std::io;

use oci_spec::runtime::Spec;
use serde::Deserialize;

/// Annotation that carries the policy until the runtime spec has a field.
pub const ANNOTATION: &str = "dev.youki.io_uring";

const IORING_REGISTER_BPF_FILTER: libc::c_uint = 37;
const IO_URING_BPF_CMD_FILTER: u16 = 1;
/// Offset of the per-opcode data in `struct io_uring_bpf_ctx`; for
/// `IORING_OP_SOCKET` the first word is the address family.
const BPF_CTX_PDU_OFFSET: u32 = 16;
// Classic BPF instruction classes and modes, from <linux/filter.h>.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

/// io_uring opcodes by name, in `enum io_uring_op` order (Linux 7.2).
const OPS: &[&str] = &[
    "IORING_OP_NOP",
    "IORING_OP_READV",
    "IORING_OP_WRITEV",
    "IORING_OP_FSYNC",
    "IORING_OP_READ_FIXED",
    "IORING_OP_WRITE_FIXED",
    "IORING_OP_POLL_ADD",
    "IORING_OP_POLL_REMOVE",
    "IORING_OP_SYNC_FILE_RANGE",
    "IORING_OP_SENDMSG",
    "IORING_OP_RECVMSG",
    "IORING_OP_TIMEOUT",
    "IORING_OP_TIMEOUT_REMOVE",
    "IORING_OP_ACCEPT",
    "IORING_OP_ASYNC_CANCEL",
    "IORING_OP_LINK_TIMEOUT",
    "IORING_OP_CONNECT",
    "IORING_OP_FALLOCATE",
    "IORING_OP_OPENAT",
    "IORING_OP_CLOSE",
    "IORING_OP_FILES_UPDATE",
    "IORING_OP_STATX",
    "IORING_OP_READ",
    "IORING_OP_WRITE",
    "IORING_OP_FADVISE",
    "IORING_OP_MADVISE",
    "IORING_OP_SEND",
    "IORING_OP_RECV",
    "IORING_OP_OPENAT2",
    "IORING_OP_EPOLL_CTL",
    "IORING_OP_SPLICE",
    "IORING_OP_PROVIDE_BUFFERS",
    "IORING_OP_REMOVE_BUFFERS",
    "IORING_OP_TEE",
    "IORING_OP_SHUTDOWN",
    "IORING_OP_RENAMEAT",
    "IORING_OP_UNLINKAT",
    "IORING_OP_MKDIRAT",
    "IORING_OP_SYMLINKAT",
    "IORING_OP_LINKAT",
    "IORING_OP_MSG_RING",
    "IORING_OP_FSETXATTR",
    "IORING_OP_SETXATTR",
    "IORING_OP_FGETXATTR",
    "IORING_OP_GETXATTR",
    "IORING_OP_SOCKET",
    "IORING_OP_URING_CMD",
    "IORING_OP_SEND_ZC",
    "IORING_OP_SENDMSG_ZC",
    "IORING_OP_READ_MULTISHOT",
    "IORING_OP_WAITID",
    "IORING_OP_FUTEX_WAIT",
    "IORING_OP_FUTEX_WAKE",
    "IORING_OP_FUTEX_WAITV",
    "IORING_OP_FIXED_FD_INSTALL",
    "IORING_OP_FTRUNCATE",
    "IORING_OP_BIND",
    "IORING_OP_LISTEN",
    "IORING_OP_RECV_ZC",
    "IORING_OP_EPOLL_WAIT",
    "IORING_OP_READV_FIXED",
    "IORING_OP_WRITEV_FIXED",
    "IORING_OP_PIPE",
    "IORING_OP_NOP128",
    "IORING_OP_URING_CMD128",
];

const IORING_OP_SOCKET: u32 = 45;
/// The SQE opcode is 8 bits.
const MAX_OPCODES: u32 = 256;

#[derive(Debug, thiserror::Error)]
pub enum IoUringError {
    #[error("invalid {ANNOTATION} annotation")]
    InvalidPolicy(#[source] serde_json::Error),
    #[error("socketFamilies is empty; to deny all sockets, leave IORING_OP_SOCKET out of ops")]
    EmptyFamilies,
    #[error("socketFamilies requires IORING_OP_SOCKET in ops")]
    FamiliesWithoutSocket,
    #[error(
        "io_uring restrictions are not supported by this kernel (Linux 7.0 or newer is required)"
    )]
    Unsupported,
    #[error("failed to register io_uring filter for {op}")]
    Register {
        op: &'static str,
        #[source]
        source: io::Error,
    },
}

type Result<T> = std::result::Result<T, IoUringError>;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IoUringPolicy {
    pub ops: Vec<String>,
    pub socket_families: Option<Vec<String>>,
}

/// A policy resolved to opcode and family numbers, ready to load.
#[derive(Debug, PartialEq, Eq)]
pub struct CompiledPolicy {
    ops: BTreeSet<u32>,
    socket_families: Option<Vec<u32>>,
    /// Names youki doesn't know, maybe newer than youki: what they would
    /// allow stays denied.
    pub ignored: Vec<String>,
}

/// Reads the policy from the spec's annotations, if there is one.
pub fn policy_from_spec(spec: &Spec) -> Result<Option<CompiledPolicy>> {
    let Some(raw) = spec.annotations().as_ref().and_then(|a| a.get(ANNOTATION)) else {
        return Ok(None);
    };
    let policy: IoUringPolicy = serde_json::from_str(raw).map_err(IoUringError::InvalidPolicy)?;
    policy.compile().map(Some)
}

impl IoUringPolicy {
    pub fn compile(&self) -> Result<CompiledPolicy> {
        let mut ignored = Vec::new();
        let mut ops = BTreeSet::new();
        for name in &self.ops {
            match op_number(name) {
                Some(op) => {
                    ops.insert(op);
                }
                None => ignored.push(name.clone()),
            }
        }
        let mut socket_families = None;
        if let Some(families) = &self.socket_families {
            if families.is_empty() {
                return Err(IoUringError::EmptyFamilies);
            }
            if !ops.contains(&IORING_OP_SOCKET) {
                return Err(IoUringError::FamiliesWithoutSocket);
            }
            // Each family is compared once, in the order first listed.
            // That also bounds the filter by the families we know, so its
            // jump distances fit in a u8.
            let mut numbers = Vec::new();
            for family in families {
                match family_number(family) {
                    Some(number) if !numbers.contains(&number) => numbers.push(number),
                    Some(_) => {}
                    None => ignored.push(family.clone()),
                }
            }
            // With no known family, deny IORING_OP_SOCKET: never allow any.
            if numbers.is_empty() {
                ops.remove(&IORING_OP_SOCKET);
            } else {
                socket_families = Some(numbers);
            }
        }
        Ok(CompiledPolicy {
            ops,
            socket_families,
            ignored,
        })
    }
}

impl CompiledPolicy {
    /// The program for an opcode: allow the listed ones and deny the rest.
    /// For `IORING_OP_SOCKET` with `socketFamilies`, allow only these.
    fn program(&self, opcode: u32) -> Vec<libc::sock_filter> {
        if !self.ops.contains(&opcode) {
            return vec![ret(0)];
        }
        match (&self.socket_families, opcode) {
            (Some(families), IORING_OP_SOCKET) => socket_family_program(families),
            _ => vec![ret(1)],
        }
    }

    fn has_socket_families(&self) -> bool {
        self.socket_families.is_some() && self.ops.contains(&IORING_OP_SOCKET)
    }
}

/// Applies the policy to the calling task. Every process it forks or execs
/// afterwards inherits it.
///
/// The caller must have CAP_SYS_ADMIN in its user namespace or have set
/// no_new_privs, as for seccomp.
pub fn apply(policy: &CompiledPolicy) -> Result<()> {
    if !supported() {
        return Err(IoUringError::Unsupported);
    }
    tracing::debug!(?policy, "applying io_uring policy");
    // Every opcode gets a filter: DENY_REST only fills the opcodes without
    // one, so an opcode that an inherited filter allows would stay allowed.
    // With a one-instruction program, EINVAL only means that the kernel
    // doesn't know this opcode, nor the later ones. The socket family
    // program is registered after the loop, where EINVAL is an error.
    let mut opcode = 0;
    while opcode < MAX_OPCODES {
        if !(opcode == IORING_OP_SOCKET && policy.has_socket_families()) {
            match register_task_filter(opcode, &policy.program(opcode)) {
                Err(IoUringError::Register { source, .. })
                    if opcode > 0 && source.raw_os_error() == Some(libc::EINVAL) =>
                {
                    break;
                }
                result => result?,
            }
        }
        opcode += 1;
    }
    tracing::debug!(opcodes = opcode, "io_uring opcodes known to the kernel");
    if policy.has_socket_families() && opcode > IORING_OP_SOCKET {
        register_task_filter(IORING_OP_SOCKET, &policy.program(IORING_OP_SOCKET))?;
    }
    Ok(())
}

#[repr(C)]
struct IoUringBpfFilter {
    opcode: u32,
    flags: u32,
    filter_len: u32,
    pdu_size: u8,
    resv: [u8; 3],
    filter_ptr: u64,
    resv2: [u64; 5],
}

#[repr(C)]
struct IoUringBpf {
    cmd_type: u16,
    cmd_flags: u16,
    resv: u32,
    filter: IoUringBpfFilter,
}

const _: () = assert!(std::mem::size_of::<IoUringBpfFilter>() == 64);
const _: () = assert!(std::mem::size_of::<IoUringBpf>() == 72);

fn register_task_filter(opcode: u32, program: &[libc::sock_filter]) -> Result<()> {
    let bpf = IoUringBpf {
        cmd_type: IO_URING_BPF_CMD_FILTER,
        cmd_flags: 0,
        resv: 0,
        filter: IoUringBpfFilter {
            opcode,
            flags: 0,
            filter_len: program.len() as u32,
            // 0 accepts the kernel's per-opcode data size, whatever it is.
            pdu_size: 0,
            resv: [0; 3],
            filter_ptr: program.as_ptr() as u64,
            resv2: [0; 5],
        },
    };
    // fd = -1 selects the task-level registration added in Linux 7.0.
    // SAFETY: `bpf` and the program it points to outlive the call, and the
    // kernel only reads them.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            -1i32,
            IORING_REGISTER_BPF_FILTER,
            &bpf as *const IoUringBpf,
            1u32,
        )
    };
    if ret == 0 {
        return Ok(());
    }
    Err(IoUringError::Register {
        op: op_name(opcode),
        source: io::Error::last_os_error(),
    })
}

/// Whether the kernel supports task-level io_uring BPF filters.
///
/// Registers with a NULL argument: a kernel with the feature fails to copy
/// it (EFAULT), or refuses the caller (EACCES) before that. Older kernels
/// reject fd -1 (EBADF), or the opcode on the fd -1 path (EINVAL, 6.13+), as
/// does a 7.x kernel built without CONFIG_IO_URING_BPF.
///
/// It doesn't tell whether the restrictions survive exec; see the module
/// documentation.
pub fn supported() -> bool {
    // SAFETY: a NULL argument is never dereferenced by userspace; the kernel
    // validates it.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            -1i32,
            IORING_REGISTER_BPF_FILTER,
            std::ptr::null::<IoUringBpf>(),
            1u32,
        )
    };
    let errno = io::Error::last_os_error().raw_os_error();
    ret < 0 && matches!(errno, Some(libc::EFAULT) | Some(libc::EACCES))
}

/// `ret K`
fn ret(k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k,
    }
}

/// Allows `IORING_OP_SOCKET` only for the given address families.
fn socket_family_program(families: &[u32]) -> Vec<libc::sock_filter> {
    let n = families.len();
    let mut program = vec![libc::sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: BPF_CTX_PDU_OFFSET,
    }];
    for (i, &family) in families.iter().enumerate() {
        // On a match, jump over the remaining comparisons and the deny.
        program.push(libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: (n - i) as u8,
            jf: 0,
            k: family,
        });
    }
    program.push(ret(0));
    program.push(ret(1));
    program
}

fn op_number(name: &str) -> Option<u32> {
    OPS.iter().position(|&op| op == name).map(|i| i as u32)
}

fn op_name(opcode: u32) -> &'static str {
    OPS.get(opcode as usize)
        .copied()
        .unwrap_or("unknown opcode")
}

/// Address families by name, from <linux/socket.h> (Linux 7.2).
const FAMILIES: &[(&str, u32)] = &[
    ("AF_UNIX", 1),
    ("AF_LOCAL", 1),
    ("AF_INET", 2),
    ("AF_AX25", 3),
    ("AF_IPX", 4),
    ("AF_APPLETALK", 5),
    ("AF_NETROM", 6),
    ("AF_BRIDGE", 7),
    ("AF_ATMPVC", 8),
    ("AF_X25", 9),
    ("AF_INET6", 10),
    ("AF_ROSE", 11),
    ("AF_DECnet", 12),
    ("AF_NETBEUI", 13),
    ("AF_SECURITY", 14),
    ("AF_KEY", 15),
    ("AF_NETLINK", 16),
    ("AF_ROUTE", 16),
    ("AF_PACKET", 17),
    ("AF_ASH", 18),
    ("AF_ECONET", 19),
    ("AF_ATMSVC", 20),
    ("AF_RDS", 21),
    ("AF_SNA", 22),
    ("AF_IRDA", 23),
    ("AF_PPPOX", 24),
    ("AF_WANPIPE", 25),
    ("AF_LLC", 26),
    ("AF_IB", 27),
    ("AF_MPLS", 28),
    ("AF_CAN", 29),
    ("AF_TIPC", 30),
    ("AF_BLUETOOTH", 31),
    ("AF_IUCV", 32),
    ("AF_RXRPC", 33),
    ("AF_ISDN", 34),
    ("AF_PHONET", 35),
    ("AF_IEEE802154", 36),
    ("AF_CAIF", 37),
    ("AF_ALG", 38),
    ("AF_NFC", 39),
    ("AF_VSOCK", 40),
    ("AF_KCM", 41),
    ("AF_QIPCRTR", 42),
    ("AF_SMC", 43),
    ("AF_XDP", 44),
    ("AF_MCTP", 45),
];

fn family_number(name: &str) -> Option<u32> {
    FAMILIES
        .iter()
        .find(|&&(family, _)| family == name)
        .map(|&(_, number)| number)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> CompiledPolicy {
        serde_json::from_str::<IoUringPolicy>(json)
            .unwrap()
            .compile()
            .unwrap()
    }

    #[test]
    fn opcode_table_matches_kernel_numbers() {
        assert_eq!(op_number("IORING_OP_NOP"), Some(0));
        assert_eq!(op_number("IORING_OP_CONNECT"), Some(16));
        assert_eq!(op_number("IORING_OP_OPENAT"), Some(18));
        assert_eq!(op_number("IORING_OP_SOCKET"), Some(IORING_OP_SOCKET));
        assert_eq!(op_number("IORING_OP_URING_CMD128"), Some(64));
        assert_eq!(op_number("IORING_OP_BOGUS"), None);
    }

    #[test]
    fn allows_listed_ops_and_denies_the_rest() {
        let policy = policy(r#"{"ops":["IORING_OP_READ","IORING_OP_NOP"]}"#);
        assert_eq!(policy.program(0), vec![ret(1)]);
        assert_eq!(policy.program(22), vec![ret(1)]);
        assert_eq!(policy.program(23), vec![ret(0)]);
        // Opcodes past the table, as a newer kernel may have.
        assert_eq!(policy.program(200), vec![ret(0)]);
    }

    #[test]
    fn no_ops_denies_everything() {
        let policy = policy(r#"{"ops":[]}"#);
        assert!((0..MAX_OPCODES).all(|opcode| policy.program(opcode) == vec![ret(0)]));
    }

    #[test]
    fn socket_families_replace_the_allow_program_on_socket() {
        let policy =
            policy(r#"{"ops":["IORING_OP_SOCKET"],"socketFamilies":["AF_INET","AF_UNIX"]}"#);
        assert!(policy.has_socket_families());
        assert_eq!(
            policy.program(IORING_OP_SOCKET),
            socket_family_program(&[2, 1])
        );
        assert_eq!(policy.program(0), vec![ret(0)]);
    }

    #[test]
    fn socket_families_are_compared_once() {
        // AF_LOCAL is AF_UNIX. 256 comparisons would overflow the u8 jumps
        // to the final "ret 1".
        let families = std::iter::once(r#""AF_INET""#)
            .chain(std::iter::repeat_n(r#""AF_UNIX""#, 300))
            .chain([r#""AF_LOCAL""#, r#""AF_INET""#])
            .collect::<Vec<_>>()
            .join(",");
        let policy = policy(&format!(
            r#"{{"ops":["IORING_OP_SOCKET"],"socketFamilies":[{families}]}}"#
        ));
        assert_eq!(
            policy.program(IORING_OP_SOCKET),
            socket_family_program(&[2, 1])
        );
    }

    #[test]
    fn socket_families_require_socket() {
        let families_without_socket = serde_json::from_str::<IoUringPolicy>(
            r#"{"ops":["IORING_OP_NOP"],"socketFamilies":["AF_INET"]}"#,
        )
        .unwrap()
        .compile();
        assert!(matches!(
            families_without_socket,
            Err(IoUringError::FamiliesWithoutSocket)
        ));
    }

    #[test]
    fn socket_family_program_jumps_to_allow_on_match() {
        let p = socket_family_program(&[1, 2, 10]);
        assert_eq!(p.len(), 6);
        // Each comparison jumps to the final "ret 1".
        for (i, insn) in p[1..4].iter().enumerate() {
            assert_eq!(1 + i + 1 + insn.jt as usize, p.len() - 1);
        }
        assert_eq!(p[4], ret(0));
        assert_eq!(p[5], ret(1));
    }

    #[test]
    fn ignores_unknown_names() {
        let known = policy(
            r#"{"ops":["IORING_OP_NOP","IORING_OP_FOO","IORING_OP_SOCKET"],"socketFamilies":["AF_FOO","AF_INET"]}"#,
        );
        assert_eq!(known.ignored, vec!["IORING_OP_FOO", "AF_FOO"]);
        assert_eq!(known.program(0), vec![ret(1)]);
        assert_eq!(known.program(IORING_OP_SOCKET), socket_family_program(&[2]));
        // With no known family, IORING_OP_SOCKET is denied.
        let unknown = policy(r#"{"ops":["IORING_OP_SOCKET"],"socketFamilies":["AF_FOO"]}"#);
        assert!(!unknown.has_socket_families());
        assert_eq!(unknown.program(IORING_OP_SOCKET), vec![ret(0)]);
    }

    #[test]
    fn family_table_matches_kernel_numbers() {
        assert_eq!(family_number("AF_UNIX"), Some(libc::AF_UNIX as u32));
        assert_eq!(family_number("AF_LOCAL"), Some(libc::AF_UNIX as u32));
        assert_eq!(family_number("AF_INET6"), Some(libc::AF_INET6 as u32));
        assert_eq!(family_number("AF_NETLINK"), Some(libc::AF_NETLINK as u32));
        assert_eq!(family_number("AF_CAN"), Some(libc::AF_CAN as u32));
        assert_eq!(family_number("AF_XDP"), Some(libc::AF_XDP as u32));
        assert_eq!(family_number("AF_MCTP"), Some(45));
    }

    #[test]
    fn rejects_invalid_policies() {
        let empty_families =
            serde_json::from_str::<IoUringPolicy>(r#"{"ops":[],"socketFamilies":[]}"#)
                .unwrap()
                .compile();
        assert!(matches!(empty_families, Err(IoUringError::EmptyFamilies)));
        // ops is required, and the fields of the earlier draft are refused.
        for json in [
            r#"{}"#,
            r#"{"ops":"IORING_OP_READ"}"#,
            r#"{"ops":[],"extra":1}"#,
            r#"{"defaultAction":"deny","ops":[]}"#,
            r#"{"ops":[],"deniedSqeFlags":["IOSQE_BUFFER_SELECT"]}"#,
        ] {
            assert!(
                serde_json::from_str::<IoUringPolicy>(json).is_err(),
                "{json}"
            );
        }
    }
}
