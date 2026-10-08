//! Experimental: restrict which io_uring operations a container may run.
//!
//! seccomp can't see io_uring operations: they are submitted through a ring
//! in shared memory, not as syscalls. That is why container runtimes block
//! io_uring entirely. Linux 7.0 added task-level io_uring restrictions with
//! classic BPF filters per opcode, which are inherited across fork and exec
//! and can only be tightened, like seccomp. This module applies such a policy
//! to the container's init process before it execs the workload.
//!
//! Until the OCI runtime spec has a field for this, the policy is read from
//! the `dev.youki.io_uring` annotation as JSON:
//!
//! ```json
//! {
//!   "defaultAction": "deny",
//!   "ops": ["IORING_OP_READ", "IORING_OP_WRITE", "IORING_OP_SOCKET"],
//!   "socketFamilies": ["AF_UNIX", "AF_INET", "AF_INET6"]
//! }
//! ```
//!
//! - `defaultAction` is the action for opcodes not listed in `ops`: `deny`
//!   (allow only `ops`) or `allow` (deny only `ops`).
//! - `socketFamilies`, when present, limits `IORING_OP_SOCKET` to these
//!   address families whenever the socket opcode is allowed.
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
/// Attach a deny filter to every opcode that has no filter yet.
const IO_URING_BPF_FILTER_DENY_REST: u32 = 1;
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

const IORING_OP_NOP: u32 = 0;
const IORING_OP_SOCKET: u32 = 45;

#[derive(Debug, thiserror::Error)]
pub enum IoUringError {
    #[error("invalid {ANNOTATION} annotation")]
    InvalidPolicy(#[source] serde_json::Error),
    #[error("unknown io_uring opcode {0}")]
    UnknownOp(String),
    #[error("unknown socket address family {0}")]
    UnknownFamily(String),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IoUringPolicy {
    pub default_action: Action,
    #[serde(default)]
    pub ops: Vec<String>,
    pub socket_families: Option<Vec<String>>,
}

/// A policy resolved to opcode and family numbers, ready to load.
#[derive(Debug, PartialEq, Eq)]
pub struct CompiledPolicy {
    default_action: Action,
    ops: BTreeSet<u32>,
    socket_families: Option<Vec<u32>>,
}

/// One BPF program to register for one opcode.
#[derive(Debug, PartialEq, Eq)]
struct FilterSpec {
    opcode: u32,
    flags: u32,
    program: Vec<libc::sock_filter>,
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
        let ops = self
            .ops
            .iter()
            .map(|name| op_number(name).ok_or_else(|| IoUringError::UnknownOp(name.clone())))
            .collect::<Result<BTreeSet<u32>>>()?;
        let socket_families = self
            .socket_families
            .as_ref()
            .map(|families| {
                families
                    .iter()
                    .map(|f| family_number(f))
                    .collect::<Result<Vec<u32>>>()
            })
            .transpose()?;
        Ok(CompiledPolicy {
            default_action: self.default_action,
            ops,
            socket_families,
        })
    }
}

impl CompiledPolicy {
    /// The filters to register, in registration order.
    fn filters(&self) -> Vec<FilterSpec> {
        let socket_allowed = match self.default_action {
            Action::Deny => self.ops.contains(&IORING_OP_SOCKET),
            Action::Allow => !self.ops.contains(&IORING_OP_SOCKET),
        };
        let family_filter = self
            .socket_families
            .as_ref()
            .filter(|_| socket_allowed)
            .map(|families| socket_family_program(families));

        let mut filters = Vec::new();
        match self.default_action {
            Action::Deny => {
                // An allow filter on every listed opcode, then deny stubs on
                // every other opcode (DENY_REST on the last registration).
                for &opcode in &self.ops {
                    let program = match (&family_filter, opcode) {
                        (Some(p), IORING_OP_SOCKET) => p.clone(),
                        _ => vec![ret(1)],
                    };
                    filters.push(FilterSpec {
                        opcode,
                        flags: 0,
                        program,
                    });
                }
                match filters.last_mut() {
                    Some(last) => last.flags |= IO_URING_BPF_FILTER_DENY_REST,
                    // Nothing allowed: deny NOP and let DENY_REST cover the rest.
                    None => filters.push(FilterSpec {
                        opcode: IORING_OP_NOP,
                        flags: IO_URING_BPF_FILTER_DENY_REST,
                        program: vec![ret(0)],
                    }),
                }
            }
            Action::Allow => {
                for &opcode in &self.ops {
                    filters.push(FilterSpec {
                        opcode,
                        flags: 0,
                        program: vec![ret(0)],
                    });
                }
                if let Some(program) = family_filter {
                    filters.push(FilterSpec {
                        opcode: IORING_OP_SOCKET,
                        flags: 0,
                        program,
                    });
                }
            }
        }
        filters
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
    let filters = policy.filters();
    tracing::debug!(?policy, filters = filters.len(), "applying io_uring policy");
    for filter in &filters {
        register_task_filter(filter)?;
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

fn register_task_filter(filter: &FilterSpec) -> Result<()> {
    let bpf = IoUringBpf {
        cmd_type: IO_URING_BPF_CMD_FILTER,
        cmd_flags: 0,
        resv: 0,
        filter: IoUringBpfFilter {
            opcode: filter.opcode,
            flags: filter.flags,
            filter_len: filter.program.len() as u32,
            // 0 accepts the kernel's per-opcode data size, whatever it is.
            pdu_size: 0,
            resv: [0; 3],
            filter_ptr: filter.program.as_ptr() as u64,
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
        op: op_name(filter.opcode),
        source: io::Error::last_os_error(),
    })
}

/// Whether the kernel supports task-level io_uring BPF filters.
///
/// Registers with a NULL argument: a kernel with the feature fails to copy
/// it (EFAULT), or refuses the caller (EACCES) before that. Older kernels
/// reject fd -1 (EBADF), or the opcode on the fd -1 path (EINVAL, 6.13+), as
/// does a 7.x kernel built without CONFIG_IO_URING_BPF.
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

fn family_number(name: &str) -> Result<u32> {
    let family = match name {
        "AF_UNIX" | "AF_LOCAL" => libc::AF_UNIX,
        "AF_INET" => libc::AF_INET,
        "AF_INET6" => libc::AF_INET6,
        "AF_NETLINK" => libc::AF_NETLINK,
        "AF_PACKET" => libc::AF_PACKET,
        "AF_VSOCK" => libc::AF_VSOCK,
        "AF_ALG" => libc::AF_ALG,
        "AF_XDP" => libc::AF_XDP,
        _ => return Err(IoUringError::UnknownFamily(name.to_string())),
    };
    Ok(family as u32)
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
    fn deny_by_default_allows_listed_ops_then_denies_the_rest() {
        let filters =
            policy(r#"{"defaultAction":"deny","ops":["IORING_OP_READ","IORING_OP_NOP"]}"#)
                .filters();
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0].opcode, 0);
        assert_eq!(filters[1].opcode, 22);
        assert!(filters.iter().all(|f| f.program == vec![ret(1)]));
        assert_eq!(filters[0].flags, 0);
        assert_eq!(filters[1].flags, IO_URING_BPF_FILTER_DENY_REST);
    }

    #[test]
    fn deny_by_default_with_no_ops_denies_everything() {
        let filters = policy(r#"{"defaultAction":"deny"}"#).filters();
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].program, vec![ret(0)]);
        assert_eq!(filters[0].flags, IO_URING_BPF_FILTER_DENY_REST);
    }

    #[test]
    fn socket_families_replace_the_allow_filter_on_socket() {
        let filters = policy(
            r#"{"defaultAction":"deny","ops":["IORING_OP_SOCKET"],"socketFamilies":["AF_INET","AF_UNIX"]}"#,
        )
        .filters();
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].opcode, IORING_OP_SOCKET);
        assert_eq!(filters[0].program, socket_family_program(&[2, 1]));
    }

    #[test]
    fn socket_families_are_ignored_when_socket_is_denied() {
        let filters = policy(
            r#"{"defaultAction":"deny","ops":["IORING_OP_NOP"],"socketFamilies":["AF_INET"]}"#,
        )
        .filters();
        assert!(filters.iter().all(|f| f.opcode != IORING_OP_SOCKET));
    }

    #[test]
    fn allow_by_default_denies_listed_ops_and_filters_sockets() {
        let filters =
            policy(r#"{"defaultAction":"allow","ops":["IORING_OP_URING_CMD"],"socketFamilies":["AF_INET6"]}"#)
                .filters();
        assert_eq!(filters.len(), 2);
        assert_eq!(
            (filters[0].opcode, filters[0].program.clone()),
            (46, vec![ret(0)])
        );
        assert_eq!(filters[1].opcode, IORING_OP_SOCKET);
        assert!(filters.iter().all(|f| f.flags == 0));
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
    fn rejects_unknown_names_and_fields() {
        let unknown_op =
            serde_json::from_str::<IoUringPolicy>(r#"{"defaultAction":"deny","ops":["read"]}"#)
                .unwrap()
                .compile();
        assert!(matches!(unknown_op, Err(IoUringError::UnknownOp(_))));
        let unknown_family = serde_json::from_str::<IoUringPolicy>(
            r#"{"defaultAction":"allow","socketFamilies":["AF_FOO"]}"#,
        )
        .unwrap()
        .compile();
        assert!(matches!(
            unknown_family,
            Err(IoUringError::UnknownFamily(_))
        ));
        assert!(
            serde_json::from_str::<IoUringPolicy>(r#"{"defaultAction":"deny","extra":1}"#).is_err()
        );
    }
}
