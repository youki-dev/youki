use oci_spec::runtime::{MemoryPolicyFlagType, MemoryPolicyModeType};

use crate::syscall::{Syscall, SyscallError};

#[derive(Debug, thiserror::Error)]
pub enum MemoryPolicyError {
    #[error("Invalid memory policy flag: {0}")]
    InvalidFlag(String),

    #[error("Invalid node specification: {0}")]
    InvalidNodes(String),

    #[error("Incompatible flag and mode combination: {0}")]
    IncompatibleFlagMode(String),

    #[error("Mutually exclusive flags: {0}")]
    MutuallyExclusiveFlags(String),

    #[error("Syscall error: {0}")]
    Syscall(#[from] SyscallError),
}

type Result<T> = std::result::Result<T, MemoryPolicyError>;

struct ValidatedMemoryPolicy {
    mode_with_flags: i32,
    nodemask: Vec<libc::c_ulong>,
    maxnode: u64,
}

fn validate_memory_policy(
    memory_policy: &Option<oci_spec::runtime::LinuxMemoryPolicy>,
) -> Result<Option<ValidatedMemoryPolicy>> {
    let Some(policy) = memory_policy else {
        return Ok(None);
    };

    // Memory policy mode constants from Linux UAPI (include/uapi/linux/mempolicy.h)
    const MPOL_DEFAULT: i32 = 0;
    const MPOL_PREFERRED: i32 = 1;
    const MPOL_BIND: i32 = 2;
    const MPOL_INTERLEAVE: i32 = 3;
    const MPOL_LOCAL: i32 = 4;
    const MPOL_PREFERRED_MANY: i32 = 5;
    const MPOL_WEIGHTED_INTERLEAVE: i32 = 6;

    // Memory policy flag constants from Linux UAPI
    const MPOL_F_NUMA_BALANCING: u32 = 1 << 13; // 0x2000
    const MPOL_F_RELATIVE_NODES: u32 = 1 << 14; // 0x4000
    const MPOL_F_STATIC_NODES: u32 = 1 << 15; // 0x8000

    let base_mode = match policy.mode() {
        MemoryPolicyModeType::MpolDefault => MPOL_DEFAULT,
        MemoryPolicyModeType::MpolPreferred => MPOL_PREFERRED,
        MemoryPolicyModeType::MpolBind => MPOL_BIND,
        MemoryPolicyModeType::MpolInterleave => MPOL_INTERLEAVE,
        MemoryPolicyModeType::MpolLocal => MPOL_LOCAL,
        MemoryPolicyModeType::MpolPreferredMany => MPOL_PREFERRED_MANY,
        MemoryPolicyModeType::MpolWeightedInterleave => MPOL_WEIGHTED_INTERLEAVE,
    };

    let mut has_static = false;
    let mut has_relative = false;
    if let Some(flags) = policy.flags() {
        for flag in flags.iter() {
            match flag {
                MemoryPolicyFlagType::MpolFNumaBalancing => {
                    if base_mode != MPOL_BIND {
                        return Err(MemoryPolicyError::IncompatibleFlagMode(
                            "MPOL_F_NUMA_BALANCING can only be used with MPOL_BIND".to_string(),
                        ));
                    }
                }
                MemoryPolicyFlagType::MpolFRelativeNodes => {
                    has_relative = true;
                }
                MemoryPolicyFlagType::MpolFStaticNodes => {
                    has_static = true;
                }
            }
        }
        if has_static && has_relative {
            return Err(MemoryPolicyError::MutuallyExclusiveFlags(
                "MPOL_F_STATIC_NODES and MPOL_F_RELATIVE_NODES are mutually exclusive".to_string(),
            ));
        }
    }

    let mut flags_value: u32 = 0;
    if let Some(flags) = policy.flags() {
        for flag in flags {
            match flag {
                MemoryPolicyFlagType::MpolFNumaBalancing => {
                    flags_value |= MPOL_F_NUMA_BALANCING;
                }
                MemoryPolicyFlagType::MpolFRelativeNodes => {
                    flags_value |= MPOL_F_RELATIVE_NODES;
                }
                MemoryPolicyFlagType::MpolFStaticNodes => {
                    flags_value |= MPOL_F_STATIC_NODES;
                }
            }
        }
    }

    let mode_with_flags = base_mode | (flags_value as i32);

    match base_mode {
        MPOL_DEFAULT | MPOL_LOCAL => {
            let mode_name = if base_mode == MPOL_DEFAULT {
                "MPOL_DEFAULT"
            } else {
                "MPOL_LOCAL"
            };

            if let Some(nodes) = policy.nodes() {
                if !nodes.trim().is_empty() {
                    return Err(MemoryPolicyError::InvalidNodes(format!(
                        "{} does not accept node specification",
                        mode_name
                    )));
                }
            }
            if flags_value != 0 {
                return Err(MemoryPolicyError::InvalidFlag(format!(
                    "{} does not accept flags",
                    mode_name
                )));
            }
            Ok(Some(ValidatedMemoryPolicy {
                mode_with_flags,
                nodemask: Vec::new(),
                maxnode: 0,
            }))
        }
        MPOL_PREFERRED => match policy.nodes() {
            None => {
                if flags_value & (MPOL_F_RELATIVE_NODES | MPOL_F_STATIC_NODES) != 0 {
                    return Err(MemoryPolicyError::IncompatibleFlagMode(
                        "MPOL_PREFERRED with empty nodes cannot use MPOL_F_STATIC_NODES or MPOL_F_RELATIVE_NODES flags".to_string(),
                    ));
                }
                Ok(Some(ValidatedMemoryPolicy {
                    mode_with_flags,
                    nodemask: Vec::new(),
                    maxnode: 0,
                }))
            }
            Some(nodes) if nodes.trim().is_empty() => {
                if flags_value & (MPOL_F_RELATIVE_NODES | MPOL_F_STATIC_NODES) != 0 {
                    return Err(MemoryPolicyError::IncompatibleFlagMode(
                        "MPOL_PREFERRED with empty nodes cannot use MPOL_F_STATIC_NODES or MPOL_F_RELATIVE_NODES flags".to_string(),
                    ));
                }
                Ok(Some(ValidatedMemoryPolicy {
                    mode_with_flags,
                    nodemask: Vec::new(),
                    maxnode: 0,
                }))
            }
            Some(nodes) => {
                let (nodemask, maxnode) = build_nodemask(nodes)?;
                if maxnode == 0 {
                    if flags_value & (MPOL_F_RELATIVE_NODES | MPOL_F_STATIC_NODES) != 0 {
                        return Err(MemoryPolicyError::IncompatibleFlagMode(
                            "MPOL_PREFERRED with empty nodes cannot use MPOL_F_STATIC_NODES or MPOL_F_RELATIVE_NODES flags".to_string(),
                        ));
                    }
                    return Ok(Some(ValidatedMemoryPolicy {
                        mode_with_flags,
                        nodemask: Vec::new(),
                        maxnode: 0,
                    }));
                }
                Ok(Some(ValidatedMemoryPolicy {
                    mode_with_flags,
                    nodemask,
                    maxnode,
                }))
            }
        },
        _ => {
            let mode_name = match policy.mode() {
                MemoryPolicyModeType::MpolDefault => "MPOL_DEFAULT",
                MemoryPolicyModeType::MpolPreferred => "MPOL_PREFERRED",
                MemoryPolicyModeType::MpolBind => "MPOL_BIND",
                MemoryPolicyModeType::MpolInterleave => "MPOL_INTERLEAVE",
                MemoryPolicyModeType::MpolLocal => "MPOL_LOCAL",
                MemoryPolicyModeType::MpolPreferredMany => "MPOL_PREFERRED_MANY",
                MemoryPolicyModeType::MpolWeightedInterleave => "MPOL_WEIGHTED_INTERLEAVE",
            };
            let nodes = match policy.nodes() {
                None => {
                    return Err(MemoryPolicyError::InvalidNodes(format!(
                        "Mode {} requires non-empty node specification",
                        mode_name
                    )));
                }
                Some(nodes) if nodes.trim().is_empty() => {
                    return Err(MemoryPolicyError::InvalidNodes(format!(
                        "Mode {} requires non-empty node specification",
                        mode_name
                    )));
                }
                Some(nodes) => nodes,
            };
            let (nodemask, maxnode) = build_nodemask(nodes)?;
            if maxnode == 0 {
                return Err(MemoryPolicyError::InvalidNodes(format!(
                    "Mode {} requires non-empty node specification (parsed result is empty)",
                    mode_name
                )));
            }
            Ok(Some(ValidatedMemoryPolicy {
                mode_with_flags,
                nodemask,
                maxnode,
            }))
        }
    }
}

/// Configure the memory policy for the process using set_mempolicy(2).
///
/// See: https://man7.org/linux/man-pages/man2/set_mempolicy.2.html
pub fn setup_memory_policy(
    memory_policy: &Option<oci_spec::runtime::LinuxMemoryPolicy>,
    syscall: &dyn Syscall,
) -> Result<()> {
    let validated = validate_memory_policy(memory_policy)?;
    if let Some(valid) = validated {
        syscall
            .set_mempolicy(valid.mode_with_flags, &valid.nodemask, valid.maxnode)
            .map_err(|err| {
                tracing::error!(?err, "failed to set memory policy");
                MemoryPolicyError::Syscall(err)
            })?;
    }
    Ok(())
}

// Build a proper nodemask for set_mempolicy
fn build_nodemask(nodes: &str) -> Result<(Vec<libc::c_ulong>, u64)> {
    let node_ids = parse_node_string(nodes)?;

    if node_ids.is_empty() {
        // Empty nodemask - return NULL equivalent (empty vector)
        return Ok((Vec::new(), 0));
    }

    // Find the highest node ID
    let highest_node = node_ids.iter().max().copied().unwrap_or(0) as usize;

    // Calculate how many c_ulong values we need to store the bitmask
    let bits_per_ulong = std::mem::size_of::<libc::c_ulong>() * 8;
    let num_ulongs = (highest_node / bits_per_ulong) + 1;

    // Calculate maxnode = number of bits provided in nodemask
    let maxnode = (num_ulongs * bits_per_ulong) as u64;

    // Build the nodemask array as Vec<c_ulong>
    let mut nodemask = vec![0 as libc::c_ulong; num_ulongs];

    // Set bits for each node ID
    for node_id in node_ids {
        let node_id = node_id as usize;
        let word_index = node_id / bits_per_ulong;
        let bit_index = node_id % bits_per_ulong;

        if word_index < nodemask.len() {
            nodemask[word_index] |= (1 as libc::c_ulong) << bit_index;
        }
    }

    Ok((nodemask, maxnode))
}

fn parse_node_string(nodes: &str) -> Result<Vec<u32>> {
    let mut node_ids = Vec::new();

    // Trim whitespace and check for empty string
    let nodes = nodes.trim();
    if nodes.is_empty() {
        return Ok(node_ids);
    }

    for range in nodes.split(',') {
        let range = range.trim();
        if range.is_empty() {
            continue; // Skip empty entries caused by multiple commas
        }
        let range = range.trim();
        if range.is_empty() {
            continue;
        }

        if let Some(dash_pos) = range.find('-') {
            // Range format: "node1-node2"
            let start_str = range[..dash_pos].trim();
            let end_str = range[dash_pos + 1..].trim();

            let start: u32 = start_str.parse().map_err(|_| {
                MemoryPolicyError::InvalidNodes(format!("Invalid node range start: {}", start_str))
            })?;
            let end: u32 = end_str.parse().map_err(|_| {
                MemoryPolicyError::InvalidNodes(format!("Invalid node range end: {}", end_str))
            })?;

            if start > end {
                return Err(MemoryPolicyError::InvalidNodes(format!(
                    "Invalid node range: {}-{}",
                    start, end
                )));
            }

            for node in start..=end {
                node_ids.push(node);
            }
        } else {
            // Single node
            let node: u32 = range
                .parse()
                .map_err(|_| MemoryPolicyError::InvalidNodes(format!("Invalid node: {}", range)))?;

            node_ids.push(node);
        }
    }

    Ok(node_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::syscall::create_syscall;
    use crate::syscall::test::TestHelperSyscall;

    #[test]
    fn test_parse_node_string() {
        // Test empty string
        assert_eq!(parse_node_string("").unwrap(), Vec::<u32>::new());

        // Test single node
        assert_eq!(parse_node_string("0").unwrap(), vec![0]);
        assert_eq!(parse_node_string("1").unwrap(), vec![1]);
        assert_eq!(parse_node_string("2").unwrap(), vec![2]);

        // Test node range
        assert_eq!(parse_node_string("0-2").unwrap(), vec![0, 1, 2]);
        assert_eq!(parse_node_string("1-3").unwrap(), vec![1, 2, 3]);

        // Test multiple nodes
        assert_eq!(parse_node_string("0,2").unwrap(), vec![0, 2]);
        assert_eq!(parse_node_string("0,1,3").unwrap(), vec![0, 1, 3]);

        // Test combination of ranges and single nodes
        assert_eq!(parse_node_string("0-1,3").unwrap(), vec![0, 1, 3]);
        assert_eq!(parse_node_string("0,2-3").unwrap(), vec![0, 2, 3]);

        // Test with spaces
        assert_eq!(parse_node_string(" 0 , 2 ").unwrap(), vec![0, 2]);
        assert_eq!(parse_node_string(" 0 - 2 ").unwrap(), vec![0, 1, 2]);

        // Test whitespace-only string
        assert_eq!(parse_node_string("   ").unwrap(), Vec::<u32>::new());
        assert_eq!(parse_node_string(" , , ").unwrap(), Vec::<u32>::new());

        // Test error cases
        assert!(parse_node_string("2-1").is_err()); // Invalid range
        assert!(parse_node_string("abc").is_err()); // Invalid format
        assert!(parse_node_string("0-abc").is_err()); // Invalid range end
    }

    #[test]
    fn test_setup_memory_policy() {
        use oci_spec::runtime::{LinuxMemoryPolicyBuilder, MemoryPolicyModeType};

        let syscall = create_syscall();

        // Test with None (no memory policy)
        assert!(setup_memory_policy(&None, syscall.as_ref()).is_ok());

        // Test with basic memory policy
        let policy = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolBind)
            .nodes("0,1".to_string())
            .flags(vec![])
            .build()
            .unwrap();

        assert!(setup_memory_policy(&Some(policy), syscall.as_ref()).is_ok());

        let got_args = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_mempolicy_args();

        assert_eq!(got_args.len(), 1);
        assert_eq!(got_args[0].mode, 2); // MPOL_BIND (corrected value)
        assert_eq!(got_args[0].nodemask.len(), 1); // One c_ulong needed
        assert_eq!(got_args[0].nodemask[0], 3); // 2^0 + 2^1 = 1 + 2 = 3
        assert_eq!(got_args[0].maxnode, 64); // (num_u64s * u64_bits) = (1 * 64) = 64

        // Test with flags
        let policy_with_flags = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolBind)
            .nodes("0".to_string())
            .flags(vec![
                oci_spec::runtime::MemoryPolicyFlagType::MpolFStaticNodes,
            ])
            .build()
            .unwrap();

        assert!(setup_memory_policy(&Some(policy_with_flags), syscall.as_ref()).is_ok());

        let got_args_with_flags = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_mempolicy_args();

        assert_eq!(got_args_with_flags.len(), 2);
        // Second call should have mode with flags OR'ed in
        // MPOL_BIND (2) | MPOL_F_STATIC_NODES (0x8000)
        assert_eq!(got_args_with_flags[1].mode, 2 | (1 << 15));
        assert_eq!(got_args_with_flags[1].nodemask.len(), 1);
        assert_eq!(got_args_with_flags[1].nodemask[0], 1); // 2^0 = 1
        assert_eq!(got_args_with_flags[1].maxnode, 64); // (num_u64s * u64_bits) = (1 * 64) = 64

        // Test invalid flag combinations
        let policy_invalid_flags = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolBind)
            .nodes("0".to_string())
            .flags(vec![
                oci_spec::runtime::MemoryPolicyFlagType::MpolFStaticNodes,
                oci_spec::runtime::MemoryPolicyFlagType::MpolFRelativeNodes,
            ])
            .build()
            .unwrap();

        assert!(setup_memory_policy(&Some(policy_invalid_flags), syscall.as_ref()).is_err());

        // Test MPOL_F_NUMA_BALANCING with non-BIND mode
        let policy_invalid_numa_balancing = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolInterleave)
            .nodes("0".to_string())
            .flags(vec![
                oci_spec::runtime::MemoryPolicyFlagType::MpolFNumaBalancing,
            ])
            .build()
            .unwrap();

        assert!(
            setup_memory_policy(&Some(policy_invalid_numa_balancing), syscall.as_ref()).is_err()
        );

        // Test MPOL_DEFAULT with nodes (should fail)
        let policy_default_with_nodes = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolDefault)
            .nodes("0".to_string())
            .flags(vec![])
            .build()
            .unwrap();

        assert!(setup_memory_policy(&Some(policy_default_with_nodes), syscall.as_ref()).is_err());

        // Test MPOL_DEFAULT with flags (should fail)
        let policy_default_with_flags = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolDefault)
            .nodes("".to_string())
            .flags(vec![
                oci_spec::runtime::MemoryPolicyFlagType::MpolFStaticNodes,
            ])
            .build()
            .unwrap();

        assert!(setup_memory_policy(&Some(policy_default_with_flags), syscall.as_ref()).is_err());

        // Test MPOL_LOCAL with nodes (should fail)
        let policy_local_with_nodes = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolLocal)
            .nodes("0".to_string())
            .flags(vec![])
            .build()
            .unwrap();

        assert!(setup_memory_policy(&Some(policy_local_with_nodes), syscall.as_ref()).is_err());

        // Test MPOL_BIND with empty nodes (should fail)
        let policy_bind_empty = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolBind)
            .nodes("".to_string())
            .flags(vec![])
            .build()
            .unwrap();

        assert!(setup_memory_policy(&Some(policy_bind_empty), syscall.as_ref()).is_err());

        // Test MPOL_BIND with whitespace-only nodes (should fail)
        let policy_bind_whitespace = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolBind)
            .nodes("   ".to_string())
            .flags(vec![])
            .build()
            .unwrap();

        assert!(setup_memory_policy(&Some(policy_bind_whitespace), syscall.as_ref()).is_err());

        // Test MPOL_PREFERRED with empty nodes and STATIC_NODES flag (should fail)
        let policy_preferred_empty_with_flags = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolPreferred)
            .nodes("".to_string())
            .flags(vec![
                oci_spec::runtime::MemoryPolicyFlagType::MpolFStaticNodes,
            ])
            .build()
            .unwrap();

        assert!(
            setup_memory_policy(&Some(policy_preferred_empty_with_flags), syscall.as_ref())
                .is_err()
        );
    }
}
