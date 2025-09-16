use oci_spec::runtime::MemoryPolicyFlagType;
use oci_spec::runtime::MemoryPolicyModeType;

use crate::syscall::{Syscall, SyscallError};

#[derive(Debug, thiserror::Error)]
pub enum MemoryPolicyError {
    #[error("Invalid memory policy flag: {0}")]
    InvalidFlag(String),

    #[error("Invalid node specification: {0}")]
    InvalidNodes(String),

    #[error("Invalid memory policy mode: {0}")]
    InvalidMode(String),

    #[error("Incompatible flag and mode combination: {0}")]
    IncompatibleFlagMode(String),

    #[error("Mutually exclusive flags: {0}")]
    MutuallyExclusiveFlags(String),

    #[error("Syscall error: {0}")]
    Syscall(#[from] SyscallError),
}

type Result<T> = std::result::Result<T, MemoryPolicyError>;

/// Configure the memory policy for the process using set_mempolicy(2).
///
/// See: https://man7.org/linux/man-pages/man2/set_mempolicy.2.html
pub fn setup_memory_policy(
    memory_policy: &Option<oci_spec::runtime::LinuxMemoryPolicy>,
    syscall: &dyn Syscall,
) -> Result<()> {
    let Some(policy) = memory_policy else {
        return Ok(());
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

    let mut flags_value: u32 = 0;
    if let Some(flags) = policy.flags() {
        let mut has_static = false;
        let mut has_relative = false;
        for flag in flags {
            match flag {
                MemoryPolicyFlagType::MpolFNumaBalancing => {
                    if base_mode != MPOL_BIND {
                        return Err(MemoryPolicyError::IncompatibleFlagMode(
                            "MPOL_F_NUMA_BALANCING can only be used with MPOL_BIND".to_string(),
                        ));
                    }
                    flags_value |= MPOL_F_NUMA_BALANCING;
                }
                MemoryPolicyFlagType::MpolFRelativeNodes => {
                    has_relative = true;
                    flags_value |= MPOL_F_RELATIVE_NODES;
                }
                MemoryPolicyFlagType::MpolFStaticNodes => {
                    has_static = true;
                    flags_value |= MPOL_F_STATIC_NODES;
                }
            }
        }
        if has_static && has_relative {
            return Err(MemoryPolicyError::MutuallyExclusiveFlags(
                "MPOL_F_STATIC_NODES and MPOL_F_RELATIVE_NODES are mutually exclusive".to_string(),
            ));
        }
    }

    let mode_with_flags = base_mode | (flags_value as i32);

    match base_mode {
        MPOL_DEFAULT => {
            if let Some(nodes) = policy.nodes() {
                if !nodes.trim().is_empty() {
                    return Err(MemoryPolicyError::InvalidNodes(
                        "MPOL_DEFAULT does not accept node specification".to_string(),
                    ));
                }
            }
            if flags_value != 0 {
                return Err(MemoryPolicyError::InvalidFlag(
                    "MPOL_DEFAULT does not accept flags".to_string(),
                ));
            }
            syscall
                .set_mempolicy(mode_with_flags, &[], 0)
                .map_err(|err| {
                    tracing::error!(?err, "failed to set memory policy (MPOL_DEFAULT)");
                    MemoryPolicyError::Syscall(err)
                })?;
            Ok(())
        }
        MPOL_LOCAL => {
            if let Some(nodes) = policy.nodes() {
                if !nodes.trim().is_empty() {
                    return Err(MemoryPolicyError::InvalidNodes(
                        "MPOL_LOCAL does not accept node specification".to_string(),
                    ));
                }
            }
            if flags_value != 0 {
                return Err(MemoryPolicyError::InvalidFlag(
                    "MPOL_LOCAL does not accept flags".to_string(),
                ));
            }
            syscall
                .set_mempolicy(mode_with_flags, &[], 0)
                .map_err(|err| {
                    tracing::error!(?err, "failed to set memory policy (MPOL_LOCAL)");
                    MemoryPolicyError::Syscall(err)
                })?;
            Ok(())
        }
        MPOL_PREFERRED => match policy.nodes() {
            None => {
                if flags_value & (MPOL_F_RELATIVE_NODES | MPOL_F_STATIC_NODES) != 0 {
                    return Err(MemoryPolicyError::IncompatibleFlagMode(
                            "MPOL_PREFERRED with empty nodes cannot use MPOL_F_STATIC_NODES or MPOL_F_RELATIVE_NODES flags".to_string(),
                        ));
                }
                syscall
                    .set_mempolicy(mode_with_flags, &[], 0)
                    .map_err(|err| {
                        tracing::error!(
                            ?err,
                            "failed to set memory policy (MPOL_PREFERRED with empty nodes)"
                        );
                        MemoryPolicyError::Syscall(err)
                    })?;
                Ok(())
            }
            Some(nodes) if nodes.trim().is_empty() => {
                if flags_value & (MPOL_F_RELATIVE_NODES | MPOL_F_STATIC_NODES) != 0 {
                    return Err(MemoryPolicyError::IncompatibleFlagMode(
                            "MPOL_PREFERRED with empty nodes cannot use MPOL_F_STATIC_NODES or MPOL_F_RELATIVE_NODES flags".to_string(),
                        ));
                }
                syscall
                    .set_mempolicy(mode_with_flags, &[], 0)
                    .map_err(|err| {
                        tracing::error!(
                            ?err,
                            "failed to set memory policy (MPOL_PREFERRED with empty nodes)"
                        );
                        MemoryPolicyError::Syscall(err)
                    })?;
                Ok(())
            }
            Some(nodes) => {
                let (nodemask, maxnode) = build_nodemask(nodes)?;
                if maxnode == 0 {
                    if flags_value & (MPOL_F_RELATIVE_NODES | MPOL_F_STATIC_NODES) != 0 {
                        return Err(MemoryPolicyError::IncompatibleFlagMode(
                                "MPOL_PREFERRED with empty nodes cannot use MPOL_F_STATIC_NODES or MPOL_F_RELATIVE_NODES flags".to_string(),
                            ));
                    }
                    syscall
                        .set_mempolicy(mode_with_flags, &[], 0)
                        .map_err(|err| {
                            tracing::error!(
                                ?err,
                                "failed to set memory policy (MPOL_PREFERRED with empty nodes)"
                            );
                            MemoryPolicyError::Syscall(err)
                        })?;
                    return Ok(());
                }
                syscall
                    .set_mempolicy(mode_with_flags, &nodemask, maxnode)
                    .map_err(|err| {
                        tracing::error!(?err, "failed to set memory policy (MPOL_PREFERRED)");
                        MemoryPolicyError::Syscall(err)
                    })?;
                Ok(())
            }
        },
        _ => {
            let nodes = match policy.nodes() {
                None => {
                    return Err(MemoryPolicyError::InvalidNodes(format!(
                        "Mode {} requires non-empty node specification",
                        base_mode
                    )));
                }
                Some(nodes) if nodes.trim().is_empty() => {
                    return Err(MemoryPolicyError::InvalidNodes(format!(
                        "Mode {} requires non-empty node specification",
                        base_mode
                    )));
                }
                Some(nodes) => nodes,
            };
            let (nodemask, maxnode) = build_nodemask(nodes)?;
            if maxnode == 0 {
                return Err(MemoryPolicyError::InvalidNodes(format!(
                    "Mode {} requires non-empty node specification (parsed result is empty)",
                    base_mode
                )));
            }
            syscall
                .set_mempolicy(mode_with_flags, &nodemask, maxnode)
                .map_err(|err| {
                    tracing::error!(?err, "failed to set memory policy");
                    MemoryPolicyError::Syscall(err)
                })?;
            Ok(())
        }
    }
}

// Build a proper nodemask for set_mempolicy
fn build_nodemask(nodes: &str) -> Result<(Vec<u64>, u64)> {
    let node_ids = parse_node_string(nodes)?;

    if node_ids.is_empty() {
        // Empty nodemask - return NULL equivalent (empty vector)
        return Ok((Vec::new(), 0));
    }

    // Find the highest node ID
    let highest_node = node_ids.iter().max().copied().unwrap_or(0) as usize;

    // Calculate how many u64 values we need to store the bitmask
    let u64_bits = 64;
    let num_u64s = (highest_node / u64_bits) + 1;

    // Calculate maxnode
    let maxnode = (num_u64s * u64_bits) as u64;

    // Build the nodemask array as Vec<u64>
    let mut nodemask = vec![0u64; num_u64s];

    // Set bits for each node ID
    for node_id in node_ids {
        let node_id = node_id as usize;
        let word_index = node_id / u64_bits;
        let bit_index = node_id % u64_bits;

        if word_index < nodemask.len() {
            nodemask[word_index] |= 1u64 << bit_index;
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
        assert_eq!(got_args[0].maxnode, 2); // highest node ID (1) + 1 = 2

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
        assert_eq!(got_args_with_flags[1].maxnode, 1); // highest node ID (0) + 1 = 1

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
            .build()
            .unwrap();

        assert!(setup_memory_policy(&Some(policy_default_with_nodes), syscall.as_ref()).is_err());

        // Test MPOL_DEFAULT with flags (should fail)
        let policy_default_with_flags = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolDefault)
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
            .build()
            .unwrap();

        assert!(setup_memory_policy(&Some(policy_local_with_nodes), syscall.as_ref()).is_err());

        // Test MPOL_BIND with empty nodes (should fail)
        let policy_bind_empty = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolBind)
            .nodes("".to_string())
            .build()
            .unwrap();

        assert!(setup_memory_policy(&Some(policy_bind_empty), syscall.as_ref()).is_err());

        // Test MPOL_BIND with whitespace-only nodes (should fail)
        let policy_bind_whitespace = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolBind)
            .nodes("   ".to_string())
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

        // Test MPOL_BIND with empty nodes (should fail)
        let policy_bind_empty = LinuxMemoryPolicyBuilder::default()
            .mode(MemoryPolicyModeType::MpolBind)
            .nodes("".to_string())
            .build()
            .unwrap();

        assert!(setup_memory_policy(&Some(policy_bind_empty), syscall.as_ref()).is_err());
    }
}
