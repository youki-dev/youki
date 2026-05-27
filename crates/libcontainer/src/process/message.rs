use core::fmt;
use std::collections::HashMap;
use std::path::PathBuf;

use oci_spec::runtime::LinuxIdMapping;
use serde::{Deserialize, Serialize};

use crate::network::cidr::CidrAddress;

/// Used as a wrapper for messages to be sent between child and parent processes
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Message {
    IntermediateReady(i32),
    InitReady,
    WriteMapping,
    MappingWritten,
    SeccompNotify,
    SeccompNotifyDone,
    SetupNetworkDeviceReady,
    MoveNetworkDevice(HashMap<String, Vec<CidrAddress>>),
    AskMountFd(MountMsg),
    MountFdReply,
    ExecFailed(String),
    OtherError(String),
    MountFdError(String),
    HookRequest,
    HookDone,
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::IntermediateReady(pid) => write!(f, "IntermediateReady({})", pid),
            Message::InitReady => write!(f, "InitReady"),
            Message::WriteMapping => write!(f, "WriteMapping"),
            Message::MappingWritten => write!(f, "MappingWritten"),
            Message::SetupNetworkDeviceReady => write!(f, "SetupNetworkDeviceReady"),
            Message::MoveNetworkDevice(addr) => write!(f, "MoveNetworkDevice({:?})", addr),
            Message::SeccompNotify => write!(f, "SeccompNotify"),
            Message::SeccompNotifyDone => write!(f, "SeccompNotifyDone"),
            Message::HookRequest => write!(f, "HookRequest"),
            Message::HookDone => write!(f, "HookDone"),
            Message::AskMountFd(msg) => write!(f, "AskMountFd({:?})", msg),
            Message::MountFdReply => write!(f, "MountFdReply"),
            Message::MountFdError(err) => write!(f, "MountFdError({})", err),
            Message::ExecFailed(s) => write!(f, "ExecFailed({})", s),
            Message::OtherError(s) => write!(f, "OtherError({})", s),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct MountMsg {
    pub source: PathBuf,
    pub idmap: Option<MountIdMap>,
    pub clone_mount_tree_recursively: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct MountIdMap {
    pub userns_source: MountIdMapUsernsSource,
    pub apply_idmap_recursively: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum MountIdMapUsernsSource {
    Mappings {
        uid_mappings: Vec<LinuxIdMapping>,
        gid_mappings: Vec<LinuxIdMapping>,
    },
    ContainerUserns,
}
