use core::fmt;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::network::cidr::CidrAddress;
use oci_spec::runtime::LinuxIdMapping;

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
    MountFdPlease(MountMsg),
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
            Message::MountFdPlease(_) => write!(f, "MountFdPlease"),
            Message::MountFdReply => write!(f, "MountFdReply"),
            Message::MountFdError(err) => write!(f, "MountFdError({})", err),
            Message::ExecFailed(s) => write!(f, "ExecFailed({})", s),
            Message::OtherError(s) => write!(f, "OtherError({})", s),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MountMsg {
    pub source: String,
    pub idmap: Option<MountIdMap>,
    pub recursive: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MountIdMap {
    pub uid_mappings: Vec<LinuxIdMapping>,
    pub gid_mappings: Vec<LinuxIdMapping>,
    pub recursive: bool,
}
