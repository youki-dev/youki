use core::fmt;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::network::serialize::SerializableAddress;

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
    MoveNetworkDevice(HashMap<String, Vec<SerializableAddress>>),
    ExecFailed(String),
    OtherError(String),
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
            Message::ExecFailed(s) => write!(f, "ExecFailed({})", s),
            Message::OtherError(s) => write!(f, "OtherError({})", s),
        }
    }
}
