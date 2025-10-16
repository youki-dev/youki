use core::fmt;

use serde::{Deserialize, Serialize};

/// Used as a wrapper for messages to be sent between child and parent processes
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Message {
    IntermediateReady(i32),
    InitReady,
    WriteMapping,
    MappingWritten,
    WriteTimeOffsets,
    TimeOffsetsWritten,
    SeccompNotify,
    SeccompNotifyDone,
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
            Message::WriteTimeOffsets => write!(f, "WriteTimeOffsets"),
            Message::TimeOffsetsWritten => write!(f, "TimeOffsetsWritten"),
            Message::SeccompNotify => write!(f, "SeccompNotify"),
            Message::SeccompNotifyDone => write!(f, "SeccompNotifyDone"),
            Message::ExecFailed(s) => write!(f, "ExecFailed({})", s),
            Message::OtherError(s) => write!(f, "OtherError({})", s),
        }
    }
}
