use std::fmt::Display;

pub enum ControllerType {
    Cpu,
    CpuSet,
    Devices,
    Io,
    Memory,
    Pids,
}

impl Display for ControllerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let print = match self {
            ControllerType::Cpu => "cpu",
            ControllerType::CpuSet => "cpuset",
            ControllerType::Devices => "devices",
            ControllerType::Io => "io",
            ControllerType::Memory => "memory",
            ControllerType::Pids => "pids",
        };

        write!(f, "{print}")
    }
}

impl AsRef<str> for ControllerType {
    fn as_ref(&self) -> &str {
        match self {
            ControllerType::Cpu => "cpu",
            ControllerType::CpuSet => "cpuset",
            ControllerType::Devices => "devices",
            ControllerType::Io => "io",
            ControllerType::Memory => "memory",
            ControllerType::Pids => "pids",
        }
    }
}

pub const CONTROLLER_TYPES: &[ControllerType] = &[
    ControllerType::Cpu,
    ControllerType::CpuSet,
    ControllerType::Devices,
    ControllerType::Io,
    ControllerType::Memory,
    ControllerType::Pids,
];
