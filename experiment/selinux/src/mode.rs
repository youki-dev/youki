use std::fmt;

#[derive(Debug, Copy, Clone)]
pub enum SELinuxMode {
    // ENFORCING constant to indicate SELinux is in enforcing mode
    ENFORCING = 1,
    // PERMISSIVE constant to indicate SELinux is in permissive mode
    PERMISSIVE = 0,
    // DISABLED constant to indicate SELinux is disabled
    DISABLED = -1,
}

impl From<i32> for SELinuxMode {
    fn from(mode: i32) -> Self {
        match mode {
            1 => SELinuxMode::ENFORCING,
            0 => SELinuxMode::PERMISSIVE,
            -1 => SELinuxMode::DISABLED,
            _ => SELinuxMode::DISABLED,
        }
    }
}

impl From<&str> for SELinuxMode {
    fn from(mode: &str) -> Self {
        match mode {
            "enforcing" => SELinuxMode::ENFORCING,
            "permissive" => SELinuxMode::PERMISSIVE,
            _ => SELinuxMode::DISABLED,
        }
    }
}

impl fmt::Display for SELinuxMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            SELinuxMode::ENFORCING => "enforcing",
            SELinuxMode::PERMISSIVE => "permissive",
            SELinuxMode::DISABLED => "disabled",
        };
        write!(f, "{}", s)
    }
}

impl SELinuxMode {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            SELinuxMode::ENFORCING => b"1",
            SELinuxMode::PERMISSIVE => b"0",
            SELinuxMode::DISABLED => b"-1",
        }
    }
}
