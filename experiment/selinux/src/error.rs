use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum SELinuxError {
    #[error("Failed to set file label for SELinux: {0}")]
    SetFileLabel(String),
    #[error("Failed to lset file label for SELinux: {0}")]
    LSetFileLabel(String),
    #[error("Failed to get file label for SELinux: {0}")]
    FileLabel(String),
    #[error("Failed to get lfile label for SELinux: {0}")]
    LFileLabel(String),
    #[error("Failed to call is_proc_handle for SELinux: {0}")]
    IsProcHandle(String),
    #[error("Failed to call read_con_fd for SELinux: {0}")]
    ReadConFd(String),
    #[error("Failed to call read_con for SELinux: {0}")]
    ReadCon(String),
    #[error("Failed to call write_con for SELinux: {0}")]
    WriteCon(String),
    #[error("Failed to find the index for a given class: {0}")]
    ClassIndex(String),
    #[error("Failed to call peer_label for SELinux: {0}")]
    PeerLabel(String),
    #[error("Failed to call open_context_file for SELinux: {0}")]
    OpenContextFile(String),
    #[error("Failed to set enforce mode of SELinux: {0}")]
    SetEnforceMode(String),
    #[error("Failed to read config file of SELinux: {0}")]
    GetConfigKey(String),
    #[error("Invalid format for SELinux label: {0}")]
    InvalidSELinuxLabel(String),
    #[error("Failed to load SELinux labels: {0}")]
    LoadLabels(String),
    #[error("Failed to load SELinux config: {0}")]
    LoadConfig(String),
    #[error("SELinux setting error: {0}")]
    SELinuxSettingError(#[from] SELinuxSettingError),
}

#[derive(Debug, thiserror::Error)]
pub enum SELinuxSettingError {
    #[error("SELinux is not installed")]
    NotInstalled,
    #[error("Enforce file in SELinux not found: {0}")]
    EnforceFileNotFound(PathBuf),
    #[error("Invalid SELinux mode: {0}")]
    InvalidMode(String),
    #[error("Failed to set enforce mode of SELinux: {0}")]
    SetEnforceMode(String),
    #[error("Failed to load SELinux config: {0}")]
    LoadConfig(String),
    #[error("Failed to read config file of SELinux: {0}")]
    GetConfigKey(String),
}
