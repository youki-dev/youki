use crate::selinux_label::SELinuxLabel;
use nix::errno::Errno;
use nix::sys::statfs;
use nix::unistd::gettid;
use std::collections::HashMap;
use std::convert::From;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

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

pub(crate) const ERR_EMPTY_PATH: &str = "empty path";
const SELINUX_FS_MOUNT: &str = "/sys/fs/selinux";
const CONTEXT_FILE: &str = "/usr/share/containers/selinux/contexts";
const SELINUX_TYPE_TAG: &str = "SELINUXTYPE";
const SELINUX_TAG: &str = "SELINUX";
const SELINUX_DIR: &str = "/etc/selinux/";
const SELINUX_CONFIG: &str = "config";

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
}

pub struct SELinux {
    // for attr_path()
    have_thread_self: AtomicBool,
    attr_path_init_done: AtomicBool,

    // for selinuxfs
    selinuxfs_init_done: AtomicBool,
    selinuxfs: Option<PathBuf>,

    // for policy_root()
    policy_root_init_done: AtomicBool,
    policy_root: Option<PathBuf>,

    // for load_labels()
    pub(crate) load_labels_init_done: AtomicBool,
    pub(crate) labels: HashMap<String, SELinuxLabel>,

    // for read config and get config key
    read_config_init_done: AtomicBool,
    configs: HashMap<String, String>,

    pub(crate) read_only_file_label: Option<SELinuxLabel>,
}

impl Default for SELinux {
    fn default() -> Self {
        SELinux::new()
    }
}

impl SELinux {
    pub fn new() -> Self {
        SELinux {
            have_thread_self: AtomicBool::new(false),
            attr_path_init_done: AtomicBool::new(false),

            selinuxfs_init_done: AtomicBool::new(false),
            selinuxfs: None,

            policy_root_init_done: AtomicBool::new(false),
            policy_root: None,

            load_labels_init_done: AtomicBool::new(false),
            labels: HashMap::new(),

            read_config_init_done: AtomicBool::new(false),
            configs: HashMap::new(),

            read_only_file_label: None,
        }
    }

    // This function returns policy_root.
    // Directories under policy root has configuration files etc.
    fn policy_root(&mut self) -> Option<&PathBuf> {
        // Avoiding code conflicts and ensuring thread-safe execution once only.
        if !self.policy_root_init_done.load(Ordering::SeqCst) {
            let policy_root_path = Self::get_config_key(self, SELINUX_TYPE_TAG).unwrap_or_default();
            self.policy_root = Some(PathBuf::from(policy_root_path));
            self.policy_root_init_done.store(true, Ordering::SeqCst);
        }
        self.policy_root.as_ref()
    }

    // This function reads SELinux config file and returns the value with a specified key.
    fn get_config_key(&mut self, target_key: &str) -> Result<String, SELinuxError> {
        if !self.read_config_init_done.load(Ordering::SeqCst) {
            let config_path = Path::new(SELINUX_DIR).join(SELINUX_CONFIG);
            if let Ok(file) = File::open(config_path) {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    if line.is_empty() {
                        continue;
                    }
                    if (line.starts_with(';')) || (line.starts_with('#')) {
                        continue;
                    }
                    let fields: Vec<&str> = line.splitn(2, '=').collect();
                    if fields.len() < 2 {
                        continue;
                    }
                    let key = fields[0].trim().to_string();
                    let value = fields[1].trim().to_string();
                    self.configs.insert(key, value);
                }
            }
            self.read_config_init_done.store(true, Ordering::SeqCst);
        }
        self.configs
            .get(target_key)
            .cloned()
            .filter(|s| !s.is_empty())
            .ok_or(SELinuxError::GetConfigKey(format!(
                "can't find the target label in the config file: {}",
                target_key
            )))
    }

    // get_enabled returns whether SELinux is enabled or not.
    pub fn get_enabled(&mut self) -> bool {
        match Self::get_selinux_mountpoint(self) {
            // If there is no SELinux mountpoint, SELinux is not enabled.
            None => false,
            Some(_) => match Self::current_label(self) {
                Ok(con) => {
                    // Check whether label is "kernel" or not.
                    if con.user != "kernel" {
                        return true;
                    }
                    false
                }
                Err(_) => false,
            },
        }
    }

    // verify_selinux_fs_mount verifies if the specified mount point is
    // properly mounted as a writable SELinux filesystem.
    fn verify_selinux_fs_mount<P: AsRef<Path>>(mnt: P) -> bool {
        let mnt = mnt.as_ref();
        loop {
            match statfs::statfs(mnt) {
                Ok(stat) => {
                    // In go-selinux, return false if it is not read-only,
                    // but selinux code in SELinuxProject return true even though it is read-only.
                    // https://github.com/SELinuxProject/selinux/blob/1f080ffd7ab24b0ad2b46f79db63d62c2ae2747c/libselinux/src/init.c#L44
                    // Therefore, this function doesn't check whether it is read-only or not.

                    // verify if the file is SELinux filesystem
                    return stat.filesystem_type() == statfs::SELINUX_MAGIC;
                }
                // check again if there is an issue while calling statfs
                Err(Errno::EAGAIN) | Err(Errno::EINTR) => continue,
                Err(_) => return false,
            }
        }
    }

    // check_line_include_selinux_fs_mount_point returns a next selinuxfs mount point found,
    // if there is one, or None in case of EOF or error.
    fn check_line_include_selinux_fs_mount_point(line: &str) -> Option<PathBuf> {
        if !line.contains(" - selinuxfs ") {
            return None;
        }
        // Need to return the path like /sys/fs/selinux
        // example: 28 24 0:25 / /sys/fs/selinux rw,relatime - selinuxfs selinuxfs rw
        let m_pos = 5;
        let fields: Vec<&str> = line.splitn(m_pos + 1, ' ').collect();
        if fields.len() < m_pos + 1 {
            return None;
        }
        let mountpoint = fields[m_pos - 1].to_string();
        Some(PathBuf::from(mountpoint))
    }

    // find_selinux_fs finds the SELinux filesystem mount point.
    fn find_selinux_fs() -> Option<PathBuf> {
        // fast path: check the default mount first
        let selinux_fs_mount_path = PathBuf::from(SELINUX_FS_MOUNT);
        if Self::verify_selinux_fs_mount(&selinux_fs_mount_path) {
            return Some(selinux_fs_mount_path);
        }

        // check if selinuxfs is available before going the slow path
        let fs = fs::read_to_string("/proc/filesystems").unwrap_or_default();
        if !fs.contains("\tselinuxfs\n") {
            return None;
        }

        // slow path: try to find among the mounts
        match File::open("/proc/self/mountinfo") {
            Ok(file) => {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    if let Some(mnt) = Self::check_line_include_selinux_fs_mount_point(&line) {
                        if Self::verify_selinux_fs_mount(&mnt) {
                            return Some(mnt);
                        }
                    }
                }
            }
            Err(_) => return None,
        }
        None
    }

    // This function returns the path to the mountpoint of an selinuxfs
    // filesystem or an empty string if no mountpoint is found. Selinuxfs is
    // a proc-like pseudo-filesystem that exposes the SELinux policy API to
    // processes. The existence of an seliuxfs mount is used to determine
    // whether SELinux is currently enabled or not.
    pub fn get_selinux_mountpoint(&mut self) -> Option<&PathBuf> {
        // Avoiding code conflicts and ensuring thread-safe execution once only.
        if !self.selinuxfs_init_done.load(Ordering::SeqCst) {
            self.selinuxfs = Self::find_selinux_fs();
            self.selinuxfs_init_done.store(true, Ordering::SeqCst);
        }
        self.selinuxfs.as_ref()
    }

    // classIndex returns the int index for an object class in the loaded policy, or an error.
    // For example, if a class is "file" or "dir", return the corresponding index for selinux.
    pub fn class_index(&mut self, class: &str) -> Result<i64, SELinuxError> {
        let permpath = format!("class/{}/index", class);
        let mountpoint = Self::get_selinux_mountpoint(self)
            .ok_or_else(|| SELinuxError::ClassIndex("SELinux mount point not found".to_string()))?;
        let indexpath = mountpoint.join(permpath);

        match fs::read_to_string(indexpath) {
            Ok(index_b) => match index_b.parse::<i64>() {
                Ok(index) => Ok(index),
                Err(e) => Err(SELinuxError::ClassIndex(e.to_string())),
            },
            Err(e) => Err(SELinuxError::ClassIndex(e.to_string())),
        }
    }

    // This function attempts to open a selinux context file, and if it fails, it tries to open another file
    // under policy root's directory.
    pub(crate) fn open_context_file(&mut self) -> Result<File, SELinuxError> {
        match File::open(CONTEXT_FILE) {
            Ok(file) => Ok(file),
            Err(_) => {
                let policy_path = Self::policy_root(self).ok_or_else(|| {
                    SELinuxError::OpenContextFile("can't get policy root".to_string())
                })?;
                let context_on_policy_root = policy_path.join("contexts").join("lxc_contexts");
                match File::open(context_on_policy_root) {
                    Ok(file) => Ok(file),
                    Err(e) => Err(SELinuxError::OpenContextFile(e.to_string())),
                }
            }
        }
    }

    // This returns selinux enforce path by using selinux mountpoint.
    // The enforce path dynamically changes SELinux mode at runtime,
    // while the config file need OS to reboot after changing the config file.
    fn selinux_enforce_path(&mut self) -> Option<PathBuf> {
        let selinux_mountpoint = Self::get_selinux_mountpoint(self);
        selinux_mountpoint.map(|m| m.join("enforce"))
    }

    // enforce_mode returns the current SELinux mode Enforcing, Permissive, Disabled
    pub fn enforce_mode(&mut self) -> SELinuxMode {
        let mode = match Self::selinux_enforce_path(self) {
            Some(enforce_path) => match fs::read_to_string(enforce_path) {
                Ok(content) => content.trim().parse::<i32>().unwrap_or(-1),
                Err(_) => -1,
            },
            None => -1,
        };
        SELinuxMode::from(mode)
    }

    // is_mls_enabled checks if MLS is enabled.
    pub fn is_mls_enabled(&mut self) -> bool {
        if let Some(mountpoint) = Self::get_selinux_mountpoint(self) {
            let mls_path = Path::new(&mountpoint).join("mls");
            match fs::read(mls_path) {
                Ok(enabled_b) => return enabled_b == vec![b'1'],
                Err(_) => return false,
            }
        }
        false
    }

    // This function updates the enforce mode of selinux.
    // Disabled is not valid, since this needs to be set at boot time.
    pub fn set_enforce_mode(&mut self, mode: SELinuxMode) -> Result<(), SELinuxError> {
        let enforce_path = Self::selinux_enforce_path(self).ok_or_else(|| {
            SELinuxError::SetEnforceMode("can't get selinux enforce path".to_string())
        })?;
        fs::write(enforce_path, mode.to_string().as_bytes())
            .map_err(|e| SELinuxError::SetEnforceMode(e.to_string()))
    }

    // This returns the systems default SELinux mode Enforcing, Permissive or Disabled.
    // note this is just the default at boot time.
    // enforce_mode function tells you the system current mode.
    pub fn default_enforce_mode(&mut self) -> SELinuxMode {
        SELinuxMode::from(
            Self::get_config_key(self, SELINUX_TAG)
                .unwrap_or_default()
                .as_str(),
        )
    }

    // write_con writes a specified value to a given file path, handling SELinux context.
    pub fn write_con<P: AsRef<Path>>(
        &mut self,
        fpath: P,
        val: &str,
    ) -> Result<usize, SELinuxError> {
        let path = fpath.as_ref();
        if path.as_os_str().is_empty() {
            return Err(SELinuxError::WriteCon(ERR_EMPTY_PATH.to_string()));
        }
        if val.is_empty() && !Self::get_enabled(self) {
            return Err(SELinuxError::WriteCon("SELinux is not enabled".to_string()));
        }

        let mut out = OpenOptions::new()
            .write(true)
            .create(false)
            .open(fpath)
            .map_err(|e| SELinuxError::WriteCon(format!("failed to open file: {}", e)))?;

        Self::is_proc_handle(&out)?;
        match out.write(val.as_bytes()) {
            Ok(u) => Ok(u),
            Err(e) => Err(SELinuxError::WriteCon(format!(
                "failed to write in file: {}",
                e
            ))),
        }
    }

    // This function checks whether this file is on the procfs filesystem.
    pub fn is_proc_handle(file: &File) -> Result<(), SELinuxError> {
        loop {
            match statfs::fstatfs(file.as_fd()) {
                Ok(stat) if stat.filesystem_type() == statfs::PROC_SUPER_MAGIC => break,
                Ok(_) => {
                    return Err(SELinuxError::IsProcHandle(format!(
                        "file {} is not on procfs",
                        file.as_raw_fd()
                    )));
                }
                Err(Errno::EINTR) => continue,
                Err(err) => {
                    return Err(SELinuxError::IsProcHandle(format!(
                        "fstatfs failed: {}",
                        err
                    )))
                }
            }
        }
        Ok(())
    }

    // This function reads a given file descriptor into a string.
    pub fn read_con_fd<F: AsFd + Read>(file: &mut F) -> Result<String, SELinuxError> {
        let mut data = String::new();
        file.read_to_string(&mut data)
            .map_err(|e| SELinuxError::ReadConFd(e.to_string()))?;

        // Remove null bytes on the end of a file.
        let trimmed_data = data.trim_end_matches(char::from(0));
        Ok(trimmed_data.to_string())
    }

    // read_con reads a label to a given file path, handling SELinux context.
    pub fn read_con<P: AsRef<Path>>(fpath: P) -> Result<String, SELinuxError> {
        let path = fpath.as_ref();
        if path.as_os_str().is_empty() {
            return Err(SELinuxError::ReadCon(ERR_EMPTY_PATH.to_string()));
        }
        let mut in_file = File::open(fpath)
            .map_err(|e| SELinuxError::ReadCon(format!("failed to open file: {}", e)))?;

        Self::is_proc_handle(&in_file)?;
        Self::read_con_fd(&mut in_file)
    }

    // attr_path determines the correct file path for accessing SELinux
    // attributes of a process or thread in a Linux environment.
    pub fn attr_path(&self, attr: &str) -> PathBuf {
        // Linux >= 3.17 provides this
        const THREAD_SELF_PREFIX: &str = "/proc/thread-self/attr";
        // Avoiding code conflicts and ensuring thread-safe execution once only.
        if !self.attr_path_init_done.load(Ordering::SeqCst) {
            let path = PathBuf::from(THREAD_SELF_PREFIX);
            let is_dir = path.is_dir();
            self.have_thread_self.store(is_dir, Ordering::SeqCst);
            self.attr_path_init_done.store(true, Ordering::SeqCst);
        }
        if self.have_thread_self.load(Ordering::SeqCst) {
            return PathBuf::from(&format!("{}/{}", THREAD_SELF_PREFIX, attr));
        }

        PathBuf::from(&format!("/proc/self/task/{}/attr/{}", gettid(), attr))
    }
}

#[cfg(test)]
mod tests {
    use crate::selinux::*;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use std::str;
    use tempfile::NamedTempFile;

    fn create_temp_file(content: &[u8], file_name: &str) {
        let path = Path::new(file_name);
        let mut file = File::create(path).expect("Failed to create file");
        file.write_all(content).expect("Failed to write to file");
        file.sync_all().expect("Failed to sync file");
    }

    #[test]
    fn test_read_con_fd() {
        let content_array: Vec<&[u8]> =
            vec![b"Hello, world\0", b"Hello, world\0\0\0", b"Hello,\0world"];
        let expected_array = ["Hello, world", "Hello, world", "Hello,\0world"];
        for (i, content) in content_array.iter().enumerate() {
            let expected = expected_array[i];
            let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
            temp_file
                .write_all(content)
                .expect("Failed to write to temp file");
            // Need to open again to get read permission.
            let mut file = File::open(temp_file).expect("Failed to open file");
            let result = SELinux::read_con_fd(&mut file).expect("Failed to read file");
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_attr_path() {
        let selinux = SELinux::new();
        // Test with "/proc/thread-self/attr" path (Linux >= 3.17)
        let attr = "bar";
        let expected_name = &format!("/proc/thread-self/attr/{}", attr);
        let expected_path = Path::new(expected_name);
        let actual_path = selinux.attr_path(attr);
        assert_eq!(expected_path, actual_path);

        // Test with not having "/proc/thread-self/attr" path by setting HAVE_THREAD_SELF as false
        selinux.attr_path_init_done.store(true, Ordering::SeqCst);
        selinux.have_thread_self.store(false, Ordering::SeqCst);
        let thread_id = gettid();
        let expected_name = &format!("/proc/self/task/{}/attr/{}", thread_id, attr);
        let expected_path = Path::new(expected_name);
        let actual_path = selinux.attr_path(attr);
        assert_eq!(expected_path, actual_path);
    }

    #[test]
    fn test_is_proc_handle() {
        let filename_array = ["/proc/self/status", "/tmp/testfile"];
        let expected_array = [true, false];

        for (i, filename) in filename_array.iter().enumerate() {
            let expected_ok = expected_array[i];
            let path = Path::new(filename);
            let file = match File::open(path) {
                Ok(file) => file,
                Err(_) => {
                    create_temp_file(b"", filename);
                    File::open(path).expect("failed to open file")
                }
            };
            let result = SELinux::is_proc_handle(&file);
            if expected_ok {
                assert!(result.is_ok(), "Expected Ok, but got Err: {:?}", result);
            } else {
                assert!(result.is_err(), "Expected Err, but got Ok");
            }
        }
    }

    #[test]
    fn test_check_line_include_selinux_fs_mount_point() {
        let input_array = [
            "28 24 0:25 / /sys/fs/selinux rw,relatime - selinuxfs selinuxfs rw",
            "28 24 0:25 /",
            "28 24 0:25 / /sys/fs/selinux rw,relatime selinuxfs rw",
        ];
        let expected_array = ["/sys/fs/selinux", "", ""];
        let succeeded_array = [true, false, false];

        for (i, input) in input_array.iter().enumerate() {
            let expected = PathBuf::from(expected_array[i]);
            match SELinux::check_line_include_selinux_fs_mount_point(input) {
                Some(output) => assert_eq!(expected, output),
                None => assert!(!succeeded_array[i]),
            }
        }
    }
}
