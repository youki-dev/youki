use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::sys::statfs;

use crate::mode::SELinuxMode;
use crate::SELinuxSettingError;

const SELINUX_CONFIG: &str = "config";
const SELINUX_FS_MOUNT: &str = "/sys/fs/selinux";

pub struct SELinuxSetting {
    // selinuxfs stores the path to the mountpoint of an selinuxfs
    // filesystem or None if no mountpoint is found. selinuxfs is
    // a proc-like pseudo-filesystem that exposes the SELinux policy API to
    // processes. The existence of an seliuxfs mount is used to determine
    // whether SELinux is currently enabled or not.
    pub selinuxfs: PathBuf,

    enforce_file: PathBuf,
    configs: HashMap<String, String>,
}

impl SELinuxSetting {
    pub fn try_default() -> Result<Self, SELinuxSettingError> {
        let selinuxfs_result = Self::find_selinux_fs();
        if let Some(selinuxfs) = selinuxfs_result {
            SELinuxSetting::new("/etc/selinux/", selinuxfs.as_path())
        } else {
            Err(SELinuxSettingError::NotInstalled)
        }
    }

    pub fn new<P1: AsRef<Path>, P2: AsRef<Path>>(
        selinux_dir: P1,
        selinuxfs: P2,
    ) -> Result<Self, SELinuxSettingError> {
        let enforce_path = selinuxfs.as_ref().join("enforce");
        if !enforce_path.exists() {
            return Err(SELinuxSettingError::EnforceFileNotFound(enforce_path));
        }

        // selinuxfs = selinuxmountpoint
        Ok(SELinuxSetting {
            selinuxfs: selinuxfs.as_ref().to_path_buf(),
            enforce_file: enforce_path,
            configs: Self::load_configs(selinux_dir)?,
        })
    }

    fn load_configs<P: AsRef<Path>>(
        selinux_dir: P,
    ) -> Result<HashMap<String, String>, SELinuxSettingError> {
        let config_path = selinux_dir.as_ref().join(SELINUX_CONFIG);
        let file =
            File::open(config_path).map_err(|e| SELinuxSettingError::LoadConfig(e.to_string()))?;
        let reader = BufReader::new(file);
        Ok(reader
            .lines()
            .map_while(Result::ok)
            .fold(HashMap::new(), |mut acc, line| {
                let line = line.trim();
                if line.is_empty() {
                    return acc;
                }
                if line.starts_with(';') || line.starts_with('#') {
                    return acc;
                }
                let fields: Vec<&str> = line.splitn(2, '=').collect();
                if fields.len() < 2 {
                    return acc;
                }
                let key = fields[0].trim().to_string();
                let value = fields[1].trim().to_string();
                acc.insert(key, value);
                acc
            }))
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

    // This function reads SELinux config file and returns the value with a specified key.
    pub fn get_config_key(&self, target_key: &str) -> Result<String, SELinuxSettingError> {
        return self
            .configs
            .get(target_key)
            .cloned()
            .filter(|s| !s.is_empty())
            .ok_or(SELinuxSettingError::GetConfigKey(format!(
                "can't find the target label in the config file: {}",
                target_key
            )));
    }

    // enforce_mode returns the current SELinux mode Enforcing, Permissive, Disabled
    pub fn enforce_mode(&self) -> Result<SELinuxMode, SELinuxSettingError> {
        match fs::read_to_string(&self.enforce_file) {
            Ok(content) => content
                .trim()
                .parse::<i32>()
                .map(SELinuxMode::from)
                .map_err(|e| SELinuxSettingError::InvalidMode(e.to_string())),
            Err(e) => Err(SELinuxSettingError::InvalidMode(e.to_string())),
        }
    }

    // This function updates the enforce mode of selinux.
    // Disabled is not valid, since this needs to be set at boot time.
    pub fn set_enforce_mode(&self, mode: SELinuxMode) -> Result<(), SELinuxSettingError> {
        fs::write(&self.enforce_file, mode.as_bytes())
            .map_err(|e| SELinuxSettingError::SetEnforceMode(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::SELinuxSetting;

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
            match SELinuxSetting::check_line_include_selinux_fs_mount_point(input) {
                Some(output) => assert_eq!(expected, output),
                None => assert!(!succeeded_array[i]),
            }
        }
    }
}
