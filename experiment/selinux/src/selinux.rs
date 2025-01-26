use crate::label::SELinuxLabel;
use crate::setting::SELinuxSetting;
use crate::SELinuxError;
use nix::errno::Errno;
use nix::sys::statfs;
use nix::unistd::gettid;
use std::collections::HashMap;
use std::convert::From;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};

pub(crate) const ERR_EMPTY_PATH: &str = "empty path";
pub const DEFAULT_SELINUX_DIR: &str = "/etc/selinux/";
const CONTEXT_FILE: &str = "/usr/share/containers/selinux/contexts";
const SELINUX_TYPE_TAG: &str = "SELINUXTYPE";
// Linux >= 3.17 provides this
const THREAD_SELF_PREFIX: &str = "/proc/thread-self/attr";

type SelinuxLabels = HashMap<String, SELinuxLabel>;

pub struct SELinux<'a> {
    setting: &'a SELinuxSetting,

    policy_root: PathBuf,

    // for load_labels()
    pub(crate) labels: SelinuxLabels,

    have_thread: bool,

    pub(crate) read_only_file_label: Option<&'a SELinuxLabel>,
}

impl<'a> SELinux<'a> {
    pub fn try_default(setting: &'a SELinuxSetting) -> Result<Self, SELinuxError> {
        let have_thread_self = PathBuf::from(THREAD_SELF_PREFIX).is_dir();
        Self::new(CONTEXT_FILE, have_thread_self, setting)
    }

    pub fn new<P: AsRef<Path>>(
        context_file: P,
        have_thread: bool,
        setting: &'a SELinuxSetting,
    ) -> Result<Self, SELinuxError> {
        let mut selinux = SELinux {
            setting,
            policy_root: PathBuf::new(),
            labels: HashMap::new(),
            read_only_file_label: None,
            have_thread,
        };

        selinux.policy_root = selinux.look_up_policy_root()?;
        selinux.labels = selinux.load_labels(context_file)?;

        Ok(selinux)
    }

    // get_enabled returns whether SELinux is enabled or not.
    pub fn get_enabled(&self) -> bool {
        match Self::current_label(self) {
            Ok(con) => {
                // Check whether label is "kernel" or not.
                if con.user != "kernel" {
                    return true;
                }
                false
            }
            Err(_) => false,
        }
    }

    // This function returns policy_root.
    // Directories under policy root has configuration files etc.
    fn look_up_policy_root(&self) -> Result<PathBuf, SELinuxError> {
        // TODO: Remove `clone`
        let policy_root_path =
            PathBuf::from(DEFAULT_SELINUX_DIR).join(self.setting.get_config_key(SELINUX_TYPE_TAG)?);
        Ok(policy_root_path)
    }

    // This function loads context file and reads labels and stores it.
    fn load_labels<P: AsRef<Path>>(
        &self,
        context_file: P,
    ) -> Result<HashMap<String, SELinuxLabel>, SELinuxError> {
        // The context file should have pairs of key and value like below.
        // ----------
        // process = "system_u:system_r:container_t:s0"
        // file = "system_u:object_r:container_file_t:s0"
        // ----------
        let file = Self::open_context_file_impl(self, context_file)
            .map_err(|e| SELinuxError::LoadLabels(e.to_string()))?;
        let reader = BufReader::new(file);
        Ok(reader
            .lines()
            .map_while(Result::ok)
            .fold(HashMap::new(), |mut acc, line| {
                let line = line.trim();
                if line.is_empty() {
                    return acc;
                }
                let fields: Vec<&str> = line.splitn(2, '=').collect();
                if fields.len() != 2 {
                    return acc;
                }
                let key = fields[0].trim().to_string();
                let value = fields[1].trim().to_string();
                if let Ok(value_label) = SELinuxLabel::try_from(value) {
                    acc.insert(key, value_label);
                }
                acc
            }))
    }

    // classIndex returns the int index for an object class in the loaded policy, or an error.
    // For example, if a class is "file" or "dir", return the corresponding index for selinux.
    pub fn class_index(&self, class: &str) -> Result<i64, SELinuxError> {
        let permpath = format!("class/{}/index", class);
        let indexpath = self.setting.selinuxfs.join(permpath);

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
    // pub(crate) fn open_context_file<P: AsRef<Path>>(&self) -> Result<File, SELinuxError> {
    //     self.open_context_file_impl(CONTEXT_FILE)
    // }

    fn open_context_file_impl<P: AsRef<Path>>(&self, path: P) -> Result<File, SELinuxError> {
        match File::open(path.as_ref()) {
            Ok(file) => Ok(file),
            Err(_) => {
                let context_on_policy_root = self.policy_root.join("contexts").join("lxc_contexts");
                match File::open(&context_on_policy_root) {
                    Ok(file) => Ok(file),
                    Err(e) => Err(SELinuxError::OpenContextFile(format!(
                        "Failed to open context file({:?} and {:?}): {}",
                        &path.as_ref().as_os_str(),
                        context_on_policy_root.as_os_str(),
                        e
                    ))),
                }
            }
        }
    }

    // is_mls_enabled checks if MLS is enabled.
    pub fn is_mls_enabled(&self) -> bool {
        let mls_path = self.setting.selinuxfs.join("mls");
        match fs::read(mls_path) {
            Ok(enabled_b) => enabled_b == vec![b'1'],
            Err(_) => false,
        }
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
        if self.have_thread {
            return PathBuf::from(&format!("{}/{}", THREAD_SELF_PREFIX, attr));
        }

        PathBuf::from(&format!("/proc/self/task/{}/attr/{}", gettid(), attr))
    }
}

#[cfg(test)]
mod tests {
    use crate::{selinux::*, SELinuxSettingError};
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use tempfile::NamedTempFile;

    fn create_temp_file<P: AsRef<Path>>(content: &[u8], path: P) {
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
    fn test_attr_path() -> Result<(), SELinuxError> {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        create_temp_file(
            b"SELINUX=enforcing\nSELINUXTYPE=targeted\n",
            temp_dir.path().join("config"),
        );
        create_temp_file(b"0", temp_dir.path().join("enforce"));

        let context_file = temp_dir.path().join("contexts");
        create_temp_file(b"process = \"system_u:system_r:container_t:s0\"\nfile = \"system_u:object_r:container_file_t:s0\"\n", context_file.as_path());

        let setting_result = SELinuxSetting::new(temp_dir.path(), temp_dir.path());
        if matches!(setting_result, Err(SELinuxSettingError::NotInstalled)) {
            // TODO: We should run the test even if SELinux is not installed.
            println!("Skipping the test because SELinux is not installed");
            return Ok(());
        }
        let setting = setting_result?;

        let selinux_result = SELinux::new(context_file.as_path(), true, &setting);
        let mut selinux = selinux_result?;

        // Test with "/proc/thread-self/attr" path (Linux >= 3.17)
        let attr = "bar";
        let expected_name = &format!("/proc/thread-self/attr/{}", attr);
        let expected_path = Path::new(expected_name);
        let actual_path = selinux.attr_path(attr);
        assert_eq!(expected_path, actual_path);

        // Test with not having "/proc/thread-self/attr" path by setting HAVE_THREAD_SELF as false
        selinux = SELinux::new(context_file.as_path(), false, &setting)?;
        let thread_id = gettid();
        let expected_name = &format!("/proc/self/task/{}/attr/{}", thread_id, attr);
        let expected_path = Path::new(expected_name);
        let actual_path = selinux.attr_path(attr);
        assert_eq!(expected_path, actual_path);

        Ok(())
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
}
