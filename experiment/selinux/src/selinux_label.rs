use crate::selinux::*;
use crate::tools::PathXattr;
use crate::tools::*;
use nix::sys::socket::getsockopt;
use std::convert::TryFrom;
use std::os::fd::AsFd;
use std::path::Path;

const XATTR_NAME_SELINUX: &str = "security.selinux";
const KEY_LABEL_PATH: &str = "/proc/self/attr/keycreate";

#[derive(Default, Clone)]
pub struct SELinuxLabel {
    pub(crate) user: String,
    role: String,
    type_: String,
    level: Option<String>,
}

impl std::fmt::Display for SELinuxLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.level {
            Some(level) => write!(f, "{}:{}:{}:{}", self.user, self.role, self.type_, level),
            None => write!(f, "{}:{}:{}", self.user, self.role, self.type_),
        }
    }
}

impl TryFrom<String> for SELinuxLabel {
    type Error = SELinuxError;
    fn try_from(label: String) -> Result<Self, SELinuxError> {
        let fields: Vec<&str> = label.split(':').collect();
        if fields.len() < 3 {
            return Err(SELinuxError::InvalidSELinuxLabel(label));
        }

        // It is possible that input label is "", which means no label is set.
        let user = fields
            .first()
            .ok_or(SELinuxError::InvalidSELinuxLabel(label.clone()))?
            .to_string();
        let role = fields
            .get(1)
            .ok_or(SELinuxError::InvalidSELinuxLabel(label.clone()))?
            .to_string();
        let type_ = fields
            .get(2)
            .ok_or(SELinuxError::InvalidSELinuxLabel(label.clone()))?
            .to_string();
        let level = fields.get(3).map(|&s| s.to_string());
        Ok(SELinuxLabel {
            user,
            role,
            type_,
            level,
        })
    }
}

// This impl is for methods related to labels in SELinux struct.
impl<'a> SELinux<'a> {
    // set_file_label sets the SELinux label for this path, following symlinks, or returns an error.
    pub fn set_file_label<P: AsRef<Path> + PathXattr>(
        fpath: P,
        label: SELinuxLabel,
    ) -> Result<(), SELinuxError> {
        let path = fpath.as_ref();
        if !path.exists() {
            return Err(SELinuxError::SetFileLabel(ERR_EMPTY_PATH.to_string()));
        }

        loop {
            match fpath.set_xattr(XATTR_NAME_SELINUX, label.to_string().as_bytes()) {
                Ok(_) => break,
                // When a system call is interrupted by a signal, it needs to be retried.
                Err(XattrError::EINTR(_)) => continue,
                Err(e) => {
                    return Err(SELinuxError::SetFileLabel(e.to_string()));
                }
            }
        }
        Ok(())
    }

    // lset_file_label sets the SELinux label for this path, not following symlinks,
    // or returns an error.
    pub fn lset_file_label<P: AsRef<Path> + PathXattr>(
        fpath: P,
        label: SELinuxLabel,
    ) -> Result<(), SELinuxError> {
        let path = fpath.as_ref();
        if !path.exists() {
            return Err(SELinuxError::LSetFileLabel(ERR_EMPTY_PATH.to_string()));
        }

        loop {
            match fpath.lset_xattr(XATTR_NAME_SELINUX, label.to_string().as_bytes()) {
                Ok(_) => break,
                // When a system call is interrupted by a signal, it needs to be retried.
                Err(XattrError::EINTR(_)) => continue,
                Err(e) => {
                    return Err(SELinuxError::LSetFileLabel(e.to_string()));
                }
            }
        }
        Ok(())
    }

    // fileLabel returns the SELinux label for this path, following symlinks,
    // or returns an error.
    pub fn file_label<P: AsRef<Path> + PathXattr>(fpath: P) -> Result<SELinuxLabel, SELinuxError> {
        let path = fpath.as_ref();
        if !path.exists() {
            return Err(SELinuxError::FileLabel(ERR_EMPTY_PATH.to_string()));
        }
        let label_str = fpath
            .get_xattr(XATTR_NAME_SELINUX)
            .map_err(|e| SELinuxError::FileLabel(e.to_string()))?;
        SELinuxLabel::try_from(label_str)
    }

    // lfile_label returns the SELinux label for this path, not following symlinks,
    // or returns an error.
    pub fn lfile_label<P: AsRef<Path> + PathXattr>(fpath: P) -> Result<SELinuxLabel, SELinuxError> {
        let path = fpath.as_ref();
        if !path.exists() {
            return Err(SELinuxError::LFileLabel(ERR_EMPTY_PATH.to_string()));
        }
        let label_str = fpath
            .lget_xattr(XATTR_NAME_SELINUX)
            .map_err(|e| SELinuxError::LFileLabel(e.to_string()))?;
        SELinuxLabel::try_from(label_str)
    }

    // set_fscreate_label sets the default label the kernel which the kernel is using
    // for file system objects.
    pub fn set_fscreate_label(&mut self, label: SELinuxLabel) -> Result<usize, SELinuxError> {
        return Self::write_con(
            self,
            self.attr_path("fscreate").as_path(),
            label.to_string().as_str(),
        );
    }

    // fscreate_label returns the default label the kernel which the kernel is using
    // for file system objects created by this task. "" indicates default.
    pub fn fscreate_label(&self) -> Result<SELinuxLabel, SELinuxError> {
        let label = Self::read_con(self.attr_path("fscreate").as_path())?;
        SELinuxLabel::try_from(label)
    }

    // pid_label returns the SELinux label of the given pid, or an error.
    pub fn pid_label(pid: i64) -> Result<SELinuxLabel, SELinuxError> {
        let file_name = &format!("/proc/{}/attr/current", pid);
        let file_path = Path::new(file_name);
        let label = Self::read_con(file_path)?;
        SELinuxLabel::try_from(label)
    }

    // exec_label returns the SELinux label that the kernel will use for any programs
    // that are executed by the current process thread, or an error.
    pub fn exec_label(&self) -> Result<SELinuxLabel, SELinuxError> {
        let label = Self::read_con(self.attr_path("exec").as_path())?;
        SELinuxLabel::try_from(label)
    }

    // set_exec_label sets the SELinux label that the kernel will use for any programs
    // that are executed by the current process thread, or an error.
    pub fn set_exec_label(&mut self, label: SELinuxLabel) -> Result<usize, SELinuxError> {
        Self::write_con(
            self,
            self.attr_path("exec").as_path(),
            label.to_string().as_str(),
        )
    }

    // set_task_label sets the SELinux label for the current thread, or an error.
    // This requires the dyntransition permission because this changes the context of current thread.
    pub fn set_task_label(&mut self, label: SELinuxLabel) -> Result<usize, SELinuxError> {
        Self::write_con(
            self,
            self.attr_path("current").as_path(),
            label.to_string().as_str(),
        )
    }

    // set_socket_label takes a process label and tells the kernel to assign the
    // label to the next socket that gets created.
    pub fn set_socket_label(&mut self, label: SELinuxLabel) -> Result<usize, SELinuxError> {
        Self::write_con(
            self,
            self.attr_path("sockcreate").as_path(),
            label.to_string().as_str(),
        )
    }

    // socket_label retrieves the current socket label setting.
    pub fn socket_label(&self) -> Result<SELinuxLabel, SELinuxError> {
        let label = Self::read_con(self.attr_path("sockcreate").as_path())?;
        SELinuxLabel::try_from(label)
    }

    // current_label returns the SELinux label of the current process thread, or an error.
    pub fn current_label(&self) -> Result<SELinuxLabel, SELinuxError> {
        let label = SELinux::read_con(self.attr_path("current").as_path())?;
        SELinuxLabel::try_from(label)
    }

    // peer_label retrieves the label of the client on the other side of a socket.
    pub fn peer_label<F: AsFd>(fd: F) -> Result<SELinuxLabel, SELinuxError> {
        // getsockopt manipulate options for the socket referred to by the file descriptor.
        // https://man7.org/linux/man-pages/man2/getsockopt.2.html
        match getsockopt(&fd, PeerSec) {
            Ok(label) => match label.into_string() {
                Ok(label_str) => SELinuxLabel::try_from(label_str),
                Err(e) => Err(SELinuxError::PeerLabel(e.to_string())),
            },
            Err(e) => Err(SELinuxError::PeerLabel(e.to_string())),
        }
    }

    // set_key_label takes a process label and tells the kernel to assign the
    // label to the next kernel keyring that gets created.
    pub fn set_key_label(&mut self, label: SELinuxLabel) -> Result<usize, SELinuxError> {
        Self::write_con(self, Path::new(KEY_LABEL_PATH), label.to_string().as_str())
    }

    // key_label retrieves the current kernel keyring label setting
    pub fn key_label() -> Result<SELinuxLabel, SELinuxError> {
        let label = Self::read_con(Path::new(KEY_LABEL_PATH))?;
        SELinuxLabel::try_from(label)
    }

    // kvm_container_labels returns the default processLabel and mountLabel to be used
    // for kvm containers by the calling process.
    pub fn kvm_container_labels(&'a mut self) -> (Option<&SELinuxLabel>, Option<&SELinuxLabel>) {
        let process_label =
            Self::label(self, "kvm_process").or_else(|| Self::label(self, "process"));
        (process_label, Self::label(self, "file"))
        // TODO: use addMcs
    }

    // init_container_labels returns the default processLabel and file labels to be
    // used for containers running an init system like systemd by the calling process.
    pub fn init_container_labels(&'a mut self) -> (Option<&SELinuxLabel>, Option<&SELinuxLabel>) {
        let process_label =
            Self::label(self, "init_process").or_else(|| Self::label(self, "process"));
        (process_label, Self::label(self, "file"))
        // TODO: use addMcs
    }

    // container_labels returns an allocated processLabel and fileLabel to be used for
    // container labeling by the calling process.
    pub fn container_labels(&'a mut self) -> (Option<&SELinuxLabel>, Option<&SELinuxLabel>) {
        if !self.get_enabled() {
            return (None, None);
        }
        // let process_label = Self::label(self, "process");
        // let file_label = Self::label(self, "file");
        let process_label = self.labels.get("process");
        let file_label = self.labels.get("file");

        if process_label.is_none() || file_label.is_none() {
            return (process_label, file_label);
        }

        self.read_only_file_label = match self.labels.get("ro_file") {
            None => file_label,
            Some(ro_file_label) => Some(ro_file_label),
        };

        (process_label, file_label)
        // TODO: use addMcs
    }

    // This function returns the value of given key on selinux context
    fn label(&'a self, key: &str) -> Option<&'a SELinuxLabel> {
        self.labels.get(key)
    }

    // format_mount_label returns a string to be used by the mount command.
    // Using the SELinux `context` mount option.
    // Changing labels of files on mount points with this option can never be changed.
    // format_mount_label returns a string to be used by the mount command.
    // The format of this string will be used to alter the labeling of the mountpoint.
    // The string returned is suitable to be used as the options field of the mount command.
    // If you need to have additional mount point options, you can pass them in as
    // the first parameter. The second parameter is the label that you wish to apply
    // to all content in the mount point.
    pub fn format_mount_label(src: &str, mount_label: &str) -> String {
        Self::format_mount_label_by_type(src, mount_label, "context")
    }

    // format_mount_label_by_type returns a string to be used by the mount command.
    // Allow caller to specify the mount options. For example using the SELinux
    // `fscontext` mount option would allow certain container processes to change
    // labels of files created on the mount points, where as `context` option does not.
    pub fn format_mount_label_by_type(src: &str, mount_label: &str, context_type: &str) -> String {
        let mut formatted_src = src.to_owned();

        if !mount_label.is_empty() {
            if formatted_src.is_empty() {
                formatted_src = format!("{}=\"{}\"", context_type, mount_label);
            } else {
                formatted_src = format!("{},{}=\"{}\"", formatted_src, context_type, mount_label);
            }
        }
        formatted_src
    }
}

#[cfg(test)]
mod tests {
    use crate::selinux::*;

    #[test]
    fn test_format_mount_label() {
        let src_array = ["", "src", "src"];
        let mount_label_array = ["foobar", "foobar", ""];
        let expected_array = ["context=\"foobar\"", "src,context=\"foobar\"", "src"];
        for (i, src) in src_array.iter().enumerate() {
            let mount_label = mount_label_array[i];
            let expected = expected_array[i];
            assert_eq!(SELinux::format_mount_label(src, mount_label), expected);
        }
    }

    #[test]
    fn test_format_mount_label_by_type() {
        let src_array = ["", "src", "src"];
        let mount_label_array = ["foobar", "foobar", ""];
        let context_array = ["fscontext", "fscontext", "rootcontext"];
        let expected_array = ["fscontext=\"foobar\"", "src,fscontext=\"foobar\"", "src"];
        for (i, src) in src_array.iter().enumerate() {
            let mount_label = mount_label_array[i];
            let context = context_array[i];
            let expected = expected_array[i];
            assert_eq!(
                SELinux::format_mount_label_by_type(src, mount_label, context),
                expected
            );
        }
    }
}
