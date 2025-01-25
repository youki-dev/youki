use nix::libc;
use rustix::fs as rfs;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum XattrError {
    #[error("Failed to set_xattr: {0}")]
    SetXattr(String),
    #[error("Failed to lset_xattr: {0}")]
    LSetXattr(String),
    #[error("Failed to get_xattr: {0}")]
    GetXattr(String),
    #[error("Failed to lget_xattr: {0}")]
    LGetXattr(String),
    #[error("EINTR error: {0}")]
    EINTR(i32),
}

// SELinux label is not so big, so we allocate 1024 bytes for the buffer.
const INITIAL_BUF_SIZE: usize = 1024;

pub trait PathXattr {
    fn set_xattr(&self, attr: &str, data: &[u8]) -> Result<(), XattrError>;
    fn lset_xattr(&self, attr: &str, data: &[u8]) -> Result<(), XattrError>;
    fn get_xattr(&self, attr: &str) -> Result<String, XattrError>;
    fn lget_xattr(&self, attr: &str) -> Result<String, XattrError>;
}

impl<P> PathXattr for P
where
    P: AsRef<Path>,
{
    // function similar with setxattr in golang.org/x/sys/unix repo.
    // set_xattr sets extended attributes on a file specified by its path.
    fn set_xattr(&self, attr: &str, data: &[u8]) -> Result<(), XattrError> {
        let path = self.as_ref();
        let op = match path.get_xattr(attr) {
            Ok(_) => rfs::XattrFlags::REPLACE,
            Err(_) => rfs::XattrFlags::CREATE,
        };
        match rfs::setxattr(path, attr, data, op) {
            Ok(_) => Ok(()),
            Err(e) => {
                let errno = e.raw_os_error();
                if errno == libc::EINTR {
                    return Err(XattrError::EINTR(errno));
                }
                Err(XattrError::SetXattr(e.to_string()))
            }
        }
    }

    // function similar with lsetxattr in golang.org/x/sys/unix repo.
    // lset_xattr sets extended attributes on a symbolic link.
    fn lset_xattr(&self, attr: &str, data: &[u8]) -> Result<(), XattrError> {
        let path = self.as_ref();
        let op = match path.lget_xattr(attr) {
            Ok(_) => rfs::XattrFlags::REPLACE,
            Err(_) => rfs::XattrFlags::CREATE,
        };
        match rfs::lsetxattr(path, attr, data, op) {
            Ok(_) => Ok(()),
            Err(e) => {
                let errno = e.raw_os_error();
                if errno == libc::EINTR {
                    return Err(XattrError::EINTR(errno));
                }
                Err(XattrError::LSetXattr(e.to_string()))
            }
        }
    }

    // function similar with getattr in go-selinux repo.
    // get_xattr returns the value of an extended attribute attr set for path.
    fn get_xattr(&self, attr: &str) -> Result<String, XattrError> {
        let path = self.as_ref();
        let mut buf_size = INITIAL_BUF_SIZE;
        let mut buf = vec![0u8; buf_size];

        loop {
            match rfs::getxattr(path, attr, &mut buf) {
                Ok(size) => {
                    if size == buf_size {
                        buf_size *= 2;
                        buf.resize(buf_size, 0);
                        continue;
                    }
                    let mut value = String::from_utf8_lossy(&buf[..size]).into_owned();
                    if value.ends_with('\x00') {
                        value.pop();
                    }
                    return Ok(value);
                }
                Err(e) => return Err(XattrError::GetXattr(e.to_string())),
            }
        }
    }

    // function similar with lgetxattr in go-selinux repo.
    // lget_xattr returns the value of an extended attribute attr set for path.
    fn lget_xattr(&self, attr: &str) -> Result<String, XattrError> {
        let path = self.as_ref();
        let mut buf_size = INITIAL_BUF_SIZE;
        let mut buf = vec![0u8; buf_size];

        loop {
            match rfs::lgetxattr(path, attr, &mut buf) {
                Ok(size) => {
                    if size == buf_size {
                        buf_size *= 2;
                        buf.resize(buf_size, 0);
                        continue;
                    }
                    let mut value = String::from_utf8_lossy(&buf[..size]).into_owned();
                    if value.ends_with('\x00') {
                        value.pop();
                    }
                    return Ok(value);
                }
                Err(e) => return Err(XattrError::LGetXattr(e.to_string())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tools::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_set_xattr_and_get_xattr() {
        // Because of the permission issue, "selinux.security" can't be used here.
        let attr_name = "user.test_attr";
        let attr_value = "system_u:object_r:some_label_t";
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let file_path = temp_file.path();

        // Verify that the first "set_xattr" operation succeeds, which means it doesn't have xattr yet.
        file_path
            .set_xattr(attr_name, attr_value.as_bytes())
            .expect("Failed to set xattr");
        let actual = file_path.get_xattr(attr_name).expect("Failed to get xattr");
        assert_eq!(actual, attr_value);

        // Verify that the second "set_xattr" operation succeeds, which means it already has xattr.
        let attr_value = "system_u:object_r:another_label_t";
        file_path
            .set_xattr(attr_name, attr_value.as_bytes())
            .expect("Failed to set xattr");
        let actual = file_path.get_xattr(attr_name).expect("Failed to get xattr");
        assert_eq!(actual, attr_value);
    }
    // The test of lset and lget is not implemented here because there is no root permission.
}
