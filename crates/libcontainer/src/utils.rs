//! Utility functionality

use std::collections::HashMap;
use std::fs::{self, DirBuilder, File};
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};

use nix::sys::stat::Mode;
use nix::sys::statfs;
use nix::unistd::{Uid, User};
use oci_spec::runtime::Spec;

use crate::error::LibcontainerError;
use crate::user_ns::UserNamespaceConfig;

#[derive(Debug, thiserror::Error)]
pub enum PathBufExtError {
    #[error("relative path cannot be converted to the path in the container")]
    RelativePath,
    #[error("failed to strip prefix from {path:?}")]
    StripPrefix {
        path: PathBuf,
        source: std::path::StripPrefixError,
    },
    #[error("failed to canonicalize path {path:?}")]
    Canonicalize {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to get current directory")]
    CurrentDir { source: std::io::Error },
}

pub trait PathBufExt {
    fn as_relative(&self) -> Result<&Path, PathBufExtError>;
    fn join_safely<P: AsRef<Path>>(&self, p: P) -> Result<PathBuf, PathBufExtError>;
    fn canonicalize_safely(&self) -> Result<PathBuf, PathBufExtError>;
    fn normalize(&self) -> PathBuf;
}

impl PathBufExt for Path {
    fn as_relative(&self) -> Result<&Path, PathBufExtError> {
        match self.is_relative() {
            true => Err(PathBufExtError::RelativePath),
            false => Ok(self
                .strip_prefix("/")
                .map_err(|e| PathBufExtError::StripPrefix {
                    path: self.to_path_buf(),
                    source: e,
                })?),
        }
    }

    fn join_safely<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, PathBufExtError> {
        let path = path.as_ref();
        if path.is_relative() {
            return Ok(self.join(path));
        }

        let stripped = path
            .strip_prefix("/")
            .map_err(|e| PathBufExtError::StripPrefix {
                path: self.to_path_buf(),
                source: e,
            })?;
        Ok(self.join(stripped))
    }

    /// Canonicalizes existing and not existing paths
    fn canonicalize_safely(&self) -> Result<PathBuf, PathBufExtError> {
        if self.exists() {
            self.canonicalize()
                .map_err(|e| PathBufExtError::Canonicalize {
                    path: self.to_path_buf(),
                    source: e,
                })
        } else {
            if self.is_relative() {
                let p = std::env::current_dir()
                    .map_err(|e| PathBufExtError::CurrentDir { source: e })?
                    .join(self);
                return Ok(p.normalize());
            }

            Ok(self.normalize())
        }
    }

    /// Normalizes a path. In contrast to canonicalize the path does not need to exist.
    // adapted from https://github.com/rust-lang/cargo/blob/fede83ccf973457de319ba6fa0e36ead454d2e20/src/cargo/util/paths.rs#L61
    fn normalize(&self) -> PathBuf {
        let mut components = self.components().peekable();
        let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
            components.next();
            PathBuf::from(c.as_os_str())
        } else {
            PathBuf::new()
        };

        for component in components {
            match component {
                Component::Prefix(..) => unreachable!(),
                Component::RootDir => {
                    ret.push(component.as_os_str());
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    ret.pop();
                }
                Component::Normal(c) => {
                    ret.push(c);
                }
            }
        }
        ret
    }
}

pub fn parse_env(envs: &[String]) -> HashMap<String, String> {
    envs.iter()
        .filter_map(|e| {
            let mut split = e.split('=');

            split.next().map(|key| {
                let value = split.collect::<Vec<&str>>().join("=");
                (key.into(), value)
            })
        })
        .collect()
}

/// Get a nix::unistd::User via UID. Potential errors will be ignored.
pub fn get_unix_user(uid: Uid) -> Option<User> {
    User::from_uid(uid).unwrap_or_default()
}

/// Get home path of a User via UID.
pub fn get_user_home(uid: u32) -> Option<PathBuf> {
    match get_unix_user(Uid::from_raw(uid)) {
        Some(user) => Some(user.dir),
        None => None,
    }
}

/// If None, it will generate a default path for cgroups.
pub fn get_cgroup_path(cgroups_path: &Option<PathBuf>, container_id: &str) -> PathBuf {
    match cgroups_path {
        Some(cpath) => cpath.clone(),
        None => PathBuf::from(format!(":youki:{container_id}")),
    }
}

pub fn write_file<P: AsRef<Path>, C: AsRef<[u8]>>(
    path: P,
    contents: C,
) -> Result<(), std::io::Error> {
    fs::write(path.as_ref(), contents).map_err(|err| {
        tracing::error!(path = ?path.as_ref(), ?err, "failed to write file");
        err
    })?;

    Ok(())
}

pub fn create_dir_all<P: AsRef<Path>>(path: P) -> Result<(), std::io::Error> {
    fs::create_dir_all(path.as_ref()).map_err(|err| {
        tracing::error!(path = ?path.as_ref(), ?err, "failed to create directory");
        err
    })?;
    Ok(())
}

pub fn open<P: AsRef<Path>>(path: P) -> Result<File, std::io::Error> {
    File::open(path.as_ref()).map_err(|err| {
        tracing::error!(path = ?path.as_ref(), ?err, "failed to open file");
        err
    })
}

#[derive(Debug, thiserror::Error)]
pub enum MkdirWithModeError {
    #[error("IO error")]
    Io(#[from] std::io::Error),
    #[error("metadata doesn't match the expected attributes")]
    MetadataMismatch,
}

/// Creates the specified directory and all parent directories with the specified mode. Ensures
/// that the directory has been created with the correct mode and that the owner of the directory
/// is the owner that has been specified
/// # Example
/// ``` no_run
/// use libcontainer::utils::create_dir_all_with_mode;
/// use nix::sys::stat::Mode;
/// use std::path::Path;
///
/// let path = Path::new("/tmp/youki");
/// create_dir_all_with_mode(&path, 1000, Mode::S_IRWXU).unwrap();
/// assert!(path.exists())
/// ```
pub fn create_dir_all_with_mode<P: AsRef<Path>>(
    path: P,
    owner: u32,
    mode: Mode,
) -> Result<(), MkdirWithModeError> {
    let path = path.as_ref();
    if !path.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(mode.bits())
            .create(path)?;
    }

    let metadata = path.metadata()?;
    if metadata.is_dir()
        && metadata.st_uid() == owner
        && metadata.st_mode() & mode.bits() == mode.bits()
    {
        Ok(())
    } else {
        Err(MkdirWithModeError::MetadataMismatch)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnsureProcfsError {
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
}

// Make sure a given path is on procfs. This is to avoid the security risk that
// /proc path is mounted over. Ref: CVE-2019-16884
pub fn ensure_procfs(path: &Path) -> Result<(), EnsureProcfsError> {
    let procfs_fd = fs::File::open(path).map_err(|err| {
        tracing::error!(?err, ?path, "failed to open procfs file");
        err
    })?;
    let fstat_info = statfs::fstatfs(&procfs_fd).map_err(|err| {
        tracing::error!(?err, ?path, "failed to fstatfs the procfs");
        err
    })?;

    if fstat_info.filesystem_type() != statfs::PROC_SUPER_MAGIC {
        tracing::error!(?path, "given path is not on the procfs");
        Err(nix::Error::EINVAL)?;
    }

    Ok(())
}

pub fn is_in_new_userns() -> Result<bool, std::io::Error> {
    let uid_map_path = "/proc/self/uid_map";
    let content = std::fs::read_to_string(uid_map_path)?;
    Ok(!content.contains("4294967295"))
}

/// Checks if rootless mode needs to be used
pub fn rootless_required() -> Result<bool, std::io::Error> {
    if !nix::unistd::geteuid().is_root() {
        return Ok(true);
    }
    is_in_new_userns()
}

/// checks if given spec is valid for current user namespace setup
pub fn validate_spec_for_new_user_ns(spec: &Spec) -> Result<(), LibcontainerError> {
    let config = UserNamespaceConfig::new(spec)?;
    let in_user_ns = is_in_new_userns().map_err(LibcontainerError::OtherIO)?;
    let is_rootless_required = rootless_required().map_err(LibcontainerError::OtherIO)?;
    // In case of rootless, there are 2 possible cases :
    // we have a new user ns specified in the spec
    // or the youki is launched in a new user ns (this is how podman does it)
    // So here, we check if rootless is required,
    // but we are neither in a new user ns nor a new user ns is specified in spec
    // then it is an error
    if is_rootless_required && !in_user_ns && config.is_none() {
        return Err(LibcontainerError::NoUserNamespace);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::{bail, Result};
    use serial_test::serial;

    use super::*;
    use crate::test_utils;

    #[test]
    pub fn test_get_unix_user() {
        let user = get_unix_user(Uid::from_raw(0));
        assert_eq!(user.unwrap().name, "root");

        // for a non-exist UID
        let user = get_unix_user(Uid::from_raw(1000000000));
        assert!(user.is_none());
    }

    #[test]
    pub fn test_get_user_home() {
        let dir = get_user_home(0);
        assert_eq!(dir.unwrap().to_str().unwrap(), "/root");

        // for a non-exist UID
        let dir = get_user_home(1000000000);
        assert!(dir.is_none());
    }

    #[test]
    fn test_get_cgroup_path() {
        let cid = "sample_container_id";
        assert_eq!(
            get_cgroup_path(&None, cid),
            PathBuf::from(":youki:sample_container_id")
        );
        assert_eq!(
            get_cgroup_path(&Some(PathBuf::from("/youki")), cid),
            PathBuf::from("/youki")
        );
    }

    #[test]
    fn test_parse_env() -> Result<()> {
        let key = "key".to_string();
        let value = "value".to_string();
        let env_input = vec![format!("{key}={value}")];
        let env_output = parse_env(&env_input);
        assert_eq!(
            env_output.len(),
            1,
            "There should be exactly one entry inside"
        );
        assert_eq!(env_output.get_key_value(&key), Some((&key, &value)));

        Ok(())
    }

    #[test]
    fn test_create_dir_all_with_mode() -> Result<()> {
        {
            let temdir = tempfile::tempdir()?;
            let path = temdir.path().join("test");
            let uid = nix::unistd::getuid().as_raw();
            let mode = Mode::S_IRWXU;
            create_dir_all_with_mode(&path, uid, mode)?;
            let metadata = path.metadata()?;
            assert!(path.is_dir());
            assert_eq!(metadata.st_uid(), uid);
            assert_eq!(metadata.st_mode() & mode.bits(), mode.bits());
        }
        {
            let temdir = tempfile::tempdir()?;
            let path = temdir.path().join("test");
            let mode = Mode::S_IRWXU;
            std::fs::create_dir(&path)?;
            assert!(path.is_dir());
            match create_dir_all_with_mode(&path, 8899, mode) {
                Err(MkdirWithModeError::MetadataMismatch) => {}
                _ => bail!("should return MetadataMismatch"),
            }
        }
        Ok(())
    }

    #[test]
    fn test_io() -> Result<()> {
        {
            let tempdir = tempfile::tempdir()?;
            let path = tempdir.path().join("test");
            write_file(&path, "test".as_bytes())?;
            open(&path)?;
            assert!(create_dir_all(path).is_err());
        }
        {
            let tempdir = tempfile::tempdir()?;
            let path = tempdir.path().join("test");
            create_dir_all(&path)?;
            assert!(write_file(&path, "test".as_bytes()).is_err());
        }
        {
            let tempdir = tempfile::tempdir()?;
            let path = tempdir.path().join("test");
            assert!(open(&path).is_err());
            create_dir_all(&path)?;
            assert!(path.is_dir())
        }

        Ok(())
    }

    // the following test is marked as serial because
    // we are doing unshare of user ns and fork, so better to run in serial,
    #[test]
    #[serial]
    fn test_userns_spec_validation() -> Result<(), test_utils::TestError> {
        use nix::sched::{unshare, CloneFlags};
        // default rootful spec
        let rootful_spec = Spec::default();
        // as we are not in a user ns, and spec does not have user ns
        // we should get error here
        assert!(validate_spec_for_new_user_ns(&rootful_spec).is_err());

        let rootless_spec = Spec::rootless(1000, 1000);
        // because the spec contains user ns info, we should not get error
        assert!(validate_spec_for_new_user_ns(&rootless_spec).is_ok());

        test_utils::test_in_child_process(|| {
            unshare(CloneFlags::CLONE_NEWUSER).unwrap();
            // here we are in a new user namespace
            let rootful_spec = Spec::default();
            // because we are already in a new user ns, it is fine if spec
            // does not have user ns, and because the test is running as
            // non root
            assert!(validate_spec_for_new_user_ns(&rootful_spec).is_ok());

            let rootless_spec = Spec::rootless(1000, 1000);
            // following should succeed irrespective if we're in user ns or not
            assert!(validate_spec_for_new_user_ns(&rootless_spec).is_ok());
            Ok(())
        })
    }
}
