use std::path::Path;
use std::path::PathBuf;

/// A systemd cgroups path as specified in the runtime spec.
/// It should be of the form [slice]:[scope_prefix]:[name].
/// The slice is the "parent" and should be expanded properly.
#[derive(Debug)]
pub struct CgroupsPath {
    /// Parent slice, e.g. `system.slice`. May be empty when unspecified.
    pub parent: String,
    /// Scope prefix, e.g. `docker`.
    pub(crate) prefix: String,
    /// Unit base name, possibly with a sub-cgroup suffix, e.g. `<id>/sub/init`.
    pub(crate) name: String,
}

#[derive(thiserror::Error, Debug)]
pub enum CgroupsPathError {
    #[error("no cgroups path has been provided")]
    NoPath,
    #[error("cgroups path does not contain valid utf8")]
    InvalidUtf8(PathBuf),
    #[error("cgroups path is malformed: {0}")]
    MalformedPath(PathBuf),
}

impl TryFrom<&Path> for CgroupsPath {
    type Error = CgroupsPathError;

    fn try_from(cgroups_path: &Path) -> Result<Self, Self::Error> {
        // If cgroups_path was provided, it should be of the form [slice]:[prefix]:[name],
        // for example: "system.slice:docker:1234".
        if cgroups_path.as_os_str().is_empty() {
            return Err(CgroupsPathError::NoPath);
        }

        let parts = cgroups_path
            .to_str()
            .ok_or_else(|| CgroupsPathError::InvalidUtf8(cgroups_path.to_path_buf()))?
            .split(':')
            .collect::<Vec<&str>>();

        let destructured_path = match parts.len() {
            2 => CgroupsPath {
                parent: "".to_owned(),
                prefix: parts[0].to_owned(),
                name: parts[1].to_owned(),
            },
            3 => CgroupsPath {
                parent: parts[0].to_owned(),
                prefix: parts[1].to_owned(),
                name: parts[2].to_owned(),
            },
            _ => {
                return Err(CgroupsPathError::MalformedPath(cgroups_path.to_path_buf()));
            }
        };

        Ok(destructured_path)
    }
}
