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

/// Splits the unit `name` into the base unit name and the sub-cgroup suffix.
/// Example: "{id}/sub/init" becomes:
///   - base name: "{id}"
///   - sub-cgroup: "/sub/init"
fn split_sub_cgroup(name: &str) -> (&str, &str) {
    match name.find('/') {
        Some(i) => name.split_at(i),
        None => (name, ""),
    }
}

impl CgroupsPath {
    /// Returns the sub-cgroup suffix, e.g. "/sub/init" for name "<id>/sub/init".
    pub fn sub_cgroup(&self) -> &str {
        split_sub_cgroup(&self.name).1
    }

    /// Returns the unit (scope) name from the path provided by the user
    /// for example: foo:docker:bar returns in '/docker-bar.scope'
    pub fn unit_name(&self) -> String {
        let (base_name, _) = split_sub_cgroup(&self.name);
        // By default we create a scope unless specified explicitly.
        if !base_name.ends_with(".slice") {
            return format!("{}-{}.scope", self.prefix, base_name);
        }
        base_name.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_systemd_cgroups_path_roundtrip() {
        let path = Path::new("system.slice:docker:abc123");
        let parsed = CgroupsPath::try_from(path).unwrap();
        assert_eq!(parsed.parent, "system.slice");
        assert_eq!(parsed.unit_name(), "docker-abc123.scope");
    }

    #[test]
    fn test_systemd_cgroups_path_two_parts() {
        let parsed = CgroupsPath::try_from(Path::new("docker:abc123")).unwrap();
        assert_eq!(parsed.unit_name(), "docker-abc123.scope");
    }

    #[test]
    fn test_systemd_cgroups_path_slice_passthrough() {
        let parsed = CgroupsPath::try_from(Path::new("system.slice:foo:my.slice")).unwrap();
        assert_eq!(parsed.unit_name(), "my.slice");
    }

    #[test]
    fn test_systemd_cgroups_path_malformed() {
        assert!(CgroupsPath::try_from(Path::new("")).is_err());
        // Single segment without any ':' separator.
        assert!(CgroupsPath::try_from(Path::new("foo")).is_err());
        // Too many ':'-separated parts.
        assert!(CgroupsPath::try_from(Path::new("a:b:c:d")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_systemd_cgroups_path_invalid_utf8() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        // 0xff is never valid UTF-8.
        let raw = vec![0xff, 0xfe, b':', b'a'];
        let path = PathBuf::from(OsString::from_vec(raw));
        assert!(matches!(
            CgroupsPath::try_from(path.as_path()),
            Err(CgroupsPathError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn test_sub_cgroup() {
        let parsed =
            CgroupsPath::try_from(Path::new("system.slice:docker:abc123/sub/init")).unwrap();
        assert_eq!(parsed.sub_cgroup(), "/sub/init");
        assert_eq!(parsed.unit_name(), "docker-abc123.scope");

        let parsed = CgroupsPath::try_from(Path::new("system.slice:docker:abc123")).unwrap();
        assert_eq!(parsed.sub_cgroup(), "");
        assert_eq!(parsed.unit_name(), "docker-abc123.scope");

        // Trailing slash yields a "/" sub-cgroup, matching the original
        // `split_sub_cgroup` behavior in `systemd::manager`.
        let parsed = CgroupsPath::try_from(Path::new("system.slice:docker:abc123/")).unwrap();
        assert_eq!(parsed.sub_cgroup(), "/");
        assert_eq!(parsed.unit_name(), "docker-abc123.scope");
    }
}
