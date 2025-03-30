use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

use nix::unistd::Pid;
use oci_spec::runtime::{Linux, LinuxIdMapping, LinuxNamespace, LinuxNamespaceType, Mount, Spec};

use crate::error::MissingSpecError;
use crate::namespaces::{NamespaceError, Namespaces};
use crate::utils;

// Wrap the uid/gid path function into a struct for dependency injection. This
// allows us to mock the id mapping logic in unit tests by using a different
// base path other than `/proc`.
#[derive(Debug, Clone)]
pub struct UserNamespaceIDMapper {
    base_path: PathBuf,
}

impl Default for UserNamespaceIDMapper {
    fn default() -> Self {
        Self {
            // By default, the `uid_map` and `gid_map` files are located in the
            // `/proc` directory. In the production code, we can use the
            // default.
            base_path: PathBuf::from("/proc"),
        }
    }
}

impl UserNamespaceIDMapper {
    // In production code, we can direct use the `new` function without the
    // need to worry about the default.
    pub fn new() -> Self {
        Default::default()
    }

    pub fn get_uid_path(&self, pid: &Pid) -> PathBuf {
        self.base_path.join(pid.to_string()).join("uid_map")
    }
    pub fn get_gid_path(&self, pid: &Pid) -> PathBuf {
        self.base_path.join(pid.to_string()).join("gid_map")
    }

    #[cfg(test)]
    pub fn ensure_uid_path(&self, pid: &Pid) -> std::result::Result<(), std::io::Error> {
        std::fs::create_dir_all(self.get_uid_path(pid).parent().unwrap())?;

        Ok(())
    }

    #[cfg(test)]
    pub fn ensure_gid_path(&self, pid: &Pid) -> std::result::Result<(), std::io::Error> {
        std::fs::create_dir_all(self.get_gid_path(pid).parent().unwrap())?;

        Ok(())
    }

    #[cfg(test)]
    // In test, we need to fake the base path to a temporary directory.
    pub fn new_test(path: PathBuf) -> Self {
        Self { base_path: path }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UserNamespaceError {
    #[error(transparent)]
    MissingSpec(#[from] crate::error::MissingSpecError),
    #[error("user namespace definition is invalid")]
    NoUserNamespace,
    #[error("invalid spec for new user namespace container")]
    InvalidSpec(#[from] ValidateSpecError),
    #[error("failed to read unprivileged userns clone")]
    ReadUnprivilegedUsernsClone(#[source] std::io::Error),
    #[error("failed to parse unprivileged userns clone")]
    ParseUnprivilegedUsernsClone(#[source] std::num::ParseIntError),
    #[error("unknown userns clone value")]
    UnknownUnprivilegedUsernsClone(u8),
    #[error(transparent)]
    IDMapping(#[from] MappingError),
    #[error(transparent)]
    OtherIO(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, UserNamespaceError>;

#[derive(Debug, thiserror::Error)]
pub enum ValidateSpecError {
    #[error(transparent)]
    MissingSpec(#[from] crate::error::MissingSpecError),
    #[error("new user namespace requires valid uid mappings")]
    NoUIDMappings,
    #[error("new user namespace requires valid gid mappings")]
    NoGIDMapping,
    #[error("no mount in spec")]
    NoMountSpec,
    #[error("unprivileged user can't set supplementary groups")]
    UnprivilegedUser,
    #[error("supplementary group needs to be mapped in the gid mappings")]
    GidNotMapped(u32),
    #[error("failed to parse ID")]
    ParseID(#[source] std::num::ParseIntError),
    #[error(
        "mount options require mapping valid uid inside the container with new user namespace"
    )]
    MountGidMapping(u32),
    #[error(
        "mount options require mapping valid gid inside the container with new user namespace"
    )]
    MountUidMapping(u32),
    #[error(transparent)]
    Namespaces(#[from] NamespaceError),
    #[error(transparent)]
    OtherIO(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum MappingError {
    #[error("newuidmap/newgidmap binaries could not be found in path")]
    BinaryNotFound,
    #[error("could not find PATH")]
    NoPathEnv,
    #[error("failed to execute newuidmap/newgidmap")]
    Execute(#[source] std::io::Error),
    #[error("at least one id mapping needs to be defined")]
    NoIDMapping,
    #[error("failed to write id mapping")]
    WriteIDMapping(#[source] std::io::Error),
}

#[derive(Debug, Clone, Default)]
pub struct UserNamespaceConfig {
    /// Location of the newuidmap binary
    pub newuidmap: Option<PathBuf>,
    /// Location of the newgidmap binary
    pub newgidmap: Option<PathBuf>,
    /// Mappings for user ids
    pub(crate) uid_mappings: Option<Vec<LinuxIdMapping>>,
    /// Mappings for group ids
    pub(crate) gid_mappings: Option<Vec<LinuxIdMapping>>,
    /// Info on the user namespaces
    pub user_namespace: Option<LinuxNamespace>,
    /// Is the container requested by a privileged user
    pub privileged: bool,
    /// Path to the id mappings
    pub id_mapper: UserNamespaceIDMapper,
}

impl UserNamespaceConfig {
    pub fn new(spec: &Spec) -> Result<Option<Self>> {
        let linux = spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;
        let namespaces = Namespaces::try_from(linux.namespaces().as_ref())
            .map_err(ValidateSpecError::Namespaces)?;
        let user_namespace = namespaces
            .get(LinuxNamespaceType::User)
            .map_err(ValidateSpecError::Namespaces)?;

        if user_namespace.is_some() && user_namespace.unwrap().path().is_none() {
            tracing::debug!("container with new user namespace should be created");

            validate_spec_for_new_user_ns(spec).map_err(|err| {
                tracing::error!("failed to validate spec for new user namespace: {}", err);
                err
            })?;
            let mut user_ns_config = UserNamespaceConfig::try_from(linux)?;
            if let Some((uid_binary, gid_binary)) = lookup_map_binaries(linux)? {
                user_ns_config.newuidmap = Some(uid_binary);
                user_ns_config.newgidmap = Some(gid_binary);
            }

            Ok(Some(user_ns_config))
        } else {
            tracing::debug!("this container does NOT create a new user namespace");
            Ok(None)
        }
    }

    pub fn write_uid_mapping(&self, target_pid: Pid) -> Result<()> {
        tracing::debug!("write UID mapping for {:?}", target_pid);
        if let Some(uid_mappings) = self.uid_mappings.as_ref() {
            write_id_mapping(
                target_pid,
                self.id_mapper.get_uid_path(&target_pid).as_path(),
                uid_mappings,
                self.newuidmap.as_deref(),
            )?;
        }
        Ok(())
    }

    pub fn write_gid_mapping(&self, target_pid: Pid) -> Result<()> {
        tracing::debug!("write GID mapping for {:?}", target_pid);
        if let Some(gid_mappings) = self.gid_mappings.as_ref() {
            write_id_mapping(
                target_pid,
                self.id_mapper.get_gid_path(&target_pid).as_path(),
                gid_mappings,
                self.newgidmap.as_deref(),
            )?;
        }
        Ok(())
    }

    pub fn with_id_mapper(&mut self, mapper: UserNamespaceIDMapper) {
        self.id_mapper = mapper
    }
}

impl TryFrom<&Linux> for UserNamespaceConfig {
    type Error = UserNamespaceError;

    fn try_from(linux: &Linux) -> Result<Self> {
        let namespaces = Namespaces::try_from(linux.namespaces().as_ref())
            .map_err(ValidateSpecError::Namespaces)?;
        let user_namespace = namespaces
            .get(LinuxNamespaceType::User)
            .map_err(ValidateSpecError::Namespaces)?;
        Ok(Self {
            newuidmap: None,
            newgidmap: None,
            uid_mappings: linux.uid_mappings().to_owned(),
            gid_mappings: linux.gid_mappings().to_owned(),
            user_namespace: user_namespace.cloned(),
            privileged: !utils::rootless_required()?,
            id_mapper: UserNamespaceIDMapper::new(),
        })
    }
}

pub fn unprivileged_user_ns_enabled() -> Result<bool> {
    let user_ns_sysctl = Path::new("/proc/sys/kernel/unprivileged_userns_clone");
    if !user_ns_sysctl.exists() {
        return Ok(true);
    }

    let content = fs::read_to_string(user_ns_sysctl)
        .map_err(UserNamespaceError::ReadUnprivilegedUsernsClone)?;

    match content
        .trim()
        .parse::<u8>()
        .map_err(UserNamespaceError::ParseUnprivilegedUsernsClone)?
    {
        0 => Ok(false),
        1 => Ok(true),
        v => Err(UserNamespaceError::UnknownUnprivilegedUsernsClone(v)),
    }
}

/// Validates that the spec contains the required information for
/// creating a new user namespace
fn validate_spec_for_new_user_ns(spec: &Spec) -> std::result::Result<(), ValidateSpecError> {
    tracing::debug!(
        ?spec,
        "validating spec for container with new user namespace"
    );
    let linux = spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;

    let gid_mappings = linux
        .gid_mappings()
        .as_ref()
        .ok_or(ValidateSpecError::NoGIDMapping)?;
    let uid_mappings = linux
        .uid_mappings()
        .as_ref()
        .ok_or(ValidateSpecError::NoUIDMappings)?;

    if uid_mappings.is_empty() {
        return Err(ValidateSpecError::NoUIDMappings);
    }
    if gid_mappings.is_empty() {
        return Err(ValidateSpecError::NoGIDMapping);
    }

    validate_mounts_for_new_user_ns(
        spec.mounts()
            .as_ref()
            .ok_or(ValidateSpecError::NoMountSpec)?,
        uid_mappings,
        gid_mappings,
    )?;

    if let Some(additional_gids) = spec
        .process()
        .as_ref()
        .and_then(|process| process.user().additional_gids().as_ref())
    {
        let privileged = !utils::rootless_required()?;

        match (privileged, additional_gids.is_empty()) {
            (true, false) => {
                for gid in additional_gids {
                    if !is_id_mapped(*gid, gid_mappings) {
                        tracing::error!(?gid,"gid is specified as supplementary group, but is not mapped in the user namespace");
                        return Err(ValidateSpecError::GidNotMapped(*gid));
                    }
                }
            }
            (false, false) => {
                tracing::error!(
                    user = ?nix::unistd::geteuid(),
                    "user is unprivileged. Supplementary groups cannot be set in \
                        a rootless container for this user due to CVE-2014-8989",
                );
                return Err(ValidateSpecError::UnprivilegedUser);
            }
            _ => {}
        }
    }

    Ok(())
}

fn validate_mounts_for_new_user_ns(
    mounts: &[Mount],
    uid_mappings: &[LinuxIdMapping],
    gid_mappings: &[LinuxIdMapping],
) -> std::result::Result<(), ValidateSpecError> {
    for mount in mounts {
        if let Some(options) = mount.options() {
            for opt in options {
                if opt.starts_with("uid=")
                    && !is_id_mapped(
                        opt[4..].parse().map_err(ValidateSpecError::ParseID)?,
                        uid_mappings,
                    )
                {
                    tracing::error!(
                        ?mount,
                        ?opt,
                        "mount specifies option which is not mapped inside the container with new user namespace"
                    );
                    return Err(ValidateSpecError::MountUidMapping(
                        opt[4..].parse().map_err(ValidateSpecError::ParseID)?,
                    ));
                }

                if opt.starts_with("gid=")
                    && !is_id_mapped(
                        opt[4..].parse().map_err(ValidateSpecError::ParseID)?,
                        gid_mappings,
                    )
                {
                    tracing::error!(
                        ?mount,
                        ?opt,
                        "mount specifies option which is not mapped inside the container with new user namespace"
                    );
                    return Err(ValidateSpecError::MountGidMapping(
                        opt[4..].parse().map_err(ValidateSpecError::ParseID)?,
                    ));
                }
            }
        }
    }

    Ok(())
}

fn is_id_mapped(id: u32, mappings: &[LinuxIdMapping]) -> bool {
    mappings
        .iter()
        .any(|m| id >= m.container_id() && id <= m.container_id() + m.size())
}

/// Looks up the location of the newuidmap and newgidmap binaries which
/// are required to write multiple user/group mappings
pub fn lookup_map_binaries(
    spec: &Linux,
) -> std::result::Result<Option<(PathBuf, PathBuf)>, MappingError> {
    if let Some(uid_mappings) = spec.uid_mappings() {
        if uid_mappings.len() == 1 && uid_mappings.len() == 1 {
            return Ok(None);
        }

        let uidmap = lookup_map_binary("newuidmap")?;
        let gidmap = lookup_map_binary("newgidmap")?;

        match (uidmap, gidmap) {
            (Some(newuidmap), Some(newgidmap)) => Ok(Some((newuidmap, newgidmap))),
            _ => Err(MappingError::BinaryNotFound),
        }
    } else {
        Ok(None)
    }
}

fn lookup_map_binary(binary: &str) -> std::result::Result<Option<PathBuf>, MappingError> {
    let paths = env::var("PATH").map_err(|_| MappingError::NoPathEnv)?;
    Ok(paths
        .split_terminator(':')
        .map(|p| Path::new(p).join(binary))
        .find(|p| p.exists()))
}

fn write_id_mapping(
    pid: Pid,
    map_file: &Path,
    mappings: &[LinuxIdMapping],
    map_binary: Option<&Path>,
) -> std::result::Result<(), MappingError> {
    tracing::debug!("Write ID mapping: {:?}", mappings);

    match mappings.len() {
        0 => return Err(MappingError::NoIDMapping),
        1 => {
            let mapping = mappings
                .first()
                .and_then(|m| format!("{} {} {}", m.container_id(), m.host_id(), m.size()).into())
                .unwrap();
            std::fs::write(map_file, &mapping).map_err(|err| {
                tracing::error!(?err, ?map_file, ?mapping, "failed to write uid/gid mapping");
                MappingError::WriteIDMapping(err)
            })?;
        }
        _ => {
            let args: Vec<String> = mappings
                .iter()
                .flat_map(|m| {
                    [
                        m.container_id().to_string(),
                        m.host_id().to_string(),
                        m.size().to_string(),
                    ]
                })
                .collect();

            // we can be certain here that map_binary will not be None,
            // as in the lookup_map_binaries function, we return error
            // if there are mappings.len() > 1 and binaries are not present
            Command::new(map_binary.unwrap())
                .arg(pid.to_string())
                .args(args)
                .output()
                .map_err(|err| {
                    tracing::error!(?err, ?map_binary, "failed to execute newuidmap/newgidmap");
                    MappingError::Execute(err)
                })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use nix::unistd::getpid;
    use oci_spec::runtime::{
        LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespaceBuilder, SpecBuilder,
    };
    use rand::Rng;
    use serial_test::serial;

    use super::*;

    fn gen_u32() -> u32 {
        rand::rng().random()
    }

    #[test]
    fn test_validate_ok() -> Result<()> {
        let userns = LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()?;
        let uid_mappings = vec![LinuxIdMappingBuilder::default()
            .host_id(gen_u32())
            .container_id(0_u32)
            .size(10_u32)
            .build()?];
        let gid_mappings = vec![LinuxIdMappingBuilder::default()
            .host_id(gen_u32())
            .container_id(0_u32)
            .size(10_u32)
            .build()?];
        let linux = LinuxBuilder::default()
            .namespaces(vec![userns])
            .uid_mappings(uid_mappings)
            .gid_mappings(gid_mappings)
            .build()?;
        let spec = SpecBuilder::default().linux(linux).build()?;
        assert!(validate_spec_for_new_user_ns(&spec).is_ok());
        Ok(())
    }

    #[test]
    fn test_validate_err() -> Result<()> {
        let userns = LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()?;
        let uid_mappings = vec![LinuxIdMappingBuilder::default()
            .host_id(gen_u32())
            .container_id(0_u32)
            .size(10_u32)
            .build()?];
        let gid_mappings = vec![LinuxIdMappingBuilder::default()
            .host_id(gen_u32())
            .container_id(0_u32)
            .size(10_u32)
            .build()?];

        let linux_uid_empty = LinuxBuilder::default()
            .namespaces(vec![userns.clone()])
            .uid_mappings(vec![])
            .gid_mappings(gid_mappings.clone())
            .build()?;
        assert!(validate_spec_for_new_user_ns(
            &SpecBuilder::default()
                .linux(linux_uid_empty)
                .build()
                .unwrap()
        )
        .is_err());

        let linux_gid_empty = LinuxBuilder::default()
            .namespaces(vec![userns.clone()])
            .uid_mappings(uid_mappings.clone())
            .gid_mappings(vec![])
            .build()?;
        assert!(validate_spec_for_new_user_ns(
            &SpecBuilder::default()
                .linux(linux_gid_empty)
                .build()
                .unwrap()
        )
        .is_err());

        let linux_uid_none = LinuxBuilder::default()
            .namespaces(vec![userns.clone()])
            .gid_mappings(gid_mappings)
            .build()?;
        assert!(validate_spec_for_new_user_ns(
            &SpecBuilder::default()
                .linux(linux_uid_none)
                .build()
                .unwrap()
        )
        .is_err());

        let linux_gid_none = LinuxBuilder::default()
            .namespaces(vec![userns])
            .uid_mappings(uid_mappings)
            .build()?;
        assert!(validate_spec_for_new_user_ns(
            &SpecBuilder::default()
                .linux(linux_gid_none)
                .build()
                .unwrap()
        )
        .is_err());

        Ok(())
    }

    #[test]
    #[serial]
    fn test_write_uid_mapping() -> Result<()> {
        let userns = LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()?;
        let host_uid = gen_u32();
        let host_gid = gen_u32();
        let container_id = 0_u32;
        let size = 10_u32;
        let uid_mappings = vec![LinuxIdMappingBuilder::default()
            .host_id(host_uid)
            .container_id(container_id)
            .size(size)
            .build()?];
        let gid_mappings = vec![LinuxIdMappingBuilder::default()
            .host_id(host_gid)
            .container_id(container_id)
            .size(size)
            .build()?];
        let linux = LinuxBuilder::default()
            .namespaces(vec![userns])
            .uid_mappings(uid_mappings)
            .gid_mappings(gid_mappings)
            .build()?;
        let spec = SpecBuilder::default().linux(linux).build()?;

        let pid = getpid();
        let tmp = tempfile::tempdir()?;
        let id_mapper = UserNamespaceIDMapper {
            base_path: tmp.path().to_path_buf(),
        };
        id_mapper.ensure_uid_path(&pid)?;

        let mut config = UserNamespaceConfig::new(&spec)?.unwrap();
        config.with_id_mapper(id_mapper.clone());
        config.write_uid_mapping(pid)?;
        assert_eq!(
            format!("{container_id} {host_uid} {size}"),
            fs::read_to_string(id_mapper.get_uid_path(&pid))?
        );
        config.write_gid_mapping(pid)?;
        Ok(())
    }

    #[test]
    #[serial]
    fn test_write_gid_mapping() -> Result<()> {
        let userns = LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()?;
        let host_uid = gen_u32();
        let host_gid = gen_u32();
        let container_id = 0_u32;
        let size = 10_u32;
        let uid_mappings = vec![LinuxIdMappingBuilder::default()
            .host_id(host_uid)
            .container_id(container_id)
            .size(size)
            .build()?];
        let gid_mappings = vec![LinuxIdMappingBuilder::default()
            .host_id(host_gid)
            .container_id(container_id)
            .size(size)
            .build()?];
        let linux = LinuxBuilder::default()
            .namespaces(vec![userns])
            .uid_mappings(uid_mappings)
            .gid_mappings(gid_mappings)
            .build()?;
        let spec = SpecBuilder::default().linux(linux).build()?;

        let pid = getpid();
        let tmp = tempfile::tempdir()?;
        let id_mapper = UserNamespaceIDMapper {
            base_path: tmp.path().to_path_buf(),
        };
        id_mapper.ensure_gid_path(&pid)?;

        let mut config = UserNamespaceConfig::new(&spec)?.unwrap();
        config.with_id_mapper(id_mapper.clone());
        config.write_gid_mapping(pid)?;
        assert_eq!(
            format!("{container_id} {host_gid} {size}"),
            fs::read_to_string(id_mapper.get_gid_path(&pid))?
        );
        Ok(())
    }
}
