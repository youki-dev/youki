use oci_spec::runtime::{Linux, LinuxIdMapping, LinuxNamespaceType, Mount as SpecMount};

use crate::error::ErrInvalidSpec;

fn has_non_empty_mappings(mappings: Option<&[LinuxIdMapping]>) -> bool {
    mappings.is_some_and(|mappings| !mappings.is_empty())
}

fn container_userns_has_mappings(linux: Option<&Linux>) -> bool {
    let Some(linux) = linux else {
        return false;
    };
    let Some(namespaces) = linux.namespaces().as_deref() else { return false };
    match namespaces.iter().find(|ns| ns.typ() == LinuxNamespaceType::User) {
        None => false,
        Some(ns) if ns.path().is_some() => true,
        Some(_) => {
          has_non_empty_mappings(linux.uid_mappings().as_deref().unwrap_or(&[]))
              && has_non_empty_mappings(linux.gid_mappings().as_deref().unwrap_or(&[]))
        }
    }
}

pub(crate) fn validate_idmapped_mounts(
    mounts: &[SpecMount],
    linux: Option<&Linux>,
) -> Result<(), ErrInvalidSpec> {
    let can_use_container_userns = container_userns_has_mappings(linux);

    for mount in mounts {
        let uid_mappings = mount.uid_mappings().as_deref();
        let gid_mappings = mount.gid_mappings().as_deref();
        let has_mount_mappings = match (uid_mappings, gid_mappings) {
            (Some(_), Some(_)) => {
                if !has_non_empty_mappings(uid_mappings) || !has_non_empty_mappings(gid_mappings) {
                    tracing::error!(
                        destination = ?mount.destination(),
                        "mount uid/gid mappings must be non-empty and specified together"
                    );
                    return Err(ErrInvalidSpec::MountIdmapInvalidConfig);
                }
                true
            }
            // idmap/ridmap can use the container user namespace when mount-specific mappings are absent.
            (None, None) => false,
            _ => {
                tracing::error!(
                    destination = ?mount.destination(),
                    "mount uid/gid mappings must be non-empty and specified together"
                );
                return Err(ErrInvalidSpec::MountIdmapInvalidConfig);
            }
        };
        let options = mount.options().as_deref().unwrap_or(&[]);
        let has_idmap_option = options.iter().any(|o| o == "idmap" || o == "ridmap");
        let is_bind = mount.typ().as_deref() == Some("bind")
            || options.iter().any(|o| o == "bind" || o == "rbind");

        if has_idmap_option && !has_mount_mappings && !can_use_container_userns {
            tracing::error!(
                destination = ?mount.destination(),
                "idmap/ridmap without mount uid/gid mappings requires a usable container user namespace"
            );
            return Err(ErrInvalidSpec::MountIdmapInvalidConfig);
        }

        if (has_idmap_option || has_mount_mappings) && !is_bind {
            tracing::error!(
                destination = ?mount.destination(),
                "mount specifies idmap option for non-bind mount"
            );
            return Err(ErrInvalidSpec::MountIdmapNonBind);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use oci_spec::runtime::{
        LinuxBuilder, LinuxIdMapping, LinuxIdMappingBuilder, LinuxNamespaceBuilder,
        LinuxNamespaceType, MountBuilder,
    };

    use super::validate_idmapped_mounts;
    use crate::error::ErrInvalidSpec;

    fn make_mapping() -> LinuxIdMapping {
        LinuxIdMappingBuilder::default()
            .container_id(0_u32)
            .host_id(0_u32)
            .size(1_u32)
            .build()
            .unwrap()
    }

    fn base_mount() -> MountBuilder {
        MountBuilder::default()
            .destination(PathBuf::from("/mnt"))
            .typ("bind")
            .source(PathBuf::from("/src"))
    }

    #[test]
    fn validate_idmapped_mounts_allows_idmap_with_mappings_bind() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(res.is_ok());
    }

    #[test]
    fn validate_idmapped_mounts_allows_mappings_without_idmap_flag() {
        let mount = base_mount()
            .options(vec!["bind".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(res.is_ok());
    }

    #[test]
    fn validate_idmapped_mounts_allows_implied_idmap_with_userns() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .build()
            .unwrap();
        let linux = LinuxBuilder::default()
            .namespaces(vec![
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::User)
                    .build()
                    .unwrap(),
            ])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], Some(&linux));
        assert!(res.is_ok());
    }

    #[test]
    fn validate_idmapped_mounts_allows_implied_idmap_with_joined_userns() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .build()
            .unwrap();
        let linux = LinuxBuilder::default()
            .namespaces(vec![
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::User)
                    .path(PathBuf::from("/proc/123/ns/user"))
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], Some(&linux));
        assert!(res.is_ok());
    }

    #[test]
    fn validate_idmapped_mounts_accepts_rbind() {
        let mount = MountBuilder::default()
            .destination(PathBuf::from("/mnt"))
            .source(PathBuf::from("/src"))
            .options(vec!["rbind".to_string(), "idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(res.is_ok());
    }

    #[test]
    fn validate_idmapped_mounts_allows_no_idmap_no_mappings_non_bind() {
        let mount = MountBuilder::default()
            .destination(PathBuf::from("/mnt"))
            .typ("tmpfs")
            .source(PathBuf::from("tmpfs"))
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(res.is_ok());
    }

    #[test]
    fn validate_idmapped_mounts_requires_both_mappings() {
        let mount = serde_json::from_value(serde_json::json!({
            "destination": "/mnt",
            "type": "bind",
            "source": "/src",
            "options": ["bind", "idmap"],
            "uidMappings": [{"containerID": 0, "hostID": 0, "size": 1}]
        }))
        .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapInvalidConfig)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_empty_mappings_without_idmap() {
        let mount = base_mount()
            .options(vec!["bind".to_string()])
            .uid_mappings(Vec::new())
            .gid_mappings(Vec::new())
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapInvalidConfig)));
    }

    #[test]
    fn validate_idmapped_mounts_requires_mappings_when_flag_present() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapInvalidConfig)));
    }

    #[test]
    fn validate_idmapped_mounts_requires_userns_or_mappings_when_ridmap_present() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "ridmap".to_string()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapInvalidConfig)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_implied_idmap_with_unmapped_new_userns() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .build()
            .unwrap();
        let linux = LinuxBuilder::default()
            .namespaces(vec![
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::User)
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], Some(&linux));
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapInvalidConfig)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_implied_idmap_without_userns() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .build()
            .unwrap();
        let linux = LinuxBuilder::default()
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], Some(&linux));
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapInvalidConfig)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_non_bind() {
        let mount = MountBuilder::default()
            .destination(PathBuf::from("/mnt"))
            .typ("tmpfs")
            .source(PathBuf::from("tmpfs"))
            .options(vec!["idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapNonBind)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_mappings_only_non_bind() {
        let mount = MountBuilder::default()
            .destination(PathBuf::from("/mnt"))
            .typ("tmpfs")
            .source(PathBuf::from("tmpfs"))
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapNonBind)));
    }
}
