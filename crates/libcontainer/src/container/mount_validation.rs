use oci_spec::runtime::{Linux, LinuxIdMapping, LinuxNamespaceType, Mount as SpecMount};

use crate::error::ErrInvalidSpec;

fn has_non_empty_mappings(mappings: Option<&[LinuxIdMapping]>) -> bool {
    mappings.is_some_and(|mappings| !mappings.is_empty())
}

fn container_userns_has_mappings(linux: Option<&Linux>) -> bool {
    let Some(linux) = linux else {
        return false;
    };
    let has_userns = linux.namespaces().as_ref().is_some_and(|namespaces| {
        namespaces
            .iter()
            .any(|ns| ns.typ() == LinuxNamespaceType::User)
    });
    if !has_userns {
        return false;
    }

    has_non_empty_mappings(linux.uid_mappings().as_deref())
        && has_non_empty_mappings(linux.gid_mappings().as_deref())
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
        let requires_idmapped_mount = has_idmap_option || has_mount_mappings;
        let is_bind = mount.typ().as_deref() == Some("bind")
            || options.iter().any(|o| o == "bind" || o == "rbind");

        if has_idmap_option && !has_mount_mappings && !can_use_container_userns {
            tracing::error!(
                destination = ?mount.destination(),
                "idmap/ridmap without mount uid/gid mappings requires a usable container user namespace"
            );
            Err(ErrInvalidSpec::MountIdmapInvalidConfig)?;
        }

        if requires_idmapped_mount && !is_bind {
            tracing::error!(
                destination = ?mount.destination(),
                "mount specifies idmap option for non-bind mount"
            );
            Err(ErrInvalidSpec::MountIdmapNonBind)?;
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

    fn linux_with_new_userns_mappings() -> oci_spec::runtime::Linux {
        LinuxBuilder::default()
            .namespaces(vec![
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::User)
                    .build()
                    .unwrap(),
            ])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap()
    }

    fn linux_with_new_userns_without_mappings() -> oci_spec::runtime::Linux {
        LinuxBuilder::default()
            .namespaces(vec![
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::User)
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap()
    }

    fn linux_with_mappings_without_userns() -> oci_spec::runtime::Linux {
        LinuxBuilder::default()
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap()
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
    fn validate_idmapped_mounts_requires_mappings_when_flag_present() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
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
    fn validate_idmapped_mounts_accepts_ridmap() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "ridmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(res.is_ok());
    }

    #[test]
    fn validate_idmapped_mounts_requires_mappings_when_ridmap_present() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "ridmap".to_string()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapInvalidConfig)));
    }

    #[test]
    fn validate_idmapped_mounts_allows_implied_idmap_with_userns() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .build()
            .unwrap();
        let linux = linux_with_new_userns_mappings();
        let res = validate_idmapped_mounts(&[mount], Some(&linux));
        assert!(res.is_ok());
    }

    #[test]
    fn validate_idmapped_mounts_allows_implied_ridmap_with_userns() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "ridmap".to_string()])
            .build()
            .unwrap();
        let linux = linux_with_new_userns_mappings();
        let res = validate_idmapped_mounts(&[mount], Some(&linux));
        assert!(res.is_ok());
    }

    #[test]
    fn validate_idmapped_mounts_rejects_implied_idmap_with_unmapped_new_userns() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .build()
            .unwrap();
        let linux = linux_with_new_userns_without_mappings();
        let res = validate_idmapped_mounts(&[mount], Some(&linux));
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapInvalidConfig)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_implied_idmap_without_userns() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .build()
            .unwrap();
        let linux = linux_with_mappings_without_userns();
        let res = validate_idmapped_mounts(&[mount], Some(&linux));
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapInvalidConfig)));
    }

    #[test]
    fn validate_idmapped_mounts_accepts_rbind() {
        let mount = MountBuilder::default()
            .destination(PathBuf::from("/mnt"))
            .typ("tmpfs")
            .source(PathBuf::from("tmpfs"))
            .options(vec!["rbind".to_string(), "idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(res.is_ok());
    }

    #[test]
    fn validate_idmapped_mounts_rejects_empty_mappings_with_idmap() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .uid_mappings(Vec::new())
            .gid_mappings(Vec::new())
            .build()
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
    fn validate_idmapped_mounts_requires_both_mappings_gid_only() {
        let mount = serde_json::from_value(serde_json::json!({
            "destination": "/mnt",
            "type": "bind",
            "source": "/src",
            "options": ["bind", "idmap"],
            "gidMappings": [{"containerID": 0, "hostID": 0, "size": 1}]
        }))
        .unwrap();
        let res = validate_idmapped_mounts(&[mount], None);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapInvalidConfig)));
    }
}
