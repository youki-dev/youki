use oci_spec::runtime::{Linux, LinuxIdMapping, LinuxNamespaceType, Mount as SpecMount};

use crate::error::ErrInvalidSpec;
use crate::syscall::Syscall;
use crate::utils::rootless_required;

fn has_non_empty_mappings(mappings: &[LinuxIdMapping]) -> bool {
    !mappings.is_empty()
}

fn container_userns_has_mappings(linux: Option<&Linux>) -> bool {
    let Some(linux) = linux else {
        return false;
    };
    let Some(namespaces) = linux.namespaces().as_deref() else {
        return false;
    };
    match namespaces
        .iter()
        .find(|ns| ns.typ() == LinuxNamespaceType::User)
    {
        None => false,
        Some(ns) if ns.path().is_some() => true,
        Some(_) => {
            has_non_empty_mappings(linux.uid_mappings().as_deref().unwrap_or(&[]))
                && has_non_empty_mappings(linux.gid_mappings().as_deref().unwrap_or(&[]))
        }
    }
}

fn validate_mount_mappings(mount: &SpecMount) -> Result<bool, ErrInvalidSpec> {
    match (
        mount.uid_mappings().as_deref(),
        mount.gid_mappings().as_deref(),
    ) {
        (Some(uid_mappings), Some(gid_mappings))
            if has_non_empty_mappings(uid_mappings) && has_non_empty_mappings(gid_mappings) =>
        {
            Ok(true)
        }
        // idmap/ridmap can use the container user namespace when mount-specific mappings are absent.
        (None, None) => Ok(false),
        _ => {
            tracing::error!(
                destination = ?mount.destination(),
                "mount uid/gid mappings must be non-empty and specified together"
            );
            Err(ErrInvalidSpec::MountIdmapMissingMappings)
        }
    }
}

pub(crate) fn validate_idmapped_mounts(
    mounts: &[SpecMount],
    linux: Option<&Linux>,
    syscall: &dyn Syscall,
) -> Result<(), ErrInvalidSpec> {
    let can_use_container_userns = container_userns_has_mappings(linux);
    let is_rootless = rootless_required(syscall).unwrap_or(false);

    for mount in mounts {
        let has_any_mount_mappings =
            mount.uid_mappings().is_some() || mount.gid_mappings().is_some();
        let options = mount.options().as_deref().unwrap_or(&[]);
        let has_idmap_option = options.iter().any(|o| o == "idmap" || o == "ridmap");
        if !has_idmap_option && !has_any_mount_mappings {
            continue;
        }

        let is_bind = mount.typ().as_deref() == Some("bind")
            || options.iter().any(|o| o == "bind" || o == "rbind");

        if !is_bind {
            tracing::error!(
                destination = ?mount.destination(),
                "mount specifies idmap option for non-bind mount"
            );
            return Err(ErrInvalidSpec::MountIdmapNonBind);
        }

        if is_rootless {
            tracing::error!(
                destination = ?mount.destination(),
                "idmapped mounts are not supported in rootless containers"
            );
            return Err(ErrInvalidSpec::MountIdmapRootless);
        }

        let has_mount_mappings = validate_mount_mappings(mount)?;

        if !has_mount_mappings && !can_use_container_userns {
            tracing::error!(
                destination = ?mount.destination(),
                "idmap/ridmap without mount uid/gid mappings requires a usable container user namespace"
            );
            return Err(ErrInvalidSpec::MountIdmapMissingMappings);
        }

        // TODO: remove this guard when idmapped mount support is implemented.
        tracing::error!(
            destination = ?mount.destination(),
            "idmapped mounts are not supported"
        );
        return Err(ErrInvalidSpec::MountIdmapUnsupported);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use nix::unistd::{Gid, Uid};
    use oci_spec::runtime::{
        LinuxBuilder, LinuxIdMapping, LinuxIdMappingBuilder, LinuxNamespaceBuilder,
        LinuxNamespaceType, MountBuilder,
    };

    use super::validate_idmapped_mounts;
    use crate::error::ErrInvalidSpec;
    use crate::syscall::Syscall;
    use crate::syscall::syscall::create_syscall;

    fn create_root_syscall() -> Box<dyn Syscall> {
        let syscall = create_syscall();
        syscall.set_id(Uid::from_raw(0), Gid::from_raw(0)).unwrap();
        syscall
    }

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
    fn validate_idmapped_mounts_rejects_idmap_with_mappings_bind_as_unsupported() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapUnsupported)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_mappings_without_idmap_flag_as_unsupported() {
        let mount = base_mount()
            .options(vec!["bind".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapUnsupported)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_implied_idmap_with_userns_as_unsupported() {
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
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], Some(&linux), &*syscall);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapUnsupported)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_implied_idmap_with_joined_userns_as_unsupported() {
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
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], Some(&linux), &*syscall);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapUnsupported)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_ridmap_with_userns_as_unsupported() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "ridmap".to_string()])
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
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], Some(&linux), &*syscall);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapUnsupported)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_rbind_idmap_as_unsupported() {
        let mount = MountBuilder::default()
            .destination(PathBuf::from("/mnt"))
            .source(PathBuf::from("/src"))
            .options(vec!["rbind".to_string(), "idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapUnsupported)));
    }

    #[test]
    fn validate_idmapped_mounts_allows_no_idmap_no_mappings_non_bind() {
        let mount = MountBuilder::default()
            .destination(PathBuf::from("/mnt"))
            .typ("tmpfs")
            .source(PathBuf::from("tmpfs"))
            .build()
            .unwrap();
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
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
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapMissingMappings)
        ));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_non_empty_uid_with_empty_gid() {
        let mount = serde_json::from_value(serde_json::json!({
            "destination": "/mnt",
            "type": "bind",
            "source": "/src",
            "options": ["bind", "idmap"],
            "uidMappings": [{"containerID": 0, "hostID": 0, "size": 1}],
            "gidMappings": []
        }))
        .unwrap();
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapMissingMappings)
        ));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_empty_mappings_without_idmap() {
        let mount = base_mount()
            .options(vec!["bind".to_string()])
            .uid_mappings(Vec::new())
            .gid_mappings(Vec::new())
            .build()
            .unwrap();
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapMissingMappings)
        ));
    }

    #[test]
    fn validate_idmapped_mounts_requires_mappings_when_flag_present() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .build()
            .unwrap();
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapMissingMappings)
        ));
    }

    #[test]
    fn validate_idmapped_mounts_requires_userns_or_mappings_when_ridmap_present() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "ridmap".to_string()])
            .build()
            .unwrap();
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapMissingMappings)
        ));
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
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], Some(&linux), &*syscall);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapMissingMappings)
        ));
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
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], Some(&linux), &*syscall);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapMissingMappings)
        ));
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
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
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
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapNonBind)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_bind_type_without_bind_option_as_unsupported() {
        // typ="bind" のみで is_bind を満たし、options に "bind"/"rbind" を含まないケース
        let mount = base_mount()
            .options(vec!["idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapUnsupported)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_unsupported_idmap_among_multiple_mounts() {
        let mapped_mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let regular_mount = MountBuilder::default()
            .destination(PathBuf::from("/tmpfs"))
            .typ("tmpfs")
            .source(PathBuf::from("tmpfs"))
            .build()
            .unwrap();
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[mapped_mount, regular_mount], None, &*syscall);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapUnsupported)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_invalid_mount_among_multiple_mounts() {
        let valid_mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let invalid_mount = MountBuilder::default()
            .destination(PathBuf::from("/tmpfs"))
            .typ("tmpfs")
            .source(PathBuf::from("tmpfs"))
            .options(vec!["idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let syscall = create_root_syscall();
        let res = validate_idmapped_mounts(&[valid_mount, invalid_mount], None, &*syscall);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapUnsupported)));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_rootless_container() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let syscall = create_syscall();
        syscall
            .set_id(Uid::from_raw(1000), Gid::from_raw(1000))
            .unwrap();
        let res = validate_idmapped_mounts(&[mount], None, &*syscall);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapRootless)));
    }
}
