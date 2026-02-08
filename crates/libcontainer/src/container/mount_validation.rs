use oci_spec::runtime::Mount as SpecMount;

use crate::error::ErrInvalidSpec;

pub(crate) fn validate_idmapped_mounts(mounts: &[SpecMount]) -> Result<(), ErrInvalidSpec> {
    for mount in mounts {
        let has_uid = mount
            .uid_mappings()
            .as_ref()
            .filter(|v| !v.is_empty())
            .is_some();
        let has_gid = mount
            .gid_mappings()
            .as_ref()
            .filter(|v| !v.is_empty())
            .is_some();
        let options = mount.options().as_deref().unwrap_or(&[]);
        let has_idmap = options.iter().any(|o| o == "idmap" || o == "ridmap");
        let is_bind = mount.typ().as_deref() == Some("bind")
            || options.iter().any(|o| o == "bind" || o == "rbind");
        let has_mappings = has_uid && has_gid;

        if has_uid != has_gid || has_idmap != has_mappings {
            tracing::error!(
                destination = ?mount.destination(),
                "idmap option and uid/gid mappings must be specified together"
            );
            Err(ErrInvalidSpec::MountIdmapInvalidConfig)?;
        }

        if has_idmap && !is_bind {
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

    use oci_spec::runtime::{LinuxIdMapping, LinuxIdMappingBuilder, MountBuilder};

    use super::validate_idmapped_mounts;
    use crate::error::ErrInvalidSpec;

    fn make_mapping() -> LinuxIdMapping {
        LinuxIdMappingBuilder::default()
            .container_id(0)
            .host_id(0)
            .size(1)
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
    fn validate_idmapped_mounts_requires_both_mappings() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount]);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapInvalidConfig)
        ));
    }

    #[test]
    fn validate_idmapped_mounts_requires_idmap_flag() {
        let mount = base_mount()
            .options(vec!["bind".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount]);
        assert!(matches!(res, Err(ErrInvalidSpec::MountIdmapInvalidConfig)));
    }

    #[test]
    fn validate_idmapped_mounts_requires_mappings_when_flag_present() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount]);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapInvalidConfig)
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
        let res = validate_idmapped_mounts(&[mount]);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapNonBind)
        ));
    }

    #[test]
    fn validate_idmapped_mounts_allows_idmap_with_mappings_bind() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount]);
        assert!(res.is_ok());
    }

    #[test]
    fn validate_idmapped_mounts_allows_no_idmap_no_mappings_bind() {
        let mount = base_mount()
            .options(vec!["bind".to_string()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount]);
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
        let res = validate_idmapped_mounts(&[mount]);
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
        let res = validate_idmapped_mounts(&[mount]);
        assert!(res.is_ok());
    }

    #[test]
    fn validate_idmapped_mounts_requires_mappings_when_ridmap_present() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "ridmap".to_string()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount]);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapInvalidConfig)
        ));
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
        let res = validate_idmapped_mounts(&[mount]);
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
        let res = validate_idmapped_mounts(&[mount]);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapInvalidConfig)
        ));
    }

    #[test]
    fn validate_idmapped_mounts_requires_both_mappings_gid_only() {
        let mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[mount]);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapInvalidConfig)
        ));
    }

    #[test]
    fn validate_idmapped_mounts_rejects_single_invalid_in_list() {
        let ok_mount = base_mount()
            .options(vec!["bind".to_string(), "idmap".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let bad_mount = base_mount()
            .options(vec!["bind".to_string()])
            .uid_mappings(vec![make_mapping()])
            .gid_mappings(vec![make_mapping()])
            .build()
            .unwrap();
        let res = validate_idmapped_mounts(&[ok_mount, bad_mount]);
        assert!(matches!(
            res,
            Err(ErrInvalidSpec::MountIdmapInvalidConfig)
        ));
    }
}
