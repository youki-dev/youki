use oci_spec::runtime::{LinuxNamespaceType, Spec};

use crate::error::ErrInvalidSpec;

pub struct Validator;

impl Validator {
    pub fn validate_spec(spec: &Spec) -> Result<(), ErrInvalidSpec> {
        Self::validate_spec_for_uts_namespace(spec)?;
        Self::validate_spec_for_new_user_ns(spec)?;
        Self::validate_spec_for_mnt_namespace(spec)?;

        Ok(())
    }

    fn validate_spec_for_uts_namespace(spec: &Spec) -> Result<(), ErrInvalidSpec> {
        let has_uts_namespace = spec
            .linux()
            .as_ref()
            .and_then(|l| l.namespaces().as_ref())
            .is_some_and(|namespaces| {
                namespaces
                    .iter()
                    .any(|ns| ns.typ() == LinuxNamespaceType::Uts)
            });

        if !has_uts_namespace {
            if spec.hostname().is_some() {
                return Err(ErrInvalidSpec::HostnameWithoutUTS);
            }

            if spec.domainname().is_some() {
                return Err(ErrInvalidSpec::DomainnameWithoutUTS);
            }
        }

        Ok(())
    }

    fn validate_spec_for_new_user_ns(spec: &Spec) -> Result<(), ErrInvalidSpec> {
        let has_user_namespace = spec
            .linux()
            .as_ref()
            .and_then(|l| l.namespaces().as_ref())
            .is_some_and(|namespaces| {
                namespaces
                    .iter()
                    .any(|ns| ns.typ() == LinuxNamespaceType::User)
            });

        if !has_user_namespace {
            let has_uid_mappings = spec
                .linux()
                .as_ref()
                .is_some_and(|l| l.uid_mappings().as_ref().is_some_and(|m| !m.is_empty()));
            let has_gid_mappings = spec
                .linux()
                .as_ref()
                .is_some_and(|l| l.gid_mappings().as_ref().is_some_and(|m| !m.is_empty()));

            if has_uid_mappings || has_gid_mappings {
                return Err(ErrInvalidSpec::UserMappingsWithoutNamespace);
            }
        }

        Ok(())
    }

    fn validate_spec_for_mnt_namespace(spec: &Spec) -> Result<(), ErrInvalidSpec> {
        let has_mnt_namespace = spec
            .linux()
            .as_ref()
            .and_then(|l| l.namespaces().as_ref())
            .is_some_and(|namespaces| {
                namespaces
                    .iter()
                    .any(|ns| ns.typ() == LinuxNamespaceType::Mount)
            });

        if !has_mnt_namespace {
            let has_masked_paths = spec
                .linux()
                .as_ref()
                .is_some_and(|l| l.masked_paths().as_ref().is_some_and(|m| !m.is_empty()));
            let has_readonly_paths = spec
                .linux()
                .as_ref()
                .is_some_and(|l| l.readonly_paths().as_ref().is_some_and(|m| !m.is_empty()));

            if has_masked_paths || has_readonly_paths {
                return Err(ErrInvalidSpec::SysEntriesWithoutMntNamespace);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use oci_spec::runtime::{
        LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespaceBuilder, SpecBuilder,
    };

    use super::*;

    #[test]
    fn test_validate_spec_for_uts_namespace() {
        let sepc_no_uts_with_hostname = SpecBuilder::default()
            .hostname("some-host")
            .linux(LinuxBuilder::default().namespaces(vec![]).build().unwrap())
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_uts_namespace(&sepc_no_uts_with_hostname).unwrap_err(),
            ErrInvalidSpec::HostnameWithoutUTS
        ));

        let mut spec_no_uts_with_domainname = SpecBuilder::default()
            .domainname("some-domain")
            .linux(LinuxBuilder::default().namespaces(vec![]).build().unwrap())
            .build()
            .unwrap();
        spec_no_uts_with_domainname.set_hostname(None);
        assert!(matches!(
            Validator::validate_spec_for_uts_namespace(&spec_no_uts_with_domainname).unwrap_err(),
            ErrInvalidSpec::DomainnameWithoutUTS
        ));

        let spec_with_uts_and_host_domain_names = SpecBuilder::default()
            .hostname("my-host")
            .domainname("my-domain")
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Uts)
                            .build()
                            .unwrap(),
                    ])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(
            Validator::validate_spec_for_uts_namespace(&spec_with_uts_and_host_domain_names)
                .is_ok()
        );

        let spec_no_uts_no_host_domain_names = SpecBuilder::default()
            .linux(LinuxBuilder::default().build().unwrap())
            .build()
            .unwrap();
        assert!(
            Validator::validate_spec_for_uts_namespace(&spec_no_uts_no_host_domain_names).is_ok()
        );
    }

    #[test]
    fn test_validate_user_ns_mappings() {
        let spec_with_mappings_no_ns = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![])
                    .uid_mappings(vec![
                        LinuxIdMappingBuilder::default()
                            .container_id(0_u32)
                            .host_id(1000_u32)
                            .size(1_u32)
                            .build()
                            .unwrap(),
                    ])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_new_user_ns(&spec_with_mappings_no_ns).unwrap_err(),
            ErrInvalidSpec::UserMappingsWithoutNamespace
        ));
    }

    #[test]
    fn test_validate_spec_for_mnt_namespace() {
        let spec_no_mnt_with_masked = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![])
                    .masked_paths(vec!["/proc/keys".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_mnt_namespace(&spec_no_mnt_with_masked).unwrap_err(),
            ErrInvalidSpec::SysEntriesWithoutMntNamespace
        ));

        let spec_no_mnt_with_readonly = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![])
                    .readonly_paths(vec!["/proc/sys".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            Validator::validate_spec_for_mnt_namespace(&spec_no_mnt_with_readonly).unwrap_err(),
            ErrInvalidSpec::SysEntriesWithoutMntNamespace
        ));

        let spec_with_mnt_and_masked = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Mount)
                            .build()
                            .unwrap(),
                    ])
                    .masked_paths(vec!["/proc/keys".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(Validator::validate_spec_for_mnt_namespace(&spec_with_mnt_and_masked).is_ok());

        let spec_with_mnt_and_readonly = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .namespaces(vec![
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Mount)
                            .build()
                            .unwrap(),
                    ])
                    .readonly_paths(vec!["/proc/sys".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(Validator::validate_spec_for_mnt_namespace(&spec_with_mnt_and_readonly).is_ok());
    }
}
