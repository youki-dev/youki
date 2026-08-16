use std::collections::HashMap;
use std::path::Path;

use super::controller_type::ControllerType;
use crate::common::{self, ControllerOpt, WrappedIoError};

#[derive(thiserror::Error, Debug)]
pub enum V2UnifiedError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("subsystem {subsystem} is not available: {err}")]
    SubsystemNotAvailable {
        subsystem: String,
        err: WrappedIoError,
    },
    #[error("unified resource {filename} must be a file name (no slashes)")]
    InvalidFilename { filename: String },
}

pub struct Unified {}

impl Unified {
    pub fn apply(
        controller_opt: &ControllerOpt,
        cgroup_path: &Path,
        controllers: Vec<ControllerType>,
    ) -> Result<(), V2UnifiedError> {
        if let Some(unified) = &controller_opt.resources.unified() {
            Self::apply_impl(unified, cgroup_path, &controllers)?;
        }

        Ok(())
    }

    fn apply_impl(
        unified: &HashMap<String, String>,
        cgroup_path: &Path,
        controllers: &[ControllerType],
    ) -> Result<(), V2UnifiedError> {
        tracing::debug!("Apply unified cgroup config");
        for (cgroup_file, value) in unified {
            if cgroup_file.contains('/') {
                return Err(V2UnifiedError::InvalidFilename {
                    filename: cgroup_file.into(),
                });
            }
            if let Err(err) = common::write_cgroup_file_str(cgroup_path.join(cgroup_file), value) {
                let (subsystem, _) = cgroup_file.split_once('.').unwrap_or((cgroup_file, ""));

                if controllers.iter().any(|c| c.to_string() == subsystem) {
                    Err(err)?;
                } else {
                    return Err(V2UnifiedError::SubsystemNotAvailable {
                        subsystem: subsystem.into(),
                        err,
                    });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;

    use oci_spec::runtime::LinuxResourcesBuilder;

    use super::*;
    use crate::test::set_fixture;
    use crate::v2::controller_type::ControllerType;

    #[test]
    fn test_set_unified() {
        // arrange
        let tmp = tempfile::tempdir().unwrap();
        let hugetlb_limit_path = set_fixture(tmp.path(), "hugetlb.1GB.limit_in_bytes", "").unwrap();
        let cpu_weight_path = set_fixture(tmp.path(), "cpu.weight", "").unwrap();

        let unified = {
            let mut u = HashMap::new();
            u.insert(
                "hugetlb.1GB.limit_in_bytes".to_owned(),
                "72348034".to_owned(),
            );
            u.insert("cpu.weight".to_owned(), "5000".to_owned());
            u
        };

        let resources = LinuxResourcesBuilder::default()
            .unified(unified)
            .build()
            .unwrap();

        let controller_opt = ControllerOpt {
            resources: &resources,
            freezer_state: None,
            oom_score_adj: None,
            disable_oom_killer: false,
        };

        // act
        Unified::apply(&controller_opt, tmp.path(), vec![]).expect("apply unified");

        // assert
        let hugetlb_limit = fs::read_to_string(hugetlb_limit_path).expect("read hugetlb limit");
        let cpu_weight = fs::read_to_string(cpu_weight_path).expect("read cpu weight");
        assert_eq!(hugetlb_limit, "72348034");
        assert_eq!(cpu_weight, "5000");
    }

    #[test]
    fn test_set_unified_failed_to_write_subsystem_not_enabled() {
        // arrange
        let tmp = tempfile::tempdir().unwrap();

        let unified = {
            let mut u = HashMap::new();
            u.insert(
                "hugetlb.1GB.limit_in_bytes".to_owned(),
                "72348034".to_owned(),
            );
            u.insert("cpu.weight".to_owned(), "5000".to_owned());
            u
        };

        let resources = LinuxResourcesBuilder::default()
            .unified(unified)
            .build()
            .unwrap();

        let controller_opt = ControllerOpt {
            resources: &resources,
            freezer_state: None,
            oom_score_adj: None,
            disable_oom_killer: false,
        };

        // act
        let result = Unified::apply(&controller_opt, tmp.path(), vec![]);

        // assert
        assert!(result.is_err());
    }

    #[test]
    fn test_set_unified_failed_to_write_subsystem_enabled() {
        // arrange
        let tmp = tempfile::tempdir().unwrap();

        let unified = {
            let mut u = HashMap::new();
            u.insert(
                "hugetlb.1GB.limit_in_bytes".to_owned(),
                "72348034".to_owned(),
            );
            u.insert("cpu.weight".to_owned(), "5000".to_owned());
            u
        };

        let resources = LinuxResourcesBuilder::default()
            .unified(unified)
            .build()
            .unwrap();

        let controller_opt = ControllerOpt {
            resources: &resources,
            oom_score_adj: None,
            disable_oom_killer: false,
            freezer_state: None,
        };

        // act
        let result = Unified::apply(
            &controller_opt,
            tmp.path(),
            vec![ControllerType::HugeTlb, ControllerType::Cpu],
        );

        // assert
        assert!(result.is_err());
    }

    #[test]
    fn test_set_unified_slash_in_key() {
        // arrange
        let tmp = tempfile::tempdir().unwrap();

        let unified = {
            let mut u = HashMap::new();
            u.insert("/memory/max".to_owned(), "100000".to_owned());
            u
        };

        let resources = LinuxResourcesBuilder::default()
            .unified(unified)
            .build()
            .unwrap();

        let controller_opt = ControllerOpt {
            resources: &resources,
            freezer_state: None,
            oom_score_adj: None,
            disable_oom_killer: false,
        };

        // act
        let result = Unified::apply(&controller_opt, tmp.path(), vec![]);

        // assert
        assert!(matches!(
            result,
            Err(V2UnifiedError::InvalidFilename { .. })
        ));
    }
}
