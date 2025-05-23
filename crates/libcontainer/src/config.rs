use std::fs;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use oci_spec::runtime::{Hooks, Spec};
use serde::{Deserialize, Serialize};

use crate::utils;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to save config")]
    SaveIO {
        source: std::io::Error,
        path: PathBuf,
    },
    #[error("failed to save config")]
    SaveEncode {
        source: serde_json::Error,
        path: PathBuf,
    },
    #[error("failed to parse config")]
    LoadIO {
        source: std::io::Error,
        path: PathBuf,
    },
    #[error("failed to parse config")]
    LoadParse {
        source: serde_json::Error,
        path: PathBuf,
    },
    #[error("missing linux in spec")]
    MissingLinux,
}

type Result<T> = std::result::Result<T, ConfigError>;

const YOUKI_CONFIG_NAME: &str = "youki_config.json";

/// A configuration for passing information obtained during container creation to other commands.
/// Keeping the information to a minimum improves performance.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct YoukiConfig {
    pub hooks: Option<Hooks>,
    pub cgroup_path: PathBuf,
}

impl YoukiConfig {
    pub fn from_spec(spec: &Spec, container_id: &str) -> Result<Self> {
        Ok(YoukiConfig {
            hooks: spec.hooks().clone(),
            cgroup_path: utils::get_cgroup_path(
                spec.linux()
                    .as_ref()
                    .ok_or(ConfigError::MissingLinux)?
                    .cgroups_path(),
                container_id,
            ),
        })
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let file = fs::File::create(path.as_ref().join(YOUKI_CONFIG_NAME)).map_err(|err| {
            ConfigError::SaveIO {
                source: err,
                path: path.as_ref().to_owned(),
            }
        })?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, self).map_err(|err| ConfigError::SaveEncode {
            source: err,
            path: path.as_ref().to_owned(),
        })?;
        writer.flush().map_err(|err| ConfigError::SaveIO {
            source: err,
            path: path.as_ref().to_owned(),
        })?;

        Ok(())
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let file =
            fs::File::open(path.join(YOUKI_CONFIG_NAME)).map_err(|err| ConfigError::LoadIO {
                source: err,
                path: path.to_owned(),
            })?;
        let reader = BufReader::new(file);
        let config = serde_json::from_reader(reader).map_err(|err| ConfigError::LoadParse {
            source: err,
            path: path.to_owned(),
        })?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[test]
    fn test_config_from_spec() -> Result<()> {
        let container_id = "sample";
        let spec = Spec::default();
        let config = YoukiConfig::from_spec(&spec, container_id)?;
        assert_eq!(&config.hooks, spec.hooks());
        dbg!(&config.cgroup_path);
        assert_eq!(
            config.cgroup_path,
            PathBuf::from(format!(":youki:{container_id}"))
        );
        Ok(())
    }

    #[test]
    fn test_config_save_and_load() -> Result<()> {
        let container_id = "sample";
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spec = Spec::default();
        let config = YoukiConfig::from_spec(&spec, container_id)?;
        config.save(&tmp)?;
        let act = YoukiConfig::load(&tmp)?;
        assert_eq!(act, config);
        Ok(())
    }
}
