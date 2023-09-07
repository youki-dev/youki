use super::{serialize::DbusSerialize, utils::SystemdClientError};
use std::collections::HashMap;
use std::path::PathBuf;

pub trait SystemdClient {
    fn is_system(&self) -> bool;

    fn transient_unit_exists(&self, unit_name: &str) -> bool;

    fn start_transient_unit(
        &self,
        container_name: &str,
        pid: u32,
        parent: &str,
        unit_name: &str,
    ) -> Result<(), SystemdClientError>;

    fn stop_transient_unit(&self, unit_name: &str) -> Result<(), SystemdClientError>;

    fn set_unit_properties(
        &self,
        unit_name: &str,
        properties: &HashMap<&str, Box<dyn DbusSerialize>>,
    ) -> Result<(), SystemdClientError>;

    fn systemd_version(&self) -> Result<u32, SystemdClientError>;

    fn control_cgroup_root(&self) -> Result<PathBuf, SystemdClientError>;
}
