use std::collections::HashMap;
use std::path::PathBuf;

use super::serialize::Variant;
use super::utils::SystemdClientError;

pub trait SystemdClient {
    #[allow(dead_code)]
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
        properties: &HashMap<&str, Variant>,
    ) -> Result<(), SystemdClientError>;

    fn systemd_version(&self) -> Result<u32, SystemdClientError>;

    fn control_cgroup_root(&self) -> Result<PathBuf, SystemdClientError>;

    fn add_process_to_unit(
        &self,
        unit_name: &str,
        subcgroup: &str,
        pid: u32,
    ) -> Result<(), SystemdClientError>;

    fn subscribe_job_remove_signal(&self) -> Result<(), SystemdClientError>;

    fn dbus_add_match(
        &self,
        filter_type: &str,
        sender: &str,
        interface: &str,
        member: &str,
    ) -> Result<(), SystemdClientError>;

    fn unsubscribe_job_remove_signal(&self) -> Result<(), SystemdClientError>;
}
