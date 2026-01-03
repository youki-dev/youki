use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::{Debug, Display};
use std::fs::{self};
use std::path::Component::RootDir;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::NixPath;
use nix::unistd::Pid;

use super::controller::Controller;
use super::controller_type::{CONTROLLER_TYPES, ControllerType};
use super::cpu::Cpu;
use super::cpuset::CpuSet;
use super::dbus_native::client::SystemdClient;
use super::dbus_native::dbus::DbusConnection;
use super::dbus_native::utils::SystemdClientError;
use super::memory::Memory;
use super::pids::Pids;
use crate::common::{
    self, AnyCgroupManager, CgroupManager, ControllerOpt, FreezerState, JoinSafelyError,
    PathBufExt, WrapIoResult, WrappedIoError,
};
use crate::stats::Stats;
use crate::systemd::dbus_native::serialize::Variant;
use crate::systemd::io::Io;
use crate::systemd::unified::Unified;
use crate::v2::manager::{Manager as FsManager, V2ManagerError};

const CGROUP_CONTROLLERS: &str = "cgroup.controllers";
const CGROUP_SUBTREE_CONTROL: &str = "cgroup.subtree_control";
pub const PROCESS_IN_CGROUP_TIMEOUT_DURATION: Duration = Duration::from_secs(5);

pub struct Manager {
    /// Root path of the cgroup hierarchy e.g. /sys/fs/cgroup
    root_path: PathBuf,
    /// Path relative to the root path e.g. /system.slice/youki-569d5ce3afe1074769f67.scope for rootfull containers
    /// and e.g. /user.slice/user-1000/user@1000.service/youki-569d5ce3afe1074769f67.scope for rootless containers
    cgroups_path: PathBuf,
    /// Combination of root path and cgroups path
    full_path: PathBuf,
    /// Destructured cgroups path as specified in the runtime spec e.g. system.slice:youki:569d5ce3afe1074769f67
    destructured_path: CgroupsPath,
    /// Name of the container e.g. 569d5ce3afe1074769f67
    container_name: String,
    /// Name of the systemd unit e.g. youki-569d5ce3afe1074769f67.scope
    unit_name: String,
    /// Client for communicating with systemd
    client: DbusConnection,
    /// Cgroup manager for the created transient unit
    fs_manager: FsManager,
    /// Last control group which is managed by systemd, e.g. /user.slice/user-1000/user@1000.service
    delegation_boundary: PathBuf,
    /// Duration to wait for a specific PID to be added to a cgroup
    cgroup_wait_timeout_duration: Duration,
}

/// Represents the systemd cgroups path:
/// It should be of the form [slice]:[scope_prefix]:[name].
/// The slice is the "parent" and should be expanded properly,
/// see expand_slice below.
#[derive(Debug)]
struct CgroupsPath {
    parent: String,
    prefix: String,
    name: String,
}

#[derive(thiserror::Error, Debug)]
pub enum CgroupsPathError {
    #[error("no cgroups path has been provided")]
    NoPath,
    #[error("cgroups path does not contain valid utf8")]
    InvalidUtf8(PathBuf),
    #[error("cgroups path is malformed: {0}")]
    MalformedPath(PathBuf),
}

impl TryFrom<&Path> for CgroupsPath {
    type Error = CgroupsPathError;

    fn try_from(cgroups_path: &Path) -> Result<Self, Self::Error> {
        // if cgroups_path was provided it should be of the form [slice]:[prefix]:[name],
        // for example: "system.slice:docker:1234".
        if cgroups_path.len() == 0 {
            return Err(CgroupsPathError::NoPath);
        }

        let parts = cgroups_path
            .to_str()
            .ok_or_else(|| CgroupsPathError::InvalidUtf8(cgroups_path.to_path_buf()))?
            .split(':')
            .collect::<Vec<&str>>();

        let destructured_path = match parts.len() {
            2 => CgroupsPath {
                parent: "".to_owned(),
                prefix: parts[0].to_owned(),
                name: parts[1].to_owned(),
            },
            3 => CgroupsPath {
                parent: parts[0].to_owned(),
                prefix: parts[1].to_owned(),
                name: parts[2].to_owned(),
            },
            _ => return Err(CgroupsPathError::MalformedPath(cgroups_path.to_path_buf())),
        };

        Ok(destructured_path)
    }
}

impl Display for CgroupsPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.parent, self.prefix, self.name)
    }
}

/// ensures that a parent unit for the current unit is specified
fn ensure_parent_unit(cgroups_path: &mut CgroupsPath, use_system: bool) {
    if cgroups_path.parent.is_empty() {
        cgroups_path.parent = match use_system {
            true => "system.slice".to_owned(),
            false => "user.slice".to_owned(),
        }
    }
}

// custom debug impl as Manager contains fields that do not implement Debug
// and therefore Debug cannot be derived
impl Debug for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Manager")
            .field("root_path", &self.root_path)
            .field("cgroups_path", &self.cgroups_path)
            .field("full_path", &self.full_path)
            .field("destructured_path", &self.destructured_path)
            .field("container_name", &self.container_name)
            .field("unit_name", &self.unit_name)
            .finish()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SystemdManagerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("failed to destructure cgroups path: {0}")]
    CgroupsPath(#[from] CgroupsPathError),
    #[error("invalid slice name: {0}")]
    InvalidSliceName(String),
    #[error(transparent)]
    SystemdClient(#[from] SystemdClientError),
    #[error("failed to join safely: {0}")]
    JoinSafely(#[from] JoinSafelyError),
    #[error("file not found: {0}")]
    FileNotFound(PathBuf),
    #[error("bad delegation boundary {boundary} for cgroups path {cgroup}")]
    BadDelegationBoundary { boundary: PathBuf, cgroup: PathBuf },
    #[error("in v2 manager: {0}")]
    V2Manager(#[from] V2ManagerError),

    #[error("Timeout waiting for pid {0} to be added to cgroup")]
    WaitForProcessInCgroupTimeout(String),

    #[error("in cpu controller: {0}")]
    Cpu(#[from] super::cpu::SystemdCpuError),
    #[error("in cpuset controller: {0}")]
    CpuSet(#[from] super::cpuset::SystemdCpuSetError),
    #[error("in io controller: {0}")]
    Io(#[from] super::io::SystemdIoError),
    #[error("in memory controller: {0}")]
    Memory(#[from] super::memory::SystemdMemoryError),
    #[error("in pids controller: {0}")]
    Pids(Infallible),
    #[error("in pids unified controller: {0}")]
    Unified(#[from] super::unified::SystemdUnifiedError),
}

impl Manager {
    pub fn new(
        root_path: PathBuf,
        cgroups_path: PathBuf,
        container_name: String,
        use_system: bool,
        cgroup_wait_timeout_duration: Duration,
    ) -> Result<Self, SystemdManagerError> {
        let mut destructured_path: CgroupsPath = cgroups_path.as_path().try_into()?;
        ensure_parent_unit(&mut destructured_path, use_system);

        let client = match use_system {
            true => DbusConnection::new_system()?,
            false => DbusConnection::new_session()?,
        };

        let (cgroups_path, delegation_boundary) =
            Self::construct_cgroups_path(&destructured_path, &client)?;
        let full_path = root_path.join_safely(&cgroups_path)?;
        let fs_manager = FsManager::new(root_path.clone(), cgroups_path.clone())?;

        Ok(Manager {
            root_path,
            cgroups_path,
            full_path,
            container_name,
            unit_name: Self::get_unit_name(&destructured_path),
            destructured_path,
            client,
            fs_manager,
            delegation_boundary,
            cgroup_wait_timeout_duration,
        })
    }

    /// get_unit_name returns the unit (scope) name from the path provided by the user
    /// for example: foo:docker:bar returns in '/docker-bar.scope'
    fn get_unit_name(cgroups_path: &CgroupsPath) -> String {
        // By default we create a scope unless specified explicitly.
        if !cgroups_path.name.ends_with(".slice") {
            return format!("{}-{}.scope", cgroups_path.prefix, cgroups_path.name);
        }
        cgroups_path.name.clone()
    }

    // get_cgroups_path generates a cgroups path from the one provided by the user via cgroupsPath.
    // an example of the final path: "/system.slice/youki-569d5ce3afe1074769f67.scope" or if we are
    // not running as root /user.slice/user-1000/user@1000.service/youki-569d5ce3afe1074769f67.scope
    fn construct_cgroups_path(
        cgroups_path: &CgroupsPath,
        client: &dyn SystemdClient,
    ) -> Result<(PathBuf, PathBuf), SystemdManagerError> {
        // if the user provided a '.slice' (as in a branch of a tree)
        // we need to convert it to a filesystem path.

        let parent = Self::expand_slice(&cgroups_path.parent)?;
        let systemd_root = client.control_cgroup_root()?;
        let unit_name = Self::get_unit_name(cgroups_path);

        let cgroups_path = systemd_root.join_safely(parent)?.join_safely(unit_name)?;
        Ok((cgroups_path, systemd_root))
    }

    // systemd represents slice hierarchy using `-`, so we need to follow suit when
    // generating the path of slice. For example, 'test-a-b.slice' becomes
    // '/test.slice/test-a.slice/test-a-b.slice'.
    fn expand_slice(slice: &str) -> Result<PathBuf, SystemdManagerError> {
        let suffix = ".slice";
        if slice.len() <= suffix.len() || !slice.ends_with(suffix) {
            return Err(SystemdManagerError::InvalidSliceName(slice.into()));
        }
        if slice.contains('/') {
            return Err(SystemdManagerError::InvalidSliceName(slice.into()));
        }
        let mut path = "".to_owned();
        let mut prefix = "".to_owned();
        let slice_name = slice.trim_end_matches(suffix);
        // if input was -.slice, we should just return root now
        if slice_name == "-" {
            return Ok(Path::new("/").to_path_buf());
        }
        for component in slice_name.split('-') {
            if component.is_empty() {
                return Err(SystemdManagerError::InvalidSliceName(slice.into()));
            }
            // Append the component to the path and to the prefix.
            path = format!("{path}/{prefix}{component}{suffix}");
            prefix = format!("{prefix}{component}-");
        }
        Ok(Path::new(&path).to_path_buf())
    }

    /// ensures that each level in the downward path from the delegation boundary down to
    /// the scope or slice of the transient unit has all available controllers enabled
    fn ensure_controllers_attached(&self) -> Result<(), SystemdManagerError> {
        let full_boundary_path = self.root_path.join_safely(&self.delegation_boundary)?;

        let controllers: Vec<String> = self
            .get_available_controllers(&full_boundary_path)?
            .into_iter()
            .map(|c| format!("{}{}", "+", c))
            .collect();

        Self::write_controllers(&full_boundary_path, &controllers)?;

        let mut current_path = full_boundary_path;
        let mut components = self
            .cgroups_path
            .strip_prefix(&self.delegation_boundary)
            .map_err(|_| SystemdManagerError::BadDelegationBoundary {
                boundary: self.delegation_boundary.clone(),
                cgroup: self.cgroups_path.clone(),
            })?
            .components()
            .filter(|c| c.ne(&RootDir))
            .peekable();
        // Verify that *each level* in the downward path from the root cgroup
        // down to the cgroup_path provided by the user is a valid cgroup hierarchy.
        // containing the attached controllers.
        while let Some(component) = components.next() {
            current_path = current_path.join(component);
            if !current_path.exists() {
                tracing::warn!(
                    "{:?} does not exist. Resource restrictions might not work correctly",
                    current_path
                );
                return Ok(());
            }

            // last component cannot have subtree_control enabled due to internal process constraint
            // if this were set, writing to the cgroups.procs file will fail with Erno 16 (device or resource busy)
            if components.peek().is_some() {
                Self::write_controllers(&current_path, &controllers)?;
            }
        }

        Ok(())
    }

    fn wait_for_process_in_cgroup(&self, pid: Pid) -> Result<(), SystemdManagerError> {
        let start = Instant::now();
        while start.elapsed() < self.cgroup_wait_timeout_duration {
            // If it fails, it most likely means that the cgroup hasn't been set up yet.
            let result = self.fs_manager.get_all_pids();
            if let Ok(pids) = result {
                if pids.contains(&pid) {
                    tracing::info!("Process {} successfully added to cgroup", pid);
                    return Ok(());
                }
            } else if let Err(e) = result {
                if let V2ManagerError::WrappedIo(ref wrapped_io_error) = e {
                    if !matches!(wrapped_io_error, WrappedIoError::Read { .. }) {
                        return Err(e.into());
                    }
                } else {
                    return Err(e.into());
                }
            }

            std::thread::sleep(Duration::from_millis(20));
        }
        Err(SystemdManagerError::WaitForProcessInCgroupTimeout(
            pid.to_string(),
        ))
    }

    fn get_available_controllers<P: AsRef<Path>>(
        &self,
        cgroups_path: P,
    ) -> Result<Vec<ControllerType>, SystemdManagerError> {
        let controllers_path = self.root_path.join(cgroups_path).join(CGROUP_CONTROLLERS);
        if !controllers_path.exists() {
            return Err(SystemdManagerError::FileNotFound(controllers_path));
        }

        let mut controllers = Vec::new();
        for controller in fs::read_to_string(&controllers_path)
            .wrap_read(controllers_path)?
            .split_whitespace()
        {
            match controller {
                "cpu" => controllers.push(ControllerType::Cpu),
                "memory" => controllers.push(ControllerType::Memory),
                "pids" => controllers.push(ControllerType::Pids),
                _ => continue,
            }
        }

        Ok(controllers)
    }

    fn write_controllers(path: &Path, controllers: &[String]) -> Result<(), SystemdManagerError> {
        for controller in controllers {
            common::write_cgroup_file_str(path.join(CGROUP_SUBTREE_CONTROL), controller)?;
        }

        Ok(())
    }

    pub fn any(self) -> AnyCgroupManager {
        AnyCgroupManager::Systemd(Box::new(self))
    }
}

impl CgroupManager for Manager {
    type Error = SystemdManagerError;

    fn add_task(&self, pid: Pid) -> Result<(), Self::Error> {
        // Dont attach any pid to the cgroup if -1 is specified as a pid
        if pid.as_raw() == -1 {
            return Ok(());
        }
        if self.client.transient_unit_exists(&self.unit_name) {
            tracing::debug!("Transient unit {:?} already exists", self.unit_name);
            self.client
                .add_process_to_unit(&self.unit_name, "", pid.as_raw() as u32)?;
            return Ok(());
        }

        tracing::debug!("Starting {:?}", self.unit_name);
        self.client.start_transient_unit(
            &self.container_name,
            pid.as_raw() as u32,
            &self.destructured_path.parent,
            &self.unit_name,
        )?;

        // There is a chance that the intermediate process ends before systemd gets the dbus message to add it to transit unit.
        self.wait_for_process_in_cgroup(pid)?;

        Ok(())
    }

    fn apply(&self, controller_opt: &ControllerOpt) -> Result<(), Self::Error> {
        let mut properties: HashMap<&str, Variant> = HashMap::new();
        let systemd_version = self.client.systemd_version()?;

        for controller in CONTROLLER_TYPES {
            match controller {
                ControllerType::Cpu => {
                    Cpu::apply(controller_opt, systemd_version, &mut properties)?;
                }

                ControllerType::CpuSet => {
                    CpuSet::apply(controller_opt, systemd_version, &mut properties)?;
                }

                ControllerType::Pids => {
                    Pids::apply(controller_opt, systemd_version, &mut properties)
                        .map_err(SystemdManagerError::Pids)?;
                }
                ControllerType::Memory => {
                    Memory::apply(controller_opt, systemd_version, &mut properties)?;
                }
                ControllerType::Io => {
                    Io::apply(controller_opt, systemd_version, &mut properties)?;
                }
            };
        }

        tracing::debug!("applying properties {:?}", properties);
        Unified::apply(controller_opt, systemd_version, &mut properties)?;

        if !properties.is_empty() {
            self.ensure_controllers_attached()?;
            self.client
                .set_unit_properties(&self.unit_name, &properties)?;
        }

        Ok(())
    }

    fn remove(&self) -> Result<(), Self::Error> {
        tracing::debug!("remove {}", self.unit_name);
        if self.client.transient_unit_exists(&self.unit_name) {
            self.client.stop_transient_unit(&self.unit_name)?;
        }

        Ok(())
    }

    fn freeze(&self, state: FreezerState) -> Result<(), Self::Error> {
        Ok(self.fs_manager.freeze(state)?)
    }

    fn stats(&self) -> Result<Stats, Self::Error> {
        Ok(self.fs_manager.stats()?)
    }

    fn get_all_pids(&self) -> Result<Vec<Pid>, Self::Error> {
        Ok(common::get_all_pids(&self.full_path)?)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};

    use super::*;
    use crate::common::DEFAULT_CGROUP_ROOT;
    use crate::systemd::dbus_native::client::SystemdClient;
    use crate::systemd::dbus_native::serialize::Variant;
    use crate::systemd::dbus_native::utils::SystemdClientError;

    struct TestSystemdClient {}

    impl SystemdClient for TestSystemdClient {
        fn is_system(&self) -> bool {
            true
        }

        fn transient_unit_exists(&self, _: &str) -> bool {
            true
        }

        fn start_transient_unit(
            &self,
            _container_name: &str,
            _pid: u32,
            _parent: &str,
            _unit_name: &str,
        ) -> Result<(), SystemdClientError> {
            Ok(())
        }

        fn stop_transient_unit(&self, _unit_name: &str) -> Result<(), SystemdClientError> {
            Ok(())
        }

        fn set_unit_properties(
            &self,
            _unit_name: &str,
            _properties: &HashMap<&str, Variant>,
        ) -> Result<(), SystemdClientError> {
            Ok(())
        }

        fn systemd_version(&self) -> Result<u32, SystemdClientError> {
            Ok(245)
        }

        fn control_cgroup_root(&self) -> Result<PathBuf, SystemdClientError> {
            Ok(PathBuf::from("/"))
        }

        fn add_process_to_unit(
            &self,
            _unit_name: &str,
            _subcgroup: &str,
            _pid: u32,
        ) -> Result<(), SystemdClientError> {
            Ok(())
        }
    }

    #[test]
    fn expand_slice_works() -> Result<()> {
        assert_eq!(
            Manager::expand_slice("test-a-b.slice")?,
            PathBuf::from("/test.slice/test-a.slice/test-a-b.slice"),
        );

        Ok(())
    }

    #[test]
    fn get_cgroups_path_works_with_a_complex_slice() -> Result<()> {
        let cgroups_path = Path::new("test-a-b.slice:docker:foo")
            .try_into()
            .context("construct path")?;

        assert_eq!(
            Manager::construct_cgroups_path(&cgroups_path, &TestSystemdClient {})?.0,
            PathBuf::from("/test.slice/test-a.slice/test-a-b.slice/docker-foo.scope"),
        );

        Ok(())
    }

    #[test]
    fn get_cgroups_path_works_with_a_simple_slice() -> Result<()> {
        let cgroups_path = Path::new("machine.slice:libpod:foo")
            .try_into()
            .context("construct path")?;

        assert_eq!(
            Manager::construct_cgroups_path(&cgroups_path, &TestSystemdClient {})?.0,
            PathBuf::from("/machine.slice/libpod-foo.scope"),
        );

        Ok(())
    }

    #[test]
    fn get_cgroups_path_works_without_parent() -> Result<()> {
        let mut cgroups_path = Path::new(":docker:foo")
            .try_into()
            .context("construct path")?;
        ensure_parent_unit(&mut cgroups_path, true);

        assert_eq!(
            Manager::construct_cgroups_path(&cgroups_path, &TestSystemdClient {})?.0,
            PathBuf::from("/system.slice/docker-foo.scope"),
        );

        Ok(())
    }

    #[test]
    fn test_task_addition() {
        let manager = Manager::new(
            DEFAULT_CGROUP_ROOT.into(),
            ":youki:test".into(),
            "youki_test_container".into(),
            false,
            PROCESS_IN_CGROUP_TIMEOUT_DURATION,
        )
        .unwrap();
        let mut p1 = std::process::Command::new("sleep")
            .arg("1s")
            .spawn()
            .unwrap();
        let p1_id = nix::unistd::Pid::from_raw(p1.id() as i32);
        let mut p2 = std::process::Command::new("sleep")
            .arg("1s")
            .spawn()
            .unwrap();
        let p2_id = nix::unistd::Pid::from_raw(p2.id() as i32);
        manager.add_task(p1_id).unwrap();
        manager.add_task(p2_id).unwrap();
        let all_pids = manager.get_all_pids().unwrap();
        assert!(all_pids.contains(&p1_id));
        assert!(all_pids.contains(&p2_id));
        // wait till both processes are finished so we can cleanup the cgroup
        let _ = p1.wait();
        let _ = p2.wait();
        manager.remove().unwrap();
        // the remove call above should remove the dir, we just do this again
        // for contingency, and thus ignore the result
        let _ = fs::remove_dir(&manager.full_path);
    }

    #[test]
    fn test_error_thrown_if_process_never_added_to_cgroup() -> Result<()> {
        let manager = Manager::new(
            DEFAULT_CGROUP_ROOT.into(),
            ":youki:test".into(),
            "youki_test_container".into(),
            false,
            Duration::from_secs(1),
        )
        .unwrap();

        // Bogus Pid
        let p1_id = nix::unistd::Pid::from_raw(-1_i32);

        let result = manager.wait_for_process_in_cgroup(p1_id);

        assert!(matches!(
            result,
            Err(SystemdManagerError::WaitForProcessInCgroupTimeout(..))
        ));
        Ok(())
    }
}
