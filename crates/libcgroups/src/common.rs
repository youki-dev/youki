use std::fmt::{Debug, Display};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf, StripPrefixError};
use std::time::Duration;

use nix::sys::statfs::{statfs, CGROUP2_SUPER_MAGIC, TMPFS_MAGIC};
use nix::unistd::Pid;
use oci_spec::runtime::LinuxResources;
#[cfg(any(feature = "cgroupsv2_devices", feature = "v1"))]
use oci_spec::runtime::{
    LinuxDevice, LinuxDeviceBuilder, LinuxDeviceCgroup, LinuxDeviceCgroupBuilder, LinuxDeviceType,
};
use serde::{Deserialize, Serialize};

use super::stats::Stats;
use super::{systemd, v1, v2};

pub const CGROUP_PROCS: &str = "cgroup.procs";
pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[cfg(feature = "systemd")]
#[inline]
fn is_true_root() -> Result<bool, WrappedIoError> {
    if !nix::unistd::geteuid().is_root() {
        return Ok(false);
    }
    let uid_map_path = "/proc/self/uid_map";
    let content = std::fs::read_to_string(uid_map_path).map_err(|e| WrappedIoError::Read {
        err: e,
        path: uid_map_path.into(),
    })?;
    Ok(content.contains("4294967295"))
}
pub trait CgroupManager {
    type Error;

    /// Adds a task specified by its pid to the cgroup
    fn add_task(&self, pid: Pid) -> Result<(), Self::Error>;

    /// Applies resource restrictions to the cgroup
    fn apply(&self, controller_opt: &ControllerOpt) -> Result<(), Self::Error>;

    /// Removes the cgroup
    fn remove(&self) -> Result<(), Self::Error>;

    /// Sets the freezer cgroup to the specified state
    fn freeze(&self, state: FreezerState) -> Result<(), Self::Error>;

    /// Retrieve statistics for the cgroup
    fn stats(&self) -> Result<Stats, Self::Error>;

    /// Gets the PIDs inside the cgroup
    fn get_all_pids(&self) -> Result<Vec<Pid>, Self::Error>;
}

#[derive(thiserror::Error, Debug)]
pub enum AnyManagerError {
    #[error(transparent)]
    Systemd(#[from] systemd::manager::SystemdManagerError),
    #[error(transparent)]
    V1(#[from] v1::manager::V1ManagerError),
    #[error(transparent)]
    V2(#[from] v2::manager::V2ManagerError),
}

// systemd is boxed due to size lint https://rust-lang.github.io/rust-clippy/master/index.html#/large_enum_variant
pub enum AnyCgroupManager {
    Systemd(Box<systemd::manager::Manager>),
    V1(v1::manager::Manager),
    V2(v2::manager::Manager),
}

impl CgroupManager for AnyCgroupManager {
    type Error = AnyManagerError;

    fn add_task(&self, pid: Pid) -> Result<(), Self::Error> {
        match self {
            AnyCgroupManager::Systemd(m) => Ok(m.add_task(pid)?),
            AnyCgroupManager::V1(m) => Ok(m.add_task(pid)?),
            AnyCgroupManager::V2(m) => Ok(m.add_task(pid)?),
        }
    }

    fn apply(&self, controller_opt: &ControllerOpt) -> Result<(), Self::Error> {
        match self {
            AnyCgroupManager::Systemd(m) => Ok(m.apply(controller_opt)?),
            AnyCgroupManager::V1(m) => Ok(m.apply(controller_opt)?),
            AnyCgroupManager::V2(m) => Ok(m.apply(controller_opt)?),
        }
    }

    fn remove(&self) -> Result<(), Self::Error> {
        match self {
            AnyCgroupManager::Systemd(m) => Ok(m.remove()?),
            AnyCgroupManager::V1(m) => Ok(m.remove()?),
            AnyCgroupManager::V2(m) => Ok(m.remove()?),
        }
    }

    fn freeze(&self, state: FreezerState) -> Result<(), Self::Error> {
        match self {
            AnyCgroupManager::Systemd(m) => Ok(m.freeze(state)?),
            AnyCgroupManager::V1(m) => Ok(m.freeze(state)?),
            AnyCgroupManager::V2(m) => Ok(m.freeze(state)?),
        }
    }

    fn stats(&self) -> Result<Stats, Self::Error> {
        match self {
            AnyCgroupManager::Systemd(m) => Ok(m.stats()?),
            AnyCgroupManager::V1(m) => Ok(m.stats()?),
            AnyCgroupManager::V2(m) => Ok(m.stats()?),
        }
    }

    fn get_all_pids(&self) -> Result<Vec<Pid>, Self::Error> {
        match self {
            AnyCgroupManager::Systemd(m) => Ok(m.get_all_pids()?),
            AnyCgroupManager::V1(m) => Ok(m.get_all_pids()?),
            AnyCgroupManager::V2(m) => Ok(m.get_all_pids()?),
        }
    }
}

#[derive(Debug)]
pub enum CgroupSetup {
    Hybrid,
    Legacy,
    Unified,
}

impl Display for CgroupSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let print = match self {
            CgroupSetup::Hybrid => "hybrid",
            CgroupSetup::Legacy => "legacy",
            CgroupSetup::Unified => "unified",
        };

        write!(f, "{print}")
    }
}

/// FreezerState is given freezer controller
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreezerState {
    /// Tasks in cgroup are undefined
    Undefined,
    /// Tasks in cgroup are suspended.
    Frozen,
    /// Tasks in cgroup are resuming.
    Thawed,
}

/// ControllerOpt is given all cgroup controller for applying cgroup configuration.
#[derive(Clone, Debug)]
pub struct ControllerOpt<'a> {
    /// Resources contain cgroup information for handling resource constraints for the container.
    pub resources: &'a LinuxResources,
    /// Disables the OOM killer for out of memory conditions.
    pub disable_oom_killer: bool,
    /// Specify an oom_score_adj for container.
    pub oom_score_adj: Option<i32>,
    /// FreezerState is given to freezer controller for suspending process.
    pub freezer_state: Option<FreezerState>,
}

#[derive(thiserror::Error, Debug)]
pub enum WrappedIoError {
    #[error("failed to open {path}: {err}")]
    Open { err: std::io::Error, path: PathBuf },
    #[error("failed to write {data} to {path}: {err}")]
    Write {
        err: std::io::Error,
        path: PathBuf,
        data: String,
    },
    #[error("failed to read {path}: {err}")]
    Read { err: std::io::Error, path: PathBuf },
    #[error("failed to create dir {path}: {err}")]
    CreateDir { err: std::io::Error, path: PathBuf },
    #[error("at {path}: {err}")]
    Other { err: std::io::Error, path: PathBuf },
}

impl WrappedIoError {
    pub fn inner(&self) -> &std::io::Error {
        match self {
            WrappedIoError::Open { err, .. } => err,
            WrappedIoError::Write { err, .. } => err,
            WrappedIoError::Read { err, .. } => err,
            WrappedIoError::CreateDir { err, .. } => err,
            WrappedIoError::Other { err, .. } => err,
        }
    }
}

#[inline]
pub fn write_cgroup_file_str<P: AsRef<Path>>(path: P, data: &str) -> Result<(), WrappedIoError> {
    let path = path.as_ref();

    fs::OpenOptions::new()
        .create(false)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|err| WrappedIoError::Open {
            err,
            path: path.to_path_buf(),
        })?
        .write_all(data.as_bytes())
        .map_err(|err| WrappedIoError::Write {
            err,
            path: path.to_path_buf(),
            data: data.into(),
        })?;

    Ok(())
}

#[inline]
pub fn write_cgroup_file<P: AsRef<Path>, T: ToString>(
    path: P,
    data: T,
) -> Result<(), WrappedIoError> {
    let path = path.as_ref();
    let data = data.to_string();

    fs::OpenOptions::new()
        .create(false)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|err| WrappedIoError::Open {
            err,
            path: path.to_path_buf(),
        })?
        .write_all(data.as_bytes())
        .map_err(|err| WrappedIoError::Write {
            err,
            path: path.to_path_buf(),
            data,
        })?;

    Ok(())
}

#[inline]
pub fn read_cgroup_file<P: AsRef<Path>>(path: P) -> Result<String, WrappedIoError> {
    let path = path.as_ref();
    fs::read_to_string(path).map_err(|err| WrappedIoError::Read {
        err,
        path: path.to_path_buf(),
    })
}

#[derive(thiserror::Error, Debug)]
pub enum GetCgroupSetupError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("non default cgroup root not supported")]
    NonDefault,
    #[error("failed to detect cgroup setup")]
    FailedToDetect,
}

/// Determines the cgroup setup of the system. Systems typically have one of
/// three setups:
/// - Unified: Pure cgroup v2 system.
/// - Legacy: Pure cgroup v1 system.
/// - Hybrid: Hybrid is basically a cgroup v1 system, except for
///   an additional unified hierarchy which doesn't have any
///   controllers attached. Resource control can purely be achieved
///   through the cgroup v1 hierarchy, not through the cgroup v2 hierarchy.
pub fn get_cgroup_setup_with_root(root_path: &Path) -> Result<CgroupSetup, GetCgroupSetupError> {
    match root_path.exists() {
        true => {
            // If the filesystem is of type cgroup2, the system is in unified mode.
            // If the filesystem is tmpfs instead the system is either in legacy or
            // hybrid mode. If a cgroup2 filesystem has been mounted under the "unified"
            // folder we are in hybrid mode, otherwise we are in legacy mode.
            let stat = statfs(root_path)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
                .wrap_other(root_path)?;
            if stat.filesystem_type() == CGROUP2_SUPER_MAGIC {
                return Ok(CgroupSetup::Unified);
            }

            if stat.filesystem_type() == TMPFS_MAGIC {
                let unified = &Path::new(root_path).join("unified");
                if Path::new(unified).exists() {
                    let stat = statfs(unified)
                        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
                        .wrap_other(unified)?;
                    if stat.filesystem_type() == CGROUP2_SUPER_MAGIC {
                        return Ok(CgroupSetup::Hybrid);
                    }
                }

                return Ok(CgroupSetup::Legacy);
            }
        }
        false => return Err(GetCgroupSetupError::NonDefault),
    }

    Err(GetCgroupSetupError::FailedToDetect)
}

pub fn get_cgroup_setup() -> Result<CgroupSetup, GetCgroupSetupError> {
    get_cgroup_setup_with_root(Path::new(DEFAULT_CGROUP_ROOT))
}

#[derive(thiserror::Error, Debug)]
pub enum CreateCgroupSetupError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("non default cgroup root not supported")]
    NonDefault,
    #[error("failed to detect cgroup setup")]
    FailedToDetect,
    #[error("v1 error: {0}")]
    V1(#[from] v1::manager::V1ManagerError),
    #[error("v2 error: {0}")]
    V2(#[from] v2::manager::V2ManagerError),
    #[error("systemd error: {0}")]
    Systemd(#[from] systemd::manager::SystemdManagerError),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CgroupConfig {
    pub cgroup_path: PathBuf,
    pub systemd_cgroup: bool,
    pub container_name: String,
}

// Create any cgroup manager with customize root path. If root_path provided
// is None, then it defaults to /sys/fs/cgroup.
pub fn create_cgroup_manager_with_root(
    root_path: Option<&Path>,
    config: CgroupConfig,
) -> Result<AnyCgroupManager, CreateCgroupSetupError> {
    let root = match root_path {
        Some(p) => p,
        None => Path::new(DEFAULT_CGROUP_ROOT),
    };

    let cgroup_setup = get_cgroup_setup_with_root(root).map_err(|err| match err {
        GetCgroupSetupError::WrappedIo(err) => CreateCgroupSetupError::WrappedIo(err),
        GetCgroupSetupError::NonDefault => CreateCgroupSetupError::NonDefault,
        GetCgroupSetupError::FailedToDetect => CreateCgroupSetupError::FailedToDetect,
    })?;
    let cgroup_path = config.cgroup_path.as_path();

    match cgroup_setup {
        CgroupSetup::Legacy | CgroupSetup::Hybrid => {
            Ok(create_v1_cgroup_manager(cgroup_path)?.any())
        }
        CgroupSetup::Unified => {
            // ref https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#cgroups-path
            if cgroup_path.is_absolute() || !config.systemd_cgroup {
                return Ok(create_v2_cgroup_manager(root, cgroup_path)?.any());
            }
            Ok(
                create_systemd_cgroup_manager(root, cgroup_path, config.container_name.as_str())?
                    .any(),
            )
        }
    }
}

pub fn create_cgroup_manager(
    config: CgroupConfig,
) -> Result<AnyCgroupManager, CreateCgroupSetupError> {
    create_cgroup_manager_with_root(Some(Path::new(DEFAULT_CGROUP_ROOT)), config)
}

#[cfg(feature = "v1")]
fn create_v1_cgroup_manager(
    cgroup_path: &Path,
) -> Result<v1::manager::Manager, v1::manager::V1ManagerError> {
    tracing::info!("cgroup manager V1 will be used");
    v1::manager::Manager::new(cgroup_path)
}

#[cfg(not(feature = "v1"))]
fn create_v1_cgroup_manager(
    _cgroup_path: &Path,
) -> Result<v1::manager::Manager, v1::manager::V1ManagerError> {
    Err(v1::manager::V1ManagerError::NotEnabled)
}

#[cfg(feature = "v2")]
fn create_v2_cgroup_manager(
    root_path: &Path,
    cgroup_path: &Path,
) -> Result<v2::manager::Manager, v2::manager::V2ManagerError> {
    tracing::info!("cgroup manager V2 will be used");
    v2::manager::Manager::new(root_path.to_path_buf(), cgroup_path.to_owned())
}

#[cfg(not(feature = "v2"))]
fn create_v2_cgroup_manager(
    _root_path: &Path,
    _cgroup_path: &Path,
) -> Result<v2::manager::Manager, v2::manager::V2ManagerError> {
    Err(v2::manager::V2ManagerError::NotEnabled)
}

#[cfg(feature = "systemd")]
fn create_systemd_cgroup_manager(
    root_path: &Path,
    cgroup_path: &Path,
    container_name: &str,
) -> Result<systemd::manager::Manager, systemd::manager::SystemdManagerError> {
    if !systemd::booted() {
        panic!(
            "systemd cgroup flag passed, but systemd support for managing cgroups is not available"
        );
    }

    let use_system = is_true_root().map_err(systemd::manager::SystemdManagerError::WrappedIo)?;

    tracing::info!(
        "systemd cgroup manager with system bus {} will be used",
        use_system
    );
    systemd::manager::Manager::new(
        root_path.into(),
        cgroup_path.to_owned(),
        container_name.into(),
        use_system,
    )
}

#[cfg(not(feature = "systemd"))]
fn create_systemd_cgroup_manager(
    _root_path: &Path,
    _cgroup_path: &Path,
    _container_name: &str,
) -> Result<systemd::manager::Manager, systemd::manager::SystemdManagerError> {
    Err(systemd::manager::SystemdManagerError::NotEnabled)
}

pub fn get_all_pids(path: &Path) -> Result<Vec<Pid>, WrappedIoError> {
    tracing::debug!("scan pids in folder: {:?}", path);
    let mut result = vec![];
    walk_dir(path, &mut |p| {
        let file_path = p.join(CGROUP_PROCS);
        if file_path.exists() {
            let file = File::open(&file_path).wrap_open(&file_path)?;
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                result.push(Pid::from_raw(
                    line.parse::<i32>()
                        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
                        .wrap_other(&file_path)?,
                ))
            }
        }
        Ok::<(), WrappedIoError>(())
    })?;
    Ok(result)
}

fn walk_dir<F, E>(path: &Path, c: &mut F) -> Result<(), E>
where
    F: FnMut(&Path) -> Result<(), E>,
    E: From<WrappedIoError>,
{
    c(path)?;
    for entry in fs::read_dir(path).wrap_read(path)? {
        let entry = entry.wrap_open(path)?;
        let path = entry.path();

        if path.is_dir() {
            walk_dir(&path, c)?;
        }
    }
    Ok(())
}

pub(crate) trait PathBufExt {
    fn join_safely<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, JoinSafelyError>;
}

#[derive(thiserror::Error, Debug)]
pub enum JoinSafelyError {
    #[error("failed to strip prefix from {path}: {err}")]
    StripPrefix {
        err: StripPrefixError,
        path: PathBuf,
    },
}

impl PathBufExt for PathBuf {
    fn join_safely<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, JoinSafelyError> {
        let path = path.as_ref();
        if path.is_relative() {
            return Ok(self.join(path));
        }

        let stripped = path
            .strip_prefix("/")
            .map_err(|err| JoinSafelyError::StripPrefix {
                err,
                path: path.to_path_buf(),
            })?;
        Ok(self.join(stripped))
    }
}

#[cfg(any(feature = "cgroupsv2_devices", feature = "v1"))]
pub(crate) fn default_allow_devices() -> Vec<LinuxDeviceCgroup> {
    vec![
        LinuxDeviceCgroupBuilder::default()
            .allow(true)
            .typ(LinuxDeviceType::C)
            .access("m")
            .build()
            .unwrap(),
        LinuxDeviceCgroupBuilder::default()
            .allow(true)
            .typ(LinuxDeviceType::B)
            .access("m")
            .build()
            .unwrap(),
        // /dev/console
        LinuxDeviceCgroupBuilder::default()
            .allow(true)
            .typ(LinuxDeviceType::C)
            .major(5)
            .minor(1)
            .access("rwm")
            .build()
            .unwrap(),
        // /dev/pts
        LinuxDeviceCgroupBuilder::default()
            .allow(true)
            .typ(LinuxDeviceType::C)
            .major(136)
            .access("rwm")
            .build()
            .unwrap(),
        LinuxDeviceCgroupBuilder::default()
            .allow(true)
            .typ(LinuxDeviceType::C)
            .major(5)
            .minor(2)
            .access("rwm")
            .build()
            .unwrap(),
        // tun/tap
        LinuxDeviceCgroupBuilder::default()
            .allow(true)
            .typ(LinuxDeviceType::C)
            .major(10)
            .minor(200)
            .access("rwm")
            .build()
            .unwrap(),
    ]
}

#[cfg(any(feature = "cgroupsv2_devices", feature = "v1"))]
pub(crate) fn default_devices() -> Vec<LinuxDevice> {
    vec![
        LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/null"))
            .typ(LinuxDeviceType::C)
            .major(1)
            .minor(3)
            .file_mode(0o066u32)
            .build()
            .unwrap(),
        LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/zero"))
            .typ(LinuxDeviceType::C)
            .major(1)
            .minor(5)
            .file_mode(0o066u32)
            .build()
            .unwrap(),
        LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/full"))
            .typ(LinuxDeviceType::C)
            .major(1)
            .minor(7)
            .file_mode(0o066u32)
            .build()
            .unwrap(),
        LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/tty"))
            .typ(LinuxDeviceType::C)
            .major(5)
            .minor(0)
            .file_mode(0o066u32)
            .build()
            .unwrap(),
        LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/urandom"))
            .typ(LinuxDeviceType::C)
            .major(1)
            .minor(9)
            .file_mode(0o066u32)
            .build()
            .unwrap(),
        LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/random"))
            .typ(LinuxDeviceType::C)
            .major(1)
            .minor(8)
            .file_mode(0o066u32)
            .build()
            .unwrap(),
    ]
}

/// Attempts to delete the path the requested number of times.
pub(crate) fn delete_with_retry<P: AsRef<Path>, L: Into<Option<Duration>>>(
    path: P,
    retries: u32,
    limit_backoff: L,
) -> Result<(), WrappedIoError> {
    let mut attempts = 0;
    let mut delay = Duration::from_millis(10);
    let path = path.as_ref();
    let limit = limit_backoff.into().unwrap_or(Duration::MAX);

    while attempts < retries {
        if fs::remove_dir(path).is_ok() {
            return Ok(());
        }

        std::thread::sleep(delay);
        attempts += 1;
        delay *= attempts;
        if delay > limit {
            delay = limit;
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "could not delete".to_string(),
    ))
    .wrap_other(path)?
}

pub(crate) trait WrapIoResult {
    type Target;

    fn wrap_create_dir<P: Into<PathBuf>>(self, path: P) -> Result<Self::Target, WrappedIoError>;
    fn wrap_read<P: Into<PathBuf>>(self, path: P) -> Result<Self::Target, WrappedIoError>;
    fn wrap_open<P: Into<PathBuf>>(self, path: P) -> Result<Self::Target, WrappedIoError>;
    fn wrap_write<P: Into<PathBuf>, D: Into<String>>(
        self,
        path: P,
        data: D,
    ) -> Result<Self::Target, WrappedIoError>;
    fn wrap_other<P: Into<PathBuf>>(self, path: P) -> Result<Self::Target, WrappedIoError>;
}

impl<T> WrapIoResult for Result<T, std::io::Error> {
    type Target = T;

    fn wrap_create_dir<P: Into<PathBuf>>(self, path: P) -> Result<Self::Target, WrappedIoError> {
        self.map_err(|err| WrappedIoError::CreateDir {
            err,
            path: path.into(),
        })
    }

    fn wrap_read<P: Into<PathBuf>>(self, path: P) -> Result<Self::Target, WrappedIoError> {
        self.map_err(|err| WrappedIoError::Read {
            err,
            path: path.into(),
        })
    }

    fn wrap_open<P: Into<PathBuf>>(self, path: P) -> Result<Self::Target, WrappedIoError> {
        self.map_err(|err| WrappedIoError::Open {
            err,
            path: path.into(),
        })
    }

    fn wrap_write<P: Into<PathBuf>, D: Into<String>>(
        self,
        path: P,
        data: D,
    ) -> Result<Self::Target, WrappedIoError> {
        self.map_err(|err| WrappedIoError::Write {
            err,
            path: path.into(),
            data: data.into(),
        })
    }

    fn wrap_other<P: Into<PathBuf>>(self, path: P) -> Result<Self::Target, WrappedIoError> {
        self.map_err(|err| WrappedIoError::Other {
            err,
            path: path.into(),
        })
    }
}

#[derive(Debug)]
pub enum EitherError<L, R> {
    Left(L),
    Right(R),
}

impl<L: Display, R: Display> Display for EitherError<L, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EitherError::Left(left) => <L as Display>::fmt(left, f),
            EitherError::Right(right) => <R as Display>::fmt(right, f),
        }
    }
}

impl<L: Debug + Display, R: Debug + Display> std::error::Error for EitherError<L, R> {}

#[derive(Debug)]
pub struct MustBePowerOfTwo;

impl Display for MustBePowerOfTwo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("page size must be in the format of 2^(integer)")
    }
}
