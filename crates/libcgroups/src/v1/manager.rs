use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::unistd::Pid;
use procfs::ProcError;
use procfs::process::Process;

use super::blkio::{Blkio, V1BlkioStatsError};
use super::controller::Controller;
use super::controller_type::CONTROLLERS;
use super::cpu::{Cpu, V1CpuStatsError};
use super::cpuacct::{CpuAcct, V1CpuAcctStatsError};
use super::cpuset::{CpuSet, V1CpuSetControllerError};
use super::devices::Devices;
use super::freezer::{Freezer, V1FreezerControllerError};
use super::hugetlb::{HugeTlb, V1HugeTlbControllerError, V1HugeTlbStatsError};
use super::memory::{Memory, V1MemoryControllerError, V1MemoryStatsError};
use super::network_classifier::NetworkClassifier;
use super::network_priority::NetworkPriority;
use super::perf_event::PerfEvent;
use super::pids::Pids;
use super::util::V1MountPointError;
use super::{ControllerType as CtrlType, util};
use crate::common::{
    self, AnyCgroupManager, CGROUP_PROCS, CgroupManager, ControllerOpt, FreezerState,
    JoinSafelyError, PathBufExt, WrapIoResult, WrappedIoError,
};
use crate::stats::{PidStatsError, Stats, StatsProvider};

pub struct Manager {
    subsystems: HashMap<CtrlType, PathBuf>,
}

#[derive(thiserror::Error, Debug)]
pub enum V1ManagerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("mount point error: {0}")]
    MountPoint(#[from] V1MountPointError),
    #[error("proc error: {0}")]
    Proc(#[from] ProcError),
    #[error("while joining paths: {0}")]
    JoinSafely(#[from] JoinSafelyError),
    #[error("cgroup {0} is required to fulfill the request, but is not supported by this system")]
    CGroupRequired(CtrlType),
    #[error("subsystem does not exist")]
    SubsystemDoesNotExist,

    #[error(transparent)]
    BlkioController(WrappedIoError),
    #[error(transparent)]
    CpuController(WrappedIoError),
    #[error(transparent)]
    CpuAcctController(WrappedIoError),
    #[error(transparent)]
    CpuSetController(#[from] V1CpuSetControllerError),
    #[error(transparent)]
    FreezerController(#[from] V1FreezerControllerError),
    #[error(transparent)]
    HugeTlbController(#[from] V1HugeTlbControllerError),
    #[error(transparent)]
    MemoryController(#[from] V1MemoryControllerError),
    #[error(transparent)]
    PidsController(WrappedIoError),

    #[error(transparent)]
    BlkioStats(#[from] V1BlkioStatsError),
    #[error(transparent)]
    CpuStats(#[from] V1CpuStatsError),
    #[error(transparent)]
    CpuAcctStats(#[from] V1CpuAcctStatsError),
    #[error(transparent)]
    PidsStats(#[from] PidStatsError),
    #[error(transparent)]
    HugeTlbStats(#[from] V1HugeTlbStatsError),
    #[error(transparent)]
    MemoryStats(#[from] V1MemoryStatsError),
}

impl Manager {
    /// Constructs a new cgroup manager with cgroups_path being relative to the root of the subsystem
    pub fn new(cgroup_path: &Path) -> Result<Self, V1ManagerError> {
        let mut subsystems = HashMap::new();
        for subsystem in CONTROLLERS {
            if let Ok(subsystem_path) = Self::get_subsystem_path(cgroup_path, subsystem) {
                subsystems.insert(*subsystem, subsystem_path);
            } else {
                tracing::warn!("cgroup {} not supported on this system", subsystem);
            }
        }

        Ok(Manager { subsystems })
    }

    fn get_subsystem_path(
        cgroup_path: &Path,
        subsystem: &CtrlType,
    ) -> Result<PathBuf, V1ManagerError> {
        tracing::debug!("Get path for subsystem: {}", subsystem);
        let mount_point = util::get_subsystem_mount_point(subsystem)?;

        let cgroup = Process::myself()?
            .cgroups()?
            .into_iter()
            .find(|c| c.controllers.contains(&subsystem.to_string()))
            .ok_or(V1ManagerError::SubsystemDoesNotExist)?;

        let p = if cgroup_path.as_os_str().is_empty() {
            mount_point.join_safely(Path::new(&cgroup.pathname))?
        } else {
            mount_point.join_safely(cgroup_path)?
        };

        Ok(p)
    }

    fn get_required_controllers(
        &self,
        controller_opt: &ControllerOpt,
    ) -> Result<HashMap<&CtrlType, &PathBuf>, V1ManagerError> {
        let mut required_controllers = HashMap::new();

        for controller in CONTROLLERS {
            let required = match controller {
                CtrlType::Cpu => Cpu::needs_to_handle(controller_opt).is_some(),
                CtrlType::CpuAcct => CpuAcct::needs_to_handle(controller_opt).is_some(),
                CtrlType::CpuSet => CpuSet::needs_to_handle(controller_opt).is_some(),
                CtrlType::Devices => Devices::needs_to_handle(controller_opt).is_some(),
                CtrlType::HugeTlb => HugeTlb::needs_to_handle(controller_opt).is_some(),
                CtrlType::Memory => Memory::needs_to_handle(controller_opt).is_some(),
                CtrlType::Pids => Pids::needs_to_handle(controller_opt).is_some(),
                CtrlType::PerfEvent => PerfEvent::needs_to_handle(controller_opt).is_some(),
                CtrlType::Blkio => Blkio::needs_to_handle(controller_opt).is_some(),
                CtrlType::NetworkPriority => {
                    NetworkPriority::needs_to_handle(controller_opt).is_some()
                }
                CtrlType::NetworkClassifier => {
                    NetworkClassifier::needs_to_handle(controller_opt).is_some()
                }
                CtrlType::Freezer => Freezer::needs_to_handle(controller_opt).is_some(),
            };

            if required {
                if let Some(subsystem_path) = self.subsystems.get(controller) {
                    required_controllers.insert(controller, subsystem_path);
                } else {
                    return Err(V1ManagerError::CGroupRequired(*controller));
                }
            }
        }

        Ok(required_controllers)
    }

    pub fn any(self) -> AnyCgroupManager {
        AnyCgroupManager::V1(self)
    }
}

impl CgroupManager for Manager {
    type Error = V1ManagerError;

    fn get_all_pids(&self) -> Result<Vec<Pid>, Self::Error> {
        let devices = self.subsystems.get(&CtrlType::Devices);
        if let Some(p) = devices {
            Ok(common::get_all_pids(p)?)
        } else {
            Err(V1ManagerError::SubsystemDoesNotExist)
        }
    }

    fn add_task(&self, pid: Pid) -> Result<(), Self::Error> {
        for (ctrl_type, cgroup_path) in &self.subsystems {
            match ctrl_type {
                CtrlType::Cpu => Cpu::add_task(pid, cgroup_path)?,
                CtrlType::CpuAcct => CpuAcct::add_task(pid, cgroup_path)?,
                CtrlType::CpuSet => CpuSet::add_task(pid, cgroup_path)?,
                CtrlType::Devices => Devices::add_task(pid, cgroup_path)?,
                CtrlType::HugeTlb => HugeTlb::add_task(pid, cgroup_path)?,
                CtrlType::Memory => Memory::add_task(pid, cgroup_path)?,
                CtrlType::Pids => Pids::add_task(pid, cgroup_path)?,
                CtrlType::PerfEvent => PerfEvent::add_task(pid, cgroup_path)?,
                CtrlType::Blkio => Blkio::add_task(pid, cgroup_path)?,
                CtrlType::NetworkPriority => NetworkPriority::add_task(pid, cgroup_path)?,
                CtrlType::NetworkClassifier => NetworkClassifier::add_task(pid, cgroup_path)?,
                CtrlType::Freezer => Freezer::add_task(pid, cgroup_path)?,
            }
        }

        Ok(())
    }

    fn apply(&self, controller_opt: &ControllerOpt) -> Result<(), Self::Error> {
        for (ctrl_type, cgroup_path) in self.get_required_controllers(controller_opt)? {
            match ctrl_type {
                CtrlType::Cpu => Cpu::apply(controller_opt, cgroup_path)?,
                CtrlType::CpuAcct => CpuAcct::apply(controller_opt, cgroup_path)?,
                CtrlType::CpuSet => CpuSet::apply(controller_opt, cgroup_path)?,
                CtrlType::Devices => Devices::apply(controller_opt, cgroup_path)?,
                CtrlType::HugeTlb => HugeTlb::apply(controller_opt, cgroup_path)?,
                CtrlType::Memory => Memory::apply(controller_opt, cgroup_path)?,
                CtrlType::Pids => Pids::apply(controller_opt, cgroup_path)?,
                CtrlType::PerfEvent => PerfEvent::apply(controller_opt, cgroup_path)?,
                CtrlType::Blkio => Blkio::apply(controller_opt, cgroup_path)?,
                CtrlType::NetworkPriority => NetworkPriority::apply(controller_opt, cgroup_path)?,
                CtrlType::NetworkClassifier => {
                    NetworkClassifier::apply(controller_opt, cgroup_path)?
                }
                CtrlType::Freezer => Freezer::apply(controller_opt, cgroup_path)?,
            }
        }

        Ok(())
    }

    fn remove(&self) -> Result<(), Self::Error> {
        for cgroup_path in self.subsystems.values() {
            if cgroup_path.exists() {
                tracing::debug!("remove cgroup {:?}", cgroup_path);
                let procs_path = cgroup_path.join(CGROUP_PROCS);
                let procs = fs::read_to_string(&procs_path).wrap_read(&procs_path)?;

                for line in procs.lines() {
                    let pid: i32 = line
                        .parse()
                        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
                        .wrap_other(&procs_path)?;
                    let _ = nix::sys::signal::kill(Pid::from_raw(pid), nix::sys::signal::SIGKILL);
                }

                common::delete_with_retry(cgroup_path, 4, Duration::from_millis(100))?;
            }
        }

        Ok(())
    }

    fn freeze(&self, state: FreezerState) -> Result<(), Self::Error> {
        let controller_opt = ControllerOpt {
            resources: &Default::default(),
            freezer_state: Some(state),
            oom_score_adj: None,
            disable_oom_killer: false,
        };
        Ok(Freezer::apply(
            &controller_opt,
            self.subsystems
                .get(&CtrlType::Freezer)
                .ok_or(V1ManagerError::SubsystemDoesNotExist)?,
        )?)
    }

    fn stats(&self) -> Result<Stats, Self::Error> {
        let mut stats = Stats::default();

        for (ctrl_type, cgroup_path) in &self.subsystems {
            match ctrl_type {
                CtrlType::Cpu => stats.cpu.throttling = Cpu::stats(cgroup_path)?,
                CtrlType::CpuAcct => stats.cpu.usage = CpuAcct::stats(cgroup_path)?,
                CtrlType::Pids => stats.pids = Pids::stats(cgroup_path)?,
                CtrlType::HugeTlb => stats.hugetlb = HugeTlb::stats(cgroup_path)?,
                CtrlType::Blkio => stats.blkio = Blkio::stats(cgroup_path)?,
                CtrlType::Memory => stats.memory = Memory::stats(cgroup_path)?,
                _ => continue,
            }
        }

        Ok(stats)
    }
}
