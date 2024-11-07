use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::BufReader;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str::FromStr;

use caps::Capability;
use nix::fcntl::OFlag;
use nix::unistd::{pipe2, read, Pid};
use oci_spec::runtime::{
    Capabilities as SpecCapabilities, Capability as SpecCapability, LinuxBuilder,
    LinuxCapabilities, LinuxCapabilitiesBuilder, LinuxNamespace, LinuxNamespaceBuilder,
    LinuxNamespaceType, LinuxSchedulerPolicy, Process, ProcessBuilder, Spec,
};
use procfs::process::Namespace;

use super::builder::ContainerBuilder;
use super::Container;
use crate::capabilities::CapabilityExt;
use crate::container::builder_impl::ContainerBuilderImpl;
use crate::error::{ErrInvalidSpec, LibcontainerError, MissingSpecError};
use crate::notify_socket::NotifySocket;
use crate::process::args::ContainerType;
use crate::user_ns::UserNamespaceConfig;
use crate::{tty, utils};

const NAMESPACE_TYPES: &[&str] = &["ipc", "uts", "net", "pid", "mnt", "cgroup"];
const TENANT_NOTIFY: &str = "tenant-notify-";
const TENANT_TTY: &str = "tenant-tty-";

/// Builder that can be used to configure the properties of a process
/// that will join an existing container sandbox
pub struct TenantContainerBuilder {
    base: ContainerBuilder,
    env: HashMap<String, String>,
    cwd: Option<PathBuf>,
    args: Vec<String>,
    no_new_privs: Option<bool>,
    capabilities: Vec<String>,
    process: Option<PathBuf>,
    detached: bool,
}

impl TenantContainerBuilder {
    /// Generates the base configuration for a process that will join
    /// an existing container sandbox from which configuration methods
    /// can be chained
    pub(super) fn new(builder: ContainerBuilder) -> Self {
        Self {
            base: builder,
            env: HashMap::new(),
            cwd: None,
            args: Vec::new(),
            no_new_privs: None,
            capabilities: Vec::new(),
            process: None,
            detached: false,
        }
    }

    /// Sets environment variables for the container
    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// Sets the working directory of the container
    pub fn with_cwd<P: Into<PathBuf>>(mut self, path: Option<P>) -> Self {
        self.cwd = path.map(|p| p.into());
        self
    }

    /// Sets the command the container will be started with
    pub fn with_container_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_no_new_privs(mut self, no_new_privs: bool) -> Self {
        self.no_new_privs = Some(no_new_privs);
        self
    }

    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn with_process<P: Into<PathBuf>>(mut self, path: Option<P>) -> Self {
        self.process = path.map(|p| p.into());
        self
    }

    pub fn with_detach(mut self, detached: bool) -> Self {
        self.detached = detached;
        self
    }

    /// Joins an existing container
    pub fn build(self) -> Result<Pid, LibcontainerError> {
        let container_dir = self.lookup_container_dir()?;
        let container = self.load_container_state(container_dir.clone())?;
        let mut spec = self.load_init_spec(&container)?;
        self.adapt_spec_for_tenant(&mut spec, &container)?;

        tracing::debug!("{:#?}", spec);

        let notify_path = Self::setup_notify_listener(&container_dir)?;
        // convert path of root file system of the container to absolute path
        let rootfs = fs::canonicalize(spec.root().as_ref().ok_or(MissingSpecError::Root)?.path())
            .map_err(LibcontainerError::OtherIO)?;

        // if socket file path is given in commandline options,
        // get file descriptors of console socket
        let csocketfd = self.setup_tty_socket(&container_dir)?;

        let use_systemd = self.should_use_systemd(&container);
        let user_ns_config = UserNamespaceConfig::new(&spec)?;

        let (read_end, write_end) =
            pipe2(OFlag::O_CLOEXEC).map_err(LibcontainerError::OtherSyscall)?;

        let mut builder_impl = ContainerBuilderImpl {
            container_type: ContainerType::TenantContainer {
                exec_notify_fd: write_end.as_raw_fd(),
            },
            syscall: self.base.syscall,
            container_id: self.base.container_id,
            pid_file: self.base.pid_file,
            console_socket: csocketfd,
            use_systemd,
            spec: Rc::new(spec),
            rootfs,
            user_ns_config,
            notify_path: notify_path.clone(),
            container: None,
            preserve_fds: self.base.preserve_fds,
            detached: self.detached,
            executor: self.base.executor,
            no_pivot: false,
        };

        let pid = builder_impl.create()?;

        let mut notify_socket = NotifySocket::new(notify_path);
        notify_socket.notify_container_start()?;

        // Explicitly close the write end of the pipe here to notify the
        // `read_end` that the init process is able to move forward. Closing one
        // end of the pipe will immediately signal the other end of the pipe,
        // which we use in the init thread as a form of barrier.  `drop` is used
        // here because `OwnedFd` supports it, so we don't have to use `close`
        // here with `RawFd`.
        drop(write_end);

        let mut err_str_buf = Vec::new();

        loop {
            let mut buf = [0; 3];
            match read(read_end.as_raw_fd(), &mut buf).map_err(LibcontainerError::OtherSyscall)? {
                0 => {
                    if err_str_buf.is_empty() {
                        return Ok(pid);
                    } else {
                        return Err(LibcontainerError::Other(
                            String::from_utf8_lossy(&err_str_buf).to_string(),
                        ));
                    }
                }
                _ => {
                    err_str_buf.extend(buf);
                }
            }
        }
    }

    fn lookup_container_dir(&self) -> Result<PathBuf, LibcontainerError> {
        let container_dir = self.base.root_path.join(&self.base.container_id);
        if !container_dir.exists() {
            tracing::error!(?container_dir, ?self.base.container_id, "container dir does not exist");
            return Err(LibcontainerError::NoDirectory);
        }

        Ok(container_dir)
    }

    fn load_init_spec(&self, container: &Container) -> Result<Spec, LibcontainerError> {
        let spec_path = container.bundle().join("config.json");

        let mut spec = Spec::load(&spec_path).map_err(|err| {
            tracing::error!(path = ?spec_path, ?err, "failed to load spec");
            err
        })?;

        Self::validate_spec(&spec)?;

        spec.canonicalize_rootfs(container.bundle())?;
        Ok(spec)
    }

    fn validate_spec(spec: &Spec) -> Result<(), LibcontainerError> {
        let version = spec.version();
        if !version.starts_with("1.") {
            tracing::error!(
                "runtime spec has incompatible version '{}'. Only 1.X.Y is supported",
                spec.version()
            );
            Err(ErrInvalidSpec::UnsupportedVersion)?;
        }

        if let Some(process) = spec.process() {
            if let Some(io_priority) = process.io_priority() {
                let priority = io_priority.priority();
                let iop_class_res = serde_json::to_string(&io_priority.class());
                match iop_class_res {
                    Ok(iop_class) => {
                        if !(0..=7).contains(&priority) {
                            tracing::error!(?priority, "io priority '{}' not between 0 and 7 (inclusive), class '{}' not in (IO_PRIO_CLASS_RT,IO_PRIO_CLASS_BE,IO_PRIO_CLASS_IDLE)",priority, iop_class);
                            Err(ErrInvalidSpec::IoPriority)?;
                        }
                    }
                    Err(e) => {
                        tracing::error!(?priority, ?e, "failed to parse io priority class");
                        Err(ErrInvalidSpec::IoPriority)?;
                    }
                }
            }

            if let Some(sc) = process.scheduler() {
                let policy = sc.policy();
                if let Some(nice) = sc.nice() {
                    // https://man7.org/linux/man-pages/man2/sched_setattr.2.html#top_of_page
                    if (*policy == LinuxSchedulerPolicy::SchedBatch
                        || *policy == LinuxSchedulerPolicy::SchedOther)
                        && (*nice < -20 || *nice > 19)
                    {
                        tracing::error!(
                            ?nice,
                            "invalid scheduler.nice: '{}', must be within -20 to 19",
                            nice
                        );
                        Err(ErrInvalidSpec::Scheduler)?;
                    }
                }
                if let Some(priority) = sc.priority() {
                    if *priority != 0
                        && (*policy != LinuxSchedulerPolicy::SchedFifo
                            && *policy != LinuxSchedulerPolicy::SchedRr)
                    {
                        tracing::error!(?policy,"scheduler.priority can only be specified for SchedFIFO or SchedRR policy");
                        Err(ErrInvalidSpec::Scheduler)?;
                    }
                }
                if *policy != LinuxSchedulerPolicy::SchedDeadline {
                    if let Some(runtime) = sc.runtime() {
                        if *runtime != 0 {
                            tracing::error!(
                                ?runtime,
                                "scheduler runtime can only be specified for SchedDeadline policy"
                            );
                            Err(ErrInvalidSpec::Scheduler)?;
                        }
                    }
                    if let Some(deadline) = sc.deadline() {
                        if *deadline != 0 {
                            tracing::error!(
                                ?deadline,
                                "scheduler deadline can only be specified for SchedDeadline policy"
                            );
                            Err(ErrInvalidSpec::Scheduler)?;
                        }
                    }
                    if let Some(period) = sc.period() {
                        if *period != 0 {
                            tracing::error!(
                                ?period,
                                "scheduler period can only be specified for SchedDeadline policy"
                            );
                            Err(ErrInvalidSpec::Scheduler)?;
                        }
                    }
                }
            }
        }

        utils::validate_spec_for_new_user_ns(spec)?;

        Ok(())
    }

    fn load_container_state(&self, container_dir: PathBuf) -> Result<Container, LibcontainerError> {
        let container = Container::load(container_dir)?;
        if !container.can_exec() {
            tracing::error!(status = ?container.status(), "cannot exec as container");
            return Err(LibcontainerError::IncorrectStatus);
        }

        Ok(container)
    }

    fn adapt_spec_for_tenant(
        &self,
        spec: &mut Spec,
        container: &Container,
    ) -> Result<(), LibcontainerError> {
        let process = if let Some(process) = &self.process {
            self.get_process(process)?
        } else {
            let mut process_builder = ProcessBuilder::default()
                .args(self.get_args()?)
                .env(self.get_environment());
            if let Some(cwd) = self.get_working_dir()? {
                process_builder = process_builder.cwd(cwd);
            }

            if let Some(no_new_priv) = self.get_no_new_privileges() {
                process_builder = process_builder.no_new_privileges(no_new_priv);
            }

            if let Some(caps) = self.get_capabilities(spec)? {
                process_builder = process_builder.capabilities(caps);
            }

            process_builder.build()?
        };

        let container_pid = container.pid().ok_or(LibcontainerError::Other(
            "could not retrieve container init pid".into(),
        ))?;

        let init_process = procfs::process::Process::new(container_pid.as_raw())?;
        let ns = self.get_namespaces(init_process.namespaces()?.0)?;

        // it should never be the case that linux is not present in spec
        let spec_linux = spec.linux().as_ref().unwrap();
        let mut linux_builder = LinuxBuilder::default().namespaces(ns);

        if let Some(ref cgroup_path) = spec_linux.cgroups_path() {
            linux_builder = linux_builder.cgroups_path(cgroup_path.clone());
        }
        let linux = linux_builder.build()?;
        spec.set_process(Some(process)).set_linux(Some(linux));

        Ok(())
    }

    fn get_process(&self, process: &Path) -> Result<Process, LibcontainerError> {
        if !process.exists() {
            tracing::error!(?process, "process.json file does not exist");
            return Err(LibcontainerError::Other(
                "process.json file does not exist".into(),
            ));
        }

        let process = utils::open(process).map_err(LibcontainerError::OtherIO)?;
        let reader = BufReader::new(process);
        let process_spec =
            serde_json::from_reader(reader).map_err(LibcontainerError::OtherSerialization)?;
        Ok(process_spec)
    }

    fn get_working_dir(&self) -> Result<Option<PathBuf>, LibcontainerError> {
        if let Some(cwd) = &self.cwd {
            if cwd.is_relative() {
                tracing::error!(?cwd, "current working directory must be an absolute path");
                return Err(LibcontainerError::Other(
                    "current working directory must be an absolute path".into(),
                ));
            }
            return Ok(Some(cwd.into()));
        }
        Ok(None)
    }

    fn get_args(&self) -> Result<Vec<String>, LibcontainerError> {
        if self.args.is_empty() {
            Err(MissingSpecError::Args)?;
        }

        Ok(self.args.clone())
    }

    fn get_environment(&self) -> Vec<String> {
        self.env.iter().map(|(k, v)| format!("{k}={v}")).collect()
    }

    fn get_no_new_privileges(&self) -> Option<bool> {
        self.no_new_privs
    }

    fn get_capabilities(
        &self,
        spec: &Spec,
    ) -> Result<Option<LinuxCapabilities>, LibcontainerError> {
        if !self.capabilities.is_empty() {
            let mut caps: Vec<Capability> = Vec::with_capacity(self.capabilities.len());
            for cap in &self.capabilities {
                caps.push(Capability::from_str(cap)?);
            }

            let caps: SpecCapabilities =
                caps.iter().map(|c| SpecCapability::from_cap(*c)).collect();

            if let Some(spec_caps) = spec
                .process()
                .as_ref()
                .ok_or(MissingSpecError::Process)?
                .capabilities()
            {
                let mut capabilities_builder = LinuxCapabilitiesBuilder::default();
                capabilities_builder = match spec_caps.ambient() {
                    Some(ambient) => {
                        let ambient: SpecCapabilities = ambient.union(&caps).copied().collect();
                        capabilities_builder.ambient(ambient)
                    }
                    None => capabilities_builder,
                };
                capabilities_builder = match spec_caps.bounding() {
                    Some(bounding) => {
                        let bounding: SpecCapabilities = bounding.union(&caps).copied().collect();
                        capabilities_builder.bounding(bounding)
                    }
                    None => capabilities_builder,
                };
                capabilities_builder = match spec_caps.effective() {
                    Some(effective) => {
                        let effective: SpecCapabilities = effective.union(&caps).copied().collect();
                        capabilities_builder.effective(effective)
                    }
                    None => capabilities_builder,
                };
                capabilities_builder = match spec_caps.inheritable() {
                    Some(inheritable) => {
                        let inheritable: SpecCapabilities =
                            inheritable.union(&caps).copied().collect();
                        capabilities_builder.inheritable(inheritable)
                    }
                    None => capabilities_builder,
                };
                capabilities_builder = match spec_caps.permitted() {
                    Some(permitted) => {
                        let permitted: SpecCapabilities = permitted.union(&caps).copied().collect();
                        capabilities_builder.permitted(permitted)
                    }
                    None => capabilities_builder,
                };

                let c = capabilities_builder.build()?;
                return Ok(Some(c));
            }

            return Ok(Some(
                LinuxCapabilitiesBuilder::default()
                    .bounding(caps.clone())
                    .effective(caps.clone())
                    .inheritable(caps.clone())
                    .permitted(caps.clone())
                    .ambient(caps)
                    .build()?,
            ));
        }

        Ok(None)
    }

    fn get_namespaces(
        &self,
        init_namespaces: HashMap<OsString, Namespace>,
    ) -> Result<Vec<LinuxNamespace>, LibcontainerError> {
        let mut tenant_namespaces = Vec::with_capacity(init_namespaces.len());

        for &ns_type in NAMESPACE_TYPES {
            if let Some(init_ns) = init_namespaces.get(OsStr::new(ns_type)) {
                let tenant_ns = LinuxNamespaceType::try_from(ns_type)?;
                tenant_namespaces.push(
                    LinuxNamespaceBuilder::default()
                        .typ(tenant_ns)
                        .path(init_ns.path.clone())
                        .build()?,
                )
            }
        }

        Ok(tenant_namespaces)
    }

    fn should_use_systemd(&self, container: &Container) -> bool {
        container.systemd()
    }

    fn setup_notify_listener(container_dir: &Path) -> Result<PathBuf, LibcontainerError> {
        let notify_name = Self::generate_name(container_dir, TENANT_NOTIFY);
        let socket_path = container_dir.join(notify_name);

        Ok(socket_path)
    }

    fn setup_tty_socket(&self, container_dir: &Path) -> Result<Option<OwnedFd>, LibcontainerError> {
        let tty_name = Self::generate_name(container_dir, TENANT_TTY);
        let csocketfd = if let Some(console_socket) = &self.base.console_socket {
            Some(tty::setup_console_socket(
                container_dir,
                console_socket,
                &tty_name,
            )?)
        } else {
            None
        };

        Ok(csocketfd)
    }

    fn generate_name(dir: &Path, prefix: &str) -> String {
        loop {
            let rand = fastrand::i32(..);
            let name = format!("{prefix}{rand:x}.sock");
            if !dir.join(&name).exists() {
                return name;
            }
        }
    }
}
