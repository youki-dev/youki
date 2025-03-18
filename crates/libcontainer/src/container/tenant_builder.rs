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
    as_sibling: bool,
}

/// This is a helper function to get capabilities for tenant container, based on
/// additional capabilities provided by user and capabilities of existing container
/// extracted into separate function for easier testing
fn get_capabilities(
    additional: &[String],
    spec: &Spec,
) -> Result<LinuxCapabilities, LibcontainerError> {
    let mut caps: Vec<Capability> = Vec::with_capacity(additional.len());
    for cap in additional {
        caps.push(Capability::from_str(cap)?);
    }
    let caps: SpecCapabilities = caps.iter().map(|c| SpecCapability::from_cap(*c)).collect();

    if let Some(spec_caps) = spec
        .process()
        .as_ref()
        .ok_or(MissingSpecError::Process)?
        .capabilities()
    {
        let mut capabilities_builder = LinuxCapabilitiesBuilder::default();

        let bounding: SpecCapabilities = match spec_caps.bounding() {
            Some(bounding) => bounding.union(&caps).copied().collect(),
            None => SpecCapabilities::new().union(&caps).copied().collect(),
        };
        capabilities_builder = capabilities_builder.bounding(bounding);

        let effective: SpecCapabilities = match spec_caps.effective() {
            Some(effective) => effective.union(&caps).copied().collect(),
            None => SpecCapabilities::new().union(&caps).copied().collect(),
        };
        capabilities_builder = capabilities_builder.effective(effective);

        let permitted: SpecCapabilities = match spec_caps.permitted() {
            Some(permitted) => permitted.union(&caps).copied().collect(),
            None => SpecCapabilities::new().union(&caps).copied().collect(),
        };
        capabilities_builder = capabilities_builder.permitted(permitted);

        // ambient capabilities are only useful when inherent capabilities
        // are set. Hence we check and set accordingly. Inherent capabilities
        // are never set from user as that can lead to vulnerability like
        // https://github.com/advisories/GHSA-f3fp-gc8g-vw66
        // Hence, we follow runc's code and set things similarly.
        let caps = if let Some(inheritable) = spec_caps.inheritable() {
            let ambient: SpecCapabilities = match spec_caps.ambient() {
                Some(ambient) => ambient.union(&caps).copied().collect(),
                None => SpecCapabilities::new().union(&caps).copied().collect(),
            };
            capabilities_builder = capabilities_builder.ambient(ambient);
            capabilities_builder = capabilities_builder.inheritable(inheritable.clone());
            capabilities_builder.build()?
        } else {
            let mut caps = capabilities_builder.build()?;
            // oci-spec-rs sets these to some default caps, so we reset them here
            caps.set_inheritable(None);
            caps.set_ambient(None);
            caps
        };

        return Ok(caps);
    }

    // If there are no caps in original container's spec,
    // we simply set given caps , excluding the inherent and ambient
    let mut caps = LinuxCapabilitiesBuilder::default()
        .bounding(caps.clone())
        .effective(caps.clone())
        .permitted(caps.clone())
        .build()?;
    caps.set_inheritable(None);
    caps.set_ambient(None);
    Ok(caps)
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
            as_sibling: false,
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

    /// Sets if the init process should be run as a child or a sibling of
    /// the calling process
    pub fn as_sibling(mut self, as_sibling: bool) -> Self {
        self.as_sibling = as_sibling;
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
            stdin: self.base.stdin,
            stdout: self.base.stdout,
            stderr: self.base.stderr,
            as_sibling: self.as_sibling,
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

            let capabilities = get_capabilities(&self.capabilities, spec)?;
            process_builder = process_builder.capabilities(capabilities);

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

#[cfg(test)]
mod test {

    use caps::Capability as Cap;
    use oci_spec::runtime::{
        Capabilities, Capability as SpecCap, LinuxCapabilities, ProcessBuilder, Spec, SpecBuilder,
    };

    use super::{get_capabilities, LibcontainerError};
    use crate::capabilities::CapabilityExt;

    fn get_spec(caps: LinuxCapabilities) -> Spec {
        SpecBuilder::default()
            .process(
                ProcessBuilder::default()
                    .capabilities(caps)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    fn cap_to_string(caps: &[Cap]) -> Vec<String> {
        caps.iter().map(|c| c.to_string()).collect()
    }

    fn caps_to_spec_set(caps: &[Cap]) -> Capabilities {
        caps.iter().map(|c| SpecCap::from_cap(*c)).collect()
    }

    fn empty_caps() -> LinuxCapabilities {
        let mut t = LinuxCapabilities::default();
        t.set_effective(None)
            .set_bounding(None)
            .set_permitted(None)
            .set_inheritable(None)
            .set_ambient(None);
        t
    }

    // if there are no existing capabilities, then tenant can only
    // set effective, bounding and permitted caps ; not inheritable or ambient
    #[test]
    fn test_capabilities_no_existing() -> Result<(), LibcontainerError> {
        let spec = get_spec(empty_caps());

        let extra_caps = &[Cap::CAP_SYS_ADMIN, Cap::CAP_NET_ADMIN, Cap::CAP_AUDIT_READ];

        let additional = cap_to_string(extra_caps);
        let caps = get_capabilities(&additional, &spec)?;

        let expected_caps = empty_caps()
            .set_effective(Some(caps_to_spec_set(extra_caps)))
            .set_bounding(Some(caps_to_spec_set(extra_caps)))
            .set_permitted(Some(caps_to_spec_set(extra_caps)))
            .clone();

        assert_eq!(caps, expected_caps);
        Ok(())
    }

    // If there are existing capabilities, but not inherent, then tenant should union
    // existing and provided caps only for effective, bounding and permitted,
    // inherent and ambient should be explicitly None
    #[test]
    fn test_capabilities_with_existing() -> Result<(), LibcontainerError> {
        let existing_caps = &[Cap::CAP_SYS_ADMIN, Cap::CAP_BPF, Cap::CAP_MKNOD];

        let existing = LinuxCapabilities::default()
            .set_effective(Some(caps_to_spec_set(existing_caps)))
            .set_bounding(Some(caps_to_spec_set(existing_caps)))
            .set_permitted(Some(caps_to_spec_set(existing_caps)))
            .set_inheritable(None)
            .set_ambient(None)
            .clone();

        let spec = get_spec(existing);

        let extra_caps = &[Cap::CAP_SYS_ADMIN, Cap::CAP_NET_ADMIN, Cap::CAP_AUDIT_READ];

        let additional = cap_to_string(extra_caps);
        let caps = get_capabilities(&additional, &spec)?;

        let mut combined_caps = existing_caps.to_vec();
        combined_caps.extend(extra_caps);
        let expected_caps = empty_caps()
            .set_effective(Some(caps_to_spec_set(&combined_caps)))
            .set_bounding(Some(caps_to_spec_set(&combined_caps)))
            .set_permitted(Some(caps_to_spec_set(&combined_caps)))
            .clone();

        assert_eq!(caps, expected_caps);
        Ok(())
    }

    // we check that if inherent capabilities are present, ambient are set correctly
    #[test]
    fn test_capabilities_with_existing_inherent() -> Result<(), LibcontainerError> {
        let existing_caps = &[Cap::CAP_SYS_ADMIN, Cap::CAP_BPF, Cap::CAP_MKNOD];
        let extra_caps = &[Cap::CAP_SYS_ADMIN, Cap::CAP_NET_ADMIN, Cap::CAP_AUDIT_READ];

        let mut combined_caps = existing_caps.to_vec();
        combined_caps.extend(extra_caps);

        // case 1 :  when inheritable are there, but no ambient

        let existing = LinuxCapabilities::default()
            .set_effective(Some(caps_to_spec_set(existing_caps)))
            .set_bounding(Some(caps_to_spec_set(existing_caps)))
            .set_permitted(Some(caps_to_spec_set(existing_caps)))
            .set_inheritable(Some(caps_to_spec_set(existing_caps)))
            .set_ambient(None)
            .clone();
        let spec = get_spec(existing);
        let additional = cap_to_string(extra_caps);
        let caps = get_capabilities(&additional, &spec)?;
        let expected_caps = empty_caps()
            .set_effective(Some(caps_to_spec_set(&combined_caps)))
            .set_bounding(Some(caps_to_spec_set(&combined_caps)))
            .set_permitted(Some(caps_to_spec_set(&combined_caps)))
            // inheritable must not change
            .set_inheritable(Some(caps_to_spec_set(existing_caps)))
            // as there were no existing ambient, only extra will be set
            .set_ambient(Some(caps_to_spec_set(extra_caps)))
            .clone();
        assert_eq!(caps, expected_caps);

        // case 2 :  when inheritable and ambient both are present

        let existing = LinuxCapabilities::default()
            .set_effective(Some(caps_to_spec_set(existing_caps)))
            .set_bounding(Some(caps_to_spec_set(existing_caps)))
            .set_permitted(Some(caps_to_spec_set(existing_caps)))
            .set_inheritable(Some(caps_to_spec_set(existing_caps)))
            .set_ambient(Some(caps_to_spec_set(existing_caps)))
            .clone();
        let spec = get_spec(existing);
        let additional = cap_to_string(extra_caps);
        let caps = get_capabilities(&additional, &spec)?;
        let expected_caps = empty_caps()
            .set_effective(Some(caps_to_spec_set(&combined_caps)))
            .set_bounding(Some(caps_to_spec_set(&combined_caps)))
            .set_permitted(Some(caps_to_spec_set(&combined_caps)))
            // inheritable must not change
            .set_inheritable(Some(caps_to_spec_set(existing_caps)))
            .set_ambient(Some(caps_to_spec_set(&combined_caps)))
            .clone();
        assert_eq!(caps, expected_caps);

        Ok(())
    }
}
