use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::os::fd::AsRawFd;
#[cfg(feature = "libseccomp")]
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use oci_spec::runtime::{Linux, LinuxNamespaceType, Spec};
#[cfg(feature = "libseccomp")]
use oci_spec::runtime::{SECCOMP_FD_NAME, VERSION as OCI_VERSION};

use crate::hooks;
use crate::network::network_device::dev_change_net_namespace;
use crate::process::args::{ContainerArgs, ContainerType};
use crate::process::fork::{self, CloneCb};
use crate::process::intel_rdt::setup_intel_rdt;
use crate::process::message::Message;
use crate::process::{channel, container_intermediate_process};
use crate::syscall::SyscallError;
use crate::user_ns::UserNamespaceConfig;

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error(transparent)]
    Channel(#[from] channel::ChannelError),
    #[error("failed to write deny to setgroups")]
    SetGroupsDeny(#[source] std::io::Error),
    #[error(transparent)]
    UserNamespace(#[from] crate::user_ns::UserNamespaceError),
    #[error("container state is required")]
    ContainerStateRequired,
    #[error("failed to wait for intermediate process")]
    WaitIntermediateProcess(#[source] nix::Error),
    #[error(transparent)]
    IntelRdt(#[from] crate::process::intel_rdt::IntelRdtError),
    #[error("failed to create intermediate process")]
    IntermediateProcessFailed(#[source] fork::CloneError),
    #[error("failed seccomp listener")]
    #[cfg(feature = "libseccomp")]
    SeccompListener(#[from] crate::process::seccomp_listener::SeccompListenerError),
    #[error("failed setup network device")]
    Network(#[from] crate::network::NetworkError),
    #[error("network device setup requested but {0}")]
    NetworkDeviceSetup(&'static str),
    #[error("failed syscall")]
    SyscallOther(#[source] SyscallError),
    #[error("failed hooks {0}")]
    Hooks(#[from] crate::hooks::HookError),
    #[error("failed to build OCI state: {0}")]
    OciStateBuild(String),
}

type Result<T> = std::result::Result<T, ProcessError>;

pub fn container_main_process(container_args: &ContainerArgs) -> Result<(Pid, bool)> {
    // We use a set of channels to communicate between parent and child process.
    // Each channel is uni-directional. Because we will pass these channel to
    // cloned process, we have to be deligent about closing any unused channel.
    // At minimum, we have to close down any unused senders. The corresponding
    // receivers will be cleaned up once the senders are closed down.
    let (mut intermediate_main_sender, mut intermediate_main_receiver) = channel::main_channel()?;
    let (mut init_main_sender, mut init_main_receiver) = channel::main_channel()?;
    let mut inter_chan = channel::intermediate_channel()?;
    let mut init_chan = channel::init_channel()?;

    let cb: CloneCb = {
        Box::new(|| {
            if let Err(ret) = prctl::set_name("youki:[1:INTER]") {
                tracing::error!(?ret, "failed to set name for child process");
                return ret;
            }

            match container_intermediate_process::container_intermediate_process(
                container_args,
                &mut inter_chan,
                &mut init_chan,
                &mut intermediate_main_sender,
                &mut init_main_sender,
            ) {
                Ok(_) => 0,
                Err(err) => {
                    tracing::error!("failed to run intermediate process {}", err);
                    match intermediate_main_sender.send_error(err.to_string()) {
                        Ok(_) => {}
                        Err(e) => {
                            tracing::error!(
                                "error in sending intermediate error message {} to main: {}",
                                err,
                                e
                            )
                        }
                    }
                    -1
                }
            }
        })
    };

    let container_clone_fn = if container_args.as_sibling {
        fork::container_clone_sibling
    } else {
        fork::container_clone
    };

    let intermediate_pid = container_clone_fn(cb).map_err(|err| {
        tracing::error!("failed to fork intermediate process: {}", err);
        ProcessError::IntermediateProcessFailed(err)
    })?;

    // Close down unused fds. The corresponding fds are duplicated to the
    // child process during clone.
    intermediate_main_sender.close().map_err(|err| {
        tracing::error!("failed to close unused sender: {}", err);
        err
    })?;
    init_main_sender.close().map_err(|err| {
        tracing::error!("failed to close unused sender: {}", err);
        err
    })?;

    let (mut inter_sender, inter_receiver) = inter_chan;
    let (mut init_sender, init_receiver) = init_chan;

    // If creating a container with new user namespace, the intermediate process will ask
    // the main process to set up uid and gid mapping, once the intermediate
    // process enters into a new user namespace.
    if let Some(config) = &container_args.user_ns_config {
        intermediate_main_receiver.wait_for_mapping_request()?;
        setup_mapping(config, intermediate_pid)?;
        inter_sender.mapping_written()?;
    }

    // At this point, we don't need to send any message to intermediate process anymore,
    // so we want to close this sender at the earliest point.
    inter_sender.close().map_err(|err| {
        tracing::error!("failed to close unused intermediate sender: {}", err);
        err
    })?;

    // The intermediate process will send the init pid once it forks the init
    // process.  The intermediate process should exit after this point.
    let init_pid = intermediate_main_receiver.wait_for_intermediate_ready()?;
    let mut need_to_clean_up_intel_rdt_subdirectory = false;

    if let Some(linux) = container_args.spec.linux() {
        if let Some(intel_rdt) = linux.intel_rdt() {
            let container_id = container_args
                .container
                .as_ref()
                .map(|container| container.id());
            need_to_clean_up_intel_rdt_subdirectory =
                setup_intel_rdt(container_id, &init_pid, intel_rdt)?;
        }
    }

    // if file to write the pid to is specified, write pid of the child
    if let Some(pid_file) = &container_args.pid_file {
        if let Err(err) = fs::write(pid_file, format!("{init_pid}")) {
            tracing::warn!("failed to write pid to file: {err}");
        }
    }

    let mut pending = PendingInitRequests::new(container_args.container_type, &container_args.spec);

    loop {
        let (msg, fd) = init_main_receiver.recv_init_message()?;
        match msg {
            Message::InitReady => {
                if pending.has_pending() {
                    return Err(unexpected_init_message(
                        "pending init setup request",
                        Message::InitReady,
                    ));
                }
                break;
            }
            Message::HookRequest => {
                let hooks = pending.hooks.take().ok_or_else(|| {
                    unexpected_init_message(EXPECTED_INIT_MESSAGE, Message::HookRequest)
                })?;
                handle_hook_request(hooks, container_args, init_pid, &mut init_sender)?;
            }
            Message::SetupNetworkDeviceReady => {
                let linux = pending.net_linux.take().ok_or_else(|| {
                    unexpected_init_message(EXPECTED_INIT_MESSAGE, Message::SetupNetworkDeviceReady)
                })?;
                handle_setup_network_device(linux, init_pid, &mut init_sender)?;
            }
            Message::SeccompNotify => {
                let seccomp = pending.seccomp.take().ok_or_else(|| {
                    unexpected_init_message(EXPECTED_INIT_MESSAGE, Message::SeccompNotify)
                })?;
                #[cfg(feature = "libseccomp")]
                {
                    let seccomp_fd = fd.ok_or(ProcessError::Channel(
                        channel::ChannelError::MissingSeccompFds,
                    ))?;
                    handle_seccomp_notify(
                        container_args,
                        init_pid,
                        seccomp,
                        seccomp_fd,
                        &mut init_sender,
                    )?;
                }
                // Without libseccomp, `pending.seccomp` is always `None`, so the
                // take above has already returned an error; this arm is
                // effectively unreachable.
                #[cfg(not(feature = "libseccomp"))]
                let _ = (seccomp, fd);
            }
            unexpected => return Err(unexpected_init_message(EXPECTED_INIT_MESSAGE, unexpected)),
        }
    }

    // We don't need to send anything to the init process after this point, so
    // close the sender.
    init_sender.close().map_err(|err| {
        tracing::error!("failed to close unused init sender: {}", err);
        err
    })?;

    tracing::debug!("init pid is {:?}", init_pid);

    // Close the receiver ends to avoid leaking file descriptors.

    inter_receiver.close().map_err(|err| {
        tracing::error!("failed to close intermediate process receiver: {}", err);
        err
    })?;

    init_receiver.close().map_err(|err| {
        tracing::error!("failed to close init process receiver: {}", err);
        err
    })?;

    intermediate_main_receiver.close().map_err(|err| {
        tracing::error!("failed to close intermediate main receiver: {}", err);
        err
    })?;

    init_main_receiver.close().map_err(|err| {
        tracing::error!("failed to close init main receiver: {}", err);
        err
    })?;

    // Before the main process returns, we want to make sure the intermediate
    // process is exit and reaped. By this point, the intermediate process
    // should already exited successfully. If intermediate process errors out,
    // the `init_ready` will not be sent.
    match waitpid(intermediate_pid, None) {
        Ok(WaitStatus::Exited(_, 0)) => (),
        Ok(WaitStatus::Exited(_, s)) => {
            tracing::warn!("intermediate process failed with exit status: {s}");
        }
        Ok(WaitStatus::Signaled(_, sig, _)) => {
            tracing::warn!("intermediate process killed with signal: {sig}")
        }
        Ok(_) => (),
        Err(nix::errno::Errno::ECHILD) => {
            // This is safe because intermediate_process and main_process check if the process is
            // finished by piping instead of exit code.
            tracing::warn!("intermediate process already reaped");
        }
        Err(err) => return Err(ProcessError::WaitIntermediateProcess(err)),
    };

    Ok((init_pid, need_to_clean_up_intel_rdt_subdirectory))
}

const EXPECTED_INIT_MESSAGE: &str = "InitReady or a pending init setup request";

/// Init-side setup requests that must be handled before accepting `InitReady`.
///
/// Each request is consumed when its message is received, so duplicates are
/// rejected as unexpected messages.
struct PendingInitRequests<'a> {
    hooks: Option<&'a oci_spec::runtime::Hooks>,
    net_linux: Option<&'a Linux>,
    seccomp: Option<&'a oci_spec::runtime::LinuxSeccomp>,
}

impl<'a> PendingInitRequests<'a> {
    fn new(container_type: ContainerType, spec: &'a Spec) -> Self {
        let hooks = match container_type {
            ContainerType::InitContainer => spec.hooks().as_ref(),
            ContainerType::TenantContainer { .. } => None,
        };
        let net_linux = spec.linux().as_ref().filter(|linux| {
            linux
                .net_devices()
                .as_ref()
                .is_some_and(|devices| !devices.is_empty())
        });
        #[cfg(feature = "libseccomp")]
        let seccomp = spec
            .linux()
            .as_ref()
            .and_then(|linux| linux.seccomp().as_ref())
            .filter(|seccomp| crate::seccomp::is_notify(seccomp));
        #[cfg(not(feature = "libseccomp"))]
        let seccomp = None;

        Self {
            hooks,
            net_linux,
            seccomp,
        }
    }

    fn has_pending(&self) -> bool {
        self.hooks.is_some() || self.net_linux.is_some() || self.seccomp.is_some()
    }
}

fn unexpected_init_message(expected: &'static str, received: Message) -> ProcessError {
    ProcessError::Channel(channel::ChannelError::UnexpectedMessage {
        expected,
        received: Box::new(received),
    })
}

fn handle_hook_request(
    hooks: &oci_spec::runtime::Hooks,
    container_args: &ContainerArgs,
    init_pid: Pid,
    init_sender: &mut channel::InitSender,
) -> Result<()> {
    if let Some(container) = container_args.container.as_ref() {
        hooks::run_hooks(
            hooks.prestart().as_ref(),
            Some(&container.state),
            None,
            Some(init_pid),
            None,
        )
        .map_err(|err| {
            tracing::error!("failed to run prestart hooks: {}", err);
            err
        })?;

        hooks::run_hooks(
            hooks.create_runtime().as_ref(),
            Some(&container.state),
            None,
            Some(init_pid),
            None,
        )
        .map_err(|err| {
            tracing::error!("failed to run create runtime hooks: {}", err);
            err
        })?;
    }

    init_sender.hook_done()?;
    Ok(())
}

/// Builds the OCI `ContainerProcessState` sent to the seccomp listener
/// alongside the notify fd.
#[cfg(feature = "libseccomp")]
fn build_container_process_state(
    container_args: &ContainerArgs,
    init_pid: Pid,
    seccomp: &oci_spec::runtime::LinuxSeccomp,
) -> Result<oci_spec::runtime::ContainerProcessState> {
    let container = container_args
        .container
        .as_ref()
        .ok_or(ProcessError::ContainerStateRequired)?;

    // Determine OCI status based on container type (matching runc behavior)
    let oci_status = match container_args.container_type {
        ContainerType::InitContainer => oci_spec::runtime::ContainerState::Creating,
        ContainerType::TenantContainer { .. } => oci_spec::runtime::ContainerState::Running,
    };

    let oci_state = oci_spec::runtime::StateBuilder::default()
        .version(OCI_VERSION)
        .id(container.state.id.clone())
        .status(oci_status)
        .pid(init_pid.as_raw())
        .bundle(container.state.bundle.clone())
        .annotations(container.state.annotations.clone().unwrap_or_default())
        .build()
        .map_err(|e| ProcessError::OciStateBuild(e.to_string()))?;

    oci_spec::runtime::ContainerProcessStateBuilder::default()
        .version(OCI_VERSION)
        .fds(vec![SECCOMP_FD_NAME.to_string()])
        .pid(init_pid.as_raw())
        .metadata(seccomp.listener_metadata().clone().unwrap_or_default())
        .state(oci_state)
        .build()
        .map_err(|e| ProcessError::OciStateBuild(e.to_string()))
}

#[cfg(feature = "libseccomp")]
fn handle_seccomp_notify(
    container_args: &ContainerArgs,
    init_pid: Pid,
    seccomp: &oci_spec::runtime::LinuxSeccomp,
    seccomp_fd: OwnedFd,
    init_sender: &mut channel::InitSender,
) -> Result<()> {
    let state = build_container_process_state(container_args, init_pid, seccomp)?;

    let listener_path = seccomp
        .listener_path()
        .as_ref()
        .ok_or(crate::process::seccomp_listener::SeccompListenerError::MissingListenerPath)?;
    let encoded_state = serde_json::to_vec(&state)
        .map_err(crate::process::seccomp_listener::SeccompListenerError::EncodeState)?;
    crate::process::seccomp_listener::sync_seccomp_send_msg(
        listener_path,
        &encoded_state,
        seccomp_fd.as_raw_fd(),
    )?;
    init_sender.seccomp_notify_done()?;
    // `seccomp_fd` is dropped here, closing the duplicated fd. The SCM_RIGHTS
    // msg already duplicated the fd to the process behind the listener.
    Ok(())
}

fn setup_mapping(config: &UserNamespaceConfig, pid: Pid) -> Result<()> {
    tracing::debug!("write mapping for pid {:?}", pid);
    if !config.privileged {
        // The main process is running as an unprivileged user and cannot write the mapping
        // until "deny" has been written to setgroups. See CVE-2014-8989.
        std::fs::write(format!("/proc/{pid}/setgroups"), "deny")
            .map_err(ProcessError::SetGroupsDeny)?;
    }

    config.write_uid_mapping(pid).map_err(|err| {
        tracing::error!("failed to write uid mapping for pid {:?}: {}", pid, err);
        err
    })?;
    config.write_gid_mapping(pid).map_err(|err| {
        tracing::error!("failed to write gid mapping for pid {:?}: {}", pid, err);
        err
    })?;
    Ok(())
}

/// Moves configured network devices from the host to the container's network namespace.
/// This runs after the init process has joined its namespace, then transfers each
/// configured device while preserving network addresses.
fn handle_setup_network_device(
    linux: &Linux,
    init_pid: Pid,
    init_sender: &mut channel::InitSender,
) -> Result<()> {
    // Builder validation should make these cases unreachable. Return an error
    // instead of silently skipping the reply init is waiting for.
    let devices = match linux.net_devices() {
        Some(devs) if !devs.is_empty() => devs,
        _ => {
            return Err(ProcessError::NetworkDeviceSetup(
                "no network devices are configured",
            ));
        }
    };
    let net_ns = linux
        .namespaces()
        .as_ref()
        .and_then(|namespaces| {
            namespaces
                .iter()
                .find(|ns| ns.typ() == LinuxNamespaceType::Network)
        })
        .ok_or(ProcessError::NetworkDeviceSetup(
            "the network namespace is not configured",
        ))?;

    // the container init process has already joined the provided net namespace,
    // so we can use the process's net ns path directly.
    let default_ns_path = PathBuf::from(format!("/proc/{}/ns/net", init_pid.as_raw()));
    let ns_path = net_ns.path().as_deref().unwrap_or(&default_ns_path);

    // Open the network namespace file and validate it exists before moving devices
    let netns_file = File::open(ns_path).map_err(|err| {
        tracing::error!(
            "failed to open network namespace at {}: {}",
            ns_path.display(),
            err
        );
        ProcessError::Network(err.into())
    })?;
    let netns_fd = netns_file.as_raw_fd();

    // If moving any of the network devices fails, we return an error immediately.
    // The runtime spec requires that the kernel handles moving back any devices
    // that were successfully moved before the failure occurred.
    // See: https://github.com/opencontainers/runtime-spec/blob/27cb0027fd92ef81eda1ea3a8153b8337f56d94a/config-linux.md#namespace-lifecycle-and-container-termination
    let addrs_map = devices
        .iter()
        .map(|(name, net_dev)| {
            let addrs = dev_change_net_namespace(name, netns_fd, net_dev).map_err(|err| {
                tracing::error!("failed to dev_change_net_namespace: {}", err);
                err
            })?;
            Ok((name.clone(), addrs))
        })
        .collect::<Result<HashMap<String, Vec<crate::network::cidr::CidrAddress>>>>()?;
    init_sender.move_network_device(addrs_map)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use nix::sched::{CloneFlags, unshare};
    use nix::unistd::{self, getgid, getuid};
    use oci_spec::runtime::{
        HooksBuilder, LinuxBuilder, LinuxIdMappingBuilder, LinuxNetDevice, SpecBuilder,
    };
    use serial_test::serial;

    use super::*;
    use crate::process::channel::{intermediate_channel, main_channel};
    use crate::user_ns::UserNamespaceIDMapper;

    #[test]
    fn pending_hooks_only_for_init_container_with_hooks() -> Result<()> {
        let spec = SpecBuilder::default()
            .hooks(HooksBuilder::default().build()?)
            .build()?;

        let pending = PendingInitRequests::new(ContainerType::InitContainer, &spec);
        assert!(pending.hooks.is_some());
        assert!(pending.has_pending());

        let pending =
            PendingInitRequests::new(ContainerType::TenantContainer { exec_notify_fd: -1 }, &spec);
        assert!(pending.hooks.is_none());
        assert!(!pending.has_pending());

        let spec = SpecBuilder::default().build()?;
        let pending = PendingInitRequests::new(ContainerType::InitContainer, &spec);
        assert!(pending.hooks.is_none());
        assert!(!pending.has_pending());
        Ok(())
    }

    #[test]
    fn pending_network_setup_requires_configured_devices() -> Result<()> {
        let devices = HashMap::from([("eth0".to_string(), LinuxNetDevice::default())]);
        let spec = SpecBuilder::default()
            .linux(LinuxBuilder::default().net_devices(devices).build()?)
            .build()?;
        let pending = PendingInitRequests::new(ContainerType::InitContainer, &spec);
        assert!(pending.net_linux.is_some());
        assert!(pending.has_pending());

        let spec = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .net_devices(HashMap::new())
                    .build()?,
            )
            .build()?;
        let pending = PendingInitRequests::new(ContainerType::InitContainer, &spec);
        assert!(pending.net_linux.is_none());
        assert!(!pending.has_pending());
        Ok(())
    }

    #[cfg(feature = "libseccomp")]
    #[test]
    fn pending_seccomp_requires_notify_action() -> Result<()> {
        use oci_spec::runtime::{LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder};

        let notify = LinuxSeccompBuilder::default()
            .syscalls(vec![
                LinuxSyscallBuilder::default()
                    .action(LinuxSeccompAction::ScmpActNotify)
                    .build()?,
            ])
            .build()?;
        let spec = SpecBuilder::default()
            .linux(LinuxBuilder::default().seccomp(notify).build()?)
            .build()?;
        let pending = PendingInitRequests::new(ContainerType::InitContainer, &spec);
        assert!(pending.seccomp.is_some());
        assert!(pending.has_pending());

        let non_notify = LinuxSeccompBuilder::default()
            .syscalls(vec![
                LinuxSyscallBuilder::default()
                    .action(LinuxSeccompAction::ScmpActErrno)
                    .build()?,
            ])
            .build()?;
        let spec = SpecBuilder::default()
            .linux(LinuxBuilder::default().seccomp(non_notify).build()?)
            .build()?;
        let pending = PendingInitRequests::new(ContainerType::InitContainer, &spec);
        assert!(pending.seccomp.is_none());
        assert!(!pending.has_pending());
        Ok(())
    }

    #[test]
    fn pending_request_can_only_be_taken_once() -> Result<()> {
        let spec = SpecBuilder::default()
            .hooks(HooksBuilder::default().build()?)
            .build()?;
        let mut pending = PendingInitRequests::new(ContainerType::InitContainer, &spec);

        assert!(pending.hooks.take().is_some());
        assert!(!pending.has_pending());
        // A second take models a duplicate request from the init process,
        // which the event loop reports as an unexpected message.
        assert!(pending.hooks.take().is_none());
        Ok(())
    }

    #[test]
    #[serial]
    fn setup_uid_mapping_should_succeed() -> Result<()> {
        let uid_mapping = LinuxIdMappingBuilder::default()
            .host_id(getuid())
            .container_id(0u32)
            .size(1u32)
            .build()?;
        let uid_mappings = vec![uid_mapping];
        let tmp = tempfile::tempdir()?;
        let id_mapper = UserNamespaceIDMapper::new_test(tmp.path().to_path_buf());
        let ns_config = UserNamespaceConfig {
            uid_mappings: Some(uid_mappings),
            privileged: true,
            id_mapper: id_mapper.clone(),
            ..Default::default()
        };
        let (mut parent_sender, mut parent_receiver) = main_channel()?;
        let (mut child_sender, mut child_receiver) = intermediate_channel()?;
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                parent_receiver.wait_for_mapping_request()?;
                parent_receiver.close()?;

                // In test, we fake the uid path in /proc/{pid}/uid_map, so we
                // need to ensure the path exists before we write the mapping.
                // The path requires the pid we use, so we can only do do after
                // obtaining the child pid here.
                id_mapper.ensure_uid_path(&child)?;
                setup_mapping(&ns_config, child)?;
                let line = fs::read_to_string(id_mapper.get_uid_path(&child))?;
                let split_lines = line.split_whitespace();
                for (act, expect) in split_lines.zip([
                    uid_mapping.container_id().to_string(),
                    uid_mapping.host_id().to_string(),
                    uid_mapping.size().to_string(),
                ]) {
                    assert_eq!(act, expect);
                }
                child_sender.mapping_written()?;
                child_sender.close()?;
            }
            unistd::ForkResult::Child => {
                prctl::set_dumpable(true).unwrap();
                unshare(CloneFlags::CLONE_NEWUSER)?;
                parent_sender.identifier_mapping_request()?;
                parent_sender.close()?;
                child_receiver.wait_for_mapping_ack()?;
                child_receiver.close()?;
                std::process::exit(0);
            }
        }
        Ok(())
    }

    #[test]
    #[serial]
    fn setup_gid_mapping_should_succeed() -> Result<()> {
        let gid_mapping = LinuxIdMappingBuilder::default()
            .host_id(getgid())
            .container_id(0u32)
            .size(1u32)
            .build()?;
        let gid_mappings = vec![gid_mapping];
        let tmp = tempfile::tempdir()?;
        let id_mapper = UserNamespaceIDMapper::new_test(tmp.path().to_path_buf());
        let ns_config = UserNamespaceConfig {
            gid_mappings: Some(gid_mappings),
            id_mapper: id_mapper.clone(),
            ..Default::default()
        };
        let (mut parent_sender, mut parent_receiver) = main_channel()?;
        let (mut child_sender, mut child_receiver) = intermediate_channel()?;
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                parent_receiver.wait_for_mapping_request()?;
                parent_receiver.close()?;

                // In test, we fake the gid path in /proc/{pid}/gid_map, so we
                // need to ensure the path exists before we write the mapping.
                // The path requires the pid we use, so we can only do do after
                // obtaining the child pid here.
                id_mapper.ensure_gid_path(&child)?;
                setup_mapping(&ns_config, child)?;
                let line = fs::read_to_string(id_mapper.get_gid_path(&child))?;
                let split_lines = line.split_whitespace();
                for (act, expect) in split_lines.zip([
                    gid_mapping.container_id().to_string(),
                    gid_mapping.host_id().to_string(),
                    gid_mapping.size().to_string(),
                ]) {
                    assert_eq!(act, expect);
                }
                assert_eq!(
                    fs::read_to_string(format!("/proc/{}/setgroups", child.as_raw()))?,
                    "deny\n",
                );
                child_sender.mapping_written()?;
                child_sender.close()?;
            }
            unistd::ForkResult::Child => {
                prctl::set_dumpable(true).unwrap();
                unshare(CloneFlags::CLONE_NEWUSER)?;
                parent_sender.identifier_mapping_request()?;
                parent_sender.close()?;
                child_receiver.wait_for_mapping_ack()?;
                child_receiver.close()?;
                std::process::exit(0);
            }
        }
        Ok(())
    }
}
