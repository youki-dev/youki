use crate::utils::test_outside_container;
use anyhow::{Error, anyhow};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, Spec, SpecBuilder,
};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Instant;
use test_framework::{Test, TestGroup, TestResult};

struct WithCleanup {
    child: Child,
}

impl WithCleanup {
    fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for WithCleanup {
    fn drop(&mut self) {
        match kill(Pid::from_raw(-(self.child.id() as i32)), Signal::SIGKILL) {
            Ok(()) => {}
            Err(_e) => {} // Not sure what else can be done here
        }
    }
}

fn create_spec(namespace_path: &Vec<NamespacePath>) -> Spec {
    let mut linux_namespace_types = Vec::new();
    for namespace_path in namespace_path {
        linux_namespace_types.push(
            LinuxNamespaceBuilder::default()
                .typ(namespace_path.lnt)
                .path(&namespace_path.path)
                .build()
                .expect("could not build spec namespace"),
        );
    }

    let mut spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                // passing in a custom namespace that we will generate
                .namespaces(linux_namespace_types)
                .build()
                .expect("could not build spec"),
        )
        .build()
        .unwrap();
    spec.set_hostname(None);
    spec
}

fn wait_for_inode_diff(
    path: &PathBuf,
    lnt: LinuxNamespaceType,
    timeout: u64,
    interval: u64,
) -> Result<(), Error> {
    let start = Instant::now();

    let pid = std::process::id();
    let process_path = PathBuf::from(format!("/proc/{}/ns/{}", pid, lnt.to_string()));
    let process_ns_inode = fs::metadata(&process_path)?.ino();

    loop {
        let unshared_ns_inode = fs::metadata(&path)?.ino();
        if unshared_ns_inode != process_ns_inode {
            return Ok(());
        }
        if start.elapsed().as_secs() > timeout {
            return Err(Error::msg(format!(
                "timeout waiting for path {}",
                path.display()
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(interval));
    }
}

fn collect_namespace_paths(
    linux_namespace_types: Vec<LinuxNamespaceType>,
    process_id: u32,
) -> Vec<NamespacePath> {
    let mut namespaces = Vec::new();
    for linux_namespace_type in linux_namespace_types {
        let mut unshare_path = format!(
            "/proc/{}/ns/{}",
            process_id,
            linux_namespace_type.to_string()
        );
        if linux_namespace_type == LinuxNamespaceType::Pid {
            // Unsharing pidns does not move the process into the new
            // pidns but the next forked process. 'unshare' is called with
            // '--fork' so the pidns will be fully created and populated
            // with a pid 1.
            //
            // However, finding out the pid of the child process is not
            // trivial: it would require to parse
            // /proc/$pid/task/$tid/children but that only works on kernels
            // with CONFIG_PROC_CHILDREN (not all distros have that).
            //
            // It is easier to look at /proc/$pid/ns/pid_for_children on
            // the parent process. Available since Linux 4.12.
            unshare_path = unshare_path + "_for_children";
        }

        let path = PathBuf::from(unshare_path);

        namespaces.push(NamespacePath {
            lnt: linux_namespace_type,
            path,
        })
    }
    namespaces
}

fn test_namespace_path(lnt: LinuxNamespaceType) -> TestResult {
    let mut namespaces = Vec::new();
    namespaces.push(lnt);
    test_namespace_paths(namespaces)
}

fn test_namespace_paths(mut linux_namespace_types: Vec<LinuxNamespaceType>) -> TestResult {
    if !linux_namespace_types.contains(&LinuxNamespaceType::Mount) {
        // to prevent mounting issues with the new container, we will always
        // create a new mount namespace. This was added for the runc runtime as the container would
        // fail to be created without it
        linux_namespace_types.push(LinuxNamespaceType::Mount);
    }

    // call unshared to create a new namespace
    let mut command = Command::new("unshare");
    for linux_namespace_type in &linux_namespace_types {
        command.arg(get_unshare_opt(linux_namespace_type));
    }

    command.arg("--fork");
    command.arg("sleep");
    command.arg("10000");
    // so we can kill the both unshared and the child sleep process
    // by setting 0 the group id will be the same as child.id()
    command.process_group(0);
    let child = command.spawn();

    let child = match child {
        Ok(child) => child,
        Err(e) => {
            return TestResult::Failed(anyhow!(format!("could not spawn unshare: {}", e)));
        }
    };
    let g_child = WithCleanup::new(child);

    let namespace_paths = collect_namespace_paths(linux_namespace_types, g_child.child.id());

    const MAX_TIMEOUT_SEC: u64 = 10;
    const RETRY_DELAY_MS: u64 = 100;
    for namespace_path in &namespace_paths {
        let err = wait_for_inode_diff(&namespace_path.path, namespace_path.lnt, MAX_TIMEOUT_SEC, RETRY_DELAY_MS).err();
        if err.is_some() {
            return TestResult::Failed(anyhow!(format!(
                "could not wait for path {}",
                &namespace_path.path.display()
            )));
        }
    }

    let spec = create_spec(&namespace_paths);

    // compare the namespaces of the container and the unshared process
    let result = test_outside_container(&spec, &move |data| {
        let pid = match data.state {
            Some(s) => s.pid.unwrap(),
            None => return TestResult::Failed(anyhow!("state command returned error")),
        };

        for unshared_namespace_path in &namespace_paths {
            let unshared_ns_inode = match fs::metadata(&unshared_namespace_path.path) {
                Ok(m) => m.ino(),
                Err(e) => {
                    return TestResult::Failed(anyhow!(format!(
                        "could not get inode of {}: {}",
                        &unshared_namespace_path.path.display(),
                        e
                    )));
                }
            };

            let container_ns_path = PathBuf::from(format!(
                "/proc/{}/ns/{}",
                pid,
                unshared_namespace_path.lnt.to_string()
            ));
            let container_ns_inode = match fs::metadata(&container_ns_path) {
                Ok(m) => m.ino(),
                Err(e) => {
                    return TestResult::Failed(anyhow!(format!(
                        "could not get inode of {}: {}",
                        container_ns_path.display(),
                        e
                    )));
                }
            };

            if container_ns_inode != unshared_ns_inode {
                return TestResult::Failed(anyhow!(
                    "error : namespaces are not correctly inherited. Expected {:?} inode {} to equal {:?} inode {}",
                    &unshared_namespace_path.path,
                    unshared_ns_inode,
                    container_ns_path,
                    container_ns_inode
                ));
            }
        }
        TestResult::Passed
    });
    result
}

struct NamespacePath {
    pub lnt: LinuxNamespaceType,
    pub path: PathBuf,
}

fn test_pid_ns() -> TestResult {
    test_namespace_path(LinuxNamespaceType::Pid)
}

fn test_uts_ns() -> TestResult {
    test_namespace_path(LinuxNamespaceType::Uts)
}

fn test_ipc_ns() -> TestResult {
    test_namespace_path(LinuxNamespaceType::Ipc)
}

fn test_mount_ns() -> TestResult {
    test_namespace_path(LinuxNamespaceType::Mount)
}

fn test_network_ns() -> TestResult {
    test_namespace_path(LinuxNamespaceType::Network)
}

fn get_unshare_opt(lnt: &LinuxNamespaceType) -> &'static str {
    match lnt {
        LinuxNamespaceType::Network => "--net",
        LinuxNamespaceType::Ipc => "--ipc",
        LinuxNamespaceType::Uts => "--uts",
        LinuxNamespaceType::Mount => "--mount",
        LinuxNamespaceType::Pid => "--pid",
        _ => panic!("Unsupported namespace type"),
    }
}

pub fn get_ns_path_test() -> TestGroup {
    let mut linux_ns_path_test_group = TestGroup::new("linux_ns_path");

    let mut tests: Vec<Box<Test>> = vec![];
    tests.push(Box::new(Test::new(
        "test_network_ns",
        Box::new(test_network_ns),
    )));
    tests.push(Box::new(Test::new(
        "test_mount_ns",
        Box::new(test_mount_ns),
    )));
    tests.push(Box::new(Test::new("test_ipc_ns", Box::new(test_ipc_ns))));
    tests.push(Box::new(Test::new("test_uts_ns", Box::new(test_uts_ns))));
    tests.push(Box::new(Test::new("test_pid_ns", Box::new(test_pid_ns))));

    linux_ns_path_test_group.add(tests);
    linux_ns_path_test_group
}
