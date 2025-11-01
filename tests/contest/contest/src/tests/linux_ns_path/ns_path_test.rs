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

fn create_spec(lnt: LinuxNamespaceType, path: PathBuf) -> Spec {
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                // passing in a custom namespace that we will generate
                .namespaces(vec![
                    LinuxNamespaceBuilder::default()
                        .typ(lnt)
                        .path(path)
                        .build()
                        .expect("could not build spec namespace"),
                ])
                .build()
                .expect("could not build spec"),
        )
        .build()
        .unwrap();
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

fn test_namespace_path(case: &Case) -> TestResult {
    // call unshared to create a new namespace
    let child = Command::new("unshare")
        .arg(case.unshare_opt)
        .arg("--fork")
        .arg("sleep")
        .arg("10000")
        // so we can kill the both unshared and the child sleep process
        // by setting 0 the group id will be the same as child.id()
        .process_group(0)
        .spawn();

    let child = match child {
        Ok(child) => child,
        Err(e) => {
            return TestResult::Failed(anyhow!(format!("could not spawn unshare: {}", e)));
        }
    };
    let guard = WithCleanup::new(child);

    let mut unshare_path = format!("/proc/{}/ns/{}", guard.child.id(), case.lnt.to_string());
    if case.lnt == LinuxNamespaceType::Pid {
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

    // waiting for the unshare ns inode and current process ns inode to be different
    let err = wait_for_inode_diff(&path, case.lnt, 10, 100).err();
    if err.is_some() {
        return TestResult::Failed(anyhow!(format!(
            "could not wait for path {}",
            path.display()
        )));
    }

    let unshared_metadata = fs::metadata(&path);
    let unshared_inode = match unshared_metadata {
        Ok(m) => m.ino(),
        Err(e) => {
            return TestResult::Failed(anyhow!(format!(
                "could not get inode of {}: {}",
                path.display(),
                e
            )));
        }
    };

    let spec = create_spec(case.lnt, path);

    // compare the namespaces of the container and the unshared process
    let result = test_outside_container(&spec, &move |data| {
        let pid = match data.state {
            Some(s) => s.pid.unwrap(),
            None => return TestResult::Failed(anyhow!("state command returned error")),
        };

        let container_ns_path = PathBuf::from(format!("/proc/{}/ns/{}", pid, case.lnt.to_string()));
        let container_ns_metadata = fs::metadata(&container_ns_path);
        let container_ns_inode = match container_ns_metadata {
            Ok(m) => m.ino(),
            Err(e) => {
                return TestResult::Failed(anyhow!(format!(
                    "could not get inode of {}: {}",
                    container_ns_path.display(),
                    e
                )));
            }
        };

        if container_ns_inode != unshared_inode {
            return TestResult::Failed(anyhow!(
                "error : namespaces are not correctly inherited. Expected inode {} but got inode {}",
                unshared_inode,
                container_ns_inode
            ));
        }
        TestResult::Passed
    });

    result
}

struct Case {
    pub lnt: LinuxNamespaceType,
    pub unshare_opt: &'static str,
}

fn test_pid_ns() -> TestResult {
    test_namespace_path(&Case {
        lnt: LinuxNamespaceType::Pid,
        unshare_opt: "--pid",
    })
}

fn test_uts_ns() -> TestResult {
    test_namespace_path(&Case {
        lnt: LinuxNamespaceType::Uts,
        unshare_opt: "--uts",
    })
}

fn test_ipc_ns() -> TestResult {
    test_namespace_path(&Case {
        lnt: LinuxNamespaceType::Ipc,
        unshare_opt: "--ipc",
    })
}

fn test_mount_ns() -> TestResult {
    test_namespace_path(&Case {
        lnt: LinuxNamespaceType::Mount,
        unshare_opt: "--mount",
    })
}

fn test_network_ns() -> TestResult {
    test_namespace_path(&Case {
        lnt: LinuxNamespaceType::Network,
        unshare_opt: "--net",
    })
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
