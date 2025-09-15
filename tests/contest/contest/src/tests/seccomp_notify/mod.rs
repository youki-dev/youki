use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use anyhow::{Result, anyhow, bail};
use oci_spec::runtime::{
    Arch, LinuxBuilder, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder, SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::{get_runtime_path, test_outside_container};

mod seccomp_agent;

const SECCOMP_LISTENER_PATH: &str = "/tmp/youki_seccomp_agent.unix";
const SECCOMP_METADATA: &str = "Hello World! This is an opaque seccomp metadata string";

fn get_seccomp_listener() -> PathBuf {
    let seccomp_listener_path = PathBuf::from(SECCOMP_LISTENER_PATH);
    // We will have to clean up leftover unix domain socket from previous runs.
    if seccomp_listener_path.exists() {
        std::fs::remove_file(&seccomp_listener_path)
            .expect("failed to clean up existing seccomp listener");
    }

    seccomp_listener_path
}

fn test_seccomp_notify() -> Result<()> {
    let seccomp_listener_path = get_seccomp_listener();
    let seccomp_meta = String::from(SECCOMP_METADATA);
    // Create a spec to include seccomp notify. We will need to have at least
    // one syscall set to seccomp notify. We also need to set seccomp listener
    // path and metadata.
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .seccomp(
                    LinuxSeccompBuilder::default()
                        .default_action(LinuxSeccompAction::ScmpActAllow)
                        .architectures(vec![Arch::ScmpArchX86_64])
                        .listener_path(&seccomp_listener_path)
                        .listener_metadata(seccomp_meta)
                        .syscalls(vec![
                            LinuxSyscallBuilder::default()
                                .names(vec![String::from("getcwd")])
                                .action(LinuxSeccompAction::ScmpActNotify)
                                .build()
                                .unwrap(),
                        ])
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // two threads. One run container life cycle. Another one run seccomp agent...
    let (sender, receiver): (
        Sender<seccomp_agent::SeccompAgentResult>,
        Receiver<seccomp_agent::SeccompAgentResult>,
    ) = mpsc::channel();
    // We have to launch the seccomp agent before we launch the container.
    // Otherwise, the container creation will be blocked on trying to send to
    // the seccomp listener and never returns.
    let child = thread::spawn(move || {
        let res = seccomp_agent::recv_seccomp_listener(&seccomp_listener_path);
        sender
            .send(res)
            .expect("failed to send seccomp agent result back to main thread");
    });
    if let TestResult::Failed(err) = test_outside_container(&spec, &move |data| {
        let (container_process_state, _) = receiver
            .recv()
            .expect("failed to receive from channel")
            .expect("failed to receive from seccomp listener");

        let state = match data.state {
            Some(s) => s,
            None => return TestResult::Failed(anyhow!("state command returned error")),
        };

        if state.id != container_process_state.state.id {
            return TestResult::Failed(anyhow!("container id doesn't match"));
        }

        if state.pid.unwrap() != container_process_state.pid {
            return TestResult::Failed(anyhow!("container process id doesn't match"));
        }

        if SECCOMP_METADATA != container_process_state.metadata {
            return TestResult::Failed(anyhow!("seccomp listener metadata doesn't match"));
        }

        TestResult::Passed
    }) {
        bail!("failed to run test outside container: {:?}", err);
    }

    if let Err(err) = child.join() {
        bail!("seccomp listener child thread fails: {:?}", err);
    }

    Ok(())
}

pub fn get_seccomp_notify_test() -> TestGroup {
    let seccomp_notify_test = Test::new(
        "seccomp_notify",
        Box::new(|| {
            let runtime = get_runtime_path();
            // runc doesn't support seccomp notify yet
            if runtime.ends_with("runc") {
                return TestResult::Skipped;
            }

            match test_seccomp_notify() {
                Ok(_) => TestResult::Passed,
                Err(err) => TestResult::Failed(err),
            }
        }),
    );
    let mut tg = TestGroup::new("seccomp_notify");
    tg.add(vec![Box::new(seccomp_notify_test)]);

    tg
}
