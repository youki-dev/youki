use std::os::fd::AsRawFd;

use anyhow::{anyhow, Context, Result};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};

use crate::utils::test_utils::{
    check_container_created, exec_container, start_container, test_outside_container,
};
use test_framework::{test_result, TestResult};

fn create_spec() -> Result<Spec> {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(
                    ["sleep", "1000"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

pub(crate) fn preserve_fds_test() -> TestResult {
    let spec = test_result!(create_spec());

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        use nix::unistd::dup2;
        use std::fs;
        fs::write(dir.join("preserve-fds.test"), b"hello world\n")
            .expect("write preserve-fds.test failed");
        let file =
            fs::File::open(dir.join("preserve-fds.test")).expect("open preserve-fds.test failed");
        let fd = file.as_raw_fd();
        dup2(fd, 4).expect("dup2(fd, 4) failed");

        let (stdout, _) = exec_container(
            id,
            dir,
            &["--preserve-fds=2", "cat", "/proc/self/fd/4"],
            None,
        )
        .expect("exec failed");

        if !stdout.contains("hello world") {
            return TestResult::Failed(anyhow!("unexpected output: {}", stdout));
        }

        TestResult::Passed
    })
}
