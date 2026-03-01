use std::fs;
use std::os::fd::AsRawFd;

use anyhow::anyhow;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::unistd::dup2;
use test_framework::{TestResult, test_result};

use crate::utils::test_utils::{
    check_container_created, exec_container, start_container, test_outside_container,
};

pub(crate) fn preserve_fds_test() -> TestResult {
    let spec = test_result!(super::create_spec(None));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        fs::write(dir.join("preserve-fds.test"), b"hello world\n")
            .expect("write preserve-fds.test failed");

        let file =
            fs::File::open(dir.join("preserve-fds.test")).expect("open preserve-fds.test failed");
        let fd = file.as_raw_fd();

        let flags = FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD).expect(""));
        fcntl(fd, FcntlArg::F_SETFD(flags & !FdFlag::FD_CLOEXEC)).expect("");
        dup2(fd, 3).expect("dup2 failed");

        let (stdout, _) = exec_container(
            id,
            dir,
            &["--preserve-fds=1", "cat", "/proc/self/fd/3"],
            None,
        )
        .expect("exec failed");

        if !stdout.contains("hello world") {
            return TestResult::Failed(anyhow!("unexpected output: {}", stdout));
        }

        drop(file);

        TestResult::Passed
    })
}
