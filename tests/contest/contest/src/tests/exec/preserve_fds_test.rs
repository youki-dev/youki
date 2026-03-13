use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;

use anyhow::anyhow;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::unistd::dup2;
use test_framework::{TestResult, test_result};

use crate::utils::test_utils::{
    build_exec_command, check_container_created, start_container, test_outside_container,
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

        let mut command = build_exec_command(
            id,
            dir,
            &["--preserve-fds=1", "cat", "/proc/self/fd/3"],
            None,
            &[],
        );

        // We use pre_exec to run this closure in the child process after fork()
        // but before exec(). This is critical because `contest` runs tests concurrently.
        // If we duplicate the file descriptor or clear O_CLOEXEC in the parent (test runner)
        // process, it will race with other tests (like `hello_world`) and leak into their
        // child processes, causing broken pipes or EPERM errors.
        unsafe {
            command.pre_exec(move || {
                let flags = FdFlag::from_bits_truncate(
                    fcntl(fd, FcntlArg::F_GETFD).expect("from_bits_truncate failed"),
                );
                fcntl(fd, FcntlArg::F_SETFD(flags & !FdFlag::FD_CLOEXEC)).expect("fcntl failed");
                dup2(fd, 3).expect("dup2 failed");
                Ok(())
            });
        }

        let output = command.output().expect("exec failed");

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            return TestResult::Failed(anyhow!(
                "exec failed with status: {:?}, stderr: {}",
                output.status,
                stderr
            ));
        }

        if !stdout.contains("hello world") {
            return TestResult::Failed(anyhow!("unexpected output: {}", stdout));
        }

        drop(file);

        TestResult::Passed
    })
}
