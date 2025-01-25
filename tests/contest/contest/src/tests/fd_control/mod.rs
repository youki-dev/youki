use std::fs;
use std::os::fd::{AsRawFd, RawFd};

use anyhow::{anyhow, Context, Result};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use test_framework::{test_result, ConditionalTest, Test, TestGroup, TestResult};

use crate::utils::{is_runtime_runc, test_inside_container, CreateOptions};

fn create_spec() -> Result<Spec> {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(
                    ["runtimetest", "fd_control"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn open_devnull_no_cloexec() -> Result<(fs::File, RawFd)> {
    // Rust std by default sets cloexec, so we undo it
    let devnull = fs::File::open("/dev/null")?;
    let devnull_fd = devnull.as_raw_fd();
    let flags = nix::fcntl::fcntl(devnull_fd, nix::fcntl::FcntlArg::F_GETFD)?;
    let mut flags = nix::fcntl::FdFlag::from_bits_retain(flags);
    flags.remove(nix::fcntl::FdFlag::FD_CLOEXEC);
    nix::fcntl::fcntl(devnull_fd, nix::fcntl::FcntlArg::F_SETFD(flags))?;
    Ok((devnull, devnull_fd))
}

// If not opening any other FDs, verify youki itself doesnt open anything that gets
// leaked in if passing --preserve-fds with a large number
// NOTE: this will also fail if the test harness itself starts leaking FDs
fn only_stdio_test() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(
        spec,
        &CreateOptions::default().with_extra_args(&["--preserve-fds".as_ref(), "100".as_ref()]),
        &|bundle_path| {
            fs::write(bundle_path.join("num-fds"), "0".as_bytes())?;
            Ok(())
        },
    )
}

// If we know we have an open FD without cloexec, it should be closed if preserve-fds
// is 0 (the default)
fn closes_fd_test() -> TestResult {
    // Open this before the setup function so it's kept alive for the container lifetime
    let (_devnull, _devnull_fd) = match open_devnull_no_cloexec() {
        Ok(v) => v,
        Err(e) => return TestResult::Failed(anyhow!("failed to open dev null: {}", e)),
    };

    let spec = test_result!(create_spec());
    test_inside_container(
        spec,
        &CreateOptions::default().with_extra_args(&["--preserve-fds".as_ref(), "0".as_ref()]),
        &|bundle_path| {
            fs::write(bundle_path.join("num-fds"), "0".as_bytes())?;
            Ok(())
        },
    )
}

// Given an open FD, verify it can be passed down with preserve-fds
fn pass_single_fd_test() -> TestResult {
    // Open this before the setup function so it's kept alive for the container lifetime
    let (_devnull, devnull_fd) = match open_devnull_no_cloexec() {
        Ok(v) => v,
        Err(e) => return TestResult::Failed(anyhow!("failed to open dev null: {}", e)),
    };

    let spec = test_result!(create_spec());
    test_inside_container(
        spec,
        &CreateOptions::default().with_extra_args(&[
            "--preserve-fds".as_ref(),
            (devnull_fd - 2).to_string().as_ref(), // relative to stdio
        ]),
        &|bundle_path| {
            fs::write(bundle_path.join("num-fds"), "1".as_bytes())?;
            Ok(())
        },
    )
}

pub fn get_fd_control_test() -> TestGroup {
    let mut test_group = TestGroup::new("fd_control");
    test_group.set_nonparallel(); // fds are process-wide state
    let test_only_stdio = ConditionalTest::new(
        "only_stdio",
        // runc errors if any of the N passed FDs via preserve-fd are not currently open
        Box::new(|| !is_runtime_runc()),
        Box::new(only_stdio_test),
    );
    let test_closes_fd = Test::new("closes_fd", Box::new(closes_fd_test));
    let test_pass_single_fd = Test::new("pass_single_fd", Box::new(pass_single_fd_test));
    // adding separately as one is conditional test and others are normal
    test_group.add(vec![Box::new(test_only_stdio)]);
    test_group.add(vec![
        Box::new(test_closes_fd),
        Box::new(test_pass_single_fd),
    ]);

    test_group
}
