use std::collections::HashSet;

use anyhow::anyhow;
use oci_spec::runtime::{
    LinuxBuilder, LinuxCapabilitiesBuilder, LinuxSeccompAction, LinuxSeccompBuilder,
    LinuxSyscallBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{TestResult, test_result};

use crate::utils::test_utils::{
    check_container_created, exec_container, start_container, test_outside_container,
};

/// Build a spec with a seccomp filter, an empty capability set, and the given
/// `noNewPrivileges` value (`None` leaves it unset). With no capabilities left after the drop, the
/// filter can only be installed if it is loaded before the capabilities are
/// dropped (the order runc uses when `noNewPrivileges` is not true).
fn create_spec_with_seccomp(no_new_privileges: Option<bool>) -> anyhow::Result<Spec> {
    let no_caps = LinuxCapabilitiesBuilder::default()
        .bounding(HashSet::new())
        .effective(HashSet::new())
        .inheritable(HashSet::new())
        .permitted(HashSet::new())
        .ambient(HashSet::new())
        .build()?;
    let seccomp = LinuxSeccompBuilder::default()
        .default_action(LinuxSeccompAction::ScmpActAllow)
        .syscalls(vec![
            LinuxSyscallBuilder::default()
                .names(vec![String::from("syslog")])
                .action(LinuxSeccompAction::ScmpActErrno)
                .build()?,
        ])
        .build()?;
    let mut process = ProcessBuilder::default()
        .args(vec!["sleep".to_string(), "1000".to_string()])
        .capabilities(no_caps);
    if let Some(no_new_privileges) = no_new_privileges {
        process = process.no_new_privileges(no_new_privileges);
    }
    let spec = SpecBuilder::default()
        .process(process.build()?)
        .linux(LinuxBuilder::default().seccomp(seccomp).build()?)
        .build()?;
    Ok(spec)
}

/// Start a container from `spec`, exec `cat <status_path>`, and check that the
/// process reports `Seccomp: 2` (filter mode) and, when given, the expected `NoNewPrivs`.
fn check_exec_status(spec: &Spec, status_path: &str, expected_nnp: Option<u8>) -> TestResult {
    test_outside_container(spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) = match exec_container(id, dir, &["cat", status_path], None, &[]) {
            Ok(output) => output,
            Err(e) => return TestResult::Failed(e),
        };

        if !stdout.contains("Seccomp:\t2") {
            return TestResult::Failed(anyhow!(
                "{status_path}: expected Seccomp: 2, got: {stdout}"
            ));
        }
        if let Some(expected_nnp) = expected_nnp {
            let nnp = format!("NoNewPrivs:\t{expected_nnp}");
            if !stdout.contains(&nnp) {
                return TestResult::Failed(anyhow!("{status_path}: expected {nnp}, got: {stdout}"));
            }
        }

        TestResult::Passed
    })
}

/// An exec'd process inherits the container's seccomp filter when
/// `noNewPrivileges` is false.
pub(crate) fn get_test_exec_seccomp_without_no_new_privileges() -> TestResult {
    let spec = test_result!(create_spec_with_seccomp(Some(false)));
    check_exec_status(&spec, "/proc/self/status", Some(0))
}

/// An exec'd process inherits the container's seccomp filter when
/// `noNewPrivileges` is true.
pub(crate) fn get_test_exec_seccomp_with_no_new_privileges() -> TestResult {
    let spec = test_result!(create_spec_with_seccomp(Some(true)));
    check_exec_status(&spec, "/proc/self/status", Some(1))
}

/// The container init process has the filter when `noNewPrivileges` is false
/// and all capabilities are dropped. This is the same ordering requirement as
/// the exec case, applied to init.
pub(crate) fn get_test_init_seccomp_without_no_new_privileges() -> TestResult {
    let spec = test_result!(create_spec_with_seccomp(Some(false)));
    check_exec_status(&spec, "/proc/1/status", Some(0))
}

/// An exec'd process inherits the container's seccomp filter when
/// `noNewPrivileges` is unset.
pub(crate) fn get_test_exec_seccomp_with_unset_no_new_privileges() -> TestResult {
    let spec = test_result!(create_spec_with_seccomp(None));
    check_exec_status(&spec, "/proc/self/status", None)
}
