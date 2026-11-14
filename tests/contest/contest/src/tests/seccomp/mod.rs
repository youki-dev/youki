use oci_spec::runtime::{
    Capabilities, Capability, LinuxBuilder, LinuxCapabilitiesBuilder, LinuxSeccomp,
    LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder, ProcessBuilder, Spec,
    SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec(seccomp: LinuxSeccomp, check: &str) -> Spec {
    SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .seccomp(seccomp)
                .build()
                .expect("error in building linux config"),
        )
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), check.to_string()])
                .build()
                .expect("error in creating process config"),
        )
        .build()
        .unwrap()
}

fn denied(syscall: &str) -> LinuxSeccomp {
    LinuxSeccompBuilder::default()
        .default_action(LinuxSeccompAction::ScmpActAllow)
        .syscalls(vec![
            LinuxSyscallBuilder::default()
                .names(vec![String::from(syscall)])
                .action(LinuxSeccompAction::ScmpActErrno)
                .build()
                .unwrap(),
        ])
        .build()
        .unwrap()
}

fn seccomp_test() -> TestResult {
    let spec = create_spec(denied("getcwd"), "seccomp");
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn seccomp_without_sys_admin_test(no_new_privileges: Option<bool>) -> TestResult {
    let mut spec = create_spec(denied("getpriority"), "seccomp_getpriority");
    let unprivileged = [
        Capability::AuditWrite,
        Capability::Kill,
        Capability::NetBindService,
    ]
    .into_iter()
    .collect::<Capabilities>();
    let capabilities = LinuxCapabilitiesBuilder::default()
        .bounding(unprivileged.clone())
        .effective(unprivileged.clone())
        .inheritable(unprivileged.clone())
        .permitted(unprivileged.clone())
        .ambient(unprivileged)
        .build()
        .expect("error in creating capabilities");
    let mut process = spec.process().clone().unwrap();
    process.set_capabilities(Some(capabilities));
    process.set_no_new_privileges(no_new_privileges);
    spec.set_process(Some(process));
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_seccomp_test() -> TestGroup {
    let mut test_group = TestGroup::new("seccomp");
    let seccomp_test = Test::new("seccomp_test", Box::new(seccomp_test));
    let unset = Test::new(
        "seccomp_without_sys_admin_no_new_privileges_unset",
        Box::new(|| seccomp_without_sys_admin_test(None)),
    );
    let explicit_false = Test::new(
        "seccomp_without_sys_admin_no_new_privileges_false",
        Box::new(|| seccomp_without_sys_admin_test(Some(false))),
    );
    let explicit_true = Test::new(
        "seccomp_without_sys_admin_no_new_privileges_true",
        Box::new(|| seccomp_without_sys_admin_test(Some(true))),
    );
    test_group.add(vec![
        Box::new(seccomp_test),
        Box::new(unset),
        Box::new(explicit_false),
        Box::new(explicit_true),
    ]);

    test_group
}
