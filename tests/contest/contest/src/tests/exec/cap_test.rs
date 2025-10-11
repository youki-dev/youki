use std::collections::HashSet;

use anyhow::anyhow;
use oci_spec::runtime::{Capability, LinuxCapabilitiesBuilder, ProcessBuilder};
use test_framework::{TestResult, test_result};

use crate::utils::test_utils::{
    check_container_created, exec_container, start_container, test_outside_container,
};

pub(crate) fn get_test_no_capabilities() -> TestResult {
    let no_caps = LinuxCapabilitiesBuilder::default()
        .bounding(HashSet::new())
        .effective(HashSet::new())
        .inheritable(HashSet::new())
        .permitted(HashSet::new())
        .ambient(HashSet::new());
    let spec = test_result!(super::create_spec(Some(
        ProcessBuilder::default()
            .no_new_privileges(true)
            .capabilities(no_caps.build().expect("build no caps failed"))
    )));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) =
            exec_container(id, dir, &["cat", "/proc/self/status"], None).expect("exec failed");

        if !stdout.contains("CapInh:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapInh unexpected output: {}", stdout));
        }
        if !stdout.contains("CapAmb:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapAmb unexpected output: {}", stdout));
        }
        if !stdout.contains("NoNewPrivs:\t1") {
            return TestResult::Failed(anyhow!("NoNewPrivs unexpected output: {}", stdout));
        }

        TestResult::Passed
    })
}

pub(crate) fn get_test_new_privileges() -> TestResult {
    let no_caps = LinuxCapabilitiesBuilder::default()
        .bounding(HashSet::new())
        .effective(HashSet::new())
        .inheritable(HashSet::new())
        .permitted(HashSet::new())
        .ambient(HashSet::new());
    let spec = test_result!(super::create_spec(Some(
        ProcessBuilder::default()
            .no_new_privileges(false)
            .capabilities(no_caps.build().expect("build no caps failed"))
    )));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) =
            exec_container(id, dir, &["cat", "/proc/self/status"], None).expect("exec failed");

        if !stdout.contains("CapInh:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapInh unexpected output: {}", stdout));
        }
        if !stdout.contains("CapAmb:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapAmb unexpected output: {}", stdout));
        }
        if !stdout.contains("NoNewPrivs:\t0") {
            return TestResult::Failed(anyhow!("NoNewPrivs unexpected output: {}", stdout));
        }

        TestResult::Passed
    })
}

pub(crate) fn get_test_some_capabilities() -> TestResult {
    let mut bounding = HashSet::new();
    bounding.insert(Capability::SysAdmin);

    let mut permitted = HashSet::new();
    permitted.insert(Capability::SysAdmin);
    permitted.insert(Capability::AuditWrite);
    permitted.insert(Capability::Kill);
    permitted.insert(Capability::NetBindService);

    let caps = LinuxCapabilitiesBuilder::default()
        .bounding(bounding)
        .effective(HashSet::new())
        .inheritable(HashSet::new())
        .permitted(permitted)
        .ambient(HashSet::new());
    let spec = test_result!(super::create_spec(Some(
        ProcessBuilder::default()
            .no_new_privileges(true)
            .capabilities(caps.build().expect("build no caps failed"))
    )));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) =
            exec_container(id, dir, &["cat", "/proc/self/status"], None).expect("exec failed");

        if !stdout.contains("CapInh:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapInh unexpected output: {}", stdout));
        }
        if !stdout.contains("CapBnd:\t0000000000200000") {
            return TestResult::Failed(anyhow!("CapBnd unexpected output: {}", stdout));
        }
        if !stdout.contains("CapEff:\t0000000000200000") {
            return TestResult::Failed(anyhow!("CapEff unexpected output: {}", stdout));
        }
        if !stdout.contains("CapPrm:\t0000000000200000") {
            return TestResult::Failed(anyhow!("CapPrm unexpected output: {}", stdout));
        }
        if !stdout.contains("NoNewPrivs:\t1") {
            return TestResult::Failed(anyhow!("NoNewPrivs unexpected output: {}", stdout));
        }

        TestResult::Passed
    })
}

pub(crate) fn get_test_capabilities_by_flag_case1() -> TestResult {
    let no_caps = LinuxCapabilitiesBuilder::default()
        .bounding(HashSet::new())
        .effective(HashSet::new())
        .inheritable(HashSet::new())
        .permitted(HashSet::new())
        .ambient(HashSet::new());
    let spec = test_result!(super::create_spec(Some(
        ProcessBuilder::default().capabilities(no_caps.build().expect("build no caps failed"))
    )));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) = exec_container(
            id,
            dir,
            &[
                "--cap=CAP_KILL",
                "--cap=CAP_AUDIT_WRITE",
                "cat",
                "/proc/self/status",
            ],
            None,
        )
        .expect("exec failed");

        if !stdout.contains("CapInh:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapInh unexpected output: {}", stdout));
        }
        if !stdout.contains("CapBnd:\t0000000020000020") {
            return TestResult::Failed(anyhow!("CapBnd unexpected output: {}", stdout));
        }
        if !stdout.contains("CapEff:\t0000000020000020") {
            return TestResult::Failed(anyhow!("CapEff unexpected output: {}", stdout));
        }
        if !stdout.contains("CapPrm:\t0000000020000020") {
            return TestResult::Failed(anyhow!("CapPrm unexpected output: {}", stdout));
        }
        if !stdout.contains("CapAmb:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapAmb unexpected output: {}", stdout));
        }

        TestResult::Passed
    })
}

pub(crate) fn get_test_capabilities_by_flag_case2() -> TestResult {
    let mut bounding = HashSet::new();
    bounding.insert(Capability::Kill);
    bounding.insert(Capability::Chown);
    bounding.insert(Capability::Syslog);

    let mut inheritable = HashSet::new();
    inheritable.insert(Capability::Chown);

    let mut permitted = HashSet::new();
    permitted.insert(Capability::Kill);
    permitted.insert(Capability::Chown);

    let mut ambient = HashSet::new();
    ambient.insert(Capability::Chown);

    let caps = LinuxCapabilitiesBuilder::default()
        .bounding(bounding)
        .effective(HashSet::new())
        .inheritable(inheritable)
        .permitted(permitted)
        .ambient(ambient);
    let spec = test_result!(super::create_spec(Some(
        ProcessBuilder::default().capabilities(caps.build().expect("build no caps failed"))
    )));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) =
            exec_container(id, dir, &["cat", "/proc/self/status"], None).expect("exec failed");

        if !stdout.contains("CapInh:\t0000000000000001") {
            return TestResult::Failed(anyhow!("CapInh unexpected output: {}", stdout));
        }
        if !stdout.contains("CapBnd:\t0000000400000021") {
            return TestResult::Failed(anyhow!("CapBnd unexpected output: {}", stdout));
        }
        if !stdout.contains("CapEff:\t0000000000000021") {
            return TestResult::Failed(anyhow!("CapEff unexpected output: {}", stdout));
        }
        if !stdout.contains("CapPrm:\t0000000000000021") {
            return TestResult::Failed(anyhow!("CapPrm unexpected output: {}", stdout));
        }
        if !stdout.contains("CapAmb:\t0000000000000001") {
            return TestResult::Failed(anyhow!("CapAmb unexpected output: {}", stdout));
        }

        let (stdout, _) = exec_container(
            id,
            dir,
            &["--cap=CAP_SYSLOG", "cat", "/proc/self/status"],
            None,
        )
        .expect("exec failed");

        if !stdout.contains("CapInh:\t0000000000000001") {
            return TestResult::Failed(anyhow!("CapInh unexpected output: {}", stdout));
        }
        if !stdout.contains("CapBnd:\t0000000400000021") {
            return TestResult::Failed(anyhow!("CapBnd unexpected output: {}", stdout));
        }
        if !stdout.contains("CapEff:\t0000000400000021") {
            return TestResult::Failed(anyhow!("CapEff unexpected output: {}", stdout));
        }
        if !stdout.contains("CapPrm:\t0000000400000021") {
            return TestResult::Failed(anyhow!("CapPrm unexpected output: {}", stdout));
        }
        if !stdout.contains("CapAmb:\t0000000000000001") {
            return TestResult::Failed(anyhow!("CapAmb unexpected output: {}", stdout));
        }

        TestResult::Passed
    })
}
