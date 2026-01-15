use std::collections::HashSet;

use anyhow::anyhow;
use oci_spec::runtime::{Capability, LinuxCapabilitiesBuilder, ProcessBuilder};
use test_framework::{TestResult, test_result};

use crate::utils::test_utils::{
    check_container_created, exec_container, start_container, test_outside_container,
};

// capabilities' bit definition
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h

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

        // The capability sets in the spec were all empty. Thus, the resulting
        // capability sets for the process are all 0.
        // CapInh is the set of inheritable capabilities.
        if !stdout.contains("CapInh:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapInh unexpected output: {}", stdout));
        }
        // CapAmb is the set of ambient capabilities.
        if !stdout.contains("CapAmb:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapAmb unexpected output: {}", stdout));
        }
        // The no_new_privileges flag was set to true in the spec.
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

        // The capability sets are empty, similar to the no_capabilities test.
        if !stdout.contains("CapInh:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapInh unexpected output: {}", stdout));
        }
        if !stdout.contains("CapAmb:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapAmb unexpected output: {}", stdout));
        }
        // no_new_privileges is set to false in the spec, so NoNewPrivs should be 0.
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

        // The inheritable set was empty in the spec, so the CapInh (inheritable capabilities)
        // bitmask for the process is all zeros.
        if !stdout.contains("CapInh:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapInh unexpected output: {}", stdout));
        }
        // The bounding set was configured to only contain CAP_SYS_ADMIN (bit 21).
        // The resulting CapBnd (bounding capabilities) bitmask is 0x200000 (1 << 21).
        if !stdout.contains("CapBnd:\t0000000000200000") {
            return TestResult::Failed(anyhow!("CapBnd unexpected output: {}", stdout));
        }
        // The CapEff (effective capabilities) is derived from the permitted set.
        // The permitted set itself is constrained by the bounding set.
        // Thus, CapEff is also just CAP_SYS_ADMIN, represented by the bitmask 0x200000.
        if !stdout.contains("CapEff:\t0000000000200000") {
            return TestResult::Failed(anyhow!("CapEff unexpected output: {}", stdout));
        }
        // The specified permitted set was {CAP_SYS_ADMIN, CAP_AUDIT_WRITE, ...}, but it
        // is intersected with the bounding set {CAP_SYS_ADMIN}.
        // The resulting CapPrm (permitted capabilities) is just {CAP_SYS_ADMIN},
        // which corresponds to the bitmask 0x200000.
        if !stdout.contains("CapPrm:\t0000000000200000") {
            return TestResult::Failed(anyhow!("CapPrm unexpected output: {}", stdout));
        }
        // The no_new_privileges flag was set to true in the spec.
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

        // The inheritable set was not specified via --cap flags, so it remains empty (0).
        if !stdout.contains("CapInh:\t0000000000000000") {
            return TestResult::Failed(anyhow!("CapInh unexpected output: {}", stdout));
        }
        // The --cap flags add capabilities to the bounding set.
        // CAP_AUDIT_WRITE is bit 29, and CAP_KILL is bit 5.
        // The bitmask is (1 << 29) | (1 << 5) = 0x20000000 | 0x20 = 0x20000020.
        if !stdout.contains("CapBnd:\t0000000020000020") {
            return TestResult::Failed(anyhow!("CapBnd unexpected output: {}", stdout));
        }
        // The --cap flags also add to the effective set.
        if !stdout.contains("CapEff:\t0000000020000020") {
            return TestResult::Failed(anyhow!("CapEff unexpected output: {}", stdout));
        }
        // The --cap flags also add to the permitted set.
        if !stdout.contains("CapPrm:\t0000000020000020") {
            return TestResult::Failed(anyhow!("CapPrm unexpected output: {}", stdout));
        }
        // The ambient set was not specified via --cap flags, so it remains empty (0).
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

        // The inheritable set in the spec contained CAP_CHOWN (bit 0).
        // The bitmask is 1 << 0 = 0x1.
        if !stdout.contains("CapInh:\t0000000000000001") {
            return TestResult::Failed(anyhow!("CapInh unexpected output: {}", stdout));
        }
        // The bounding set contained CAP_SYSLOG (34), CAP_KILL (5), and CAP_CHOWN (0).
        // The bitmask is (1 << 34) | (1 << 5) | (1 << 0) = 0x400000000 | 0x20 | 0x1 = 0x400000021.
        if !stdout.contains("CapBnd:\t0000000400000021") {
            return TestResult::Failed(anyhow!("CapBnd unexpected output: {}", stdout));
        }
        // The effective set is derived from the permitted set {CAP_KILL, CAP_CHOWN}.
        // The bitmask is (1 << 5) | (1 << 0) = 0x20 | 0x1 = 0x21.
        if !stdout.contains("CapEff:\t0000000000000021") {
            return TestResult::Failed(anyhow!("CapEff unexpected output: {}", stdout));
        }
        // The permitted set contained CAP_KILL (5) and CAP_CHOWN (0).
        // The bitmask is (1 << 5) | (1 << 0) = 0x20 | 0x1 = 0x21.
        if !stdout.contains("CapPrm:\t0000000000000021") {
            return TestResult::Failed(anyhow!("CapPrm unexpected output: {}", stdout));
        }
        // The ambient set contained CAP_CHOWN (bit 0). The bitmask is 1 << 0 = 0x1.
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

        // Inheritable and ambient sets are not affected by the --cap flag.
        // It remains CAP_CHOWN (0x1).
        if !stdout.contains("CapInh:\t0000000000000001") {
            return TestResult::Failed(anyhow!("CapInh unexpected output: {}", stdout));
        }
        // The bounding set already contained CAP_SYSLOG, so it remains unchanged.
        // It is still 0x400000021.
        if !stdout.contains("CapBnd:\t0000000400000021") {
            return TestResult::Failed(anyhow!("CapBnd unexpected output: {}", stdout));
        }
        // CAP_SYSLOG (bit 34) is added to the effective set.
        // The new bitmask is 0x21 | (1 << 34) = 0x400000021.
        if !stdout.contains("CapEff:\t0000000400000021") {
            return TestResult::Failed(anyhow!("CapEff unexpected output: {}", stdout));
        }
        // CAP_SYSLOG (bit 34) is added to the permitted set.
        // The new bitmask is 0x21 | (1 << 34) = 0x400000021.
        if !stdout.contains("CapPrm:\t0000000400000021") {
            return TestResult::Failed(anyhow!("CapPrm unexpected output: {}", stdout));
        }
        // Ambient set is not affected by --cap. It remains CAP_CHOWN (0x1).
        if !stdout.contains("CapAmb:\t0000000000000001") {
            return TestResult::Failed(anyhow!("CapAmb unexpected output: {}", stdout));
        }

        TestResult::Passed
    })
}
