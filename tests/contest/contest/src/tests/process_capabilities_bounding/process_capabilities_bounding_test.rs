use std::collections::HashSet;

use anyhow::{Context, Ok, anyhow};
use oci_spec::runtime::{Capability, LinuxCapabilitiesBuilder, ProcessBuilder, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

// Happy path: bounding is unset and the other four sets are
// empty. With the fix for #3434, youki defaults the bounding set to empty and drops it,
// so runtimetest sees all five cap bitmasks as zero in /proc/self/status.
// Without the fix, CapBnd would retain the host's full root bounding set.
fn bounding_dropped_when_unset_test() -> TestResult {
    let spec = test_result!({
        let mut caps = LinuxCapabilitiesBuilder::default()
            .effective(HashSet::new())
            .inheritable(HashSet::new())
            .permitted(HashSet::new())
            .ambient(HashSet::new())
            .build()
            .expect("error in creating capabilities");
        caps.set_bounding(None);

        let process = ProcessBuilder::default()
            .args(vec![
                "runtimetest".to_string(),
                "process_capabilities_bounding_unset".to_string(),
            ])
            .capabilities(caps)
            .build()
            .expect("error in creating process config");

        SpecBuilder::default()
            .process(process)
            .build()
            .context("failed to build spec")
    });
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

// Unhappy path: bounding is unset but inheritable contains CAP_SYS_ADMIN.
// With the fix for #3434, youki drops bounding to empty first, then capset() for the
// non-empty inheritable is rejected by the kernel with EPERM (inheritable
// caps must be in bounding). The test passes if the runtime surfaces EPERM.
fn bounding_unset_with_other_caps_fails_test() -> TestResult {
    let spec = test_result!({
        let mut non_empty = HashSet::new();
        non_empty.insert(Capability::SysAdmin);

        let mut caps = LinuxCapabilitiesBuilder::default()
            .effective(non_empty.clone())
            .inheritable(non_empty.clone())
            .permitted(non_empty)
            .ambient(HashSet::new())
            .build()
            .expect("error in creating capabilities");
        caps.set_bounding(None);

        let process = ProcessBuilder::default()
            .args(vec!["sleep".to_string(), "1s".to_string()])
            .capabilities(caps)
            .build()
            .expect("error in creating process config");

        SpecBuilder::default()
            .process(process)
            .build()
            .context("failed to build spec")
    });
    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()));

    match result {
        TestResult::Failed(e) => {
            let err = format!("{e:?}");
            if err.contains("EPERM")
                || err.contains("Operation not permitted")
                || err.contains("operation not permitted")
            {
                TestResult::Passed
            } else {
                TestResult::Failed(anyhow!("expected EPERM in container error, got: {err}"))
            }
        }
        TestResult::Passed => TestResult::Failed(anyhow!("container start unexpectedly succeeded")),
        TestResult::Skipped => TestResult::Failed(anyhow!("test was skipped unexpectedly")),
    }
}

pub fn get_process_capabilities_bounding_test() -> TestGroup {
    let mut tg = TestGroup::new("process_capabilities_bounding");
    let dropped = Test::new(
        "bounding_dropped_when_unset_test",
        Box::new(bounding_dropped_when_unset_test),
    );
    let fails = Test::new(
        "bounding_unset_with_other_caps_fails_test",
        Box::new(bounding_unset_with_other_caps_fails_test),
    );
    tg.add(vec![Box::new(dropped), Box::new(fails)]);
    tg
}
