use std::collections::HashMap;

use oci_spec::runtime::{LinuxBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec(sysctl: HashMap<String, String>) -> Spec {
    SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .sysctl(sysctl)
                .build()
                .expect("error in building linux config"),
        )
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "sysctl".to_string()])
                .build()
                .expect("error in creating process config"),
        )
        .build()
        .unwrap()
}

fn sysctl_test() -> TestResult {
    let spec = create_spec(HashMap::from([(
        "net.ipv4.ip_forward".to_string(),
        "1".to_string(),
    )]));
    test_inside_container(spec, &CreateOptions::default(), &|_| {
        // As long as the container is created, we expect the kernel parameters to be determined by
        // the spec, so nothing to prepare prior.
        Ok(())
    })
}

pub fn get_sysctl_test() -> TestGroup {
    let mut test_group = TestGroup::new("sysctl");
    let sysctl_test = Test::new("sysctl_test", Box::new(sysctl_test));
    test_group.add(vec![Box::new(sysctl_test)]);

    test_group
}
