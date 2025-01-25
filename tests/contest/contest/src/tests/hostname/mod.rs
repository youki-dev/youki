use oci_spec::runtime::{LinuxBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec(hostname: &str) -> Spec {
    SpecBuilder::default()
        .hostname(hostname)
        .linux(
            // Need to reset the read-only paths
            LinuxBuilder::default()
                .readonly_paths(vec![])
                .build()
                .expect("error in building linux config"),
        )
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "set_host_name".to_string()])
                .build()
                .expect("error in creating process config"),
        )
        .build()
        .unwrap()
}

fn hostname_test() -> TestResult {
    let spec = create_spec("hostname-specific");
    test_inside_container(spec, &CreateOptions::default(), &|_| {
        // As long as the container is created, we expect the hostname to be determined
        // by the spec, so nothing to prepare prior.
        Ok(())
    })
}

fn empty_hostname() -> TestResult {
    let spec = create_spec("");
    test_inside_container(spec, &CreateOptions::default(), &|_| {
        // As long as the container is created, we expect the hostname to be determined
        // by the spec, so nothing to prepare prior.
        Ok(())
    })
}

pub fn get_hostname_test() -> TestGroup {
    let mut test_group = TestGroup::new("set_host_name");
    let hostname_test = Test::new("set_host_name_test", Box::new(hostname_test));
    let empty_hostname_test = Test::new("set_empty_host_name_test", Box::new(empty_hostname));
    test_group.add(vec![Box::new(hostname_test), Box::new(empty_hostname_test)]);

    test_group
}
