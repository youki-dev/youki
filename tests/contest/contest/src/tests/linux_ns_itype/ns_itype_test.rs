use anyhow::anyhow;
use oci_spec::runtime::{LinuxBuilder, Spec, SpecBuilder};
use procfs::process::Process;
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_outside_container;

// get spec for the test
fn get_spec() -> Spec {
    let mut r = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .namespaces(
                    // we have to remove all namespaces, so we directly
                    // provide an empty vec here
                    vec![],
                )
                // if these both are not empty, we cannot set a inherited
                // mnt namespace, as these both require a private mnt namespace
                .masked_paths(vec![])
                .readonly_paths(vec![])
                .build()
                .expect("could not build spec"),
        )
        .build()
        .unwrap();
    // We need to remove hostname to avoid test failures when not creating UTS namespace
    r.set_hostname(None);
    r
}

fn get_test(test_name: &'static str) -> Test {
    Test::new(
        test_name,
        Box::new(move || {
            let host_proc = Process::myself().expect("error in getting /proc/self");
            let host_namespaces = match host_proc.namespaces() {
                Ok(n) => n,
                Err(e) => {
                    return TestResult::Failed(anyhow!(
                        "error in resolving host namespaces : {}",
                        e
                    ));
                }
            };
            let spec = get_spec();
            test_outside_container(&spec, &move |data| {
                let pid = match data.state {
                    Some(s) => s.pid.unwrap(),
                    None => return TestResult::Failed(anyhow!("state command returned error")),
                };
                let container_process =
                    Process::new(pid).expect("error in getting /proc for container process");
                let container_namespaces = container_process
                    .namespaces()
                    .expect("error in getting namespaces of container process");
                if container_namespaces != host_namespaces {
                    return TestResult::Failed(anyhow!(
                        "error : namespaces are not correctly inherited"
                    ));
                }
                TestResult::Passed
            })
        }),
    )
}

pub fn get_ns_itype_tests() -> TestGroup {
    let mut tg = TestGroup::new("ns_itype");
    let tests: Vec<_> = vec![Box::new(get_test("ns_itype"))];
    tg.add(tests);
    tg
}
