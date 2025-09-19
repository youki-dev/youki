use std::path::Path;

use anyhow::{Context, Result};
use oci_spec::runtime::{
    LinuxBuilder, LinuxInterfacePriorityBuilder, LinuxNetworkBuilder, LinuxResourcesBuilder, Spec,
    SpecBuilder,
};
use pnet_datalink::interfaces;
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use super::{check_network_cgroup_paths, validate_network};
use crate::utils::test_outside_container;
use crate::utils::test_utils::check_container_created;

fn create_spec(cgroup_name: &str, class_id: u32, prio: u32, if_name: &str) -> Result<Spec> {
    // Create the Linux Spec
    let linux_spec = LinuxBuilder::default()
        .cgroups_path(Path::new(cgroup_name))
        .resources(
            LinuxResourcesBuilder::default()
                .network(
                    LinuxNetworkBuilder::default()
                        .class_id(class_id)
                        .priorities(vec![
                            LinuxInterfacePriorityBuilder::default()
                                .name(if_name)
                                .priority(prio)
                                .build()
                                .context("failed to build network interface priority spec")?,
                        ])
                        .build()
                        .context("failed to build network spec")?,
                )
                .build()
                .context("failed to build resource spec")?,
        )
        .build()
        .context("failed to build linux spec")?;

    // Create the top level Spec
    let spec = SpecBuilder::default()
        .linux(linux_spec)
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

// Gets the loopback interface if it exists
fn get_loopback_interface() -> Option<String> {
    interfaces()
        .into_iter()
        .find(|iface| iface.is_loopback())
        .map(|iface| iface.name)
}

fn test_relative_network_cgroups() -> TestResult {
    const CGROUP_NAME: &str = "testdir/runtime-test/container/test_relative_network_cgroups";

    const ID: u32 = 255;
    const PRIO: u32 = 10;
    const IF_NAME: &str = "lo";
    let spec = test_result!(create_spec(CGROUP_NAME, ID, PRIO, IF_NAME));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(validate_network(CGROUP_NAME, &spec));
        TestResult::Passed
    })
}

fn can_run() -> bool {
    // Ensure the expected network interfaces exist on the system running the test
    let iface_exists = get_loopback_interface().is_some();

    // This is kind of annoying, network controller can be at a number of mount points
    let cgroup_paths_exists = check_network_cgroup_paths().is_ok();

    iface_exists && cgroup_paths_exists
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v1_relative_network");
    let linux_cgroups_network = ConditionalTest::new(
        "test_linux_cgroups_relative_network",
        Box::new(can_run),
        Box::new(test_relative_network_cgroups),
    );

    test_group.add(vec![Box::new(linux_cgroups_network)]);

    test_group
}
