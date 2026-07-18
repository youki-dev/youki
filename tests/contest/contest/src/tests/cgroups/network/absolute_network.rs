use std::path::Path;

use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{
    LinuxBuilder, LinuxInterfacePriorityBuilder, LinuxNamespace, LinuxNamespaceType,
    LinuxNetworkBuilder, LinuxResourcesBuilder, Spec, SpecBuilder,
};
use pnet_datalink::interfaces;
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use super::{check_network_cgroup_paths, validate_network};
use crate::utils::test_outside_container;
use crate::utils::test_utils::check_container_created;

fn create_spec(
    cgroup_name: &str,
    class_id: u32,
    prio: u32,
    if_name: &str,
    with_net_ns: bool,
    with_user_ns: bool,
) -> Result<Spec> {
    // Get default namespaces and filter them to optional exclude network or user namespaces
    let default_namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces()
        .into_iter()
        .filter(|ns| match ns.typ() {
            LinuxNamespaceType::Network => with_net_ns,
            LinuxNamespaceType::User => with_user_ns,
            _ => true,
        })
        .collect();

    // Create the Linux Spec
    let linux_spec = LinuxBuilder::default()
        .cgroups_path(Path::new("/runtime-test").join(cgroup_name))
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
        .namespaces(default_namespaces)
        .build()
        .context("failed to build linux spec")?;

    // Create the top level Spec
    let spec = SpecBuilder::default()
        .linux(linux_spec)
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

// Gets the loopback interface and the first ethernet/wlan interface if it exists
fn get_network_interfaces() -> Option<(String, String)> {
    let interfaces = interfaces();
    let lo_if_name = interfaces.first().map(|iface| &iface.name)?;
    let eth_if_name = interfaces.get(1).map(|iface| &iface.name)?;

    Some((lo_if_name.to_string(), eth_if_name.to_string()))
}

fn test_network_cgroups() -> TestResult {
    let cgroup_name = "test_network_cgroups";

    let interfaces = test_result!(
        get_network_interfaces()
            .ok_or_else(|| anyhow!("Could not find network interfaces required for test"))
    );

    let lo_if_name = &interfaces.0;
    let eth_if_name = &interfaces.1;

    let cases = vec![
        test_result!(create_spec(cgroup_name, 255, 10, lo_if_name, true, true)),
        test_result!(create_spec(cgroup_name, 255, 10, lo_if_name, true, false)),
        test_result!(create_spec(cgroup_name, 255, 10, lo_if_name, false, true)),
        test_result!(create_spec(cgroup_name, 255, 10, lo_if_name, false, false)),
        test_result!(create_spec(cgroup_name, 255, 10, eth_if_name, true, true)),
        test_result!(create_spec(cgroup_name, 255, 10, eth_if_name, true, false)),
        test_result!(create_spec(cgroup_name, 255, 10, eth_if_name, false, true)),
        test_result!(create_spec(cgroup_name, 255, 10, eth_if_name, false, false)),
        test_result!(create_spec(cgroup_name, 255, 30, lo_if_name, true, true)),
        test_result!(create_spec(cgroup_name, 255, 30, lo_if_name, true, false)),
        test_result!(create_spec(cgroup_name, 255, 30, lo_if_name, false, true)),
        test_result!(create_spec(cgroup_name, 255, 30, lo_if_name, false, false)),
        test_result!(create_spec(cgroup_name, 255, 30, eth_if_name, true, true)),
        test_result!(create_spec(cgroup_name, 255, 30, eth_if_name, true, false)),
        test_result!(create_spec(cgroup_name, 255, 30, eth_if_name, false, true)),
        test_result!(create_spec(cgroup_name, 255, 30, eth_if_name, false, false)),
        test_result!(create_spec(cgroup_name, 550, 10, lo_if_name, true, true)),
        test_result!(create_spec(cgroup_name, 550, 10, lo_if_name, true, false)),
        test_result!(create_spec(cgroup_name, 550, 10, lo_if_name, false, true)),
        test_result!(create_spec(cgroup_name, 550, 10, lo_if_name, false, false)),
        test_result!(create_spec(cgroup_name, 550, 10, eth_if_name, true, true)),
        test_result!(create_spec(cgroup_name, 550, 10, eth_if_name, true, false)),
        test_result!(create_spec(cgroup_name, 550, 10, eth_if_name, false, true)),
        test_result!(create_spec(cgroup_name, 550, 10, eth_if_name, false, false)),
        test_result!(create_spec(cgroup_name, 550, 30, lo_if_name, true, true)),
        test_result!(create_spec(cgroup_name, 550, 30, lo_if_name, true, false)),
        test_result!(create_spec(cgroup_name, 550, 30, lo_if_name, false, true)),
        test_result!(create_spec(cgroup_name, 550, 30, lo_if_name, false, false)),
        test_result!(create_spec(cgroup_name, 550, 30, eth_if_name, true, true)),
        test_result!(create_spec(cgroup_name, 550, 30, eth_if_name, true, false)),
        test_result!(create_spec(cgroup_name, 550, 30, eth_if_name, false, true)),
        test_result!(create_spec(cgroup_name, 550, 30, eth_if_name, false, false)),
    ];

    for spec in cases.into_iter() {
        let test_result = test_outside_container(&spec, &|data| {
            test_result!(check_container_created(&data));
            test_result!(validate_network(
                format!("/runtime-test/{}", cgroup_name).as_str(),
                &spec
            ));

            TestResult::Passed
        });
        if let TestResult::Failed(_) = test_result {
            return test_result;
        }
    }

    TestResult::Passed
}

fn can_run() -> bool {
    // Ensure the expected network interfaces exist on the system running the test
    let iface_exists = get_network_interfaces().is_some();

    // This is kind of annoying, network controller can be at a number of mount points
    let cgroup_paths_exists = check_network_cgroup_paths().is_ok();

    iface_exists && cgroup_paths_exists
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v1_network");
    let linux_cgroups_network = ConditionalTest::new(
        "test_linux_cgroups_network",
        Box::new(can_run),
        Box::new(test_network_cgroups),
    );

    test_group.add(vec![Box::new(linux_cgroups_network)]);

    test_group
}
