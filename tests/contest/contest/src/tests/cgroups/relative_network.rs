use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use oci_spec::runtime::{
    LinuxBuilder, LinuxInterfacePriorityBuilder, LinuxNetworkBuilder, LinuxResourcesBuilder, Spec,
    SpecBuilder,
};
use pnet_datalink::interfaces;
use test_framework::{test_result, ConditionalTest, TestGroup, TestResult};

use crate::utils::test_outside_container;
use crate::utils::test_utils::{check_container_created, CGROUP_ROOT};

fn create_spec(cgroup_name: &str, class_id: u32, prio: u32, if_name: &str) -> Result<Spec> {
    // Create the Linux Spec
    let linux_spec = LinuxBuilder::default()
        .cgroups_path(Path::new("testdir/runtime-test/container").join(cgroup_name))
        .resources(
            LinuxResourcesBuilder::default()
                .network(
                    LinuxNetworkBuilder::default()
                        .class_id(class_id)
                        .priorities(vec![LinuxInterfacePriorityBuilder::default()
                            .name(if_name)
                            .priority(prio)
                            .build()
                            .context("failed to build network interface priority spec")?])
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
    let interfaces = interfaces();
    let lo_if_name = interfaces.first().map(|iface| &iface.name)?;

    Some(lo_if_name.to_string())
}

fn test_relative_network_cgroups() -> TestResult {
    let cgroup_name = "test_relative_network_cgroups";

    let id = 255;
    let prio = 10;
    let if_name = "lo";
    let spec = test_result!(create_spec(cgroup_name, id, prio, if_name));

    test_outside_container(spec.clone(), &|data| {
        test_result!(check_container_created(&data));
        test_result!(validate_network(cgroup_name, &spec));
        TestResult::Passed
    })
}

/// validates the Network structure parsed from /sys/fs/cgroup/net_cls,net_prio with the spec
fn validate_network(cgroup_name: &str, spec: &Spec) -> Result<()> {
    let (net_cls_path, net_prio_path) = if Path::new("/sys/fs/cgroup/net_cls/net_cls.classid")
        .exists()
        && Path::new("/sys/fs/cgroup/net_prio/net_prio.ifpriomap").exists()
    {
        (
            net_cls_path(PathBuf::from(CGROUP_ROOT).join("net_cls"), cgroup_name),
            net_prio_path(PathBuf::from(CGROUP_ROOT).join("net_prio"), cgroup_name),
        )
    } else if Path::new("/sys/fs/cgroup/net_cls,net_prio/net_cls.classid").exists()
        && Path::new("/sys/fs/cgroup/net_cls,net_prio/net_prio.ifpriomap").exists()
    {
        (
            net_cls_path(
                PathBuf::from(CGROUP_ROOT).join("net_cls,net_prio"),
                cgroup_name,
            ),
            net_prio_path(
                PathBuf::from(CGROUP_ROOT).join("net_cls,net_prio"),
                cgroup_name,
            ),
        )
    } else if Path::new("/sys/fs/cgroup/net_prio,net_cls/net_cls.classid").exists()
        && Path::new("/sys/fs/cgroup/net_prio,net_cls/net_prio.ifpriomap").exists()
    {
        (
            net_cls_path(
                PathBuf::from(CGROUP_ROOT).join("net_prio,net_cls"),
                cgroup_name,
            ),
            net_prio_path(
                PathBuf::from(CGROUP_ROOT).join("net_prio,net_cls"),
                cgroup_name,
            ),
        )
    } else {
        return Err(anyhow::anyhow!("Required cgroup paths do not exist"));
    };

    let resources = spec.linux().as_ref().unwrap().resources().as_ref().unwrap();
    let spec_network = resources.network().as_ref().unwrap();

    // Validate net_cls.classid
    let classid_content = fs::read_to_string(&net_cls_path)
        .with_context(|| format!("failed to read {:?}", net_cls_path))?;
    let expected_classid = spec_network.class_id().unwrap();
    let actual_classid: u32 = classid_content
        .trim()
        .parse()
        .with_context(|| format!("could not parse {:?}", classid_content.trim()))?;
    if expected_classid != actual_classid {
        bail!(
            "expected {:?} to contain a classid of {}, but the classid was {}",
            net_cls_path,
            expected_classid,
            actual_classid
        );
    }

    // Validate net_prio.ifpriomap
    let ifpriomap_content = fs::read_to_string(&net_prio_path)
        .with_context(|| format!("failed to read {:?}", net_prio_path))?;
    let expected_priorities = spec_network.priorities().as_ref().unwrap();
    for priority in expected_priorities {
        let expected_entry = format!("{} {}", priority.name(), priority.priority());
        if !ifpriomap_content.contains(&expected_entry) {
            bail!(
                "expected {:?} to contain an entry '{}', but it was not found",
                net_prio_path,
                expected_entry
            );
        }
    }

    Ok(())
}

fn net_cls_path(base_path: PathBuf, cgroup_name: &str) -> PathBuf {
    base_path
        .join("testdir/runtime-test/container")
        .join(cgroup_name)
        .join("net_cls.classid")
}

fn net_prio_path(base_path: PathBuf, cgroup_name: &str) -> PathBuf {
    base_path
        .join("testdir/runtime-test/container")
        .join(cgroup_name)
        .join("net_prio.ifpriomap")
}

fn can_run() -> bool {
    // Ensure the expected network interfaces exist on the system running the test
    let iface_exists = get_loopback_interface().is_some();

    // This is kind of annoying, network controller can be at a number of mount points
    let cgroup_paths_exists = (Path::new("/sys/fs/cgroup/net_cls/net_cls.classid").exists()
        && Path::new("/sys/fs/cgroup/net_prio/net_prio.ifpriomap").exists())
        || (Path::new("/sys/fs/cgroup/net_cls,net_prio/net_cls.classid").exists()
            && Path::new("/sys/fs/cgroup/net_cls,net_prio/net_prio.ifpriomap").exists())
        || (Path::new("/sys/fs/cgroup/net_prio,net_cls/net_cls.classid").exists()
            && Path::new("/sys/fs/cgroup/net_prio,net_cls/net_prio.ifpriomap").exists());

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
