use anyhow::{Context, Ok, Result};
use oci_spec::runtime::{
    Capability, LinuxBuilder, LinuxCapabilitiesBuilder, LinuxSeccompBuilder, ProcessBuilder,
    RootBuilder, Spec, SpecBuilder,
};
use test_framework::{test_result, ConditionalTest, TestGroup, TestResult};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{is_runtime_runc, test_inside_container};

fn create_spec(propagation: String) -> Result<Spec> {
    let root = RootBuilder::default()
        .readonly(false)
        .build()
        .context("failed to build root")?;

    let capabilities = LinuxCapabilitiesBuilder::default()
        .bounding([Capability::SysAdmin])
        .effective([Capability::SysAdmin])
        .inheritable([Capability::SysAdmin])
        .permitted([Capability::SysAdmin])
        .ambient([Capability::SysAdmin])
        .build()
        .context("failed to build linux capabilities")?;

    let process = ProcessBuilder::default()
        .args(vec![
            "runtimetest".to_string(),
            "rootfs_propagation".to_string(),
        ])
        .capabilities(capabilities)
        .build()
        .context("failed to build process")?;

    let seccomp = LinuxSeccompBuilder::default()
        .build()
        .context("failed to build seccomp")?;

    let linux = LinuxBuilder::default()
        .rootfs_propagation(propagation)
        .seccomp(seccomp)
        .build()
        .context("failed to build linux spec")?;

    let spec = SpecBuilder::default()
        .root(root)
        .linux(linux)
        .process(process)
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn rootfs_propagation_shared_test() -> TestResult {
    let spec = test_result!(create_spec("shared".to_string()));
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn rootfs_propagation_slave_test() -> TestResult {
    let spec = test_result!(create_spec("slave".to_string()));
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn rootfs_propagation_private_test() -> TestResult {
    let spec = test_result!(create_spec("private".to_string()));
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn rootfs_propagation_unbindable_test() -> TestResult {
    let spec = test_result!(create_spec("unbindable".to_string()));
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_rootfs_propagation_test() -> TestGroup {
    let mut rootfs_propagation_test_group = TestGroup::new("rootfs_propagation");

    let rootfs_propagation_shared_test = ConditionalTest::new(
        "rootfs_propagation_shared_test",
        Box::new(|| !is_runtime_runc()),
        Box::new(rootfs_propagation_shared_test),
    );
    let rootfs_propagation_slave_test = ConditionalTest::new(
        "rootfs_propagation_slave_test",
        Box::new(|| true),
        Box::new(rootfs_propagation_slave_test),
    );
    let rootfs_propagation_private_test = ConditionalTest::new(
        "rootfs_propagation_private_test",
        Box::new(|| true),
        Box::new(rootfs_propagation_private_test),
    );
    let rootfs_propagation_unbindable_test = ConditionalTest::new(
        "rootfs_propagation_unbindable_test",
        Box::new(|| !is_runtime_runc()),
        Box::new(rootfs_propagation_unbindable_test),
    );
    rootfs_propagation_test_group.add(vec![
        Box::new(rootfs_propagation_shared_test),
        Box::new(rootfs_propagation_slave_test),
        Box::new(rootfs_propagation_private_test),
        Box::new(rootfs_propagation_unbindable_test),
    ]);

    rootfs_propagation_test_group
}
