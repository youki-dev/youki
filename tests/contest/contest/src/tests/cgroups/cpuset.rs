use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use libcgroups::common::DEFAULT_CGROUP_ROOT;
use libcgroups::v2::controller_type::ControllerType;
use libcontainer::utils::PathBufExt;
use oci_spec::runtime::{LinuxBuilder, LinuxCpuBuilder, LinuxResourcesBuilder, Spec, SpecBuilder};
use test_framework::{ConditionalTest, TestGroup, TestResult, assert_result_eq, test_result};

use crate::tests::cgroups::attach_controller;
use crate::utils::test_utils::{CGROUP_ROOT, check_container_created};
use crate::utils::{is_cgroup_v2_with_controller, test_outside_container};

const CPUSET_CPUS: &str = "cpuset.cpus";
const CPUSET_MEMS: &str = "cpuset.mems";

// SPEC: the runtime spec carries the cpuset values as plain strings under the
// cpu resource, and youki writes each one verbatim to the matching cgroup v2
// file. "0" is used for both: CPU 0 and memory node 0 exist on every host
// that has the controller.

fn can_run() -> bool {
    is_cgroup_v2_with_controller(ControllerType::CpuSet)
}

// The leaf cgroup only carries the cpuset.* files once the controller is
// enabled along the path, so the cgroup is created and the controller
// attached before the runtime is invoked, following the setup the cpu tests
// use for cpu.max.
fn prepare_cpuset_cgroup(spec: &Spec) -> Result<()> {
    let cgroups_path = spec
        .linux()
        .as_ref()
        .and_then(|l| l.cgroups_path().as_ref())
        .context("spec has no cgroups path")?;
    let full_cgroup_path = PathBuf::from(DEFAULT_CGROUP_ROOT).join_safely(cgroups_path)?;
    fs::create_dir_all(&full_cgroup_path)
        .with_context(|| format!("could not create cgroup {full_cgroup_path:?}"))?;
    attach_controller(Path::new(DEFAULT_CGROUP_ROOT), cgroups_path, "cpuset")?;

    Ok(())
}

fn create_spec(cgroup_name: &str, case: LinuxCpuBuilder) -> Result<Spec> {
    let case = case.build().context("failed to build cpu spec")?;
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(PathBuf::from("/runtime-test").join(cgroup_name))
                .resources(
                    LinuxResourcesBuilder::default()
                        .cpu(case)
                        .build()
                        .context("failed to build resource spec")?,
                )
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

/// Tests that the cpu list is written to cpuset.cpus
fn test_cpuset_cpus_set() -> TestResult {
    let spec = test_result!(create_spec(
        "test_cpuset_cpus_set",
        LinuxCpuBuilder::default().cpus("0".to_owned()),
    ));
    test_result!(prepare_cpuset_cgroup(&spec));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cgroup_file("test_cpuset_cpus_set", CPUSET_CPUS, "0"));
        TestResult::Passed
    })
}

/// Tests that the memory node list is written to cpuset.mems
fn test_cpuset_mems_set() -> TestResult {
    let spec = test_result!(create_spec(
        "test_cpuset_mems_set",
        LinuxCpuBuilder::default().mems("0".to_owned()),
    ));
    test_result!(prepare_cpuset_cgroup(&spec));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cgroup_file("test_cpuset_mems_set", CPUSET_MEMS, "0"));
        TestResult::Passed
    })
}

/// Tests that a spec carrying both the cpu list and the memory node list
/// writes both files, so a partial application cannot pass unnoticed
fn test_cpuset_cpus_and_mems_set() -> TestResult {
    let spec = test_result!(create_spec(
        "test_cpuset_cpus_and_mems_set",
        LinuxCpuBuilder::default()
            .cpus("0".to_owned())
            .mems("0".to_owned()),
    ));
    test_result!(prepare_cpuset_cgroup(&spec));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        test_result!(check_cgroup_file(
            "test_cpuset_cpus_and_mems_set",
            CPUSET_CPUS,
            "0"
        ));
        test_result!(check_cgroup_file(
            "test_cpuset_cpus_and_mems_set",
            CPUSET_MEMS,
            "0"
        ));
        TestResult::Passed
    })
}

fn check_cgroup_file(cgroup_name: &str, cgroup_file: &str, expected: &str) -> Result<()> {
    let cgroup_path = PathBuf::from(CGROUP_ROOT)
        .join("runtime-test")
        .join(cgroup_name)
        .join(cgroup_file);

    let content = fs::read_to_string(&cgroup_path)
        .with_context(|| format!("failed to read {cgroup_path:?}"))?;
    assert_result_eq!(expected, content.trim(), "unexpected {cgroup_file}")
}

pub fn get_test_group() -> TestGroup {
    let cpuset_cpus_set = ConditionalTest::new(
        "test_cpuset_cpus_set",
        Box::new(can_run),
        Box::new(test_cpuset_cpus_set),
    );

    let cpuset_mems_set = ConditionalTest::new(
        "test_cpuset_mems_set",
        Box::new(can_run),
        Box::new(test_cpuset_mems_set),
    );

    let cpuset_cpus_and_mems_set = ConditionalTest::new(
        "test_cpuset_cpus_and_mems_set",
        Box::new(can_run),
        Box::new(test_cpuset_cpus_and_mems_set),
    );

    let mut test_group = TestGroup::new("cgroup_v2_cpuset");

    test_group.add(vec![
        Box::new(cpuset_cpus_set),
        Box::new(cpuset_mems_set),
        Box::new(cpuset_cpus_and_mems_set),
    ]);

    test_group
}
