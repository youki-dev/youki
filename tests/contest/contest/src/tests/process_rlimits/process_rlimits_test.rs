use anyhow::{Context, Ok, Result};
use nix::sys::resource::{RLIM_INFINITY, Resource, getrlimit};
use oci_spec::runtime::{
    LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, PosixRlimit,
    PosixRlimitBuilder, PosixRlimitType, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

const GIGABYTES: u64 = 1024 * 1024 * 1024;

fn create_rlimit(
    rlimit_type: PosixRlimitType,
    hard_val: u64,
    soft_val: u64,
) -> Result<PosixRlimit> {
    let rlimit = PosixRlimitBuilder::default()
        .typ(rlimit_type)
        .hard(hard_val)
        .soft(soft_val)
        .build()?;
    Ok(rlimit)
}

#[allow(clippy::identity_op)]
fn create_spec() -> Result<Spec> {
    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec![
                    "runtimetest".to_string(),
                    "process_rlimits".to_string(),
                ])
                .rlimits(vec![
                    create_rlimit(PosixRlimitType::RlimitAs, 2 * GIGABYTES, 1 * GIGABYTES).unwrap(),
                    create_rlimit(PosixRlimitType::RlimitCore, 4 * GIGABYTES, 3 * GIGABYTES)
                        .unwrap(),
                    create_rlimit(PosixRlimitType::RlimitData, 6 * GIGABYTES, 5 * GIGABYTES)
                        .unwrap(),
                    create_rlimit(PosixRlimitType::RlimitFsize, 8 * GIGABYTES, 7 * GIGABYTES)
                        .unwrap(),
                    create_rlimit(PosixRlimitType::RlimitStack, 10 * GIGABYTES, 9 * GIGABYTES)
                        .unwrap(),
                    create_rlimit(PosixRlimitType::RlimitCpu, 120, 60).unwrap(),
                    create_rlimit(PosixRlimitType::RlimitNofile, 4000, 3000).unwrap(),
                ])
                .build()
                .expect("error in creating process config"),
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn process_rlimits_test() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn create_raised_nproc_rlimit() -> Result<Option<PosixRlimit>> {
    let (soft, hard) = getrlimit(Resource::RLIMIT_NPROC)?;
    if hard == RLIM_INFINITY {
        return Ok(None);
    }
    create_rlimit(PosixRlimitType::RlimitNproc, hard + 1, soft).map(Some)
}

fn create_userns_spec(rlimit: PosixRlimit) -> Result<Spec> {
    let mut namespaces = oci_spec::runtime::get_default_namespaces();
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()?,
    );
    let id_mapping = LinuxIdMappingBuilder::default()
        .host_id(100000_u32)
        .container_id(0_u32)
        .size(65536_u32)
        .build()?;

    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .namespaces(namespaces)
                .uid_mappings(vec![id_mapping])
                .gid_mappings(vec![id_mapping])
                .build()?,
        )
        .process(
            ProcessBuilder::default()
                .args(vec![
                    "runtimetest".to_string(),
                    "process_rlimits".to_string(),
                ])
                .rlimits(vec![rlimit])
                .build()?,
        )
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

// Regression test: with a user namespace, a hard limit above the host's one
// used to fail with EPERM because youki called setrlimit(2) after entering
// the user namespace.
fn process_rlimits_userns_raise_hard_test() -> TestResult {
    let Some(rlimit) = test_result!(create_raised_nproc_rlimit()) else {
        return TestResult::Skipped("RLIMIT_NPROC hard limit is already unlimited".to_string());
    };
    let spec = test_result!(create_userns_spec(rlimit));
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_process_rlimits_test() -> TestGroup {
    let mut process_rlimits_test_group = TestGroup::new("process_rlimits");

    let test = Test::new("process_rlimits_test", Box::new(process_rlimits_test));
    let userns_raise_hard_test = Test::new(
        "process_rlimits_userns_raise_hard_test",
        Box::new(process_rlimits_userns_raise_hard_test),
    );
    process_rlimits_test_group.add(vec![Box::new(test), Box::new(userns_raise_hard_test)]);

    process_rlimits_test_group
}
