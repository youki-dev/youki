use anyhow::{Context, Ok, Result, anyhow};
use oci_spec::runtime::{
    LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespace, LinuxNamespaceType, ProcessBuilder, Spec,
    SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult, test_result};

mod util;
use crate::tests::time_ns::util::{TimeOffsets, create_time_offset};
use crate::utils::test_utils::CreateOptions;
use crate::utils::{
    exec_container, start_container, test_inside_container, test_outside_container,
};

fn create_spec_for_set_times() -> Result<Spec> {
    let mut default_namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces();
    default_namespaces.push(
        LinuxNamespace::default()
            .set_typ(LinuxNamespaceType::Time)
            .to_owned(),
    );

    let time_offsets = create_time_offset(&TimeOffsets {
        boottime_secs: 1337,
        boottime_nanosecs: 3141519,
        monotonic_secs: 7881,
        monotonic_nanosecs: 2718281,
    });

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(
                    ["runtimetest", "time_offsets"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?,
        )
        .linux(
            LinuxBuilder::default()
                .time_offsets(time_offsets)
                .namespaces(default_namespaces)
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn create_spec_for_set_times_sleep_infinity(offsets: &TimeOffsets) -> Result<Spec> {
    let mut default_namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces();
    default_namespaces.push(
        LinuxNamespace::default()
            .set_typ(LinuxNamespaceType::Time)
            .to_owned(),
    );

    let time_offsets = create_time_offset(offsets);

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "infinity".to_string()])
                .build()
                .unwrap(),
        )
        .linux(
            LinuxBuilder::default()
                .time_offsets(time_offsets)
                .namespaces(default_namespaces)
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn create_spec_for_timens_no_offsets() -> Result<Spec> {
    let mut default_namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces();
    default_namespaces.push(
        LinuxNamespace::default()
            .set_typ(LinuxNamespaceType::Time)
            .to_owned(),
    );

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(
                    ["runtimetest", "time_offsets"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?,
        )
        .linux(
            LinuxBuilder::default()
                .namespaces(default_namespaces)
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn create_spec_for_set_times_plus_userns() -> Result<Spec> {
    let mut default_namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces();
    default_namespaces.push(
        LinuxNamespace::default()
            .set_typ(LinuxNamespaceType::Time)
            .to_owned(),
    );

    default_namespaces.push(
        LinuxNamespace::default()
            .set_typ(LinuxNamespaceType::User)
            .to_owned(),
    );

    let id_mapping = LinuxIdMappingBuilder::default()
        .host_id(100000_u32)
        .container_id(0_u32)
        .size(65534_u32)
        .build()
        .expect("error in building LinuxIdMapping");

    let gid_mapping = LinuxIdMappingBuilder::default()
        .host_id(200000_u32)
        .container_id(0_u32)
        .size(65534_u32)
        .build()
        .expect("error in building LinuxIdMapping");

    let time_offsets = create_time_offset(&TimeOffsets {
        boottime_secs: 1337,
        boottime_nanosecs: 3141519,
        monotonic_secs: 7881,
        monotonic_nanosecs: 2718281,
    });

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(
                    ["runtimetest", "time_offsets"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?,
        )
        .linux(
            LinuxBuilder::default()
                .time_offsets(time_offsets)
                .namespaces(default_namespaces)
                .uid_mappings(vec![id_mapping])
                .gid_mappings(vec![gid_mapping])
                .build()?,
        )
        .build()
        .context("failed to create spec")
}

fn set_times_test() -> TestResult {
    let spec = test_result!(create_spec_for_set_times());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn timens_no_offsets_test() -> TestResult {
    let spec = test_result!(create_spec_for_timens_no_offsets());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn timens_and_userns_test() -> TestResult {
    let spec = test_result!(create_spec_for_set_times_plus_userns());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn set_times_and_exec_into_container_test() -> TestResult {
    let boottime_secs = 1337;
    let monotonic_secs = 7881;
    let spec = test_result!(create_spec_for_set_times_sleep_infinity(&TimeOffsets {
        boottime_secs,
        boottime_nanosecs: 0,
        monotonic_secs,
        monotonic_nanosecs: 0,
    }));

    test_outside_container(&spec, &|data| {
        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) = exec_container(id, dir, &["cat", "/proc/self/timens_offsets"], None)
            .expect("exec failed");

        if !stdout.contains(&boottime_secs.to_string())
            || !stdout.contains(&monotonic_secs.to_string())
        {
            return TestResult::Failed(anyhow!("unexpected : {}", stdout));
        }

        TestResult::Passed
    })
}

pub fn get_time_ns_test() -> TestGroup {
    let mut test_group = TestGroup::new("time_ns");
    let test1 = Test::new("simple timens", Box::new(set_times_test));
    let test2 = Test::new("timens with no offsets", Box::new(timens_no_offsets_test));
    let test3 = Test::new("simple timens + userns", Box::new(timens_and_userns_test));
    let test4 = Test::new(
        "simple timens + exec",
        Box::new(set_times_and_exec_into_container_test),
    );
    test_group.add(vec![
        Box::new(test1),
        Box::new(test2),
        Box::new(test3),
        Box::new(test4),
    ]);

    test_group
}
