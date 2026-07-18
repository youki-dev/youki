use std::path::Path;

use anyhow::{Context, Result};
use oci_spec::runtime::{
    LinuxBuilder, LinuxMemoryBuilder, LinuxResourcesBuilder, Spec, SpecBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_outside_container;
use crate::utils::test_utils::check_container_created;

const CGROUP_MEMORY_LIMIT: &str = "/sys/fs/cgroup/memory/memory.limit_in_bytes";
const CGROUP_MEMORY_SWAPPINESS: &str = "/sys/fs/cgroup/memory/memory.swappiness";

fn create_spec(cgroup_name: &str, limit: i64, swappiness: u64) -> Result<Spec> {
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(Path::new("/runtime-test").join(cgroup_name))
                .resources(
                    LinuxResourcesBuilder::default()
                        .memory(
                            LinuxMemoryBuilder::default()
                                .limit(limit)
                                .swappiness(swappiness)
                                .build()
                                .context("failed to build memory spec")?,
                        )
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

fn test_memory_cgroups() -> TestResult {
    let cgroup_name = "test_memory_cgroups";

    let cases = vec![
        test_result!(create_spec(cgroup_name, 50593792, 10)),
        test_result!(create_spec(cgroup_name, 50593792, 50)),
        test_result!(create_spec(cgroup_name, 50593792, 100)),
        test_result!(create_spec(cgroup_name, 151781376, 10)),
        test_result!(create_spec(cgroup_name, 151781376, 50)),
        test_result!(create_spec(cgroup_name, 151781376, 100)),
    ];

    for spec in cases.into_iter() {
        let test_result = test_outside_container(&spec, &|data| {
            test_result!(check_container_created(&data));

            TestResult::Passed
        });
        if let TestResult::Failed(_) = test_result {
            return test_result;
        }
    }

    TestResult::Passed
}

fn can_run() -> bool {
    Path::new(CGROUP_MEMORY_LIMIT).exists() && Path::new(CGROUP_MEMORY_SWAPPINESS).exists()
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v1_memory");
    let linux_cgroups_memory = ConditionalTest::new(
        "test_linux_cgroups_memory",
        Box::new(can_run),
        Box::new(test_memory_cgroups),
    );

    test_group.add(vec![Box::new(linux_cgroups_memory)]);

    test_group
}
