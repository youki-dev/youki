use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{
    LinuxBuilder, LinuxPersonalityBuilder, LinuxPersonalityDomain, ProcessBuilder, Spec,
    SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_utils::{
    check_container_created, exec_container, start_container, test_outside_container,
};

fn create_spec(domain: LinuxPersonalityDomain) -> Result<Spec> {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(
                    ["sleep", "1000"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()
                .context("failed to create process")?,
        )
        .linux(
            LinuxBuilder::default()
                .personality(
                    LinuxPersonalityBuilder::default()
                        .domain(domain)
                        .build()
                        .context("failed to create personality")?,
                )
                .build()
                .context("failed to create linux")?,
        )
        .build()
        .context("failed to create spec")
}

fn personality_for_linux(domain: LinuxPersonalityDomain, expect: &str) -> TestResult {
    let spec = test_result!(create_spec(domain));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) = exec_container(id, dir, &["uname", "-m"], None).expect("exec failed");

        if !stdout.contains(expect) {
            return TestResult::Failed(anyhow!("unexpected personality: {}", stdout));
        }

        TestResult::Passed
    })
}

fn personality_for_linux32() -> TestResult {
    personality_for_linux(LinuxPersonalityDomain::PerLinux32, "i686")
}

fn personality_for_linux64() -> TestResult {
    personality_for_linux(LinuxPersonalityDomain::PerLinux, "x86_64")
}

pub fn get_personality_test() -> TestGroup {
    let mut test_group = TestGroup::new("personality");
    let personality_for_linux32 =
        Test::new("personality_for_linux32", Box::new(personality_for_linux32));
    test_group.add(vec![Box::new(personality_for_linux32)]);

    let personality_for_linux64 =
        Test::new("personality_for_linux64", Box::new(personality_for_linux64));
    test_group.add(vec![Box::new(personality_for_linux64)]);

    test_group
}
