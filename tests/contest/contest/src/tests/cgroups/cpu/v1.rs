use std::path::Path;

use libcgroups::common;
use num_cpus;
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use super::{create_cpu_spec, create_empty_spec, create_spec};
use crate::utils::test_outside_container;
use crate::utils::test_utils::check_container_created;

const CPU_CGROUP_PREFIX: &str = "/sys/fs/cgroup/cpu,cpuacct";
const DEFAULT_REALTIME_PERIOD: u64 = 1000000;
const DEFAULT_REALTIME_RUNTIME: i64 = 950000;

fn get_realtime_period() -> Option<u64> {
    if Path::new(CPU_CGROUP_PREFIX)
        .join("cpu.rt_period_us")
        .exists()
    {
        return Some(DEFAULT_REALTIME_PERIOD);
    }
    None
}

fn get_realtime_runtime() -> Option<i64> {
    if Path::new(CPU_CGROUP_PREFIX)
        .join("cpu.rt_runtime_us")
        .exists()
    {
        return Some(DEFAULT_REALTIME_RUNTIME);
    }
    None
}

fn test_cpu_cgroups() -> TestResult {
    let cgroup_name = "test_cpu_cgroups";
    // Kernel counts 0 as a CPU, so on a system with 8 logical cores you will need `0-7` range set.
    let cpu_range = format!("0-{}", num_cpus::get().saturating_sub(1));

    let realtime_period = get_realtime_period();
    let realtime_runtime = get_realtime_runtime();

    let cases = vec![
        test_result!(create_cpu_spec(
            1024,
            100000,
            50000,
            None,
            "0",
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            1024,
            100000,
            50000,
            None,
            &cpu_range,
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            1024,
            100000,
            200000,
            None,
            "0",
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            1024,
            100000,
            200000,
            None,
            &cpu_range,
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            1024,
            500000,
            50000,
            None,
            "0",
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            1024,
            500000,
            50000,
            None,
            &cpu_range,
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            1024,
            500000,
            200000,
            None,
            "0",
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            1024,
            500000,
            200000,
            None,
            &cpu_range,
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            2048,
            100000,
            50000,
            None,
            "0",
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            2048,
            100000,
            50000,
            None,
            &cpu_range,
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            2048,
            100000,
            200000,
            None,
            "0",
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            2048,
            100000,
            200000,
            None,
            &cpu_range,
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            2048,
            500000,
            50000,
            None,
            "0",
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            2048,
            500000,
            50000,
            None,
            &cpu_range,
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            2048,
            500000,
            200000,
            None,
            "0",
            "0",
            realtime_period,
            realtime_runtime,
        )),
        test_result!(create_cpu_spec(
            2048,
            500000,
            200000,
            None,
            &cpu_range,
            "0",
            realtime_period,
            realtime_runtime,
        )),
    ];

    for case in cases.into_iter() {
        let spec = test_result!(create_spec(cgroup_name, case));
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

fn test_empty_cpu() -> TestResult {
    let cgroup_name = "test_empty_cpu";
    let spec = test_result!(create_empty_spec(cgroup_name));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        TestResult::Passed
    })
}

// Tests if a cpu idle value can be set
fn test_cpu_idle_set() -> TestResult {
    let idle: i64 = 1;
    let realtime_period = get_realtime_period();
    let realtime_runtime = get_realtime_runtime();

    let cgroup_name = "test_cpu_idle_set";

    let cpu = test_result!(create_cpu_spec(
        2048,
        500000,
        200000,
        Some(idle),
        "0",
        "0",
        realtime_period,
        realtime_runtime,
    ));

    let spec = test_result!(create_spec(cgroup_name, cpu));
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        TestResult::Passed
    })
}

/// Tests default idle value
fn test_cpu_idle_default() -> TestResult {
    let realtime_period = get_realtime_period();
    let realtime_runtime = get_realtime_runtime();

    let cgroup_name = "test_cpu_idle_default";

    let cpu = test_result!(create_cpu_spec(
        2048,
        500000,
        200000,
        None,
        "0",
        "0",
        realtime_period,
        realtime_runtime,
    ));
    let spec = test_result!(create_spec(cgroup_name, cpu));
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        TestResult::Passed
    })
}

fn can_run() -> bool {
    Path::new(CPU_CGROUP_PREFIX).exists()
}

fn can_run_idle() -> bool {
    const CPU: &str = "cpu";
    const CGROUP_CPU_IDLE: &str = "cpu.idle";
    let idle_path = Path::new(common::DEFAULT_CGROUP_ROOT)
        .join(CPU)
        .join(CGROUP_CPU_IDLE);
    can_run() && idle_path.exists()
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v1_cpu");
    let linux_cgroups_cpus = ConditionalTest::new(
        "test_linux_cgroups_cpus",
        Box::new(can_run),
        Box::new(test_cpu_cgroups),
    );

    let empty_cpu = ConditionalTest::new(
        "test_empty_cpu",
        Box::new(can_run),
        Box::new(test_empty_cpu),
    );

    let cpu_idle_default = ConditionalTest::new(
        "test_cpu_idle_default",
        Box::new(can_run_idle),
        Box::new(test_cpu_idle_default),
    );

    let cpu_idle_set = ConditionalTest::new(
        "test_cpu_idle_set",
        Box::new(can_run_idle),
        Box::new(test_cpu_idle_set),
    );

    test_group.add(vec![
        Box::new(linux_cgroups_cpus),
        Box::new(empty_cpu),
        Box::new(cpu_idle_set),
        Box::new(cpu_idle_default),
    ]);

    test_group
}
