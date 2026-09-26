use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use libcgroups::v2::controller_type::ControllerType;
use oci_spec::runtime::{
    LinuxBuilder, LinuxHugepageLimitBuilder, LinuxResourcesBuilder, Spec, SpecBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_utils::{CGROUP_ROOT, check_container_created};
use crate::utils::{cgroup_has_file, is_cgroup_v2_with_controller, test_outside_container};

const HUGE_TLB_RSVD: &str = "rsvd";

// SPEC: the runtime spec does not state how hugepage limits map onto the
// cgroup v2 interface. youki follows runc here: the limit is written to
// hugetlb.<size>.max, and hugetlb.<size>.rsvd.max gets the same value when
// the kernel provides that file. The page sizes come from
// /sys/kernel/mm/hugepages, which is kernel-wide and does not change
// between cgroup versions.

fn can_run() -> bool {
    is_cgroup_v2_with_controller(ControllerType::HugeTlb)
}

fn can_run_rsvd() -> bool {
    if !can_run() {
        return false;
    }

    // hugetlb.<size>.rsvd.max is written only when it exists, so every
    // supported page size must provide it before the test can assert it.
    get_tlb_sizes()
        .iter()
        .all(|size| cgroup_has_file(&format!("hugetlb.{size}.{HUGE_TLB_RSVD}.max")))
}

fn make_hugetlb_spec(cgroup_name: &str, page_size: &str, limit: i64) -> Result<Spec> {
    let spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(PathBuf::from("/runtime-test").join(cgroup_name))
                .resources(
                    LinuxResourcesBuilder::default()
                        .hugepage_limits(vec![
                            LinuxHugepageLimitBuilder::default()
                                .page_size(page_size.to_owned())
                                .limit(limit)
                                .build()
                                .context("could not build hugepage limit")?,
                        ])
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

/// Tests that a page size that is not a power of 2 is rejected
fn test_wrong_tlb() -> TestResult {
    // 3 MB pagesize is wrong, as valid values must be a power of 2
    let page = "3MB";
    let limit = 100 * 3 * 1024 * 1024;
    let spec = test_result!(make_hugetlb_spec("test_invalid_tlb", page, limit));
    test_outside_container(&spec, &|data| {
        match data.create_result {
            Err(e) => TestResult::Failed(anyhow!(e)),
            Ok(res) => {
                if data.state.is_some() {
                    return TestResult::Failed(anyhow!(
                        "stdout of state command was non-empty : {:?}",
                        data.state
                    ));
                }
                if data.state_err.is_empty() {
                    return TestResult::Failed(anyhow!("stderr of state command was empty"));
                }
                if res.success() {
                    // The operation should not have succeeded as pagesize was not power of 2
                    TestResult::Failed(anyhow!("invalid page size of {} was allowed", page))
                } else {
                    TestResult::Passed
                }
            }
        }
    })
}

fn extract_page_size(dir_name: &str) -> Option<String> {
    let name_stripped = dir_name.strip_prefix("hugepages-")?;
    let size = name_stripped.strip_suffix("kB")?;
    let size: u64 = size.parse().ok()?;

    if size >= (1 << 20) {
        Some((size >> 20).to_string() + "GB")
    } else if size >= (1 << 10) {
        Some((size >> 10).to_string() + "MB")
    } else {
        Some(size.to_string() + "KB")
    }
}

fn get_tlb_sizes() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/sys/kernel/mm/hugepages") else {
        // No hugepage support in the running kernel, nothing to test.
        return Vec::new();
    };

    entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| extract_page_size(entry.file_name().to_str()?))
        .collect()
}

fn read_cgroup_data(cgroup_name: &str, cgroup_file: &str) -> Result<String> {
    let cgroup_path = PathBuf::from(CGROUP_ROOT)
        .join("runtime-test")
        .join(cgroup_name)
        .join(cgroup_file);

    let content = std::fs::read_to_string(&cgroup_path)
        .with_context(|| format!("failed to read {cgroup_path:?}"))?;
    Ok(content.trim().to_owned())
}

fn validate_tlb(cgroup_name: &str, size: &str, limit: i64) -> Result<()> {
    let path = format!("hugetlb.{size}.max");
    let val_str = read_cgroup_data(cgroup_name, &path)?;
    let val: i64 = val_str
        .parse()
        .with_context(|| format!("failed to parse {val_str:?}"))?;
    if val == limit {
        Ok(())
    } else {
        Err(anyhow!(
            "page limit not set correctly : for size {}, expected {}, got {}",
            size,
            limit,
            val
        ))
    }
}

fn validate_rsvd_tlb(cgroup_name: &str, size: &str, limit: i64) -> Result<()> {
    let path = format!("hugetlb.{size}.{HUGE_TLB_RSVD}.max");
    let val_str = read_cgroup_data(cgroup_name, &path)?;
    let val: i64 = val_str
        .parse()
        .with_context(|| format!("failed to parse {val_str:?}"))?;
    if val == limit {
        Ok(())
    } else {
        Err(anyhow!(
            "page limit not set correctly : for size {}, expected {}, got {}",
            size,
            limit,
            val
        ))
    }
}

/// Tests that a hugepage limit is written to hugetlb.<size>.max
fn test_valid_tlb() -> TestResult {
    // When setting the limit just for checking if writing works, the amount of memory
    // requested does not matter, as all unsigned integers will be accepted.
    // Use 1GiB as an example
    let limit: i64 = 1 << 30;
    let tlb_sizes = get_tlb_sizes();
    for size in tlb_sizes.iter() {
        let spec = test_result!(make_hugetlb_spec("test_valid_tlb", size, limit));
        let res = test_outside_container(&spec, &|data| {
            test_result!(check_container_created(&data));

            test_result!(validate_tlb("test_valid_tlb", size, limit));
            TestResult::Passed
        });
        if matches!(res, TestResult::Failed(_)) {
            return res;
        }
    }
    TestResult::Passed
}

/// Tests that the same limit is written to hugetlb.<size>.rsvd.max
fn test_valid_rsvd_tlb() -> TestResult {
    let limit: i64 = 1 << 30;
    let tlb_sizes = get_tlb_sizes();
    for size in tlb_sizes.iter() {
        let spec = test_result!(make_hugetlb_spec("test_valid_rsvd_tlb", size, limit));
        let res = test_outside_container(&spec, &|data| {
            test_result!(check_container_created(&data));
            // The same value is written to both hugetlb.<size>.max and
            // hugetlb.<size>.rsvd.max, so both must hold the limit.
            test_result!(validate_tlb("test_valid_rsvd_tlb", size, limit));
            test_result!(validate_rsvd_tlb("test_valid_rsvd_tlb", size, limit));
            TestResult::Passed
        });
        if matches!(res, TestResult::Failed(_)) {
            return res;
        }
    }
    TestResult::Passed
}

pub fn get_hugetlb_test() -> TestGroup {
    let wrong_tlb =
        ConditionalTest::new("invalid_tlb", Box::new(can_run), Box::new(test_wrong_tlb));
    let valid_tlb = ConditionalTest::new("valid_tlb", Box::new(can_run), Box::new(test_valid_tlb));
    let valid_rsvd_tlb = ConditionalTest::new(
        "valid_rsvd_tlb",
        Box::new(can_run_rsvd),
        Box::new(test_valid_rsvd_tlb),
    );
    let mut tg = TestGroup::new("cgroup_v2_hugetlb");
    tg.add(vec![
        Box::new(wrong_tlb),
        Box::new(valid_tlb),
        Box::new(valid_rsvd_tlb),
    ]);
    tg
}
