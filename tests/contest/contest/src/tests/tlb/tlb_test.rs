use std::path::PathBuf;

use anyhow::anyhow;
use oci_spec::runtime::{
    LinuxBuilder, LinuxHugepageLimitBuilder, LinuxResourcesBuilder, Spec, SpecBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_outside_container;
use crate::utils::test_utils::check_container_created;

fn check_hugetlb() -> bool {
    PathBuf::from("/sys/fs/cgroup/hugetlb").exists()
}

fn check_hugetlb_rsvd() -> bool {
    let sizes = get_tlb_sizes();
    for size in sizes.iter() {
        let rsvd_path = format!(
            "/sys/fs/cgroup/hugetlb/hugetlb.{}.rsvd.limit_in_bytes",
            size
        );
        if !PathBuf::from(rsvd_path).exists() {
            return false;
        }
    }
    true
}

fn make_hugetlb_spec(page_size: &str, limit: i64) -> Spec {
    SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .resources(
                    LinuxResourcesBuilder::default()
                        .hugepage_limits(vec![
                            LinuxHugepageLimitBuilder::default()
                                .page_size(page_size.to_owned())
                                .limit(limit)
                                .build()
                                .expect("could not build"),
                        ])
                        .build()
                        .unwrap(),
                )
                .build()
                .expect("could not build"),
        )
        .build()
        .unwrap()
}

fn test_wrong_tlb() -> TestResult {
    // 3 MB pagesize is wrong, as valid values must be a power of 2
    let page = "3MB";
    let limit = 100 * 3 * 1024 * 1024;
    let spec = make_hugetlb_spec(page, limit);
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

fn extract_page_size(dir_name: &str) -> String {
    let name_stripped = dir_name.strip_prefix("hugepages-").unwrap();
    let size = name_stripped.strip_suffix("kB").unwrap();
    let size: u64 = size.parse().unwrap();

    if size >= (1 << 20) {
        (size >> 20).to_string() + "GB"
    } else if size >= (1 << 10) {
        (size >> 10).to_string() + "MB"
    } else {
        size.to_string() + "KB"
    }
}

fn get_tlb_sizes() -> Vec<String> {
    let mut sizes = Vec::new();
    for hugetlb_entry in std::fs::read_dir("/sys/kernel/mm/hugepages")
        .expect("error in reading /sys/kernel/mm/hugepages")
    {
        let hugetlb_entry = hugetlb_entry.expect("error in reading /sys/kernel/mm/hugepages entry");
        if !hugetlb_entry.path().is_dir() {
            continue;
        }

        let dir_name = hugetlb_entry.file_name();
        let dir_name = dir_name.to_str().unwrap();

        sizes.push(extract_page_size(dir_name));
    }
    sizes
}

fn validate_tlb(id: &str, size: &str, limit: i64) -> TestResult {
    let root = "/sys/fs/cgroup/hugetlb";
    let path = format!("{root}/{id}/hugetlb.{size}.limit_in_bytes");
    let val_str = std::fs::read_to_string(path).unwrap();
    let val: i64 = val_str.trim().parse().unwrap();
    if val == limit {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "page limit not set correctly : for size {}, expected {}, got {}",
            size,
            limit,
            val
        ))
    }
}

fn validate_rsvd_tlb(id: &str, size: &str, limit: i64) -> TestResult {
    let root = "/sys/fs/cgroup/hugetlb";
    let path = format!("{root}/{id}/hugetlb.{size}.rsvd.limit_in_bytes");
    let val_str = std::fs::read_to_string(path).unwrap();
    let val: i64 = val_str.trim().parse().unwrap();
    if val == limit {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "page limit not set correctly : for size {}, expected {}, got {}",
            size,
            limit,
            val
        ))
    }
}

fn test_valid_tlb() -> TestResult {
    // When setting the limit just for checking if writing works, the amount of memory
    // requested does not matter, as all unsigned integers will be accepted.
    // Use 1GiB as an example
    let limit: i64 = 1 << 30;
    let tlb_sizes = get_tlb_sizes();
    for size in tlb_sizes.iter() {
        let spec = make_hugetlb_spec(size, limit);
        let res = test_outside_container(&spec, &|data| {
            test_result!(check_container_created(&data));

            let r = validate_tlb(&data.id, size, limit);
            if matches!(r, TestResult::Failed(_)) {
                return r;
            }
            TestResult::Passed
        });
        if matches!(res, TestResult::Failed(_)) {
            return res;
        }
    }
    TestResult::Passed
}

fn test_valid_rsvd_tlb() -> TestResult {
    let limit: i64 = 1 << 30;
    let tlb_sizes = get_tlb_sizes();
    for size in tlb_sizes.iter() {
        let spec = make_hugetlb_spec(size, limit);
        let res = test_outside_container(&spec, &|data| {
            test_result!(check_container_created(&data));
            // Currentle, we write the same value to both limit_in_bytes and rsvd.limit_in_bytes
            let non_rsvd = validate_tlb(&data.id, size, limit);
            let rsvd = validate_rsvd_tlb(&data.id, size, limit);
            if matches!(non_rsvd, TestResult::Failed(_)) {
                return non_rsvd;
            } else if matches!(rsvd, TestResult::Failed(_)) {
                return rsvd;
            }
            TestResult::Passed
        });
        if matches!(res, TestResult::Failed(_)) {
            return res;
        }
    }
    TestResult::Passed
}

pub fn get_tlb_test() -> TestGroup {
    let wrong_tlb = ConditionalTest::new(
        "invalid_tlb",
        Box::new(check_hugetlb),
        Box::new(test_wrong_tlb),
    );
    let valid_tlb = ConditionalTest::new(
        "valid_tlb",
        Box::new(check_hugetlb),
        Box::new(test_valid_tlb),
    );
    let valid_rsvd_tlb = ConditionalTest::new(
        "valid_rsvd_tlb",
        Box::new(check_hugetlb_rsvd),
        Box::new(test_valid_rsvd_tlb),
    );
    let mut tg = TestGroup::new("huge_tlb");
    tg.add(vec![
        Box::new(wrong_tlb),
        Box::new(valid_tlb),
        Box::new(valid_rsvd_tlb),
    ]);
    tg
}
