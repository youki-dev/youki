use std::collections::HashMap;
use std::num::ParseIntError;
use std::path::Path;

use oci_spec::runtime::LinuxHugepageLimit;

use super::controller::Controller;
use crate::common::{
    self, ControllerOpt, EitherError, MustBePowerOfTwo, WrappedIoError, read_cgroup_file,
};
use crate::stats::{HugeTlbStats, StatsProvider, SupportedPageSizesError, supported_page_sizes};

#[derive(thiserror::Error, Debug)]
pub enum V1HugeTlbControllerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("malformed page size {page_size}: {err}")]
    MalformedPageSize {
        page_size: String,
        err: EitherError<ParseIntError, MustBePowerOfTwo>,
    },
}

pub struct HugeTlb {}

impl Controller for HugeTlb {
    type Error = V1HugeTlbControllerError;
    type Resource = Vec<LinuxHugepageLimit>;

    fn apply(
        controller_opt: &ControllerOpt,
        cgroup_root: &std::path::Path,
    ) -> Result<(), Self::Error> {
        tracing::debug!("Apply Hugetlb cgroup config");

        if let Some(hugepage_limits) = Self::needs_to_handle(controller_opt) {
            for hugetlb in hugepage_limits {
                Self::apply(cgroup_root, hugetlb)?
            }
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        if let Some(hugepage_limits) = controller_opt.resources.hugepage_limits() {
            if !hugepage_limits.is_empty() {
                return controller_opt.resources.hugepage_limits().as_ref();
            }
        }

        None
    }
}

#[derive(thiserror::Error, Debug)]
pub enum V1HugeTlbStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("error getting supported page sizes: {0}")]
    SupportedPageSizes(#[from] SupportedPageSizesError),
    #[error("error parsing value: {0}")]
    Parse(#[from] ParseIntError),
}

impl StatsProvider for HugeTlb {
    type Error = V1HugeTlbStatsError;
    type Stats = HashMap<String, HugeTlbStats>;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        let page_sizes = supported_page_sizes()?;
        let mut hugetlb_stats = HashMap::with_capacity(page_sizes.len());

        for page_size in &page_sizes {
            let stats = Self::stats_for_page_size(cgroup_path, page_size)?;
            hugetlb_stats.insert(page_size.to_owned(), stats);
        }

        Ok(hugetlb_stats)
    }
}

impl HugeTlb {
    fn apply(
        root_path: &Path,
        hugetlb: &LinuxHugepageLimit,
    ) -> Result<(), V1HugeTlbControllerError> {
        let raw_page_size: String = hugetlb
            .page_size()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        let page_size: u64 = match raw_page_size.parse() {
            Ok(page_size) => page_size,
            Err(err) => {
                return Err(V1HugeTlbControllerError::MalformedPageSize {
                    page_size: raw_page_size,
                    err: EitherError::Left(err),
                });
            }
        };
        if !Self::is_power_of_two(page_size) {
            return Err(V1HugeTlbControllerError::MalformedPageSize {
                page_size: raw_page_size,
                err: EitherError::Right(MustBePowerOfTwo),
            });
        }

        common::write_cgroup_file(
            root_path.join(format!("hugetlb.{}.limit_in_bytes", hugetlb.page_size())),
            hugetlb.limit(),
        )?;

        let rsvd_file_path = root_path.join(format!(
            "hugetlb.{}.rsvd.limit_in_bytes",
            hugetlb.page_size()
        ));
        if rsvd_file_path.exists() {
            common::write_cgroup_file(rsvd_file_path, hugetlb.limit())?;
        }

        Ok(())
    }

    fn is_power_of_two(number: u64) -> bool {
        (number != 0) && (number & (number.saturating_sub(1))) == 0
    }

    fn stats_for_page_size(
        cgroup_path: &Path,
        page_size: &str,
    ) -> Result<HugeTlbStats, V1HugeTlbStatsError> {
        let mut stats = HugeTlbStats::default();
        let mut file_prefix = format!("hugetlb.{page_size}.rsvd");
        let mut usage_file = format!("{file_prefix}.usage_in_bytes");
        let usage_content = read_cgroup_file(cgroup_path.join(&usage_file)).or_else(|_| {
            file_prefix = format!("hugetlb.{page_size}");
            usage_file = format!("{file_prefix}.usage_in_bytes");
            read_cgroup_file(cgroup_path.join(&usage_file))
        })?;
        stats.usage = usage_content.trim().parse()?;

        let max_file = format!("{file_prefix}.max_usage_in_bytes");
        let max_content = common::read_cgroup_file(cgroup_path.join(max_file))?;
        stats.max_usage = max_content.trim().parse()?;

        let failcnt_file = format!("{file_prefix}.failcnt");
        let failcnt_content = common::read_cgroup_file(cgroup_path.join(failcnt_file))?;
        stats.fail_count = failcnt_content.trim().parse()?;

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::read_to_string;

    use oci_spec::runtime::LinuxHugepageLimitBuilder;

    use super::*;
    use crate::test::set_fixture;

    #[test]
    fn test_set_hugetlb() {
        let page_file_name = "hugetlb.2MB.limit_in_bytes";
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), page_file_name, "0").expect("Set fixture for 2 MB page size");

        let hugetlb = LinuxHugepageLimitBuilder::default()
            .page_size("2MB")
            .limit(16384)
            .build()
            .unwrap();

        HugeTlb::apply(tmp.path(), &hugetlb).expect("apply hugetlb");
        let content =
            read_to_string(tmp.path().join(page_file_name)).expect("Read hugetlb file content");
        assert_eq!(hugetlb.limit().to_string(), content);
    }

    #[test]
    fn test_set_rsvd_hugetlb() {
        let page_file_name = "hugetlb.2MB.limit_in_bytes";
        let rsvd_page_file_name = "hugetlb.2MB.rsvd.limit_in_bytes";
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), page_file_name, "0").expect("Set fixture for 2 MB page size");
        set_fixture(tmp.path(), rsvd_page_file_name, "0")
            .expect("Set fixture for 2 MB rsvd page size");

        let hugetlb = LinuxHugepageLimitBuilder::default()
            .page_size("2MB")
            .limit(16384)
            .build()
            .unwrap();

        HugeTlb::apply(tmp.path(), &hugetlb).expect("apply hugetlb");
        let content =
            read_to_string(tmp.path().join(page_file_name)).expect("Read hugetlb file content");
        let rsvd_content = read_to_string(tmp.path().join(rsvd_page_file_name))
            .expect("Read rsvd hugetlb file content");

        // Both files should have been written to
        assert_eq!(hugetlb.limit().to_string(), content);
        assert_eq!(hugetlb.limit().to_string(), rsvd_content);
    }

    #[test]
    fn test_set_hugetlb_with_invalid_page_size() {
        let tmp = tempfile::tempdir().unwrap();

        let hugetlb = LinuxHugepageLimitBuilder::default()
            .page_size("3MB")
            .limit(16384)
            .build()
            .unwrap();

        let result = HugeTlb::apply(tmp.path(), &hugetlb);
        assert!(
            result.is_err(),
            "page size that is not a power of two should be an error"
        );
    }

    quickcheck! {
        fn property_test_set_hugetlb(hugetlb: LinuxHugepageLimit) -> bool {
            let page_file_name = format!("hugetlb.{:?}.limit_in_bytes", hugetlb.page_size());
            let tmp = tempfile::tempdir().unwrap();
            set_fixture(tmp.path(), &page_file_name, "0").expect("Set fixture for page size");

            let result = HugeTlb::apply(tmp.path(), &hugetlb);

            let page_size: String = hugetlb
            .page_size()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
            let page_size: u64 = page_size.parse().expect("parse page size");

            if HugeTlb::is_power_of_two(page_size) && page_size != 1 {
                let content =
                    read_to_string(tmp.path().join(page_file_name)).expect("Read hugetlb file content");
                hugetlb.limit().to_string() == content
            } else {
                result.is_err()
            }
        }
    }

    #[test]
    fn test_stat_hugetlb() {
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), "hugetlb.2MB.usage_in_bytes", "1024\n").expect("set hugetlb usage");
        set_fixture(tmp.path(), "hugetlb.2MB.max_usage_in_bytes", "4096\n")
            .expect("set hugetlb max usage");
        set_fixture(tmp.path(), "hugetlb.2MB.failcnt", "5").expect("set hugetlb fail count");

        let actual = HugeTlb::stats_for_page_size(tmp.path(), "2MB").expect("get cgroup stats");

        let expected = HugeTlbStats {
            usage: 1024,
            max_usage: 4096,
            fail_count: 5,
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_stat_rsvd_hugetlb() {
        let tmp = tempfile::tempdir().unwrap();

        set_fixture(tmp.path(), "hugetlb.2MB.rsvd.usage_in_bytes", "1024\n")
            .expect("set hugetlb usage");
        set_fixture(tmp.path(), "hugetlb.2MB.rsvd.max_usage_in_bytes", "4096\n")
            .expect("set hugetlb max usage");
        set_fixture(tmp.path(), "hugetlb.2MB.rsvd.failcnt", "5").expect("set hugetlb fail count");

        set_fixture(tmp.path(), "hugetlb.2MB.usage_in_bytes", "2048\n").expect("set hugetlb usage");
        set_fixture(tmp.path(), "hugetlb.2MB.max_usage_in_bytes", "8192\n")
            .expect("set hugetlb max usage");
        set_fixture(tmp.path(), "hugetlb.2MB.failcnt", "10").expect("set hugetlb fail count");

        let actual = HugeTlb::stats_for_page_size(tmp.path(), "2MB").expect("get cgroup stats");

        // Should prefer rsvd stats over non-rsvd stats
        let expected = HugeTlbStats {
            usage: 1024,
            max_usage: 4096,
            fail_count: 5,
        };
        assert_eq!(actual, expected);
    }
}
