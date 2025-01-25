//! Contains Basic setup for testing, testable trait and its result type
use std::fmt::Debug;

use anyhow::{bail, Error, Result};

#[derive(Debug)]
/// Enum indicating result of the test. This is like an extended std::result,
/// which includes a Skip variant to indicate that a test was skipped, and the Ok variant has no associated value
pub enum TestResult {
    /// Test was ok
    Passed,
    /// Test needed to be skipped
    Skipped,
    /// Test was error
    Failed(Error),
}

impl<T> From<Result<T>> for TestResult {
    fn from(result: Result<T>) -> Self {
        match result {
            Ok(_) => TestResult::Passed,
            Err(err) => TestResult::Failed(err),
        }
    }
}

/// This trait indicates that something can be run as a test, or is 'testable'
/// This forms the basis of the framework, as all places where tests are done,
/// expect structs which implement this
pub trait Testable {
    fn get_name(&self) -> &'static str;
    fn can_run(&self) -> bool {
        true
    }
    fn run(&self) -> TestResult;
}

/// This trait indicates that something forms a group of tests.
/// Test groups are used to group tests in sensible manner as well as provide namespacing to tests
pub trait TestableGroup {
    fn get_name(&self) -> &'static str;
    fn parallel(&self) -> bool;
    fn run_all(&self) -> Vec<(&'static str, TestResult)>;
    fn run_selected(&self, selected: &[&str]) -> Vec<(&'static str, TestResult)>;
}

#[macro_export]
macro_rules! test_result {
    ($e:expr $(,)?) => {
        match $e {
            core::result::Result::Ok(val) => val,
            core::result::Result::Err(err) => {
                return $crate::testable::TestResult::Failed(err);
            }
        }
    };
}

#[macro_export]
macro_rules! assert_result_eq {
    ($expected:expr, $actual:expr $(,)?) => ({
        match (&$expected, &$actual) {
            (expected_val, actual_val) => {
                if !(*expected_val == *actual_val) {
                   test_framework::testable::assert_failed(&*expected_val, &*actual_val, std::option::Option::None)
                } else {
                    Ok(())
                }
            }
        }
    });
    ($expected:expr, $actual:expr, $($arg:tt)+) => ({
        match (&$expected, &$actual) {
            (expected_val, actual_val) => {
                if !(*expected_val == *actual_val) {
                    test_framework::testable::assert_failed(&*expected_val, &*actual_val, std::option::Option::Some(format_args!($($arg)+)))
                } else {
                    Ok(())
                }
            }
        }
    });
}

#[doc(hidden)]
pub fn assert_failed<T, U>(
    expected: &T,
    actual: &U,
    args: Option<std::fmt::Arguments<'_>>,
) -> Result<()>
where
    T: Debug + ?Sized,
    U: Debug + ?Sized,
{
    match args {
        Some(args) => {
            bail!(
                r#"assertion failed:
            expected: `{:?}`,
            actual: `{:?}`: {}"#,
                expected,
                actual,
                args
            )
        }
        None => {
            bail!(
                r#"assertion failed:
            expected: `{:?}`,
            actual: `{:?}`"#,
                expected,
                actual
            )
        }
    }
}
