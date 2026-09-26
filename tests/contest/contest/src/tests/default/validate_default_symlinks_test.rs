use test_framework::{TestGroup, TestResult, test_result};

use crate::tests::default::create_spec;
use crate::utils::{CreateOptions, test_inside_container};

fn validate_default_symlinks() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_validate_default_symlinks_test() -> TestGroup {
    let mut test_group = test_framework::TestGroup::new("validate_default_symlinks");
    let test = test_framework::Test::new(
        "validate_default_symlinks_test",
        Box::new(validate_default_symlinks),
    );

    test_group.add(vec![Box::new(test)]);
    test_group
}
