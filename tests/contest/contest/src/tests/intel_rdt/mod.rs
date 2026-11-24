use test_framework::{ConditionalTest, TestGroup};

use self::intel_rdt_test::{can_run, test_intel_rdt};

mod intel_rdt_test;

pub fn get_intel_rdt_test() -> TestGroup {
    let mut test_group = TestGroup::new("intel_rdt");
    let intel_rdt = ConditionalTest::new("intel_rdt", Box::new(can_run), Box::new(test_intel_rdt));

    test_group.add(vec![Box::new(intel_rdt)]);

    test_group
}

test_framework::register_test_group!(get_intel_rdt_test);
