mod preserve_fds_test;

use test_framework::{Test, TestGroup};

pub fn get_exec_test() -> TestGroup {
    let mut test_group = TestGroup::new("exec");

    let preserve_fds_test = Test::new(
        "preserve_fds_test",
        Box::new(preserve_fds_test::preserve_fds_test),
    );

    test_group.add(vec![Box::new(preserve_fds_test)]);

    test_group
}
