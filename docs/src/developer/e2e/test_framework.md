# test_framework

**Note** that these tests resides in /tests/test_framework at the time of writing.

This crate contains the testing framework specifically developed for porting the OCI integration test to rust. This contains structs to represent the individual tests, group of tests and a test manager that has responsibility to run tests. This Also exposes traits which can be used to implement custom test structs or test group structs if needed.

By default the test groups are run in parallel using the [crossbeam crate](https://www.crates.io/crates/crossbeam), and the default test_group implementation also runs individual tests parallelly.

Sometimes you might need to run the tests in a test group serially or in certain order, for example in case of testing container lifecycle, a container must be created and started before stopping it. In such cases, you will need to implement the respective traits on your own structs, so that you can have fine control over the running of tests. Check the readme of the test_framework crate to see the struct and trait documentation [here](https://github.com/youki-dev/youki/tree/main/crates/test_framework).
