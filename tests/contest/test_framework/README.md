# Test Framework for the Integration test

This is a simple test framework which provides various structs to setup and run tests.

## Docs

One important thing to note here, is that all structs provided by default, TestGroup and TestManager run the individual test cases, and test groups , respectively, in parallel. Also the default Test, ConditionalTest and TestGroup structs are meant for stateless tests. For stateful tests, or for tests which need to be run in serial, please implement respective traits on custom structs.

This crate provides following things.

#### TestResult

A Simple enum, similar to Rust Result, but Ok has no associated value, and has Skip variant to indicate that a test is skipped.

#### Trait Testable

This trait indicates that something can be used as a test. This is the smallest individual unit of the framework.

The implementor must implement three functions :

- get_name : returns name of the test.
- can_run : returns boolean indicating that if the particular test can be run or not. Defaults to returning true.
- run : runs the actual test, and returns a TestResult.

#### Trait TestableGroup

This trait indicates that something is a group of multiple tests. Primarily used for grouping tests, as well as providing namespacing.

The implementor must implement three functions :

- get_name : returns name of the test group
- run_all : run all of the tests belonging to this group, and return vector of tuples, each pair having name of test and its result.
- run_selected : takes slice of test names which are to be run, and should run only those tests. Return vector of tuples, each pair having name of test and its result.

#### Struct Test

Provides a simple template for a simple test, implements Testable. This is intended to quickly create tests which are always run, and do not require state information. The new function takes name and Boxed function, which is the test function.

#### Struct ConditionalTest

Provides a simple template for test which is to be run conditionally. Implements Testable, and is intended to be used for stateless tests, which may or may not run depending on some condition (system config, env var etc.) The new function takes name, a Boxed function which is condition function, which returns a boolean indicating if the test can be run or not, and another Boxed function, which is the test function.

#### Struct TestGroup

Provides a simple template for a test group. This implement TestableGroup. The new function takes the name of the test group, and add function takes vector of Testables. This is intended to used for grouping of simple, stateless tests.

#### Macro register_test_group

Registers a TestableGroup so that `TestManager::add_registered_test_groups` picks it up. It takes the path of a function that returns the group, e.g. `register_test_group!(get_pidfile_test);` or `register_test_group!(ContainerLifecycle::new);`. The registrations are collected at link time with the [inventory](https://crates.io/crates/inventory) crate, so the order in which groups are registered is not defined; TestManager keeps the groups sorted by name.

#### Struct TestManager

This is the core manager for running of the tests. This stores test groups, controls running of them, and printing of results. It has following functions :

- add_test_group : adds a TestableGroup.
- add_registered_test_groups : adds every TestableGroup registered with the `register_test_group!` macro. Panics if two groups have the same name.
- run_all : runs all the tests in all test groups which can be run (whose can_run returns true) and prints their results to stdout
- run_selected : takes a vector of tuples of the form (group-name, optional vector of test names) . Then runs only selected tests. If the optional vector is not present (None) then runs all tests in the group, or else runs only the selected tests from the group.
