# integration_test

**Note** that these tests resides in `/tests/integration_test/` at the time of writing.

This crate contains the Rust port of OCI-runtime tools integration tests, which are used to test if the runtime works as per the OCI spec or not. Initially youki used the original implementation of these test provided in the OCI repository [here](https://github.com/opencontainers/runtime-tools/tree/master/validation). But those tests are written in Go, which made the developers depend on two language environments Rust and Go to compile youki and test it. The Validation tests themselves also have an optional dependency on node js to parse their output, which can make it a third language dependency.

Other than that, those tests also showed some issues while running on some local systems, and thus running the tests would be difficult on local system. As the runtime is a complex piece of software, it becomes useful to have a set of tests that can be run with changes in code, so one can verify that change in one part of youki has not accidentally broken some other part of youki.

Thus we decided to port the tests to Rust, and validate them, so that we have a set of unit tests as well of integration tests to validate the working of runtime. These tests are still under development, and you can check the [tracking issue](https://github.com/youki-dev/youki/issues/361) for more details. More details on working of these tests can be found at [https://github.com/youki-dev/youki/tree/main/crates/integration_test](https://github.com/youki-dev/youki/tree/main/crates/integration_test).

As these tests are under development, these are validated on a standard runtime such as runc in the GitHub CI, so validate the tests themselves.

## Notes

### About the create container function

The test_utils provides a `create_container` function which can be used to run the `youki create` command. It returns the child process struct, which can be either `wait()` or `wait_with_output()` to wait for it finishing. Unless you know what are you doing, it is recommended to call `wait()` on it, as otherwise the process will hang. As explained in the [youki docs](../youki.md) , the `youki create` process, after starting forks, and the forked process keeps waiting for another youki process to send it the `start` signal , and after receiving it, that forked process execs the container program. If you are simply trying to create a container, such as in case of `test_outside_runtime` then calling `wait_with_output()` will cause it to hang. If you are actually going to start a container, and need output from the container process, then you must keep the `Child struct` returned by `create` function and call `wait_with_output()` on it **AFTER** you have called the start command on that container, which will give you the `stdout` and `stderr` of the process running inside the container.

To understand how this works, take a look at [handling stdio](https://github.com/opencontainers/runc/blob/master/docs/terminals.md) of the runc, specially the [detached pass-through mode](https://github.com/opencontainers/runc/blob/master/docs/terminals.md#detached-pass-through) section. As explained in it, we setup the stdio for the original youki process in `youki create` by setting the stdio to `Stdio::piped()` in the `create` function. Then we set the `terminal` option to `false` (which is the default anyway) in the spec, which makes it run in the pass-through mode. Then when the create process is done its work, and its forked process is waiting for the start signal, it uses the same stdio pipes. Thus calling `wait_with_output()` without starting will keep it hanged up, and after calling start, stdio of the program to be run inside the container can be obtained from the `youki create`'s process.

### How test inside container works

We use `test_inside_container` for making sure that the restrictions and constraints are uphold from inside the container process.
For that, first whichever integration test needs to use it, must define the runtimetest as the container process in the spec, and then use `test_inside_container` function. It requires a function which will do the necessary setup for the tests that are to be run inside. Then the counterpart for the test should be added to the `runtimetest` crate, which will run inside the container and if there is any error, print it to the `stderr`. The `test_inside_container` function will wait for the tests to be over and then check the `stderr` to be empty. If it is not, the test is assumed to fail.
