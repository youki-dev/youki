# Integration test

This provides a test suite to test low level OCI spec compliant container runtime

## Usage

```console
# in root folder
$ ./build.sh
$ cd crates/youki_integration_test
$ cp ../youki .
$ ./build.sh
# currently root access is required
$ sudo ./youki_integration_test -r ./youki
```

This provides following commandline options :

- --runtime (-r) : Required. Takes path of runtime executable to be tested. If the path is not valid, the program exits.
- --tests (-t) : Optional. Takes a list of tests to be run, and runs only those tests. Format for it is : `test-grp-1::test-1,test-2 <space> test-grp-2 <space> test-grp-3::test-3 ...`. The test groups with no specific tests specified, (test-grp-2 in the example) , will run all of its tests, and in other cases, only selected tests will be run. Test groups not mentioned will be ignored.

## Adding tests

To create and run tests, we use a custom test_framework, which resides in youki_integration_test/test_framework.
It provides some basic build in structs to define and run tests, but sometimes custom implementation of them might be required. For more info on the test_framework structs and how to use them, see the README.md file.

### Types of tests

The main two ways to add tests are :

- Use default provided Test, ConditionalTest and TestGroup structs. These are meant to be used for stateless tests, such as HugeTLB tests. Note that all these are run in parallel, so when using these defaults, please make sure there are no cross test dependencies. Currently **HugeTLB** tests are implemented in this way.
- For stateful tests, make a custom struct, and implement the TestableGroup trait, which can be then given to TestManager. That way you can add state information in the struct, and define and control the ordering of the test. Currently **lifecycle** and **create** tests are implemented in this way. This is required, as for lifecycle tests, the commands must be run in specific order, e.g. create must be executed before run, which must be done before stop and so on. Though there is some improvement needed in these tests.

When implementing tests, you should prefer one of these approaches. If required you can also make your own custom one.

The tests are modeled after the [OCI runtime tools](https://github.com/opencontainers/runtime-tools/tree/master/validation) tests. These tests should be taken as inspiration, but note that some of these tests are not passed successfully even by production level runtimes such as runc. The most important goal for these tests is that both youki and other runtimes are passing them successfully and to test these runtimes as carefully as possible.

### Utils provided

This framework also has some test utils, meant to help doing common operations in tests, which should be used whenever possible. If you notice that you are using the same patterns over and over again, you should think about adding them to the test utils. Some notable function provided are:

- generate_uuid : generates a unique id for the container
- prepare_bundle : creates a temp directory, and sets up the bundle and default config.json. This folder is automatically deleted when dropped.
- set_config : takes an OCI Spec struct, and saves it as config.json in the given bundle folder
- create_container : runs the runtime command with create argument, with given id and with given bundle directory
- kill_container: runs the runtime command with kill argument, with given id and with given bundle directory
- delete_container : runs the runtime command with delete argument, with given id and with given bundle directory
- get_state : runs the runtime command with state argument, with given id and with given bundle directory
- test_outside_container : this is meant to mimic [RuntimeOutsideValidate](https://github.com/opencontainers/runtime-tools/blob/59cdde06764be8d761db120664020f0415f36045/validation/util/test.go#L263) function of original tests.
- test_inside_container : this is meant to mimic [RuntimeInsideValidate](https://github.com/opencontainers/runtime-tools/blob/59cdde06764be8d761db120664020f0415f36045/validation/util/test.go#L180) function of original tests.
- check_container_created: this checks if the container was created successfully.
- test_result!: this is a macro, that allows you to convert from a Result<T,E> to a TestResult

Note that even though all of the above functions are provided, most of the time the only required function is test_outside_container, as it does all the work of setting up the bundle, creating and running the container, getting the state of the container, killing the container and then deleting the container.

In case you manually call any of these functions, make sure that the folder, cgroups ,spawned processes and other stuff created are disposed correctly when the test function completes.

### Test creation workflow

Usually the test creation workflow will be something like :

1. Create a new folder in src/tests with appropriate name.
2. Make a function which will check if the test can be run or not on a given system. This is important, as some tests such as blkio or cgroups memory need the kernel to be configured with certain flags, without which the test cannot be run. **Note** that this is different from the test failing: the test should fail when it is capable of running, but gives unexpected results, whereas the test should be skipped / not run in the first place, when the host system does not support it.
3. Create a function which will generate the OCI Spec required for test, using oci-spec-rs 's builder pattern. See the `make_hugetlb_spec` function in src/tests/tlb/tlb_test.rs to get an idea. Usually to understand the types of fields and which fields are available, you'll need to check [this file](https://github.com/youki-dev/oci-spec-rs/blob/main/src/runtime/linux.rs) and other source files to get an idea of what fields you need. The builder pattern is quite consistent, and using the github - vs code integration and doing a global search for what you need should do the trick.
4. Write the test functions and whatever needed: custom structs, etc.
5. Create a function which will create the custom/default tests, create a TestGroup/custom impl TestableGroup out of it, and return that. Make this function public, and `pub use` it from the mod.rs .
6. In the src/main.rs, import your function, and run it to get an instance of your test group, for example see lines 58-60 ish, where lifecycle, create and huge_tlb structs are created.
7. Add the reference of this to the test_manager in the main function.
8. Run your tests individually, run your test group individually and then run the whole suite against youki and some other production level runtime, such as runc. As stated previously, the important thing is to make sure runc passes it as well.
9. Make sure that the system is returned to the original state afterwards: make sure that no youki/runc/runtime process is running in the background, make sure that the /tmp (or respective on Windows/MacOS) does not have a uuid-looking directory in it, make sure that the /sys/fs/cgroup/\* directories do not have a runtime sub-directory of uuid-looking directory in them.
10. Commit, push and make a PR ;)

### Some common issues/errors

This lists some of the things that can be tricky, and can cause issues in running tests. **In case you encounter something, please update this list**.

- The create command should be waited by `wait`, and not `wait_with_output` on it after spawning if you are simply creating the container. The reason is, runtime process forks itself to create the container, and then keeps running to start the container. Thus if we try to `wait_with_output` on it, without having called `start` on it, it hangs. Trying to kill tests by `Ctrl+C` will cause the system to stay in modified state (/tmp directories, cgroup directories etc). In case you do this and need to end tests, open a new terminal and send a kill signal to the runtime process, that way that youki process will exit and the tests will continue.

- The kill and state commands take time. Thus whenever running these, call `wait` or `wait_with_output` on the spawned process to make sure you do not accidentally modify the directories that these use. One example is when running tests, as temp directory deletes itself when dropped, it can cause a race condition when state, or kill command is spawned and not waited. This will cause the directory in /tmp to be deleted first in the drop, and then to get created again due to kill / state command. _In the start of this implementation this problem caused several days to be spent on debugging where the directory in /tmp is getting created from_.
