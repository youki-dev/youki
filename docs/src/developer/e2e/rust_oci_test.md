# Contest

This is youki's original integration to verify the behavior of the low-level container runtime.

![Overview](../../assets/rust_oci_tests.png)

# How to run

```console
just test-contest
```

# How to write

We will not go into detail here, but will explain how to write and add a new test case based on an example test.

<details>
<summary>Fully the code of the example test</summary>
<p>

```rust,no_run,noplayground
{{#include ../../../../tests/contest/contest/src/tests/example/hello_world.rs}}
```

</p>
</details>


1. Build the OCI Runtime Spec you want to verify

    This testing framework automatically places [runtimetest](./runtimetest.md) in the container.
    In other words, you can test the processes you want to execute within a container by writing them in runtimetest.
    Therefore, it is common practice here to write an OCI Runtime Spec that executes `runtimetest`.

```rust,no_run,noplayground
{{#include ../../../../tests/contest/contest/src/tests/example/hello_world.rs:get_example_spec}}
```

2. Prepare a function that returns a `TestResult`, which represents the result of the test.

```rust,no_run,noplayground
{{#include ../../../../tests/contest/contest/src/tests/example/hello_world.rs:example_test}}
```

3. Create a `TestGroup`, add the test case you created to it, and register the `TestGroup` with `test_framework::register_test_group!`. The macro takes the function (or `Type::new`) that builds the group, and goes next to that function.

```rust,no_run,noplayground
{{#include ../../../../tests/contest/contest/src/tests/example/hello_world.rs:get_example_test}}
```

4. `main.rs` collects every registered group into the `TestManager`. Each group needs a unique name: contest panics at startup if two groups share one.

```rust,no_run,noplayground
{{#include ../../../../tests/contest/contest/src/main.rs:register_test_groups}}
```

5. Write the validation you want to run within a test container
```rust,no_run,noplayground
{{#include ../../../../tests/contest/runtimetest/src/main.rs:example_runtimetest_main}}
```
```rust,no_run,noplayground
{{#include ../../../../tests/contest/runtimetest/src/tests.rs:example_hello_world}}
```
