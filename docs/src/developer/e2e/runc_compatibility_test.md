# runc compatibility test

## Notes

This test verifies compatibility with runc by running runc’s
[integration tests](https://github.com/opencontainers/runc/tree/main/tests/integration)
against the youki binary.

The list of tests to run is defined in `tests/runc/runc_test_pattern`.
Each line must match the test name in runc’s Bats test files (the string in `@test "..."`).
Prefix a line with `[skip]` to skip that test.

## Local

```console
$ git submodule update --init --recursive
$ just test-runc-comp
```
