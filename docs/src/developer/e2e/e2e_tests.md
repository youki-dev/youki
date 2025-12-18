# e2e tests

There are various e2e tests:

- [rust oci tests](./rust_oci_test.md)

  This is youki's original integration to verify the behavior of the low-level container runtime.

- [containerd integration test](./containerd_integration_test_using_youki.md)

  This is the method that containerd's integration test runs with youki.

- [runtime tools](./runtime_tools.md)

  This is the method to run the runtime tools that OCI manages as a test tool to verify meeting the OCI Runtime Spec

- [Kubernetes test](./kubernetes_test.md)

  This test verifies youki works as a Kubernetes container runtime using Kind.
