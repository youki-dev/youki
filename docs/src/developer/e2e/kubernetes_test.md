# Kubernetes test

## Notes

This test verifies that youki works correctly as a container runtime in a Kubernetes environment using [Kind](https://kind.sigs.k8s.io/) (Kubernetes in Docker).

The test builds a custom Kind node image with youki, creates a cluster, and deploys nginx pods using a RuntimeClass that specifies youki as the runtime.

## Local

```console
$ just test-kind
```

To clean up an existing Kind cluster first:

```console
$ just clean-test-kind
```
