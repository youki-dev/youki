# Kubernetes test

## Notes

This test verifies that youki works correctly as a container runtime in a Kubernetes environment using [Kind](https://kind.sigs.k8s.io/) (Kubernetes in Docker).

## Single Node deploy test

The test builds a custom Kind node image with youki, creates a cluster, and deploys nginx pods using a RuntimeClass that specifies youki as the runtime.

## Local

```console
$ just test-kind
```

To clean up an existing Kind cluster first:

```console
$ just clean-test-kind
```

## Multi Node deploy test

In addition to the single-node `test-kind` flow above, there is a
multi-node variant that mirrors how youki would be installed on a real
Kubernetes cluster: the cluster nodes themselves stay as vanilla
`kindest/node` images, and a DaemonSet running on every node
installs youki onto the host and registers it with containerd at
runtime.

### Local

```console
$ just test-kind-deploy
```

Or to only stand up the cluster + DaemonSet without the nginx smoke test:

```console
$ just kind-deploy
```

Clean up:

```console
$ just clean-test-kind-deploy
```
