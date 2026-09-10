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
installs youki onto the host and registers it with the node's CRI
runtime at runtime.

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

## Multi Node deploy test (CRI-O)

The same flow again, against CRI-O instead of containerd, covering
`tools/youki-deploy/youki-deploy-crio.yaml` and the `crio` branch of
`install-youki.sh`.

Stock `kindest/node` images only ship containerd, so this variant builds
its own node image - the `kind-node-crio` target in
`tests/k8s/Dockerfile`, which installs CRI-O from the upstream
`isv:/cri-o:/stable` repository, disables `containerd.service` and
enables `crio.service`. Like the containerd variant, youki is *not*
baked into the node image: the DaemonSet installs it, which is what the
test is checking. `tools/youki-deploy/kind-config-crio.yaml` points
kubeadm at `unix:///var/run/crio/crio.sock` on every node.

One wrinkle worth knowing about: `kind load docker-image` imports into
containerd, so it cannot be used here. The recipe instead does
`docker save` and has `skopeo` copy the archive into each node's
containers-storage, which is also why the installer image is referenced
as `localhost/youki-installer:latest` on this cluster - CRI-O resolves
unqualified names against its search registries.

### Local

```console
$ just test-kind-deploy-crio
```

Or to only stand up the cluster + DaemonSet without the nginx smoke test:

```console
$ just kind-deploy-crio
```

Clean up:

```console
$ just clean-test-kind-deploy-crio
```
