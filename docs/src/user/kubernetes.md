# Using youki as a Kubernetes runtime

youki implements the OCI runtime spec, so it can be plugged into any
Kubernetes cluster. Once youki is installed on each node and the
node's container runtime is configured to know about it, individual
Pods can opt in via `runtimeClassName: youki`.

## youki-deploy: ready-to-use installer for kind / containerd

The repository ships a small installer under
[`tools/youki-deploy/`](https://github.com/youki-dev/youki/tree/main/tools/youki-deploy)
which automates install the youki binary on every node, and register
it as a containerd runtime. It is composed of:

- A Docker image that bundles the youki release binary and an
  `install-youki.sh` script.
- A Kubernetes DaemonSet manifest that runs that image as a privileged
  pod on every node, mounts the host's `/usr/local/bin` and
  `/etc/containerd`, copies the binary into place, patches
  `/etc/containerd/config.toml`, and restarts containerd.

It is currently exercised against [kind](https://kind.sigs.k8s.io/)
(Kubernetes-in-Docker) but the manifests are Kubernetes
resources and should apply to any containerd-based cluster.

## Try it locally on kind

To stand up the cluster + DaemonSet:

```console
$ just kind-deploy
```

To tear it down:

```console
$ just clean-test-kind-deploy
```

See also
[Developer Documentation > Kubernetes test](../developer/e2e/kubernetes_test.md).

## Using youki for your own Pods

Once the DaemonSet is installed, just add `runtimeClassName: youki` to
the pod spec:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-youki
spec:
  runtimeClassName: youki
  containers:
    - name: nginx
      image: nginx:1.27-alpine
```

Pods without `runtimeClassName` continue to use whatever the cluster's
default OCI runtime is (typically `runc`), so installing youki-deploy
is non-disruptive for existing workloads.

## Caveats

- The installer modifies `/usr/local/bin/youki` and
  `/etc/containerd/config.toml` on the host. It does not currently
  uninstall on DaemonSet deletion - removing youki and the containerd
  config patch must be done manually.
- The DaemonSet manifest references the installer image as
  `youki-installer:latest`, which is loaded into the local kind cluster
  by `just kind-deploy`. To deploy on a real cluster, build the image
  from `tools/youki-deploy/Dockerfile` and push it to a registry that
  your cluster nodes can pull from, then update the image field in
  `tools/youki-deploy/youki-deploy.yaml`.
