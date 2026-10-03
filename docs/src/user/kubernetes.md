# Using youki as a Kubernetes runtime

youki implements the OCI runtime spec, so it can be plugged into any
Kubernetes cluster. Once youki is installed on each node and the
node's container runtime is configured to know about it, individual
Pods can opt in via `runtimeClassName: youki`.

## youki-deploy: ready-to-use installer for containerd / CRI-O

The repository ships a small installer under
[`tools/youki-deploy/`](https://github.com/youki-dev/youki/tree/main/tools/youki-deploy)
which automates install the youki binary on every node, and register
it as a runtime with the node's CRI implementation. It is composed of:

- A Docker image that bundles the youki release binary and an
  `install-youki.sh` script.
- A Kubernetes DaemonSet manifest that runs that image as a privileged
  pod on every node, mounts the host's `/usr/local/bin` plus the config
  location of the target runtime, copies the binary into place,
  registers youki, and restarts the runtime.

There is one manifest per CRI implementation. They differ only in the
DaemonSet - the Namespace, RuntimeClass and RBAC are identical, so a
cluster with a mix of both can apply both files:

| Runtime | Manifest | Host path mounted | How youki is registered |
| --- | --- | --- | --- |
| containerd | `youki-deploy.yaml` | `/etc/containerd` | appends a `runtimes.youki` block to `config.toml` |
| CRI-O | `youki-deploy-crio.yaml` | `/etc/crio` | writes a `crio.conf.d/99-youki.conf` drop-in |

```console
$ kubectl apply -f tools/youki-deploy/youki-deploy.yaml       # containerd
$ kubectl apply -f tools/youki-deploy/youki-deploy-crio.yaml  # CRI-O
```

The DaemonSet picks the runtime through the `CRI_RUNTIME` environment
variable, which each manifest sets explicitly. Setting it to `auto`
makes `install-youki.sh` detect the runtime from the node instead,
which is useful when you template your own manifest.

For CRI-O the drop-in only declares the youki runtime. It deliberately
leaves `cgroup_manager` alone, because that setting is global to the
node rather than per-runtime, so youki follows whatever CRI-O already
uses. The installer also runs `restorecon` on the copied binary, since
CRI-O nodes are commonly SELinux-enforcing and a binary written over a
bind mount can otherwise end up without the runtime exec label.

Both paths are exercised against [kind](https://kind.sigs.k8s.io/)
(Kubernetes-in-Docker) - the CRI-O one on a node image that swaps
containerd out for CRI-O - and both manifests are plain Kubernetes
resources, so they should apply to any cluster on the matching runtime.

## Try it locally on kind

To stand up the cluster + DaemonSet:

```console
$ just kind-deploy       # containerd nodes
$ just kind-deploy-crio  # CRI-O nodes
```

To tear it down:

```console
$ just clean-test-kind-deploy
$ just clean-test-kind-deploy-crio
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

- The installer modifies `/usr/local/bin/youki` and, depending on the
  runtime, `/etc/containerd/config.toml` or
  `/etc/crio/crio.conf.d/99-youki.conf` on the host. It does not
  currently uninstall on DaemonSet deletion - removing youki and the
  runtime config must be done manually.
- The DaemonSet manifest references the installer image as
  `youki-installer:latest`, which is loaded into the local kind cluster
  by `just kind-deploy`. To deploy on a real cluster, build the image
  from `tools/youki-deploy/Dockerfile` and push it to a registry that
  your cluster nodes can pull from, then update the image field in
  the manifest you apply.
