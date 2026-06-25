# VM Support (libkrun)

youki can launch microVM-based containers using the [libkrun](https://github.com/containers/libkrun) microVM library. Here, we describe how to launch a container with youki using libkrun.

1. Build youki with krun feature flag enabled
2. Prepare KVM on the host
3. Install libkrunfw
4. Run the bundle with youki using the krun handler

## MicroVM-based container

A conventional container (youki's default, like runc) shares the host kernel
with every other container and is isolated by Linux namespaces, cgroups,
and other Linux security mechanisms such as seccomp and capabilities. This is lightweight, but the shared kernel is a large attack surface.

A microVM-based container instead runs the workload inside a lightweight virtual machine with its own guest kernel, isolated from the host by hardware virtualization (KVM). It gives a VM-strength isolation boundary while keeping container-like startup time and footprint. libkrun is a library that embeds a VMM, so a runtime can boot a microVM in-process rather than shelling out to a separate hypervisor.

<p align="center">
  <img src="../assets/libkrun.drawio.svg" width="800">
</p>

## Build youki with krun support

Enable the `krun` feature when building youki:

```bash
./scripts/build.sh -o . -r -f krun
```

## Prepare KVM on the host

libkrun uses KVM to start a microVM.
Therefore, KVM must be enabled on the host.

Verify that the KVM kernel modules are loaded.

```bash
$ lsmod | grep kvm
kvm_intel             483328  0
kvm                  1425408  1 kvm_intel
irqbypass              12288  1 kvm
```

## Install libkrunfw

To use youki with libkrun, you need to install libkrunfw in advance.

Please follow the official installation instructions:
- libkrunfw: [Building](https://github.com/containers/libkrunfw?tab=readme-ov-file#building)

Note: libkrun itself is statically linked into youki via its Rust crate, so only libkrunfw needs to be installed as a runtime shared library.

## Run a container with youki

### Edit config.json

Add the following annotation to the top-level `annotations` object:

```json
{
  "annotations": {
    "run.oci.handler": "krun"
  }
}
```

### Run

Make sure `libkrunfw` is available in the library path. For example:

```bash
ls /usr/local/lib64/libkrunfw.so*
```

Run the command with LD_LIBRARY_PATH set.

```bash
LD_LIBRARY_PATH=/usr/local/lib64 youki run -b tutorial container
```

### Configuration

You can configure the libkrun handler via the following annotations:

`run.oci.handler` is the only required annotation; all other annotations are optional.

```json
{
  "annotations": {
    "run.oci.handler": "krun",
    "krun.cpus": "2",
    "krun.ram_mib": "2048"
  }
}
```

* `run.oci.handler`: Set to `krun` (tells youki to use the libkrun handler)
* `krun.cpus`: Number of vCPUs assigned to the guest (default: 1)
* `krun.ram_mib`: Guest RAM in MiB (default: 2048)

## Limitations

* `exec` is not supported.
* The host must provide `/dev/kvm`.
* The libkrun handler currently requires the `run.oci.handler=krun` annotation.
