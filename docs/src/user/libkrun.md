# VM Support (libkrun)

youki can launch microVM-based containers by dynamically loading the libkrun shared library. Here, we describe how to launch a container with youki using libkrun.

1. Build youki with libkrun feature flag enabled
2. Prepare KVM on the host
3. Install libkrun and libkrunfw
4. Run the bundle with youki using the krun handler

## Build youki with `libkrun` feature flag enabled

Run `build.sh` with `-f libkrun` option.

```bash
./scripts/build.sh -o . -r -f libkrun
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

## Install libkrun and libkrunfw

To use youki with libkrun, you need to install libkrun and libkrunfw in advance.

Please follow the official installation instructions:
- libkrun: [Building and installing](https://github.com/containers/libkrun?tab=readme-ov-file#building-and-installing)
- libkrunfw: [Building](https://github.com/containers/libkrunfw?tab=readme-ov-file#building)

## Run a container with youki

### Edit config.json

Update the following top-level annotations:

```json
{
  "annotations": {
    "run.oci.handler": "krun"
  }
}
```

### Run

Make sure `libkrun` and `libkrunfw` are available in the library path. For example:

```bash
ls /usr/local/lib64/libkrun.so* /usr/local/lib64/libkrunfw.so*
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
    "krun.ram_mib": "2048",
    "krun.log_level": "1",
    "krun.libkrun.path": "/usr/local/lib64/libkrun.so.1"
  }
}
```

* `run.oci.handler`: Set to `krun` (tells youki to use the libkrun handler)
* `krun.cpus`: Number of vCPUs assigned to the guest
* `krun.ram_mib`: Guest RAM in MiB
* `krun.log_level`: libkrun log level (Use a numeric value)
  * `0` => `"off"`
  * `1` => `"error"`
  * `2` => `"warn"`
  * `3` => `"info"`
  * `4` => `"debug"`
  * otherwise => `"trace"`

* `krun.libkrun.path`: Path to the libkrun shared library

## Limitations

* `exec` is not supported
