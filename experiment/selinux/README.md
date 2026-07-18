# SELinux for Youki

This is an experimental project to create a SELinux library in Rust.
Ref: https://github.com/youki-dev/youki/issues/2718.  
Reimplementation of [opencontainers/selinux](https://github.com/opencontainers/selinux) in Rust.  

## Requirements

- [Lima](https://github.com/lima-vm/lima)
- QEMU
- Rust and Cargo

## Development Environment

### Setup with Lima

```console
# Start the VM with default settings (non-interactive mode)
$ ./lima-setup.sh

# For interactive mode (when not running in CI)
$ ./lima-setup.sh --interactive

# See all available options
$ ./lima-setup.sh --help
```

### Running the Project

Once the VM is set up:

```console
# Inside the VM, run tests
$ ./lima-run.sh cargo test

# Inside the VM, run the application
$ ./lima-run.sh cargo run

# Connect to the VM
$ limactl shell --workdir /workdir/youki/experiment/shared youki-selinux

```

### Cleaning Up

When finished with development:

```console
# Remove the Lima VM
$ ./lima-setup.sh --cleanup
```
