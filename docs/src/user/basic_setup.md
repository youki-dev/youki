# Basic Setup

This explains the requirements to use youki as a low-level container runtime, or to depend once of its crates as dependency for your own project.

Youki currently only supports Linux Platform, and to use it on other platform you will need to use some kind of virtualization.

Also note that youki currently only supports and expects systemd as init system, and would not work on other systems. There is currently work on-going to put systemd dependent features behind a feature flag, but till then you will need a systemd enabled system to work with youki.

## Getting Started

### Runtime requirements

The static binary (musl) builds of youki have no additional runtime requirements. Otherwise you need to install the runtime requirements using your distribution's package manager:

#### Debian, Ubuntu and related distributions
```console
sudo apt-get install libseccomp2
```

#### Fedora, CentOS, RHEL and related distributions
```console
sudo dnf install libseccomp
```

### Install youki (prebuilt binary)

Install from the GitHub release as root:

<!--youki release begin-->
```console
# curl -sSfL https://github.com/youki-dev/youki/releases/download/v0.5.8/youki-0.5.8-$(uname -m)-musl.tar.gz | tar -xzvC /usr/bin/ youki
```
<!--youki release end-->

### Running youki

You can use youki by itself to start and run containers, but it can be a little tedious, as it is a low-level container runtime. You can use a High-level container runtime, with its runtime set to youki, so that it will be easier to use.

This documentation uses Docker in its examples, which can be installed from [here](https://docs.docker.com/engine/install).
After installing Docker, configure youki as a Docker runtime as follows:

```console
sudo cat > /etc/docker/daemon.json <<EOF
{
  "runtimes": {
    "youki": {
      "path": "/usr/bin/youki"
    }
  }
}
EOF

sudo systemctl reload docker
```

Once configured, you can run a container using youki like this:

```console
docker run --rm --runtime youki hello-world
```

For more details, see [Basic Usage](./basic_usage.md).

---

## Installing youki from source

### Build Requirements

As youki is written in Rust, you will need to install and setup Rust toolchain to compile it. The instructions for that can be found on Rust's official site [here](https://www.rust-lang.org/tools/install).
If you installed it using rustup, the correct compiler version will be setup automatically from `rust-toolchain.toml` in the repo root.

### Build with cross-rs

You can compile youki using [cross-rs](https://github.com/cross-rs/cross), which provides:
* Seamless compilation for different architectures (see `Cross.toml` in the repo root for the list of supported targets)
* No build time dependencies (compilation runs in a container)
* No runtime dependencies when building static binaries (musl targets)

The only build dependency is [cross-rs](https://github.com/cross-rs/cross?tab=readme-ov-file#installation) and its [dependencies](https://github.com/cross-rs/cross?tab=readme-ov-file#dependencies) (rustup and docker or podman).


```console
CARGO=cross TARGET=musl just youki-dev # or youki-release
```

### Build without cross-rs

Install the build dependencies and then run:
```console
just youki-dev # or youki-release
```

Install the build dependencies using your distribution's package manger

#### Debian, Ubuntu and related distributions
```console
sudo apt-get install    \
      pkg-config        \
      libsystemd-dev    \
      build-essential   \
      libelf-dev        \
      libseccomp-dev    \
      libclang-dev      \
      libssl-dev
```

#### Fedora, CentOS, RHEL and related distributions
```console
sudo dnf install            \
      pkg-config            \
      systemd-devel         \
      elfutils-libelf-devel \
      libseccomp-devel      \
      clang-devel           \
      openssl-devel
```

### Getting the source

Currently youki can only be installed from the source code itself, so you will need to clone the youki GitHub repository to get the source code for using it as a runtime. If you are using any crates of youki as dependency you need to do this step, as Cargo will automatically clone the repository for you.

To clone the repository, run

```console
git clone https://github.com/youki-dev/youki.git
```

This will create a directory named youki in the directory you ran the command in. This youki directory will be referred to as root directory throughout the documentation.

### Build from source

Once you have cloned the source, you can build it with [just](https://github.com/casey/just#installation) :

```console
# go into the cloned directory
cd youki
just youki-dev # or youki-release
./youki -h # get information about youki command
```

This will build the youki binary, and put it at the root level of the cloned directory, that is in the youki/ .

---

### Using sub-crates as dependency

To use any of the sub-crate as a dependency in your own project, you can specify the dependency as follows,

```toml
[dependencies]
...
liboci-cli = { git = "https://github.com/youki-dev/youki.git" }
...
```

Here we use `liboci-cli` as an example, which can be replaced by the sub-crate that you need.

Then you can use it in your source as

```
use liboci_cli::{...}
```

---

### Using Vagrant to run youki on non-Linux Platform

As explained before, youki only support Linux, and to build/use it on non-Linux Platforms, you will need to use some kind of virtualization. The repo provides a Vagrantfile to do the required VM setup using Vagrant, which can be installed from [here](https://www.vagrantup.com/docs/installation).

Once installed and setup, you can run vagrant commands in the cloned directory to run youki inside the VM created by vagrant :

```console
# in the youki directory

# for rootless mode, which is default
vagrant up default
vagrant ssh default

# or if you want to develop in rootful mode
vagrant up rootful
vagrant ssh rootful

# in virtual machine
cd youki
just youki-dev # or youki-release
```
