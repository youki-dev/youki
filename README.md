# youki: A container runtime in Rust

[![Discord](https://img.shields.io/discord/849943000770412575.svg?logo=discord)](https://discord.gg/zHnyXKSQFD)
[![GitHub contributors](https://img.shields.io/github/contributors/containers/youki)](https://github.com/containers/youki/graphs/contributors)
[![Github CI](https://github.com/containers/youki/actions/workflows/basic.yml/badge.svg?branch=main)](https://github.com/containers/youki/actions)
[![codecov](https://codecov.io/gh/containers/youki/branch/main/graph/badge.svg)](https://codecov.io/gh/containers/youki)

<p align="center">
  <img src="docs/youki.png" width="450">
</p>

**youki** is an implementation of the [OCI runtime-spec](https://github.com/opencontainers/runtime-spec) in Rust, similar to [runc](https://github.com/opencontainers/runc).  
Your ideas are welcome [here](https://github.com/containers/youki/issues/10).

# 🏷️ About the name

youki is pronounced as /joʊki/ or yoh-key.
youki is named after the Japanese word 'youki', which means 'a container'. In Japanese language, youki also means 'cheerful', 'merry', or 'hilarious'.

# 🚀 Quick Start

> [!TIP]
> You can immediately set up your environment with youki on GitHub Codespaces and try it out.  
>
> [![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/containers/youki?quickstart=1)
> ```console
> $ just build
> $ docker run --runtime youki hello-world
> $ sudo podman run --cgroup-manager=cgroupfs --runtime /workspaces/youki/youki hello-world
> ```

[User Documentation](https://youki-dev.github.io/youki/user/basic_setup.html#quick-install)

# 🎯 Motivation

Here is why we are writing a new container runtime in Rust.

- Rust is one of the best languages to implement the oci-runtime spec. Many very nice container tools are currently written in Go. However, the container runtime requires the use of system calls, which requires a bit of special handling when implemented in Go. This tricky (e.g. _namespaces(7)_, _fork(2)_); with Rust too, but it's not that tricky. And, unlike in C, Rust provides the benefit of memory safety. While Rust is not yet a major player in the container field, it has the potential to contribute a lot: something this project attempts to exemplify.
- youki has the potential to be faster and use less memory than runc, and therefore work in environments with tight memory usage requirements. Here is a simple benchmark of a container from creation to deletion.
  |  Runtime | Time (mean ± σ) | 	Range (min … max) | vs youki(mean) | Version | 
  | -------- | -------- | -------- | -------- | -------- |
  | youki     | 111.5 ms ± 11.6 ms  | 84.0 ms ± 142.5 ms   | 100% | 0.3.3 |
  | runc     | 224.6 ms ± 12.0 ms  | 190.5 ms ± 255.4 ms   | 200% | 1.1.7 |
  | crun     | 47.3 ms ± 2.8 ms  | 42.4 ms ± 56.2 ms   | 42% | 1.15 |
    <details>
  <summary>Details about the benchmark</summary>

  - A command used for the benchmark

    ```bash
    hyperfine --prepare 'sudo sync; echo 3 | sudo tee /proc/sys/vm/drop_caches' --warmup 10 --min-runs 100 'sudo ./youki create -b tutorial a && sudo ./youki start a && sudo ./youki delete -f a'
    ```

  - Environment

    ```console
    $ ./youki info
    Version           0.3.3
    Commit            4f3c8307
    Kernel-Release    6.5.0-35-generic
    Kernel-Version    #35~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue May  7 09:00:52 UTC 2
    Architecture      x86_64
    Operating System  Ubuntu 22.04.4 LTS
    Cores             16
    Total Memory      63870
    Cgroup setup      unified
    Cgroup mounts
    Namespaces        enabled
      mount           enabled
      uts             enabled
      ipc             enabled
      user            enabled
      pid             enabled
      network         enabled
      cgroup          enabled
    Capabilities
    CAP_BPF           available
    CAP_PERFMON       available
    CAP_CHECKPOINT_RESTORE available
    ```

  </details>

- I have fun implementing this. In fact, this may be the most important.

# 📍 Status of youki

**youki** has aced real-world use cases, including containerd's e2e test, and is now adopted by several production environments.
We have [our roadmap](https://github.com/orgs/containers/projects/15).

![youki demo](docs/demo.gif)

# 🔗 Related project

- [containers/oci-spec-rs](https://github.com/containers/oci-spec-rs) - OCI Runtime and Image Spec in Rust

# 🎨 Design and implementation of youki

The User and Developer Documentation for youki is hosted at [https://youki-dev.github.io/youki/](https://youki-dev.github.io/youki/)

![Architecture](docs/.drawio.svg)

# 🎬 Getting Started

Local build is only supported on Linux.
For other platforms, please use the [Vagrantfile](#setting-up-vagrant) that we have prepared. You can also spin up a fully preconfigured development environment in the cloud with [GitHub Codespaces](https://docs.github.com/en/codespaces/getting-started/quickstart).

## Requires

- Rust(See [here](https://www.rust-lang.org/tools/install)), edition 2021
- linux kernel ≥ 5.3

## Dependencies

To install `just`, follow the instruction [here](https://github.com/casey/just#installation).

### Debian, Ubuntu and related distributions

```console
$ sudo apt-get install    \
      pkg-config          \
      libsystemd-dev      \
      build-essential     \
      libelf-dev          \
      libseccomp-dev      \
      libclang-dev        \
      libssl-dev
```

### Fedora, CentOS, RHEL and related distributions

```console
$ sudo dnf install          \
      pkg-config            \
      systemd-devel         \
      elfutils-libelf-devel \
      libseccomp-devel      \
      clang-devel           \
      openssl-devel
```

## Build

```bash
git clone git@github.com:containers/youki.git
cd youki
just youki-dev # or youki-release
./youki -h # you can get information about youki command
```

## Tutorial

### Requires

- Docker(See [here](https://docs.docker.com/engine/install))

### Create and run a container

Let's try to run a container that executes `sleep 30` with youki. This tutorial may need root permission.

```bash
git clone git@github.com:containers/youki.git
cd youki
just youki-dev # or youki-release

mkdir -p tutorial/rootfs
cd tutorial
# use docker to export busybox into the rootfs directory
docker export $(docker create busybox) | tar -C rootfs -xvf -
```

Then, we need to prepare a configuration file. This file contains metadata and specs for a container, such as the process to run, environment variables to inject, sandboxing features to use, etc.

```bash
../youki spec  # will generate a spec file named config.json
```

We can edit the `config.json` to add customized behaviors for container. Here, we modify the `process` field to run `sleep 30`.

```json
  "process": {
    ...
    "args": [
      "sleep", "30"
    ],

  ...
  }
```

Then we can explore the lifecycle of a container:

```bash
cd ..                                                # go back to the repository root
sudo ./youki create -b tutorial tutorial_container   # create a container with name `tutorial_container`
sudo ./youki state tutorial_container                # you can see the state the container is `created`
sudo ./youki start tutorial_container                # start the container
sudo ./youki list                                    # will show the list of containers, the container is `running`
sudo ./youki delete tutorial_container               # delete the container
```

Change the command to be executed in `config.json` and try something other than `sleep 30`.

### Rootless container

`youki` provides the ability to run containers as non-root user([rootless mode](https://docs.docker.com/engine/security/rootless/)). To run a container in rootless mode, we need to add some extra options in `config.json`, other steps are same with above:

```bash
$ mkdir -p tutorial/rootfs
$ cd tutorial
# use docker to export busybox into the rootfs directory
$ docker export $(docker create busybox) | tar -C rootfs -xvf -

$ ../youki spec --rootless          # will generate a spec file named config.json with rootless mode
## Modify the `args` field as you like

$ ../youki run rootless-container   # will create and run a container with rootless mode
```

## Usage

Start the docker daemon.

```bash
dockerd --experimental --add-runtime="youki=$(pwd)/youki"
```

If you get an error like the below, that means your normal Docker daemon is running, and it needs to be stopped. Do that with your init system (i.e., with systemd, run `systemctl stop docker`, as root if necessary).

```console
failed to start daemon: pid file found, ensure docker is not running or delete /var/run/docker.pid
```

Now repeat the command, which should start the docker daemon.

You can use youki in a different terminal to start the container.

```bash
docker run -it --rm --runtime youki busybox
```

Afterwards, you can close the docker daemon process in other the other terminal. To restart normal docker daemon (if you had stopped it before), run:

```bash
systemctl start docker # might need root permission
```

### Integration Tests

Go and node-tap are required to run integration tests. See the [opencontainers/runtime-tools](https://github.com/opencontainers/runtime-tools) README for details.

```bash
git submodule update --init --recursive
just test-oci
```

### Setting up Vagrant

You can try youki on platforms other than Linux by using the Vagrantfile we have prepared. We have prepared two environments for vagrant, namely rootless mode and rootful mode

```bash
git clone git@github.com:containers/youki.git
cd youki

# If you want to develop in rootless mode, and this is the default mode
vagrant up
vagrant ssh

# or if you want to develop in rootful mode
VAGRANT_VAGRANTFILE=Vagrantfile.root vagrant up
VAGRANT_VAGRANTFILE=Vagrantfile.root vagrant ssh

# in virtual machine
cd youki
just youki-dev # or youki-release
```

# 👥 Community and Contributing

Please refer to [our community page](https://youki-dev.github.io/youki/community/introduction.html).

Thanks to all the people who already contributed!

<a href="https://github.com/containers/youki/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=containers/youki" />
</a>
