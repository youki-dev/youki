# Adopters and Use Cases

This page collects public examples of projects that use youki or its crates.

If you would like to add your project, please open a pull request with:

- project name and link
- a one-line summary
- crates being used, if you want to share them

## [rk8s](https://github.com/rk8s-dev/rk8s)

A lightweight Kubernetes-compatible container orchestration system written in Rust, implementing the Container Runtime Interface (CRI) with support for single containers, Kubernetes-style pods, and Docker Compose-style multi-container applications.

Uses: `libcontainer`, `libcgroups`

## [runwasi](https://github.com/containerd/runwasi)

A containerd shim that runs WebAssembly workloads in Docker and Kubernetes while using an OCI-compatible sandbox.

Uses: `libcontainer`

## [SpinKube](https://www.spinkube.dev/)

A platform for running Spin applications on Kubernetes. SpinKube uses `runwasi`, which in turn uses `libcontainer` to provide an OCI-compatible sandbox for workloads.
