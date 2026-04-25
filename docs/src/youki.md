# Youki

<p align="center">
  <img src="./assets/youki.png" width="450">
</p>

youki is an implementation of the [OCI runtime-spec](https://github.com/opencontainers/runtime-spec) in Rust, similar to [runc](https://github.com/opencontainers/runc).

## About the name

**youki** is pronounced as /joʊki/ or yoh-key. The name youki comes from the 
Japanese word **容器** (**ようき**), which means 'a container' or 'a vessel', youki can also be written as **陽気** (**ようき**, youki), meaning 'cheerful' or 'merry'.

## Motivation

Here is why we are writing a new container runtime in Rust.

- Rust is one of the best languages to implement the oci-runtime spec. Many very nice container tools are currently written in Go. However, the container runtime requires the use of system calls, which requires a bit of special handling when implemented in Go. This is too tricky (e.g. _namespaces(7)_, _fork(2)_); with Rust, it's not that tricky. And, unlike in C, Rust provides the benefit of memory safety. While Rust is not yet a major player in the container field, it has the potential to contribute a lot: something this project attempts to exemplify.
- youki has the potential to be faster and use less memory than runc, and therefore work in environments with tight memory usage requirements. Here is a simple benchmark of a container from creation to deletion.

  | Runtime |  Time (mean ± σ)   |  Range (min … max)  |
  | :-----: | :----------------: | :-----------------: |
  |  youki  | 198.4 ms ± 52.1 ms | 97.2 ms … 296.1 ms  |
  |  runc   | 352.3 ms ± 53.3 ms | 248.3 ms … 772.2 ms |
  |  crun   | 153.5 ms ± 21.6 ms | 80.9 ms … 196.6 ms  |

  <details>
  <summary>Details about the benchmark</summary>

  - A command used for the benchmark
    ```console
    $ hyperfine --prepare 'sudo sync; echo 3 | sudo tee /proc/sys/vm/drop_caches' --warmup 10 --min-runs 100 'sudo ./youki create -b tutorial a && sudo ./youki start a && sudo ./youki delete -f a'
    ```
  - Environment
   `console $ ./youki info Version 0.0.1 Kernel-Release 5.11.0-41-generic Kernel-Version #45-Ubuntu SMP Fri Nov 5 11:37:01 UTC 2021 Architecture x86_64 Operating System Ubuntu 21.04 Cores 12 Total Memory 32025 Cgroup setup hybrid Cgroup mounts blkio /sys/fs/cgroup/blkio cpu /sys/fs/cgroup/cpu,cpuacct cpuacct /sys/fs/cgroup/cpu,cpuacct cpuset /sys/fs/cgroup/cpuset devices /sys/fs/cgroup/devices freezer /sys/fs/cgroup/freezer hugetlb /sys/fs/cgroup/hugetlb memory /sys/fs/cgroup/memory net_cls /sys/fs/cgroup/net_cls,net_prio net_prio /sys/fs/cgroup/net_cls,net_prio perf_event /sys/fs/cgroup/perf_event pids /sys/fs/cgroup/pids unified /sys/fs/cgroup/unified CGroup v2 controllers cpu detached cpuset detached hugetlb detached io detached memory detached pids detached device attached Namespaces enabled mount enabled uts enabled ipc enabled user enabled pid enabled network enabled cgroup enabled $ ./youki --version youki version 0.0.1 commit: 0.0.1-0-0be33bf $ runc -v runc version 1.0.0-rc93 commit: 12644e614e25b05da6fd08a38ffa0cfe1903fdec spec: 1.0.2-dev go: go1.13.15 libseccomp: 2.5.1 $ crun --version crun version 0.19.1.45-4cc7 commit: 4cc7fa1124cce75dc26e12186d9cbeabded2b710 spec: 1.0.0 +SYSTEMD +SELINUX +APPARMOR +CAP +SECCOMP +EBPF +CRIU +YAJL `
  </details>

- The development of [railcar](https://github.com/oracle/railcar) has been suspended. This project was very nice but is no longer being developed. This project is inspired by it.
- I have fun implementing this. In fact, this may be the most important.
