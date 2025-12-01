# libcontainer

This crate is one of the core crates of the youki workspace, and has functions and structs that deal with the actual creation and management of the container processes.

Remember, in the end, a container is just another process in Linux, which has control groups, namespaces, pivot_root and other mechanisms applied to it. The program executing has the impression that it is running on a complete system, but from the host system's perspective, it is just another process, and has attributes such as pid, file descriptors, etc. associated with it like any other process.

Along with the container related functions, this crate also provides Youki Config, a subset of the OCI spec config. This config contains only the essential data required for running the containers, and due to its smaller size, parsing it and passing it around is more efficient than the complete OCI spec config struct.

Other than that, this crate also provides a wrapper over basic Linux sockets, which are then used internally as well as by youki to communicate between the main youki process and the forked container process as well as the intermediate process.

This crate also provides an interface for Apparmor which is another Linux Kernel module allowing to apply security profiles on a per-program basis. More information about it can be found at [https://apparmor.net/](https://apparmor.net/).

### Notes

#### Some other modules exposed by this crate are

- rootfs, which is a ramfs like simple filesystem used by kernel during initialization
- hooks, which allow running of specified program at certain points in the container lifecycle, such as before and after creation, start etc.
- signals, which provide a wrapper to convert to and from signal numbers and text representation of signal names
- capabilities, which has functions related to set and reset specific capabilities, as well as to drop extra privileges
  - [Simple explanation of capabilities](https://blog.container-solutions.com/linux-capabilities-in-practice)
  - [man page for capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- tty module which deals with providing terminal interface to the container process
  - [pseudoterminal man page](https://man7.org/linux/man-pages/man7/pty.7.html) : Information about the pseudoterminal system, useful to understand console_socket parameter in create subcommand

#### Executor

By default and traditionally, the executor forks and execs into the binary
command that specified in the oci spec. Using executors, we can override this
behavior. For example, `youki` uses executor to implement running wasm
workloads. Instead of running the command specified in the process section of
the OCI spec, the wasm related executors can choose to execute wasm code
instead. The executor will run at the end of the container init process.

The API accepts only a single executor, so when using multiple executors, (try
wasm first, then defaults to running a binary), the users should compose
multiple executors into a single executor. The executor will return an error
when the executor can't handle the workload.

#### Namespaces : namespaces provide isolation of resources such as filesystem, process ids networks etc on kernel level. This module contains structs and functions related to applying or un-applying namespaces to the calling process

- [pid namespace man page](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [CLONE_NEWUSER flag](https://man7.org/linux/man-pages/man2/clone.2.html)

> Note: clone(2) offers us the ability to enter into user and pid namespace by creating only one process. However, clone(2) can only create new pid namespace, but cannot enter into existing pid namespaces. Therefore, to enter into existing pid namespaces, we would need to fork twice. Currently, there is no getting around this limitation.

- [fork(2) man page](https://man7.org/linux/man-pages/man2/fork.2.html)
- [clone(2) man page](https://man7.org/linux/man-pages/man2/clone.2.html)

#### Pausing and resuming

Pausing a container indicates suspending all processes in it. This can be done with signals SIGSTOP and SIGCONT, but these can be intercepted. Using cgroups to suspend and resume processes without letting tasks know.

- [cgroups man page](https://man7.org/linux/man-pages/man7/cgroups.7.html)
- [freezer cgroup kernel documentation](https://www.kernel.org/doc/Documentation/cgroup-v1/freezer-subsystem.txt)

#### The following are some resources that can help understand with various Linux features used in the code of this crate

- [oom-score-adj](https://dev.to/rrampage/surviving-the-linux-oom-killer-2ki9)
- [unshare man page](https://man7.org/linux/man-pages/man1/unshare.1.html)
- [user-namespace man page](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [wait man page](https://man7.org/linux/man-pages/man3/wait.3p.html)
- [pipe2 man page](https://man7.org/linux/man-pages/man2/pipe.2.html) : Definition and usage of pipe2
- [Unix Sockets man page](https://man7.org/linux/man-pages/man7/unix.7.html) : Useful to understand sockets
- [prctl man page](https://man7.org/linux/man-pages/man2/prctl.2.html) : Process control man pages
