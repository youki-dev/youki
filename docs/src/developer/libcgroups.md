# libcgroups

This crate provides an interface for working with cgroups in Linux. cgroups or control groups is a Linux kernel feature which can be used to fine-control resources and permissions given to a particular process or a group of processes. You can read more about them on the [cgroups man page](https://man7.org/linux/man-pages/man7/cgroups.7.html).

The initial version of cgroups is called the version 1 was implemented in kernel 2.6.24, and later in kernel version 4.5, a new version of cgroups was released, aimed to solve issues with v1, the version v2.

This crates exposes several functions and modules that can be used to work with cgroups :

- Common traits and functions which are used by both v1 and v2 such as

  - Trait `CgroupManager`, this abstracts over the underlying implementation of interacting with specific version of cgroups, and gives functions to add certain process to a certain cgroup, apply resource restrictions, get statistics of a cgroups, freeze a cgroup, remove a cgroup or get list of all processes belonging to a cgroup. v1 and v2 modules both contain a version specific cgroup manager which implements this trait, and thus either can be given to functions or structs which expects a cgroup manager, depending on which cgroups the host system uses.
  - Apart from the trait, this also contains functions which help with reading cgroups files, and write data to a cgroup file, which are used throughout this crate.
  - Functions to detect which cgroup setup (v1, v2 or hybrid) is on the host system with/without specified mounted cgroup root path, as well as functions to get the corresponding cgroups manager w/o cgroup root path.

- Functions and structs to get and store the statistics of a cgroups such as

  - CPU stats including usage and throttling
  - Memory stats including usage of normal and swap memory, usage of kernel memory, page cache in bytes etc
  - Pid stat including current active pids and maximum allowed pids
  - Block IO stats such as number of bytest transferred to/from a device in the cgroup, io operations performed by a device in the cgroup, amount of time cgroup had access to a device etc
  - Huge TLB stats such as usage and maximum usage etc.
  - Function to get pid stats
  - Function to get supported hugepage size
  - Function to parse flat keyed data and nested keyed data that can be in a cgroups file
  - Parse a device number

- Cgroups V1 module which deal with implementing a cgroup manager for systems which have cgroups v1 or hybrid cgroups
- Cgroups V2 module which deal with implementing a cgroup manager for systems which have cgroups v2

As youki currently depends on systemd as an init system, this crate also exposes module systemd, which provides interface for working with systemd related operations. [systemd resource control](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html) is a good place to read more about systemd and its involvement in resource control.

## Dbus Native

This module is the native implementation of dbus connection functionality used for connecting with systemd via dbus. Refer to [this issue discussion](https://github.com/youki-dev/youki/issues/2208) following for the discussion regarding moving away from existing dbus-interfacing library.

Note that this implements the minimal required functionality for youki to use dbus, and thus does not have all the dbus features.

- Refer to see [dbus specification](https://dbus.freedesktop.org/doc/dbus-specification.html) and [header format](https://dbus.freedesktop.org/doc/api/html/structDBusHeader.html) for the individual specifications.

- For systemd interface and types, you can generate the following file and take help from the auto-generated functions
`dbus-codegen-rust -s -g -m None -d org.freedesktop.systemd1 -p /org/freedesktop/systemd1`, see https://github.com/diwic/dbus-rs
