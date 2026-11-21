# libcgroups

libcgroups is the crate that contains functionality to work with Linux cgroups. This provide an easy to use interface over reading and writing cgroups files, as well as various structs that represent the cgroups data.

The modules that it exposes are :

- common
- stats
- systemd
- test_manager
- v2

Following is a short explanation of these modules.

### common

This module contains functionality that is general to any type of cgroup. Some of the things it provides are:

- trait `CgroupManager` which gives and interface for the following:

  - add a task to a cgroup
  - apply resource restriction
  - remove a cgroup
  - control freezer cgroup state
  - get stats from a cgroup
  - get pids belonging to the cgroup

- functions `write_cgroup_file_str` and `write_cgroup_file` which write data to a cgroup file
- function `read_cgroup_file` which reads data from given cgroup file
- function `get_cgroup_setup_with_root` which returns setup of cgroups (v1,v2, hybrid) on the system with specified cgroup root path
- function `get_cgroup_setup` which returns setup of cgroups (v1,v2, hybrid) on the system with default cgroup root path `/sys/fs/cgroup`
- function `create_cgroup_manager_with_root` which returns corresponding cgroup manager on the system with specified cgroup root path, if the passed `root_path` argument is `None`, then it's same as function `create_cgroup_manager`
- function `create_cgroup_manager` which returns corresponding cgroup manager on the system with default cgroup root path `/sys/fs/cgroup`

### stats

This module has functionalities related to statistics data of the cgroups, and structs representing it.

Some of the things it exposes are

- struct `Stats` which contains following structs:

  - `CpuStats` : contains cpu usage and throttling information

  - `MemoryStats` : contains usage of memory, swap and memory combined, kernel memory, kernel tcp memory and other memory stats

  - `PidStats` : contains current number of active pids and allowed number of pids

  - `BlkioStats` : contains block io related stats, such as number of bytes transferred from/to a device in cgroup, number of io operations done by a device in cgroup, device access and queue information etc.

  - `HugeTlbStats` : containing stats for Huge TLB such as usage, max_usage, and fail count

- function `supported_page_size` which returns hugepage size supported by the system

- utility functions to operate with data in cgroups files such as:

  - `parse_single_value` : reads file expecting it to have a single value, and returns the value

  - `parse_flat_keyed_data` : parses cgroup file data which is in flat keyed format (key value)

  - `parse_nested_keyed_data` : parses cgroup file data which is in nested keyed format (key list of values)

  - `parse_device_number` : parses major and minor number of device

### systemd

This is the module used by youki to interact with systemd, and it exposes several functions to interact:

- function `booted` to check if the system was booted with systemd or not

- module `controller_type`, which contains enum `ControllerType` which is used to specify cgroup controllers available on a system

- module `manager`, which contains `Manager` struct, which is the cgroup manager, and contain information such as the root cgroups path, path for the specific cgroups, client to communicate with systemd etc. This also implements `CgroupManager` trait, and thus can be used for cgroups related operations.

- module `dbus-native` is the native implementation for dbus connection, which is used to interact with systemd in rootless mode.

### test_manager

This exposes a `TestManager` struct which can be used as dummy for cgroup testing purposes, which also implements `CgroupManager`.

### v2

This module contains functionalities specific to cgroups version 2. It exposes the cgroup v2 manager, as well as some utility functions such as `get_unified_mount_point` and `get_available_controllers`.

The v2 module exposes devices module, which provides functionality for working with bpf, such as load a bpf program, query info of a bpf program, attach and detach a bpf program to a cgroup, etc.
