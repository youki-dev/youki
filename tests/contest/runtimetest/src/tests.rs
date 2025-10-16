use std::env;
use std::ffi::OsStr;
use std::fs::{self, File, read_dir};
use std::io::{self, BufRead};
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;

use anyhow::{Result, bail};
use nix::errno::Errno;
use nix::libc;
use nix::mount::{MsFlags, mount};
use nix::sys::resource::{Resource, getrlimit};
use nix::sys::stat::{Mode, umask};
use nix::sys::utsname;
use nix::unistd::{Gid, Uid, getcwd, getgid, getgroups, getuid};
use oci_spec::runtime::IOPriorityClass::{self, IoprioClassBe, IoprioClassIdle, IoprioClassRt};
use oci_spec::runtime::{
    LinuxDevice, LinuxDeviceType, LinuxIdMapping, LinuxSchedulerPolicy, MemoryPolicyModeType,
    PosixRlimit, PosixRlimitType, Spec,
};
use tempfile::Builder;

use crate::utils::{
    self, test_dir_read_access, test_dir_write_access, test_read_access, test_write_access,
};

////////// ANCHOR: example_hello_world
pub fn hello_world(_spec: &Spec) {
    println!("Hello world");
}
////////// ANCHOR_END: example_hello_world

pub fn validate_readonly_paths(spec: &Spec) {
    let linux = spec.linux().as_ref().unwrap();
    let ro_paths = match linux.readonly_paths() {
        Some(p) => p,
        None => {
            eprintln!("in readonly paths, expected some readonly paths to be set, found none");
            return;
        }
    };

    if ro_paths.is_empty() {
        return;
    }

    // TODO when https://github.com/rust-lang/rust/issues/86442 stabilizes,
    // change manual matching of i32 to e.kind() and match statement
    for path in ro_paths {
        if let std::io::Result::Err(e) = test_read_access(path) {
            let errno = Errno::from_raw(e.raw_os_error().unwrap());
            // In the integration tests we test for both existing and non-existing readonly paths
            // to be specified in the spec, so we allow ENOENT here
            if errno == Errno::ENOENT {
                /* This is expected */
            } else {
                eprintln!(
                    "in readonly paths, error in testing read access for path {path} : {e:?}"
                );
                return;
            }
        } else {
            /* Expected */
        }

        if let std::io::Result::Err(e) = test_write_access(path) {
            let errno = Errno::from_raw(e.raw_os_error().unwrap());
            // In the integration tests we test for both existing and non-existing readonly paths
            // being specified in the spec, so we allow ENOENT, and we expect EROFS as the paths
            // should be read-only
            if errno == Errno::ENOENT || errno == Errno::EROFS {
                /* This is expected */
            } else {
                eprintln!(
                    "in readonly paths, error in testing write access for path {path} : {e:?}"
                );
                return;
            }
        } else {
            eprintln!("in readonly paths, path {path} expected to not be writable, found writable");
            return;
        }
    }
}

pub fn validate_hostname(spec: &Spec) {
    if let Some(expected_hostname) = spec.hostname() {
        if expected_hostname.is_empty() {
            // Skipping empty hostname
            return;
        }
        let actual_hostname = nix::unistd::gethostname().expect("failed to get current hostname");
        let actual_hostname = actual_hostname.to_str().unwrap();
        if actual_hostname != expected_hostname {
            eprintln!(
                "Unexpected hostname, expected: {expected_hostname:?} found: {actual_hostname:?}"
            );
        }
    }
}

pub fn validate_domainname(spec: &Spec) {
    if let Some(expected_domainname) = spec.domainname() {
        if expected_domainname.is_empty() {
            return;
        }

        let uname_info = utsname::uname().unwrap();
        let actual_domainname = uname_info.domainname();
        if actual_domainname.to_str().unwrap() != expected_domainname {
            eprintln!(
                "Unexpected domainname, expected: {:?} found: {:?}",
                expected_domainname,
                actual_domainname.to_str().unwrap()
            );
        }
    }
}

// Run argument test recursively for files after base_dir
fn do_test_mounts_recursive(base_dir: &Path, test_fn: &dyn Fn(&Path) -> Result<()>) -> Result<()> {
    let dirs = read_dir(base_dir).unwrap();
    for dir in dirs {
        let dir = dir.unwrap();
        let f_type = dir.file_type().unwrap();
        if f_type.is_dir() {
            do_test_mounts_recursive(dir.path().as_path(), test_fn)?;
        }

        if f_type.is_file() {
            test_fn(dir.path().as_path())?;
        }
    }

    Ok(())
}

pub fn validate_mounts_recursive(spec: &Spec) {
    if let Some(mounts) = spec.mounts() {
        for mount in mounts {
            if let Some(options) = mount.options() {
                for option in options {
                    match option.as_str() {
                        "rro" => {
                            if let Err(e) =
                                do_test_mounts_recursive(mount.destination(), &|test_file_path| {
                                    if utils::test_write_access(test_file_path.to_str().unwrap())
                                        .is_ok()
                                    {
                                        // Return Err if writeable
                                        bail!(
                                            "path {:?} expected to be read-only, found writable",
                                            test_file_path
                                        );
                                    }
                                    Ok(())
                                })
                            {
                                eprintln!("error in testing rro recursive mounting : {e}");
                            }
                        }
                        "rrw" => {
                            if let Err(e) =
                                do_test_mounts_recursive(mount.destination(), &|test_file_path| {
                                    if utils::test_write_access(test_file_path.to_str().unwrap())
                                        .is_err()
                                    {
                                        // Return Err if not writeable
                                        bail!(
                                            "path {:?} expected to be  writable, found read-only",
                                            test_file_path
                                        );
                                    }
                                    Ok(())
                                })
                            {
                                eprintln!("error in testing rro recursive mounting : {e}");
                            }
                        }
                        "rnoexec" => {
                            if let Err(e) = do_test_mounts_recursive(
                                mount.destination(),
                                &|test_file_path| {
                                    if utils::test_file_executable(test_file_path.to_str().unwrap())
                                        .is_ok()
                                    {
                                        bail!(
                                            "path {:?} expected to be not executable, found executable",
                                            test_file_path
                                        );
                                    }
                                    Ok(())
                                },
                            ) {
                                eprintln!("error in testing rnoexec recursive mounting: {e}");
                            }
                        }
                        "rexec" => {
                            if let Err(e) = do_test_mounts_recursive(
                                mount.destination(),
                                &|test_file_path| {
                                    if let Err(ee) = utils::test_file_executable(
                                        test_file_path.to_str().unwrap(),
                                    ) {
                                        bail!(
                                            "path {:?} expected to be executable, found not executable, error: {ee}",
                                            test_file_path
                                        );
                                    }
                                    Ok(())
                                },
                            ) {
                                eprintln!("error in testing rexec recursive mounting: {e}");
                            }
                        }
                        "rdiratime" => {
                            let rest = utils::test_dir_update_access_time(
                                mount.destination().to_str().unwrap(),
                            );
                            if let Err(e) = rest {
                                eprintln!("error in testing rdiratime recursive mounting: {e}");
                            }
                        }
                        "rnodiratime" => {
                            let rest = utils::test_dir_not_update_access_time(
                                mount.destination().to_str().unwrap(),
                            );
                            if let Err(e) = rest {
                                eprintln!("error in testing rnodiratime recursive mounting: {e}");
                            }
                        }
                        "rdev" => {
                            let rest =
                                utils::test_device_access(mount.destination().to_str().unwrap());
                            if let Err(e) = rest {
                                eprintln!("error in testing rdev recursive mounting: {e}");
                            }
                        }
                        "rnodev" => {
                            let rest =
                                utils::test_device_unaccess(mount.destination().to_str().unwrap());
                            if rest.is_ok() {
                                // because /rnodev/null device not access,so rest is err
                                eprintln!("error in testing rnodev recursive mounting");
                            }
                        }
                        "rrelatime" => {
                            if let Err(e) = utils::test_mount_releatime_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!(
                                    "path expected to be rrelatime, found not rrelatime, error: {e}"
                                );
                            }
                        }
                        "rnorelatime" => {
                            if let Err(e) = utils::test_mount_noreleatime_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!(
                                    "path expected to be rnorelatime, found not rnorelatime, error: {e}"
                                );
                            }
                        }
                        "rnoatime" => {
                            if let Err(e) = utils::test_mount_rnoatime_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!(
                                    "path expected to be rnoatime, found not rnoatime, error: {e}"
                                );
                            }
                        }
                        "rstrictatime" => {
                            if let Err(e) = utils::test_mount_rstrictatime_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!(
                                    "path expected to be rstrictatime, found not rstrictatime, error: {e}"
                                );
                            }
                        }
                        "rnosymfollow" => {
                            if let Err(e) = utils::test_mount_rnosymfollow_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!(
                                    "path expected to be rnosymfollow, found not rnosymfollow, error: {e}"
                                );
                            }
                        }
                        "rsymfollow" => {
                            if let Err(e) = utils::test_mount_rsymfollow_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!(
                                    "path expected to be rsymfollow, found not rsymfollow, error: {e}"
                                );
                            }
                        }
                        "rsuid" => {
                            if let Err(e) = utils::test_mount_rsuid_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!("path expected to be rsuid, found not rsuid, error: {e}");
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

pub fn validate_seccomp(spec: &Spec) {
    let linux = spec.linux().as_ref().unwrap();
    if linux.seccomp().is_some() {
        if let Err(errno) = getcwd() {
            if errno != Errno::EPERM {
                eprintln!(
                    "'getcwd()' failed with unexpected error code '{errno}', expected  'EPERM'"
                );
            }
        } else {
            eprintln!(
                "'getcwd()' syscall succeeded. It was expected to fail due to seccomp policies."
            );
        }
    }
}

pub fn validate_sysctl(spec: &Spec) {
    let linux = spec.linux().as_ref().unwrap();
    if let Some(expected_linux_sysctl) = linux.sysctl() {
        for (key, expected_value) in expected_linux_sysctl {
            let key_path = Path::new("/proc/sys").join(key.replace('.', "/"));
            let actual_value = match fs::read(&key_path) {
                Ok(actual_value_bytes) => String::from_utf8_lossy(&actual_value_bytes)
                    .trim()
                    .to_string(),
                Err(e) => {
                    return eprintln!(
                        "error due to fail to read the file {key_path:?}, error: {e}"
                    );
                }
            };
            if &actual_value != expected_value {
                eprintln!(
                    "Unexpected kernel parameter, expected: {expected_value} found: {actual_value}"
                );
            }
        }
    }
}

pub fn validate_scheduler_policy(spec: &Spec) {
    let proc = spec.process().as_ref().unwrap();
    let sc = proc.scheduler().as_ref().unwrap();
    let mut get_sched_attr = nc::sched_attr_t {
        size: 0,
        sched_policy: 0,
        sched_flags: 0,
        sched_nice: 0,
        sched_priority: 0,
        sched_runtime: 0,
        sched_deadline: 0,
        sched_period: 0,
        sched_util_min: 0,
        sched_util_max: 0,
    };
    unsafe {
        match nc::sched_getattr(0, &mut get_sched_attr, 0) {
            Ok(_) => {}
            Err(e) => {
                return eprintln!("error due to fail to get sched attr error: {e}");
            }
        };
    }
    let sp = get_sched_attr.sched_policy;
    let want_sp: u32 = match *sc.policy() {
        LinuxSchedulerPolicy::SchedOther => 0,
        LinuxSchedulerPolicy::SchedFifo => 1,
        LinuxSchedulerPolicy::SchedRr => 2,
        LinuxSchedulerPolicy::SchedBatch => 3,
        LinuxSchedulerPolicy::SchedIso => 4,
        LinuxSchedulerPolicy::SchedIdle => 5,
        LinuxSchedulerPolicy::SchedDeadline => 6,
    };
    if sp != want_sp {
        return eprintln!("error due to sched_policy want {want_sp}, got {sp}");
    }
    let sn = get_sched_attr.sched_nice;
    let want_sn = sc.nice().unwrap();
    if sn != want_sn {
        eprintln!("error due to sched_nice want {want_sn}, got {sn}")
    }
}

pub fn validate_devices(spec: &Spec) {
    let linux = spec.linux().as_ref().unwrap();
    if let Some(devices) = linux.devices() {
        for (i, device) in devices.iter().enumerate() {
            validate_device(
                device,
                &format!(
                    "{} (linux.devices[{}])",
                    device.path().as_path().to_str().unwrap(),
                    i
                ),
            );
        }
    }
}

fn validate_device(device: &LinuxDevice, description: &str) {
    let file_data = match fs::metadata(device.path()) {
        Ok(data) => data,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                eprintln!(
                    "error due to device not being present in path: {:?}",
                    device.path()
                );
            } else {
                eprintln!(
                    "error due to fail to get metadata for device path {:?}, error: {}",
                    device.path(),
                    e
                );
            }
            return;
        }
    };

    let mut expected_type = device.typ();
    if expected_type == LinuxDeviceType::U {
        expected_type = LinuxDeviceType::C;
    }

    let file_type = file_data.file_type();
    let actual_type = if file_type.is_char_device() {
        LinuxDeviceType::C
    } else if file_type.is_block_device() {
        LinuxDeviceType::B
    } else if file_type.is_fifo() {
        LinuxDeviceType::P
    } else {
        LinuxDeviceType::U
    };

    if actual_type != expected_type {
        eprintln!("error due to device type want {expected_type:?}, got {actual_type:?}");
    }

    if actual_type != LinuxDeviceType::P {
        let dev = file_data.st_rdev();
        let major = (dev >> 8) & 0xfff;
        let minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
        if major != device.major() as u64 {
            eprintln!(
                "error due to device major want {}, got {}",
                device.major(),
                major
            );
        }
        if minor != device.minor() as u64 {
            eprintln!(
                "error due to device minor want {}, got {}",
                device.minor(),
                minor
            );
        }
    }

    let expected_permissions = device.file_mode();
    if let Some(expected) = expected_permissions {
        let actual_permissions = file_data.permissions().mode() & 0o777;
        if actual_permissions != expected {
            eprintln!(
                "error due to device file mode want {expected:?}, got {actual_permissions:?}"
            );
        }
    }

    if description == "/dev/console (default device)" {
        eprintln!("we need the major/minor from the controlling TTY");
    }

    if let Some(expected_uid) = device.uid()
        && file_data.st_uid() != expected_uid
    {
        eprintln!(
            "error due to device uid want {}, got {}",
            expected_uid,
            file_data.st_uid()
        );
    }

    if let Some(expected_gid) = device.gid()
        && file_data.st_gid() != expected_gid
    {
        eprintln!(
            "error due to device gid want {}, got {}",
            expected_gid,
            file_data.st_gid()
        );
    }
}

pub fn test_io_priority_class(spec: &Spec, io_priority_class: IOPriorityClass) {
    let io_priority_spec = spec
        .process()
        .as_ref()
        .unwrap()
        .io_priority()
        .as_ref()
        .unwrap();
    if io_priority_spec.class() != io_priority_class {
        let io_class = io_priority_spec.class();
        return eprintln!("error io_priority class want {io_priority_class:?}, got {io_class:?}");
    }

    let io_priority_who_progress: libc::c_int = 1;
    let io_priority_who_pid = 0;
    let res = unsafe {
        libc::syscall(
            libc::SYS_ioprio_get,
            io_priority_who_progress,
            io_priority_who_pid,
        )
    };
    if let Err(e) = Errno::result(res) {
        return eprintln!("error ioprio_get error {e}");
    }

    // ref: https://docs.kernel.org/block/ioprio.html
    let class = res as u16 >> 13;
    let priority = res as u16 & 0xFF;

    let expected_class = match io_priority_class {
        IoprioClassRt => 1,
        IoprioClassBe => 2,
        IoprioClassIdle => 3,
    };
    if class != expected_class {
        return eprintln!(
            "error ioprio_get class expected {io_priority_class:?} ({expected_class}), got {class}"
        );
    }

    // these number mappings are arbitrary, we set the priority in test cases io_priority_test.rs file
    let expected_priority = match io_priority_class {
        IoprioClassRt => 1,
        IoprioClassBe => 2,
        IoprioClassIdle => 3,
    };
    if priority != expected_priority {
        eprintln!("error ioprio_get expected priority {expected_priority:?}, got {priority}")
    }
}

fn parse_node_string(nodes: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let s = nodes.trim();
    if s.is_empty() {
        return out;
    }
    for part in s.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if let Some(dash) = p.find('-') {
            let start = p[..dash].trim().parse::<u32>();
            let end = p[dash + 1..].trim().parse::<u32>();
            match (start, end) {
                (Ok(a), Ok(b)) if a <= b => {
                    for n in a..=b {
                        out.push(n);
                    }
                }
                _ => {
                    // invalid token, ignore
                }
            }
        } else if let Ok(n) = p.parse::<u32>() {
            out.push(n);
        }
    }
    out
}

fn expected_nodes_from_spec(spec: &Spec) -> Option<Vec<u32>> {
    let linux = spec.linux().as_ref()?;
    let mp = linux.memory_policy().as_ref()?;
    let nodes = mp.nodes().as_deref()?;
    Some(parse_node_string(nodes))
}

fn numa_maps_indicates_node0(policy_field: &str) -> bool {
    if let Some((_, nodes_spec)) = policy_field.rsplit_once(':') {
        return parse_node_string(nodes_spec).contains(&0);
    }

    false
}

pub fn validate_memory_policy(spec: &Spec) {
    let linux = spec.linux().as_ref().unwrap();
    let memory_policy = linux.memory_policy();
    let expected_mode = memory_policy.as_ref().map(|p| p.mode());

    // Read and parse /proc/self/numa_maps to verify the policy is applied
    let numa_maps_content = match fs::read_to_string("/proc/self/numa_maps") {
        Ok(content) => content,
        Err(e) => {
            eprintln!("failed to read /proc/self/numa_maps: {}", e);
            return;
        }
    };

    let policy_entries: Vec<(&str, &str)> = numa_maps_content
        .lines()
        .filter_map(|line| {
            if line.trim().is_empty() {
                return None;
            }
            let mut parts = line.split_whitespace();
            parts.next()?; // skip address field
            let policy_field = parts.next()?;
            Some((policy_field, line))
        })
        .collect();

    if policy_entries.is_empty() {
        eprintln!("no parsable entries found in /proc/self/numa_maps");
        return;
    }

    let fallback_entry = policy_entries[0];
    let default_policy_field = fallback_entry.0;
    let find_with_substring = |needle: &str| -> (&str, &str) {
        policy_entries
            .iter()
            .copied()
            .find(|(policy, _)| policy.contains(needle))
            .unwrap_or(fallback_entry)
    };

    // Get auxiliary info from spec (nodes/flags)
    let expected_nodes = expected_nodes_from_spec(spec);
    let (nodes_is_empty, has_static_flag, has_relative_flag) = if let Some(p) = memory_policy {
        let nodes_is_empty = p.nodes().as_ref().is_none_or(|n| n.trim().is_empty());
        let mut has_static = false;
        let mut has_relative = false;
        if let Some(flags) = p.flags() {
            for f in flags {
                use oci_spec::runtime::MemoryPolicyFlagType::*;
                match f {
                    MpolFStaticNodes => has_static = true,
                    MpolFRelativeNodes => has_relative = true,
                    _ => {}
                }
            }
        }
        (nodes_is_empty, has_static, has_relative)
    } else {
        (true, false, false)
    };

    // Verify the policy matches expected mode
    match expected_mode {
        Some(MemoryPolicyModeType::MpolDefault) => {
            let (policy_field, _) = find_with_substring("default");
            if !policy_field.contains("default") {
                eprintln!("expected default policy, but found: {}", policy_field);
            }
        }
        Some(MemoryPolicyModeType::MpolInterleave) => {
            let (policy_field, full_line) = find_with_substring("interleave");
            if !policy_field.contains("interleave") {
                eprintln!("expected interleave policy, but found: {}", policy_field);
            }
            if expected_nodes.as_ref().is_some_and(|v| v.contains(&0))
                && !numa_maps_indicates_node0(policy_field)
            {
                eprintln!(
                    "expected interleave including node0, but got: {}",
                    full_line
                );
            }
        }
        Some(MemoryPolicyModeType::MpolBind) => {
            let (policy_field, full_line) = find_with_substring("bind");
            if !policy_field.contains("bind") {
                eprintln!("expected bind policy, but found: {}", policy_field);
            }
            if has_static_flag && !policy_field.contains("static") {
                eprintln!("expected bind static, but found: {}", policy_field);
            }
            if expected_nodes.as_ref().is_some_and(|v| v.contains(&0))
                && !numa_maps_indicates_node0(policy_field)
            {
                eprintln!("expected bind including node0, but got: {}", full_line);
            }
        }
        Some(MemoryPolicyModeType::MpolPreferred) => {
            if nodes_is_empty {
                let (policy_field, _) = find_with_substring("local");
                if !policy_field.contains("local") {
                    eprintln!(
                        "expected preferred(empty)->local, but found: {}",
                        policy_field
                    );
                }
            } else {
                let (policy_field, full_line) = find_with_substring("prefer");
                if !policy_field.contains("prefer") {
                    eprintln!("expected preferred policy, but found: {}", policy_field);
                }
                if has_relative_flag && !policy_field.contains("relative") {
                    eprintln!("expected preferred relative, but found: {}", policy_field);
                }
                if expected_nodes.as_ref().is_some_and(|v| v.contains(&0))
                    && !numa_maps_indicates_node0(policy_field)
                {
                    eprintln!("expected preferred including node0, but got: {}", full_line);
                }
            }
        }
        Some(MemoryPolicyModeType::MpolLocal) => {
            let (policy_field, _) = find_with_substring("local");
            if !policy_field.contains("local") {
                eprintln!("expected local policy, but found: {}", policy_field);
            }
        }
        Some(_) => {
            // For newer policy types that might not be easily verifiable
            println!(
                "memory policy {} applied (non-strict check)",
                default_policy_field
            );
        }
        None => {
            if !policy_entries.iter().any(|(policy_field, _)| {
                policy_field.contains("default") || policy_field.contains("local")
            }) {
                eprintln!(
                    "expected default/local with no expected policy, got: {}",
                    default_policy_field
                );
            }
        }
    }
}

pub fn test_validate_root_readonly(spec: &Spec) {
    let root = spec.root().as_ref().unwrap();
    if root.readonly().unwrap() {
        if let Err(e) = test_dir_write_access("/") {
            let errno = Errno::from_raw(e.raw_os_error().unwrap());
            if errno == Errno::EROFS {
                /* This is expected */
            } else {
                eprintln!(
                    "readonly root filesystem, error in testing write access for path /, error: {}",
                    errno
                );
            }
        }
        if let Err(e) = test_dir_read_access("/") {
            eprintln!(
                "readonly root filesystem, but error in testing read access for path /, error: {}",
                e
            );
        }
    } else {
        if let Err(e) = test_dir_write_access("/") {
            eprintln!(
                "readonly root filesystem is false, but error in testing write access for path /, error: {}",
                e
            );
        }
        if let Err(e) = test_dir_read_access("/") {
            eprintln!(
                "readonly root filesystem is false, but error in testing read access for path /, error: {}",
                e
            );
        }
    }
}

pub fn validate_process(spec: &Spec) {
    let process = spec.process().as_ref().unwrap();
    let expected_cwd = process.cwd();
    let cwd = &getcwd().unwrap();

    if expected_cwd != cwd {
        eprintln!(
            "error due to spec cwd want {:?}, got {:?}",
            expected_cwd, cwd
        )
    }

    for env_str in process.env().as_ref().unwrap().iter() {
        match env_str.split_once("=") {
            Some((env_key, expected_val)) => {
                let actual_val = env::var(env_key).unwrap();
                if actual_val != expected_val {
                    eprintln!(
                        "error due to spec environment value of {:?} want {:?}, got {:?}",
                        env_key, expected_val, actual_val
                    )
                }
            }
            None => {
                eprintln!(
                    "spec env value is not correct : expected key=value format, got {env_str}"
                )
            }
        }
    }
}

pub fn validate_process_user(spec: &Spec) {
    let process = spec.process().as_ref().unwrap();
    let expected_uid = Uid::from(process.user().uid());
    let expected_gid = Gid::from(process.user().gid());
    let expected_umask = Mode::from_bits(process.user().umask().unwrap()).unwrap();

    let uid = getuid();
    let gid = getgid();
    // The umask function not only gets the current mask, but also has the ability to set a new mask,
    // so we need to set it back after getting the latest value.
    let current_umask = umask(nix::sys::stat::Mode::empty());
    umask(current_umask);

    if expected_uid != uid {
        eprintln!("error due to uid want {}, got {}", expected_uid, uid)
    }

    if expected_gid != gid {
        eprintln!("error due to gid want {}, got {}", expected_gid, gid)
    }

    if let Err(e) = validate_additional_gids(process.user().additional_gids().as_ref().unwrap()) {
        eprintln!("error additional gids {e}");
    }

    if expected_umask != current_umask {
        eprintln!(
            "error due to umask want {:?}, got {:?}",
            expected_umask, current_umask
        )
    }
}

// validate_additional_gids function is used to validate additional groups of user
fn validate_additional_gids(expected_gids: &Vec<u32>) -> Result<()> {
    let current_gids = getgroups().unwrap();

    if expected_gids.len() != current_gids.len() {
        bail!(
            "error : additional group mismatch, want {:?}, got {:?}",
            expected_gids,
            current_gids
        );
    }

    for gid in expected_gids {
        if !current_gids.contains(&Gid::from_raw(*gid)) {
            bail!(
                "error : additional gid {} is not in current groups, expected {:?}, got {:?}",
                gid,
                expected_gids,
                current_gids
            );
        }
    }

    Ok(())
}

pub fn validate_process_rlimits(spec: &Spec) {
    let process = spec.process().as_ref().unwrap();
    let spec_rlimits: &Vec<PosixRlimit> = process.rlimits().as_ref().unwrap();

    for spec_rlimit in spec_rlimits.iter() {
        let (soft_limit, hard_limit) = getrlimit(change_resource_type(spec_rlimit.typ())).unwrap();
        if spec_rlimit.hard() != hard_limit {
            eprintln!(
                "error type of {:?} hard rlimit expected {:?} , got {:?}",
                spec_rlimit.typ(),
                spec_rlimit.hard(),
                hard_limit
            )
        }

        if spec_rlimit.soft() != soft_limit {
            eprintln!(
                "error type of {:?} soft rlimit expected {:?} , got {:?}",
                spec_rlimit.typ(),
                spec_rlimit.soft(),
                soft_limit
            )
        }
    }
}

fn change_resource_type(resource_type: PosixRlimitType) -> Resource {
    match resource_type {
        PosixRlimitType::RlimitCpu => Resource::RLIMIT_CPU,
        PosixRlimitType::RlimitFsize => Resource::RLIMIT_FSIZE,
        PosixRlimitType::RlimitData => Resource::RLIMIT_DATA,
        PosixRlimitType::RlimitStack => Resource::RLIMIT_STACK,
        PosixRlimitType::RlimitCore => Resource::RLIMIT_CORE,
        PosixRlimitType::RlimitRss => Resource::RLIMIT_RSS,
        PosixRlimitType::RlimitNproc => Resource::RLIMIT_NPROC,
        PosixRlimitType::RlimitNofile => Resource::RLIMIT_NOFILE,
        PosixRlimitType::RlimitMemlock => Resource::RLIMIT_MEMLOCK,
        PosixRlimitType::RlimitAs => Resource::RLIMIT_AS,
        PosixRlimitType::RlimitLocks => Resource::RLIMIT_LOCKS,
        PosixRlimitType::RlimitSigpending => Resource::RLIMIT_SIGPENDING,
        PosixRlimitType::RlimitMsgqueue => Resource::RLIMIT_MSGQUEUE,
        PosixRlimitType::RlimitNice => Resource::RLIMIT_NICE,
        PosixRlimitType::RlimitRtprio => Resource::RLIMIT_RTPRIO,
        PosixRlimitType::RlimitRttime => Resource::RLIMIT_RTTIME,
    }
}

// the validate_rootfs function is used to validate the rootfs of the container is
// as expected. This function is used in the no_pivot test to validate the rootfs
pub fn validate_rootfs() {
    // list the first level directories in the rootfs
    let mut entries = fs::read_dir("/")
        .unwrap()
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                let path = e.path();
                if path.is_dir() {
                    path.file_name()
                        .and_then(|name| name.to_str().map(|s| s.to_owned()))
                } else {
                    None
                }
            })
        })
        .collect::<Vec<String>>();
    // sort the entries to make the test deterministic
    entries.sort();

    // this is the list of directories that we expect to find in the rootfs
    let mut expected = vec![
        "bin", "dev", "etc", "home", "proc", "root", "sys", "tmp", "usr", "var",
    ];
    // sort the expected entries to make the test deterministic
    expected.sort();

    // compare the expected entries with the actual entries
    if entries != expected {
        eprintln!("error due to rootfs want {expected:?}, got {entries:?}");
    }
}

pub fn validate_process_oom_score_adj(spec: &Spec) {
    let process = spec.process().as_ref().unwrap();
    let expected_value = process.oom_score_adj().unwrap();

    let pid = std::process::id();
    let oom_score_adj_path = format!("/proc/{}/oom_score_adj", pid);

    let actual_value = fs::read_to_string(oom_score_adj_path)
        .unwrap_or_else(|_| panic!("Failed to read file content"));

    if actual_value.trim() != expected_value.to_string() {
        eprintln!("Unexpected oom_score_adj, expected: {expected_value} found: {actual_value}");
    }
}

pub fn validate_fd_control(_spec: &Spec) {
    // --preserve-fds does not get passed via the spec so we have to communicate information
    // via the root filesystem
    let expected_num_fds: usize = fs::read_to_string("/num-fds").unwrap().parse().unwrap();

    let mut entries = vec![];
    let stdio: &[&OsStr] = &["0".as_ref(), "1".as_ref(), "2".as_ref()];
    for entry in fs::read_dir("/proc/self/fd").unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if stdio.contains(&name.as_os_str()) {
            // Ignore stdio
            continue;
        }
        entries.push((entry.path(), fs::read_link(entry.path())))
    }

    // NOTE: we do this in a separate loop so we can filter out the dirfd used behind
    // the scenes in 'fs::read_dir'. It is important to *not* store the full DirEntry
    // type, as that keeps the dirfd open.
    let mut fd_details = vec![];
    let mut found_dirfd = false;
    for (path, linkpath) in &entries {
        // The difference between metadata.unwrap() and fs::metadata is that the latter
        // will now try to follow the symlink
        match fs::metadata(path) {
            Ok(m) => fd_details.push((path, linkpath, m)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !found_dirfd => {
                // Expected for the dirfd
                found_dirfd = true
            }
            Err(e) => {
                eprintln!("unexpected error reading metadata: {}", e)
            }
        }
    }

    if fd_details.len() != expected_num_fds {
        eprintln!("mismatched fds inside container! {:?}", fd_details);
    }
}

pub fn validate_masked_paths(spec: &Spec) {
    let linux = spec.linux().as_ref().unwrap();
    let masked_paths = match linux.masked_paths() {
        Some(p) => p,
        None => {
            eprintln!("in masked paths, expected some masked paths to be set, found none");
            return;
        }
    };

    for path in masked_paths.iter().map(Path::new) {
        if !path.is_absolute() {
            eprintln!("in masked paths, the path must be absolute.")
        }
        match test_read_access(path) {
            Ok(true) => {
                eprintln!(
                    "in masked paths, expected path {:?} to be masked, but was found readable",
                    path.iter().as_path(),
                );
                return;
            }
            Ok(false) => { /* This is expected */ }
            Err(e) => {
                let errno = Errno::from_raw(e.raw_os_error().unwrap());
                if errno == Errno::ENOENT {
                    /* This is expected */
                } else {
                    eprintln!(
                        "in masked paths, error in testing read access for path {:?} : {errno:?}",
                        path.iter().as_path(),
                    );
                    return;
                }
            }
        }
    }
}

pub fn validate_rootfs_propagation(spec: &Spec) {
    let linux = spec.linux().as_ref().unwrap();
    let propagation = linux.rootfs_propagation().as_ref().unwrap();

    let target_dir = Builder::new()
        .prefix("target")
        .tempdir()
        .expect("create target directory");
    let target_path = target_dir.path();

    match propagation.as_str() {
        "shared" | "slave" | "private" => {
            if let Err(e) = mount(
                Some("/"),
                target_dir.path(),
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            ) {
                eprintln!("bind-mount / {}: {}", target_dir.path().display(), e);
            }

            let mount_dir = Builder::new()
                .prefix("mount")
                .tempdir()
                .expect("create mount directory");
            let test_dir = Builder::new()
                .prefix("test")
                .tempdir()
                .expect("create test directory");
            let tmpfile_path = test_dir.path().join("example");
            let _file = File::create(&tmpfile_path).expect("create temp file");

            mount(
                Some(test_dir.path()),
                mount_dir.path(),
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )
            .map_err(|e| {
                format!(
                    "Failed to bind-mount {} to {}: {}",
                    test_dir.path().display(),
                    mount_dir.path().display(),
                    e
                )
            })
            .unwrap();

            let target_file = target_path
                .join(mount_dir.path().strip_prefix("/").unwrap())
                .join(tmpfile_path.file_name().unwrap());
            let file_visible = target_file.exists();

            match propagation.as_str() {
                "shared" => {
                    if !file_visible {
                        eprintln!(
                            "Error: shared root propagation failed to expose {:?}",
                            target_file
                        );
                    }
                }
                "slave" | "private" => {
                    if file_visible {
                        eprintln!(
                            "Error: {} root propagation unexpectedly exposed {:?}",
                            propagation, target_file
                        );
                    }
                }
                _ => unreachable!(),
            }
        }
        "unbindable" => {
            if let Err(e) = mount(
                Some("/"),
                target_dir.path(),
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            ) && e != nix::errno::Errno::EINVAL
            {
                eprintln!("Error occurred during mount: {}", e);
            }
        }
        _ => {
            eprintln!("Unrecognized rootfsPropagation: {}", propagation);
        }
    }
}

fn validate_id_mappings(expected_id_mappings: &[LinuxIdMapping], path: &str, property: &str) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open {}: {}", path, e);
            return;
        }
    };

    let reader = io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(|line| line.ok()).collect();

    if expected_id_mappings.len() != lines.len() {
        eprintln!(
            "Mismatch in {}: expected {} lines, found {}",
            property,
            expected_id_mappings.len(),
            lines.len()
        );
    }

    for (expected, line) in expected_id_mappings.iter().zip(lines.iter()) {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // "man 7 user_namespaces" explains the format of uid_map and gid_map:
        // <container_id> <host_id> <map_size>
        if parts.len() != 3 {
            eprintln!("Unexpected format in {}: {}", path, line);
            continue;
        }

        let actual_container_id = parts.first().unwrap().parse::<u32>().unwrap();
        let actual_host_id = parts.get(1).unwrap().parse::<u32>().unwrap();
        let actual_map_size = parts.get(2).unwrap().parse::<u32>().unwrap();

        if !(actual_host_id == expected.host_id()
            && actual_container_id == expected.container_id()
            && actual_map_size == expected.size())
        {
            eprintln!(
                "Unexpected {}, expected: ({} {} {}) found: ({} {} {})",
                property,
                expected.container_id(),
                expected.host_id(),
                expected.size(),
                actual_container_id,
                actual_host_id,
                actual_map_size
            );
        }
    }
}

pub fn validate_uid_mappings(spec: &Spec) {
    let linux = spec.linux().as_ref().unwrap();

    let expected_uid_mappings = linux.uid_mappings().as_ref().unwrap();
    validate_id_mappings(expected_uid_mappings, "/proc/self/uid_map", "uid_mappings");

    let expected_gid_mappings = linux.gid_mappings().as_ref().unwrap();
    validate_id_mappings(expected_gid_mappings, "/proc/self/gid_map", "gid_mappings");
}
