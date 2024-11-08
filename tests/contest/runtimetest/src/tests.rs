use std::fs::{self, read_dir};
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;

use anyhow::{bail, Result};
use nix::errno::Errno;
use nix::libc;
use nix::sys::resource::{getrlimit, Resource};
use nix::sys::utsname;
use nix::unistd::getcwd;
use oci_spec::runtime::IOPriorityClass::{self, IoprioClassBe, IoprioClassIdle, IoprioClassRt};
use oci_spec::runtime::{
    LinuxDevice, LinuxDeviceType, LinuxSchedulerPolicy, PosixRlimit, PosixRlimitType, Spec,
};

use crate::utils::{self, test_read_access, test_write_access};

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
                                        bail!("path {:?} expected to be not executable, found executable", test_file_path);
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
                                        bail!("path {:?} expected to be executable, found not executable, error: {ee}", test_file_path);
                                    }
                                    Ok(())
                                },
                            ) {
                                eprintln!("error in testing rexec recursive mounting: {e}");
                            }
                        }
                        "rdiratime" => {
                            println!("test_dir_update_access_time: {mount:?}");
                            let rest = utils::test_dir_update_access_time(
                                mount.destination().to_str().unwrap(),
                            );
                            if let Err(e) = rest {
                                eprintln!("error in testing rdiratime recursive mounting: {e}");
                            }
                        }
                        "rnodiratime" => {
                            println!("test_dir_not_update_access_time: {mount:?}");
                            let rest = utils::test_dir_not_update_access_time(
                                mount.destination().to_str().unwrap(),
                            );
                            if let Err(e) = rest {
                                eprintln!("error in testing rnodiratime recursive mounting: {e}");
                            }
                        }
                        "rdev" => {
                            println!("test_device_access: {mount:?}");
                            let rest =
                                utils::test_device_access(mount.destination().to_str().unwrap());
                            if let Err(e) = rest {
                                eprintln!("error in testing rdev recursive mounting: {e}");
                            }
                        }
                        "rnodev" => {
                            println!("test_device_unaccess: {mount:?}");
                            let rest =
                                utils::test_device_unaccess(mount.destination().to_str().unwrap());
                            if rest.is_ok() {
                                // because /rnodev/null device not access,so rest is err
                                eprintln!("error in testing rnodev recursive mounting");
                            }
                        }
                        "rrelatime" => {
                            println!("rrelatime: {mount:?}");
                            if let Err(e) = utils::test_mount_releatime_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!("path expected to be rrelatime, found not rrelatime, error: {e}");
                            }
                        }
                        "rnorelatime" => {
                            println!("rnorelatime: {mount:?}");
                            if let Err(e) = utils::test_mount_noreleatime_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!("path expected to be rnorelatime, found not rnorelatime, error: {e}");
                            }
                        }
                        "rnoatime" => {
                            println!("rnoatime: {mount:?}");
                            if let Err(e) = utils::test_mount_rnoatime_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!(
                                    "path expected to be rnoatime, found not rnoatime, error: {e}"
                                );
                            }
                        }
                        "rstrictatime" => {
                            println!("rstrictatime: {mount:?}");
                            if let Err(e) = utils::test_mount_rstrictatime_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!("path expected to be rstrictatime, found not rstrictatime, error: {e}");
                            }
                        }
                        "rnosymfollow" => {
                            if let Err(e) = utils::test_mount_rnosymfollow_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!("path expected to be rnosymfollow, found not rnosymfollow, error: {e}");
                            }
                        }
                        "rsymfollow" => {
                            if let Err(e) = utils::test_mount_rsymfollow_option(
                                mount.destination().to_str().unwrap(),
                            ) {
                                eprintln!("path expected to be rsymfollow, found not rsymfollow, error: {e}");
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
    println!("schedule is {:?}", spec);
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
            Ok(_) => {
                println!("sched_getattr get success");
            }
            Err(e) => {
                return eprintln!("error due to fail to get sched attr error: {e}");
            }
        };
    }
    println!("get_sched_attr is {:?}", get_sched_attr);
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
    println!("want_sp {:?}", want_sp);
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

    if let Some(expected_uid) = device.uid() {
        if file_data.st_uid() != expected_uid {
            eprintln!(
                "error due to device uid want {}, got {}",
                expected_uid,
                file_data.st_uid()
            );
        }
    }

    if let Some(expected_gid) = device.gid() {
        if file_data.st_gid() != expected_gid {
            eprintln!(
                "error due to device gid want {}, got {}",
                expected_gid,
                file_data.st_gid()
            );
        }
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
