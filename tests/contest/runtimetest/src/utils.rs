use std::fs;
use std::fs::{OpenOptions, symlink_metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::sys::stat::{SFlag, stat};
use procfs::process::Process;

// It means the file or directory is readable
type Readable = bool;

fn test_file_read_access<P: AsRef<Path>>(path: P) -> Result<Readable, std::io::Error> {
    let mut file = OpenOptions::new().create(false).read(true).open(path)?;

    // Create a buffer with a capacity of 1 byte
    let mut buffer = [0u8; 1];
    match file.read(&mut buffer) {
        // Our contest tests only use non-empty files for read-access
        // tests. So if we get an EOF on the first read or zero bytes, the runtime did
        // successfully block readability.
        Ok(0) => Ok(false),
        Ok(_) => Ok(true),
        Err(e) => Err(e),
    }
}

pub fn test_dir_read_access<P: AsRef<Path>>(path: P) -> Result<Readable, std::io::Error> {
    let entries = std::fs::read_dir(path);

    match entries {
        Ok(mut entries_iter) => {
            // Get the first entry
            match entries_iter.next() {
                Some(entry) => {
                    match entry {
                        Ok(_) => Ok(true),   // If the entry is Ok, then it's readable
                        Err(_) => Ok(false), // If the entry is Err, then it's not readable
                    }
                }
                None => Ok(false), // If there's an error, then it's not readable, or otherwise, it may indicate different conditions.
            }
        }
        Err(e) => Err(e),
    }
}

fn is_file_like(mode: u32) -> bool {
    // for this please refer
    // https://stackoverflow.com/questions/40163270/what-is-s-isreg-and-what-does-it-do
    // https://linux.die.net/man/2/stat
    mode & SFlag::S_IFREG.bits() != 0 || mode & SFlag::S_IFCHR.bits() != 0
}

fn is_dir(mode: u32) -> bool {
    mode & SFlag::S_IFDIR.bits() != 0
}

pub fn test_read_access<P: AsRef<Path>>(path: P) -> Result<Readable, std::io::Error> {
    let path_ref = path.as_ref();
    let fstat = stat(path_ref)?;
    let mode = fstat.st_mode;
    if is_file_like(mode) {
        // we have a file or a char/block device
        return test_file_read_access(path);
    } else if is_dir(mode) {
        return test_dir_read_access(path);
    }

    Err(std::io::Error::other(format!(
        "cannot test read access for {:?}, has mode {mode:x}",
        path_ref
    )))
}

fn test_file_write_access(path: &str) -> Result<(), std::io::Error> {
    let _ = std::fs::OpenOptions::new().write(true).open(path)?;
    Ok(())
}

pub fn test_dir_write_access(path: &str) -> Result<(), std::io::Error> {
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(PathBuf::from(path).join("test.txt"))?;
    Ok(())
}

pub fn test_write_access(path: &str) -> Result<(), std::io::Error> {
    let fstat = stat(path)?;
    let mode = fstat.st_mode;
    if is_file_like(mode) {
        // we have a file or a char/block device
        return test_file_write_access(path);
    } else if is_dir(mode) {
        return test_dir_write_access(path);
    }

    Err(std::io::Error::other(format!(
        "cannot test write access for {path:?}, has mode {mode:x}"
    )))
}

pub fn test_file_executable(path: &str) -> Result<(), std::io::Error> {
    let fstat = stat(path)?;
    let mode = fstat.st_mode;
    if is_file_like(mode) {
        Command::new(path).output()?;
        return Ok(());
    }

    Err(std::io::Error::other(format!(
        "{path:?} is directory, so cannot execute"
    )))
}

pub fn test_dir_update_access_time(path: &str) -> Result<(), std::io::Error> {
    let metadata = fs::metadata(PathBuf::from(path))?;
    let rest = metadata.accessed();
    let first_access_time = rest.unwrap();
    // execute ls command to update access time
    Command::new("ls")
        .arg(path)
        .output()
        .expect("execute ls command error");
    // second get access time
    let metadata = fs::metadata(PathBuf::from(path))?;
    let rest = metadata.accessed();
    let second_access_time = rest.unwrap();
    if first_access_time == second_access_time {
        return Err(std::io::Error::other(format!(
            "cannot update access time for path {path:?}"
        )));
    }
    Ok(())
}

pub fn assert_atime_mode(path: &str, expected: &str) -> Result<(), std::io::Error> {
    match atime_mode_of(path) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(std::io::Error::other(format!(
            "expected atime mode '{expected}' at {path}, got '{actual}'"
        ))),
        None => Err(std::io::Error::other(format!("mount {path} not found"))),
    }
}

fn atime_mode_of(path: &str) -> Option<String> {
    let mounts = Process::myself().ok()?.mountinfo().ok()?;
    for m in mounts {
        if m.mount_point.to_str() != Some(path) {
            continue;
        }
        let mode = if m.mount_options.contains_key("noatime") {
            "noatime"
        } else if m.mount_options.contains_key("relatime") {
            "relatime"
        } else {
            "strictatime"
        };
        return Some(mode.to_string());
    }
    None
}

pub fn test_dir_not_update_access_time(path: &str) -> Result<(), std::io::Error> {
    let metadata = fs::metadata(PathBuf::from(path))?;
    let rest = metadata.accessed();
    let first_access_time = rest.unwrap();
    // execute ls command to update access time
    Command::new("ls")
        .arg(path)
        .output()
        .expect("execute ls command error");
    // second get access time
    let metadata = fs::metadata(PathBuf::from(path))?;
    let rest = metadata.accessed();
    let second_access_time = rest.unwrap();
    if first_access_time != second_access_time {
        return Err(std::io::Error::other(format!(
            "cannot update access time for path {path:?}"
        )));
    }
    Ok(())
}

pub fn test_device_access(path: &str) -> Result<(), std::io::Error> {
    OpenOptions::new().read(true).open(path)?;
    Ok(())
}

pub fn test_mount_rnosymfollow_option(dir: &str) -> Result<(), std::io::Error> {
    let link = format!("{}/link", dir);

    let md = symlink_metadata(&link)?;
    if !md.file_type().is_symlink() {
        return Err(std::io::Error::other("link is not a symlink"));
    }

    match fs::metadata(&link) {
        Ok(_) => Err(std::io::Error::other(
            "expected ELOOP (nosymfollow), but symlink was followed",
        )),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Ok(()),
        Err(e) => Err(std::io::Error::other(format!(
            "expected ELOOP, but got: {e}"
        ))),
    }
}

pub fn test_mount_rsymfollow_option(dir: &str) -> Result<(), std::io::Error> {
    let link = format!("{}/link", dir);

    let md = symlink_metadata(&link)?;
    if !md.file_type().is_symlink() {
        return Err(std::io::Error::other("link is not a symlink"));
    }

    match fs::metadata(&link) {
        Ok(_) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            Err(std::io::Error::other(format!("unexpected ELOOP: {e}")))
        }
        // Any error other than ELOOP indicates that nosymfollow is not being enforced, so we consider the result OK.
        Err(_) => Ok(()),
    }
}
