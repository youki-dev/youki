use std::fs;
use std::fs::{metadata, symlink_metadata, OpenOptions};
use std::io::Read;
use std::os::unix::prelude::MetadataExt;
use std::path::PathBuf;
use std::process::Command;

use nix::sys::stat::{stat, SFlag};

fn test_file_read_access(path: &str) -> Result<bool, std::io::Error> {
    let mut file = OpenOptions::new().create(false).read(true).open(path)?;

    // Create a buffer with a capacity of 1 byte
    let mut buffer = [0u8; 1];
    match file.read(&mut buffer) {
        // Our contest tests only use non-empty files for read-access
		// tests. So if we get an EOF on the first read or zero bytes, the runtime did
		// successfully block readability.
        Ok(0) => Ok(false),
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

pub fn test_dir_read_access(path: &str) -> Result<bool, std::io::Error> {
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

pub fn test_read_access(path: &str) -> Result<bool, std::io::Error> {
    let fstat = stat(path)?;
    let mode = fstat.st_mode;
    if is_file_like(mode) {
        // we have a file or a char/block device
        return test_file_read_access(path);
    } else if is_dir(mode) {
        return test_dir_read_access(path);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("cannot test read access for {path:?}, has mode {mode:x}"),
    ))
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

    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("cannot test write access for {path:?}, has mode {mode:x}"),
    ))
}

pub fn test_file_executable(path: &str) -> Result<(), std::io::Error> {
    let fstat = stat(path)?;
    let mode = fstat.st_mode;
    if is_file_like(mode) {
        Command::new(path).output()?;
        return Ok(());
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("{path:?} is directory, so cannot execute"),
    ))
}

pub fn test_dir_update_access_time(path: &str) -> Result<(), std::io::Error> {
    println!("test_dir_update_access_time path: {path:?}");
    let metadata = fs::metadata(PathBuf::from(path))?;
    let rest = metadata.accessed();
    let first_access_time = rest.unwrap();
    println!("{path:?} dir first access time is {first_access_time:?}");
    // execute ls command to update access time
    Command::new("ls")
        .arg(path)
        .output()
        .expect("execute ls command error");
    // second get access time
    let metadata = fs::metadata(PathBuf::from(path))?;
    let rest = metadata.accessed();
    let second_access_time = rest.unwrap();
    println!("{path:?} dir second access time is {second_access_time:?}");
    if first_access_time == second_access_time {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("cannot update access time for path {path:?}"),
        ));
    }
    Ok(())
}

pub fn test_dir_not_update_access_time(path: &str) -> Result<(), std::io::Error> {
    println!("test_dir_not_update_access_time path: {path:?}");
    let metadata = fs::metadata(PathBuf::from(path))?;
    let rest = metadata.accessed();
    let first_access_time = rest.unwrap();
    println!("{path:?} dir first access time is {first_access_time:?}");
    // execute ls command to update access time
    Command::new("ls")
        .arg(path)
        .output()
        .expect("execute ls command error");
    // second get access time
    let metadata = fs::metadata(PathBuf::from(path))?;
    let rest = metadata.accessed();
    let second_access_time = rest.unwrap();
    println!("{path:?} dir second access time is {second_access_time:?}");
    if first_access_time != second_access_time {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("cannot update access time for path {path:?}"),
        ));
    }
    Ok(())
}

pub fn test_device_access(path: &str) -> Result<(), std::io::Error> {
    println!("test_device_access path: {path:?}");
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(PathBuf::from(path).join("null"))?;
    Ok(())
}

pub fn test_device_unaccess(path: &str) -> Result<(), std::io::Error> {
    println!("test_device_unaccess path: {path:?}");
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(PathBuf::from(path).join("null"))?;
    Ok(())
}

// https://man7.org/linux/man-pages/man2/mount_setattr.2.html
// When a file is accessed via this mount, update the
// file's last access time (atime) only if the current
// value of atime is less than or equal to the file's
// last modification time (mtime) or last status
// change time (ctime).
// case:
// 1. create test.txt file, get one atime
// 2. cat a.txt, get two atime; check atime whether update, conditions are met atime less than or equal mtime or ctime
// 3. cat a.txt, get three atime, check now two atime whether equal three atime
pub fn test_mount_releatime_option(path: &str) -> Result<(), std::io::Error> {
    let test_file_path = PathBuf::from(path).join("test.txt");
    Command::new("touch")
        .arg(test_file_path.to_str().unwrap())
        .output()?;
    let one_metadata = fs::metadata(test_file_path.clone())?;
    println!(
        "{:?} file one metadata atime is {:?},mtime is {:?},current time is{:?}",
        test_file_path,
        one_metadata.atime(),
        one_metadata.mtime(),
        std::time::SystemTime::now()
    );
    std::thread::sleep(std::time::Duration::from_millis(1000));

    // execute cat command to update access time
    Command::new("cat")
        .arg(test_file_path.to_str().unwrap())
        .output()
        .expect("execute cat command error");
    let two_metadata = fs::metadata(test_file_path.clone())?;
    println!(
        "{:?} file two metadata atime is {:?},mtime is {:?},current time is{:?}",
        test_file_path,
        two_metadata.atime(),
        two_metadata.mtime(),
        std::time::SystemTime::now()
    );

    if one_metadata.atime() == two_metadata.atime() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "not update access time for file {:?}",
                test_file_path.to_str()
            ),
        ));
    }

    // execute cat command to update access time
    std::thread::sleep(std::time::Duration::from_millis(1000));
    Command::new("cat")
        .arg(test_file_path.to_str().unwrap())
        .output()
        .expect("execute cat command error");
    let three_metadata = fs::metadata(test_file_path.clone())?;
    println!(
        "{:?} file three metadata atime is {:?}",
        test_file_path,
        three_metadata.atime()
    );
    if two_metadata.atime() != three_metadata.atime() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("update access time for file {:?}", test_file_path.to_str()),
        ));
    }

    Ok(())
}

// case: because filesystem having relatime option
// 1. create test.txt file, get one atime
// 2. cat a.txt, get two atime; check atime whether update
// 3. cat a.txt, get three atime, check now two atime whether equal three atime
pub fn test_mount_noreleatime_option(path: &str) -> Result<(), std::io::Error> {
    let test_file_path = PathBuf::from(path).join("noreleatime.txt");
    Command::new("touch")
        .arg(test_file_path.to_str().unwrap())
        .output()?;
    let one_metadata = fs::metadata(test_file_path.clone())?;
    println!(
        "{:?} file one atime is {:?},mtime is {:?}, current time is {:?}",
        test_file_path,
        one_metadata.atime(),
        one_metadata.mtime(),
        std::time::SystemTime::now()
    );

    std::thread::sleep(std::time::Duration::from_millis(1000));
    // execute cat command to update access time
    Command::new("cat")
        .arg(test_file_path.to_str().unwrap())
        .output()
        .expect("execute cat command error");
    let two_metadata = fs::metadata(test_file_path.clone())?;
    println!(
        "{:?} file two atime is {:?},mtime is {:?},current time is {:?}",
        test_file_path,
        two_metadata.atime(),
        two_metadata.mtime(),
        std::time::SystemTime::now()
    );

    if one_metadata.atime() == two_metadata.atime() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "not update access time for file {:?}",
                test_file_path.to_str()
            ),
        ));
    }

    // execute cat command to update access time
    std::thread::sleep(std::time::Duration::from_millis(1000));
    Command::new("cat")
        .arg(test_file_path.to_str().unwrap())
        .output()
        .expect("execute cat command error");
    let three_metadata = fs::metadata(test_file_path.clone())?;
    println!(
        "{:?} file three atime is {:?},mtime is {:?},current time is {:?}",
        test_file_path,
        three_metadata.atime(),
        three_metadata.mtime(),
        std::time::SystemTime::now()
    );

    if two_metadata.atime() != three_metadata.atime() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("update access time for file {:?}", test_file_path.to_str()),
        ));
    }
    Ok(())
}

// Do not update access times for (all types of) files on this mount.
// case:
// 1. touch rnoatime.txt file, get atime
// 2. cat rnoatime.txt, check atime whether update, if update return error, else return Ok
pub fn test_mount_rnoatime_option(path: &str) -> Result<(), std::io::Error> {
    let test_file_path = PathBuf::from(path).join("rnoatime.txt");
    Command::new("touch")
        .arg(test_file_path.to_str().unwrap())
        .output()?;
    let one_metadata = fs::metadata(test_file_path.clone())?;
    println!(
        "{:?} file one atime is {:?},mtime is {:?}, current time is {:?}",
        test_file_path,
        one_metadata.atime(),
        one_metadata.mtime(),
        std::time::SystemTime::now()
    );
    std::thread::sleep(std::time::Duration::from_millis(1000));

    // execute cat command to update access time
    Command::new("cat")
        .arg(test_file_path.to_str().unwrap())
        .output()
        .expect("execute cat command error");
    let two_metadata = fs::metadata(test_file_path.clone())?;
    println!(
        "{:?} file two atime is {:?},mtime is {:?},current time is {:?}",
        test_file_path,
        two_metadata.atime(),
        two_metadata.mtime(),
        std::time::SystemTime::now()
    );
    if one_metadata.atime() != two_metadata.atime() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "update access time for file {:?}, expected not update",
                test_file_path.to_str()
            ),
        ));
    }
    Ok(())
}

// Always update the last access time (atime) when files are accessed on this mount.
pub fn test_mount_rstrictatime_option(path: &str) -> Result<(), std::io::Error> {
    let test_file_path = PathBuf::from(path).join("rstrictatime.txt");
    Command::new("touch")
        .arg(test_file_path.to_str().unwrap())
        .output()?;
    let one_metadata = fs::metadata(test_file_path.clone())?;
    println!(
        "{:?} file one atime is {:?},mtime is {:?}, current time is {:?}",
        test_file_path,
        one_metadata.atime(),
        one_metadata.mtime(),
        std::time::SystemTime::now()
    );

    std::thread::sleep(std::time::Duration::from_millis(1000));
    // execute cat command to update access time
    Command::new("cat")
        .arg(test_file_path.to_str().unwrap())
        .output()
        .expect("execute cat command error");
    let two_metadata = fs::metadata(test_file_path.clone())?;
    println!(
        "{:?} file two atime is {:?},mtime is {:?},current time is {:?}",
        test_file_path,
        two_metadata.atime(),
        two_metadata.mtime(),
        std::time::SystemTime::now()
    );

    if one_metadata.atime() == two_metadata.atime() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "not update access time for file {:?}",
                test_file_path.to_str()
            ),
        ));
    }

    // execute cat command to update access time
    std::thread::sleep(std::time::Duration::from_millis(1000));
    Command::new("cat")
        .arg(test_file_path.to_str().unwrap())
        .output()
        .expect("execute cat command error");
    let three_metadata = fs::metadata(test_file_path.clone())?;
    println!(
        "{:?} file three atime is {:?},mtime is {:?},current time is {:?}",
        test_file_path,
        two_metadata.atime(),
        two_metadata.mtime(),
        std::time::SystemTime::now()
    );

    if two_metadata.atime() == three_metadata.atime() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("update access time for file {:?}", test_file_path.to_str()),
        ));
    }
    Ok(())
}

pub fn test_mount_rnosymfollow_option(path: &str) -> Result<(), std::io::Error> {
    let path = format!("{}/{}", path, "link");
    let metadata = match symlink_metadata(path.clone()) {
        Ok(metadata) => metadata,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("get file symlink_metadata err {path:?}, {e}"),
            ));
        }
    };
    // check symbolic is followed
    if metadata.file_type().is_symlink() && metadata.mode() & 0o777 == 0o777 {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("get file symlink_metadata err {path:?}"),
        ))
    }
}

pub fn test_mount_rsymfollow_option(path: &str) -> Result<(), std::io::Error> {
    let path = format!("{}/{}", path, "link");
    let metadata = match symlink_metadata(path.clone()) {
        Ok(metadata) => metadata,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("get file symlink_metadata err {path:?}, {e}"),
            ));
        }
    };
    // check symbolic is followed
    if metadata.file_type().is_symlink() && metadata.mode() & 0o777 == 0o777 {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("get file symlink_metadata err {path:?}"),
        ))
    }
}

pub fn test_mount_rsuid_option(path: &str) -> Result<(), std::io::Error> {
    let path = PathBuf::from(path).join("file");

    let metadata = match metadata(path.clone()) {
        Ok(metadata) => metadata,
        Err(e) => {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
        }
    };
    // check suid and sgid
    let suid = metadata.mode() & 0o4000 == 0o4000;
    let sgid = metadata.mode() & 0o2000 == 0o2000;
    println!("suid: {suid:?},sgid: {sgid:?}");
    if suid && sgid {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("rsuid error {path:?}"),
    ))
}
