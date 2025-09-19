use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Result, bail};

use crate::utils::get_runtime_path;

// There are still some issues here in case we put stdout and stderr as piped
// the youki process created halts indefinitely which is why we pass null, and
// use wait instead of wait_with_output
pub fn create(project_path: &Path, id: &str) -> Result<()> {
    let res = Command::new(get_runtime_path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .arg("--root")
        .arg(project_path.join("runtime"))
        .arg("create")
        .arg("--bundle")
        .arg(project_path.join("bundle"))
        .arg(id)
        .spawn()
        .expect("Cannot execute create command")
        .wait();
    match res {
        io::Result::Ok(status) => {
            if status.success() {
                Ok(())
            } else {
                bail!("create exited with nonzero status : {}", status)
            }
        }
        io::Result::Err(e) => bail!("create failed : {}", e),
    }
}
