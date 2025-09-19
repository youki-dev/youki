use std::{io, process};

use anyhow::{Result, bail};

pub fn get_result_from_output(res: io::Result<process::Output>) -> Result<()> {
    match res {
        io::Result::Ok(output) => {
            let stderr = String::from_utf8(output.stderr).unwrap();
            if stderr.contains("Error") || stderr.contains("error") {
                let stdout = String::from_utf8(output.stdout).unwrap();
                bail!("Error :\nstdout : {}\nstderr : {}", stdout, stderr)
            } else {
                Ok(())
            }
        }
        io::Result::Err(e) => Err(anyhow::Error::new(e)),
    }
}

pub fn criu_installed() -> bool {
    which::which("criu").is_ok()
}
