use std::ffi::CString;
use std::path::{Path, PathBuf};

use nix::unistd;
use oci_spec::runtime::Spec;

use super::{Executor, ExecutorError, ExecutorValidationError};

#[derive(Clone)]
pub struct DefaultExecutor {}

impl Executor for DefaultExecutor {
    fn exec(&self, spec: &Spec) -> Result<(), ExecutorError> {
        tracing::debug!("executing workload with default handler");
        let args = spec
            .process()
            .as_ref()
            .and_then(|p| p.args().as_ref())
            .ok_or_else(|| {
                tracing::error!("no arguments provided to execute");
                ExecutorError::InvalidArg
            })?;

        let executable = args[0].as_str();
        let cstring_path = CString::new(executable.as_bytes()).map_err(|err| {
            tracing::error!("failed to convert path {executable:?} to cstring: {}", err,);
            ExecutorError::InvalidArg
        })?;
        let a: Vec<CString> = args
            .iter()
            .map(|s| CString::new(s.as_bytes()).unwrap_or_default())
            .collect();
        unistd::execvp(&cstring_path, &a).map_err(|err| {
            tracing::error!(?err, filename = ?cstring_path, args = ?a, "failed to execvp");
            ExecutorError::Execution(
                format!(
                    "error '{}' executing '{:?}' with args '{:?}'",
                    err, cstring_path, a
                )
                .into(),
            )
        })?;

        // After execvp is called, the process is replaced with the container
        // payload through execvp, so it should never reach here.
        unreachable!();
    }

    fn validate(&self, spec: &Spec) -> Result<(), ExecutorValidationError> {
        let proc = spec
            .process()
            .as_ref()
            .ok_or(ExecutorValidationError::ArgValidationError(
                "spec did not contain process".into(),
            ))?;

        if let Some(args) = proc.args() {
            let envs: Vec<String> = proc.env().as_ref().unwrap_or(&vec![]).clone();
            let path_vars: Vec<&String> = envs.iter().filter(|&e| e.starts_with("PATH=")).collect();
            if path_vars.is_empty() {
                tracing::error!("PATH environment variable is not set");
                Err(ExecutorValidationError::ArgValidationError(
                    "PATH environment variable is not set".into(),
                ))?;
            }
            let path_var = path_vars[0].trim_start_matches("PATH=");
            match get_executable_path(&args[0], path_var) {
                None => {
                    tracing::error!(
                        executable = ?args[0],
                        "executable for container process not found in PATH",
                    );
                    Err(ExecutorValidationError::ArgValidationError(format!(
                        "executable '{}' not found in $PATH",
                        args[0]
                    )))?;
                }
                Some(path) => match is_executable(&path) {
                    Ok(true) => {
                        tracing::debug!(executable = ?path, "found executable in executor");
                    }
                    Ok(false) => {
                        tracing::error!(
                            executable = ?path,
                            "executable does not have the correct permission set",
                        );
                        Err(ExecutorValidationError::ArgValidationError(format!(
                            "executable '{}' at path '{:?}' does not have correct permissions",
                            args[0], path
                        )))?;
                    }
                    Err(err) => {
                        tracing::error!(
                            executable = ?path,
                            ?err,
                            "failed to check permissions for executable",
                        );
                        Err(ExecutorValidationError::ArgValidationError(format!(
                            "failed to check permissions for executable '{}' at path '{:?}' : {}",
                            args[0], path, err
                        )))?;
                    }
                },
            }
        }

        Ok(())
    }
}

pub fn get_executor() -> Box<dyn Executor> {
    Box::new(DefaultExecutor {})
}

fn get_executable_path(name: &str, path_var: &str) -> Option<PathBuf> {
    // if path has / in it, we have to assume absolute path, as per runc impl
    if name.contains('/') && PathBuf::from(name).exists() {
        return Some(PathBuf::from(name));
    }
    for path in path_var.split(':') {
        let potential_path = PathBuf::from(path).join(name);
        if potential_path.exists() {
            return Some(potential_path);
        }
    }
    None
}

fn is_executable(path: &Path) -> std::result::Result<bool, std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = path.metadata()?;
    let permissions = metadata.permissions();
    // we have to check if the path is file and the execute bit
    // is set. In case of directories, the execute bit is also set,
    // so have to check if this is a file or not
    Ok(metadata.is_file() && permissions.mode() & 0o001 != 0)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::env;

    use serial_test::serial;

    use super::*;

    #[test]
    fn test_get_executable_path() {
        let non_existing_abs_path = "/some/non/existent/absolute/path";
        let existing_abs_path = "/usr/bin/sh";
        let existing_binary = "sh";
        let non_existing_binary = "non-existent";
        let path_value = "/usr/bin:/bin";

        assert_eq!(
            get_executable_path(existing_abs_path, path_value),
            Some(PathBuf::from(existing_abs_path))
        );
        assert_eq!(get_executable_path(non_existing_abs_path, path_value), None);

        assert_eq!(
            get_executable_path(existing_binary, path_value),
            Some(PathBuf::from("/usr/bin/sh"))
        );

        assert_eq!(get_executable_path(non_existing_binary, path_value), None);
    }

    #[test]
    fn test_is_executable() {
        let tmp = tempfile::tempdir().expect("create temp directory for test");
        let executable_path = PathBuf::from("/bin/sh");
        let directory_path = tmp.path();
        let non_executable_path = directory_path.join("non_executable_file");
        let non_existent_path = PathBuf::from("/some/non/existent/path");

        std::fs::File::create(non_executable_path.as_path()).unwrap();

        assert!(is_executable(&non_existent_path).is_err());
        assert!(is_executable(&executable_path).unwrap());
        assert!(!is_executable(&non_executable_path).unwrap());
        assert!(!is_executable(directory_path).unwrap());
    }

    #[test]
    #[serial]
    fn test_executor_set_envs() {
        // Store original environment variables to restore later
        let original_envs: HashMap<String, String> = env::vars().collect();

        // Test setting environment variables
        {
            let executor = get_executor();
            let envs = HashMap::from([
                ("FOO".to_owned(), "hoge".to_owned()),
                ("BAR".to_owned(), "fuga".to_owned()),
                ("BAZ".to_owned(), "piyo".to_owned()),
            ]);
            assert!(executor.setup_envs(envs).is_ok());

            // Check if the environment variables are set correctly
            let current_envs = std::env::vars().collect::<HashMap<String, String>>();
            assert_eq!(current_envs.get("FOO").unwrap(), "hoge");
            assert_eq!(current_envs.get("BAR").unwrap(), "fuga");
            assert_eq!(current_envs.get("BAZ").unwrap(), "piyo");
            // No other environment variables should be set
            assert_eq!(current_envs.len(), 3);
        }

        // Restore original environment variables
        original_envs.iter().for_each(|(key, value)| {
            unsafe { env::set_var(key, value) };
        });
    }
}
