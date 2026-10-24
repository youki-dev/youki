use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::os::unix::prelude::CommandExt;
use std::path::Path;
use std::{process, thread, time};

use nix::sys::signal;
use nix::unistd::Pid;
use oci_spec::runtime::{Hook, State as OciState};

use crate::container::{State, StateConversionError};
use crate::utils;

#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("failed to execute hook command")]
    CommandExecute(#[source] std::io::Error),
    #[error("failed to encode container state")]
    EncodeContainerState(#[source] serde_json::Error),
    #[error("hook command exited with non-zero exit code: {0}")]
    NonZeroExitCode(i32),
    #[error("hook command was killed by a signal")]
    Killed,
    #[error("failed to execute hook command due to a timeout")]
    Timeout,
    #[error("container state is required to run hook")]
    MissingContainerState,
    #[error("failed to write container state to stdin")]
    WriteContainerState(#[source] std::io::Error),
    #[error("failed to convert state to OCI format")]
    StateConversion(#[from] StateConversionError),
}

type Result<T> = std::result::Result<T, HookError>;

pub fn run_hooks(
    hooks: Option<&Vec<Hook>>,
    state: Option<&State>,
    cwd: Option<&Path>,
    pid: Option<Pid>,
    default_env: Option<&HashMap<String, String>>,
) -> Result<()> {
    run_hooks_with_policy(hooks, state, cwd, pid, default_env, false)
}

/// Runs all poststop hooks, logging failures and continuing as required by the OCI runtime spec.
pub fn run_poststop_hooks(
    hooks: Option<&Vec<Hook>>,
    state: Option<&State>,
    cwd: Option<&Path>,
    pid: Option<Pid>,
    default_env: Option<&HashMap<String, String>>,
) -> Result<()> {
    run_hooks_with_policy(hooks, state, cwd, pid, default_env, true)
}

fn run_hooks_with_policy(
    hooks: Option<&Vec<Hook>>,
    state: Option<&State>,
    cwd: Option<&Path>,
    pid: Option<Pid>,
    default_env: Option<&HashMap<String, String>>,
    continue_after_failure: bool,
) -> Result<()> {
    let base_state = state.ok_or(HookError::MissingContainerState)?;

    // High-level container runtimes use OCI state to pass the container state to the hooks.
    // So we need to convert the container state to OCI state.
    // Ref: https://github.com/containerd/containerd/blob/v2.2.1/cmd/containerd/command/oci-hook.go#L82
    let mut oci_state = OciState::try_from(base_state)?;

    // The pid parameter allows overriding the PID in the state. This is needed because
    // high-level container runtimes like containerd set the PID separately for certain hooks.
    // Ref: https://github.com/containerd/containerd/blob/main/cmd/containerd/command/oci-hook.go#L90
    if let Some(override_pid) = pid {
        oci_state.set_pid(Some(override_pid.as_raw()));
    }

    if let Some(hooks) = hooks {
        for hook in hooks {
            let hook_result = (|| -> Result<()> {
                let mut hook_command = process::Command::new(hook.path());

                if let Some(cwd) = cwd {
                    hook_command.current_dir(cwd);
                }

                // The first OCI args entry is arg0, which can differ from the executable path.
                if let Some((arg0, args)) = hook.args().as_ref().and_then(|a| a.split_first()) {
                    tracing::debug!("run_hooks arg0: {:?}, args: {:?}", arg0, args);
                    hook_command.arg0(arg0).args(args)
                } else {
                    hook_command.arg0(hook.path().display().to_string())
                };

                let envs: HashMap<String, String> = if let Some(env) = hook.env() {
                    utils::parse_env(env)
                } else if let Some(default) = default_env {
                    default.clone()
                } else {
                    HashMap::new()
                };
                tracing::debug!("run_hooks envs: {:?}", envs);

                let mut hook_process = hook_command
                    .env_clear()
                    .envs(envs)
                    .stdin(process::Stdio::piped())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::inherit())
                    .spawn()
                    .map_err(HookError::CommandExecute)?;
                let hook_process_pid = Pid::from_raw(hook_process.id() as i32);
                // Pipe the OCI state into the hook command through stdin.
                if let Some(stdin) = &mut hook_process.stdin {
                    let encoded_state = serde_json::to_string(&oci_state)
                        .map_err(HookError::EncodeContainerState)?;
                    if let Err(e) = stdin.write_all(encoded_state.as_bytes()) {
                        if e.kind() != ErrorKind::BrokenPipe {
                            let _ = signal::kill(hook_process_pid, signal::Signal::SIGKILL);
                            return Err(HookError::WriteContainerState(e));
                        }
                    }
                }

                let res = if let Some(timeout_sec) = hook.timeout() {
                    let (s, r) = std::sync::mpsc::channel();
                    thread::spawn(move || {
                        let res = hook_process.wait();
                        let _ = s.send(res);
                    });
                    match r.recv_timeout(time::Duration::from_secs(timeout_sec as u64)) {
                        Ok(res) => res,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            let _ = signal::kill(hook_process_pid, signal::Signal::SIGKILL);
                            return Err(HookError::Timeout);
                        }
                        Err(_) => unreachable!(),
                    }
                } else {
                    hook_process.wait()
                };

                match res {
                    Ok(exit_status) => match exit_status.code() {
                        Some(0) => Ok(()),
                        Some(exit_code) => Err(HookError::NonZeroExitCode(exit_code)),
                        None => Err(HookError::Killed),
                    },
                    Err(e) => Err(HookError::CommandExecute(e)),
                }?;
                Ok(())
            })();

            if let Err(err) = hook_result {
                if continue_after_failure {
                    tracing::warn!(
                        hook = ?hook.path(),
                        error = %err,
                        "poststop hook failed; continuing with remaining hooks"
                    );
                } else {
                    return Err(err);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use std::{env, fs};

    use anyhow::{Context, Result, bail};
    use oci_spec::runtime::HookBuilder;
    use serial_test::serial;

    use super::*;
    use crate::container::Container;

    fn is_command_in_path(program: &str) -> bool {
        if let Ok(path) = env::var("PATH") {
            for p in path.split(':') {
                let p_str = format!("{p}/{program}");
                if fs::metadata(p_str).is_ok() {
                    return true;
                }
            }
        }
        false
    }

    // Note: the run_hook will require the use of pipe to write the container
    // state into stdin of the hook command. When cargo test runs these tests in
    // parallel with other tests, the pipe becomes flaky and often we will get
    // broken pipe or bad file descriptors. There is not much we can do and we
    // decide not to retry in the test. The most sensible way to test this is
    // ask cargo test to run these tests in serial.

    #[test]
    #[serial]
    fn test_run_hook() -> Result<()> {
        {
            let default_container: Container = Default::default();
            run_hooks(None, Some(&default_container.state), None, None, None)
                .context("Failed simple test")?;
        }

        {
            assert!(is_command_in_path("true"), "The true was not found.");
            let default_container: Container = Default::default();

            let hook = HookBuilder::default().path("true").build()?;
            let hooks = Some(vec![hook]);
            run_hooks(
                hooks.as_ref(),
                Some(&default_container.state),
                None,
                None,
                None,
            )
            .context("Failed true")?;
        }

        {
            assert!(
                is_command_in_path("printenv"),
                "The printenv was not found."
            );
            // Use `printenv` to make sure the environment is set correctly.
            let default_container: Container = Default::default();
            let hook = HookBuilder::default()
                .path("bash")
                .args(vec![
                    String::from("bash"),
                    String::from("-c"),
                    String::from("printenv key > /dev/null"),
                ])
                .env(vec![String::from("key=value")])
                .build()?;
            let hooks = Some(vec![hook]);
            run_hooks(
                hooks.as_ref(),
                Some(&default_container.state),
                None,
                None,
                None,
            )
            .context("Failed printenv test")?;
        }

        {
            assert!(is_command_in_path("pwd"), "The pwd was not found.");

            let tmp = tempfile::tempdir()?;

            let default_container: Container = Default::default();
            let hook = HookBuilder::default()
                .path("bash")
                .args(vec![
                    String::from("bash"),
                    String::from("-c"),
                    format!("test $(pwd) = {:?}", tmp.path()),
                ])
                .build()?;
            let hooks = Some(vec![hook]);
            run_hooks(
                hooks.as_ref(),
                Some(&default_container.state),
                Some(tmp.path()),
                None,
                None,
            )
            .context("Failed pwd test")?;
        }

        {
            let default_container: Container = Default::default();
            let expected_pid = Pid::from_raw(1000);

            let hook = HookBuilder::default()
                .path("bash")
                .args(vec![
                    String::from("bash"),
                    String::from("-c"),
                    format!("cat | grep '\"pid\":{}'", expected_pid),
                ])
                .build()?;
            let hooks = Some(vec![hook]);
            run_hooks(
                hooks.as_ref(),
                Some(&default_container.state),
                None,
                Some(expected_pid),
                None,
            )
            .context("Failed pid test")?;
        }

        Ok(())
    }

    #[test]
    #[serial]
    // This will test executing hook with a timeout. Since the timeout is set in
    // secs, minimally, the test will run for 1 second to trigger the timeout.
    fn test_run_hook_timeout() -> Result<()> {
        let default_container: Container = Default::default();
        // We use `tail -f /dev/null` here to simulate a hook command that hangs.
        let hook = HookBuilder::default()
            .path("tail")
            .args(vec![
                String::from("tail"),
                String::from("-f"),
                String::from("/dev/null"),
            ])
            .timeout(1)
            .build()?;
        let hooks = Some(vec![hook]);
        match run_hooks(
            hooks.as_ref(),
            Some(&default_container.state),
            None,
            None,
            None,
        ) {
            Ok(_) => {
                bail!(
                    "The test expects the hook to error out with timeout. Should not execute cleanly"
                );
            }
            Err(HookError::Timeout) => {}
            Err(err) => {
                bail!(
                    "The test expects the hook to error out with timeout. Got error: {}",
                    err
                );
            }
        };

        Ok(())
    }

    #[test]
    #[serial]
    fn test_run_poststop_hooks_continue_after_failures() -> Result<()> {
        let default_container: Container = Default::default();
        let temp_dir = tempfile::tempdir()?;
        let output = temp_dir.path().join("hooks.log");
        let output_arg = output.to_string_lossy().to_string();

        let first_hook = HookBuilder::default()
            .path("/bin/sh")
            .args(vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo first >> \"$1\"; exit 7".to_string(),
                "sh".to_string(),
                output_arg.clone(),
            ])
            .build()?;
        let timed_out_hook = HookBuilder::default()
            .path("/bin/sh")
            .args(vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo second >> \"$1\"; exec sleep 10".to_string(),
                "sh".to_string(),
                output_arg.clone(),
            ])
            .timeout(1)
            .build()?;
        let last_hook = HookBuilder::default()
            .path("/bin/sh")
            .args(vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo third >> \"$1\"".to_string(),
                "sh".to_string(),
                output_arg,
            ])
            .build()?;
        let hooks = vec![first_hook, timed_out_hook, last_hook];

        run_poststop_hooks(
            Some(&hooks),
            Some(&default_container.state),
            None,
            None,
            None,
        )?;

        assert_eq!(fs::read_to_string(output)?, "first\nsecond\nthird\n");
        Ok(())
    }

    #[test]
    #[serial]
    fn test_run_hooks_still_stops_on_failure() -> Result<()> {
        let default_container: Container = Default::default();
        let temp_dir = tempfile::tempdir()?;
        let output = temp_dir.path().join("hooks.log");
        let output_arg = output.to_string_lossy().to_string();
        let hooks = vec![
            HookBuilder::default()
                .path("/bin/sh")
                .args(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "echo first >> \"$1\"; exit 7".to_string(),
                    "sh".to_string(),
                    output_arg.clone(),
                ])
                .build()?,
            HookBuilder::default()
                .path("/bin/sh")
                .args(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "echo second >> \"$1\"".to_string(),
                    "sh".to_string(),
                    output_arg,
                ])
                .build()?,
        ];

        assert!(
            run_hooks(
                Some(&hooks),
                Some(&default_container.state),
                None,
                None,
                None,
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(output)?, "first\n");
        Ok(())
    }

    #[test]
    #[serial]
    fn test_run_hook_default_env() -> Result<()> {
        // Test: hook without explicit env uses default_env
        {
            let default_container: Container = Default::default();
            let hook = HookBuilder::default()
                .path("sh")
                .args(vec![
                    String::from("sh"),
                    String::from("-c"),
                    String::from("test \"$TEST_ENV\" = 'default_value'"),
                ])
                .build()?;
            let hooks = Some(vec![hook]);
            let mut default_env = HashMap::new();
            default_env.insert("TEST_ENV".to_string(), "default_value".to_string());
            run_hooks(
                hooks.as_ref(),
                Some(&default_container.state),
                None,
                None,
                Some(&default_env),
            )
            .context("Failed: hook without explicit env should use default_env")?;
        }

        // Test: hook with explicit env takes priority over default_env
        {
            let default_container: Container = Default::default();
            let hook = HookBuilder::default()
                .path("sh")
                .args(vec![
                    String::from("sh"),
                    String::from("-c"),
                    String::from("test \"$TEST_ENV\" = 'explicit_value'"),
                ])
                .env(vec![String::from("TEST_ENV=explicit_value")])
                .build()?;
            let hooks = Some(vec![hook]);
            let mut default_env = HashMap::new();
            default_env.insert("TEST_ENV".to_string(), "default_value".to_string());
            run_hooks(
                hooks.as_ref(),
                Some(&default_container.state),
                None,
                None,
                Some(&default_env),
            )
            .context("Failed: hook with explicit env should ignore default_env")?;
        }

        // Test: hook without explicit env and no default_env gets empty environment
        {
            let default_container: Container = Default::default();
            let hook = HookBuilder::default()
                .path("sh")
                .args(vec![
                    String::from("sh"),
                    String::from("-c"),
                    // Verify that the environment is empty (no TEST_ENV, etc.)
                    String::from("test -z \"$TEST_ENV\""),
                ])
                .build()?;
            let hooks = Some(vec![hook]);
            run_hooks(
                hooks.as_ref(),
                Some(&default_container.state),
                None,
                None,
                None,
            )
            .context("Failed: hook without env and without default_env should have empty env")?;
        }

        Ok(())
    }
}
