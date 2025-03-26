use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::os::unix::prelude::CommandExt;
use std::path::Path;
use std::{process, thread, time};

use nix::sys::signal;
use nix::unistd::Pid;
use oci_spec::runtime::Hook;

use crate::container::Container;
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
    #[error("failed to write container state to stdin")]
    WriteContainerState(#[source] std::io::Error),
}

type Result<T> = std::result::Result<T, HookError>;

pub fn run_hooks(
    hooks: Option<&Vec<Hook>>,
    container: &Container,
    cwd: Option<&Path>,
) -> Result<()> {
    let state = &container.state;

    if let Some(hooks) = hooks {
        for hook in hooks {
            let mut hook_command = process::Command::new(hook.path());

            if let Some(cwd) = cwd {
                hook_command.current_dir(cwd);
            }

            // Based on OCI spec, the first argument of the args vector is the
            // arg0, which can be different from the path.  For example, path
            // may be "/usr/bin/true" and arg0 is set to "true". However, rust
            // command differentiates arg0 from args, where rust command arg
            // doesn't include arg0. So we have to make the split arg0 from the
            // rest of args.
            if let Some((arg0, args)) = hook.args().as_ref().and_then(|a| a.split_first()) {
                tracing::debug!("run_hooks arg0: {:?}, args: {:?}", arg0, args);
                hook_command.arg0(arg0).args(args)
            } else {
                hook_command.arg0(hook.path().display().to_string())
            };

            let envs: HashMap<String, String> = if let Some(env) = hook.env() {
                utils::parse_env(env)
            } else {
                HashMap::new()
            };
            tracing::debug!("run_hooks envs: {:?}", envs);

            let mut hook_process = hook_command
                .env_clear()
                .envs(envs)
                .stdin(process::Stdio::piped())
                .spawn()
                .map_err(HookError::CommandExecute)?;
            let hook_process_pid = Pid::from_raw(hook_process.id() as i32);
            // Based on the OCI spec, we need to pipe the container state into
            // the hook command through stdin.
            if let Some(stdin) = &mut hook_process.stdin {
                // We want to ignore BrokenPipe here. A BrokenPipe indicates
                // either the hook is crashed/errored or it ran successfully.
                // Either way, this is an indication that the hook command
                // finished execution.  If the hook command was successful,
                // which we will check later in this function, we should not
                // fail this step here. We still want to check for all the other
                // error, in the case that the hook command is waiting for us to
                // write to stdin.
                let encoded_state =
                    serde_json::to_string(state).map_err(HookError::EncodeContainerState)?;
                if let Err(e) = stdin.write_all(encoded_state.as_bytes()) {
                    if e.kind() != ErrorKind::BrokenPipe {
                        // Not a broken pipe. The hook command may be waiting
                        // for us.
                        let _ = signal::kill(hook_process_pid, signal::Signal::SIGKILL);
                        return Err(HookError::WriteContainerState(e));
                    }
                }
            }

            let res = if let Some(timeout_sec) = hook.timeout() {
                // Rust does not make it easy to handle executing a command and
                // timeout. Here we decided to wait for the command in a
                // different thread, so the main thread is not blocked. We use a
                // channel shared between main thread and the wait thread, since
                // the channel has timeout functions out of the box. Rust won't
                // let us copy the Command structure, so we can't share it
                // between the wait thread and main thread. Therefore, we will
                // use pid to identify the process and send a kill signal. This
                // is what the Command.kill() does under the hood anyway. When
                // timeout, we have to kill the process and clean up properly.
                let (s, r) = std::sync::mpsc::channel();
                thread::spawn(move || {
                    let res = hook_process.wait();
                    let _ = s.send(res);
                });
                match r.recv_timeout(time::Duration::from_secs(timeout_sec as u64)) {
                    Ok(res) => res,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Kill the process. There is no need to further clean
                        // up because we will be error out.
                        let _ = signal::kill(hook_process_pid, signal::Signal::SIGKILL);
                        return Err(HookError::Timeout);
                    }
                    Err(_) => {
                        unreachable!();
                    }
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
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use std::{env, fs};

    use anyhow::{bail, Context, Result};
    use oci_spec::runtime::HookBuilder;
    use serial_test::serial;

    use super::*;

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
            run_hooks(None, &default_container, None).context("Failed simple test")?;
        }

        {
            assert!(is_command_in_path("true"), "The true was not found.");
            let default_container: Container = Default::default();

            let hook = HookBuilder::default().path("true").build()?;
            let hooks = Some(vec![hook]);
            run_hooks(hooks.as_ref(), &default_container, None).context("Failed true")?;
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
            run_hooks(hooks.as_ref(), &default_container, None).context("Failed printenv test")?;
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
            run_hooks(hooks.as_ref(), &default_container, Some(tmp.path()))
                .context("Failed pwd test")?;
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
        match run_hooks(hooks.as_ref(), &default_container, None) {
            Ok(_) => {
                bail!("The test expects the hook to error out with timeout. Should not execute cleanly");
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
}
