use std::ffi::OsStr;
use std::fs;
use std::process::Stdio;
use std::time::Duration;

use anyhow::anyhow;
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use serde_json::json;
use test_framework::{TestResult, test_result};

use super::{drain_master, poll_size_script, saw_line, sized_pty, spawn_on_pty, wait_timeout};
use crate::utils::test_utils::{build_exec_command, check_container_created};
use crate::utils::{start_container, test_outside_container};

// The exec tests keep a long-running container around and exec into it.
fn sleeper_spec() -> Spec {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "1000".to_string()])
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

// foreground `youki exec` with a terminal=true process.json and no --console-socket must bridge
// the PTY master to the caller's stdio (like run), so the exec'd process's tty output is captured.
pub(crate) fn terminal_exec_no_console_socket_test() -> TestResult {
    test_outside_container(&sleeper_spec(), &|data| {
        test_result!(check_container_created(&data));
        let id = &data.id;
        let dir = &data.bundle;

        let start = start_container(id, dir).unwrap().wait().unwrap();
        if !start.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let process_json = json!({
            "terminal": true,
            "cwd": "/",
            "args": ["sh", "-c", "if [ -t 1 ]; then echo TTY; else echo NOT_TTY; fi"],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "user": { "uid": 0, "gid": 0 }
        });
        let process_path = dir.join("terminal-process.json");
        if let Err(e) = fs::write(
            &process_path,
            serde_json::to_vec_pretty(&process_json).unwrap(),
        ) {
            return TestResult::Failed(anyhow!("failed to write process.json: {e}"));
        }

        let pty = match sized_pty(24, 80) {
            Ok(pty) => pty,
            Err(e) => return TestResult::Failed(anyhow!("failed to open test pty: {e}")),
        };
        let mut child = match spawn_on_pty(
            build_exec_command(id, dir, &[OsStr::new("")], Some(&process_path), &[]),
            pty.slave,
        ) {
            Ok(child) => child,
            Err(e) => return TestResult::Failed(anyhow!("failed to spawn exec: {e:?}")),
        };

        let reader = drain_master(pty.master);
        let status = wait_timeout(&mut child, Duration::from_secs(30));
        let output = reader.join().unwrap_or_default();

        if saw_line(&output, "NOT_TTY") {
            return TestResult::Failed(anyhow!("exec stdout was not a tty despite terminal=true"));
        }
        if saw_line(&output, "TTY") {
            TestResult::Passed
        } else {
            TestResult::Failed(anyhow!(
                "exec terminal output not bridged to caller: output={:?} status={:?}",
                output,
                status
            ))
        }
    })
}

// `youki exec -t/--tty` without a --process file must allocate a PTY, like runc.
pub(crate) fn terminal_exec_tty_flag_test() -> TestResult {
    test_outside_container(&sleeper_spec(), &|data| {
        test_result!(check_container_created(&data));
        let id = &data.id;
        let dir = &data.bundle;

        let start = start_container(id, dir).unwrap().wait().unwrap();
        if !start.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let pty = match sized_pty(24, 80) {
            Ok(pty) => pty,
            Err(e) => return TestResult::Failed(anyhow!("failed to open test pty: {e}")),
        };
        let mut child = match spawn_on_pty(
            build_exec_command(
                id,
                dir,
                &[
                    "--tty",
                    "sh",
                    "-c",
                    "if [ -t 1 ]; then echo TTY; else echo NOT_TTY; fi",
                ],
                None,
                &[],
            ),
            pty.slave,
        ) {
            Ok(child) => child,
            Err(e) => return TestResult::Failed(anyhow!("failed to spawn exec: {e:?}")),
        };

        let reader = drain_master(pty.master);
        let status = wait_timeout(&mut child, Duration::from_secs(30));
        let output = reader.join().unwrap_or_default();

        if saw_line(&output, "NOT_TTY") {
            return TestResult::Failed(anyhow!("exec --tty did not allocate a terminal"));
        }
        if saw_line(&output, "TTY") {
            TestResult::Passed
        } else {
            TestResult::Failed(anyhow!(
                "no tty marker in exec --tty output: output={:?} status={:?}",
                output,
                status
            ))
        }
    })
}

// When --process is given, runc ignores -t/--tty entirely: the process.json decides.
pub(crate) fn terminal_exec_tty_flag_with_process_json_test() -> TestResult {
    test_outside_container(&sleeper_spec(), &|data| {
        test_result!(check_container_created(&data));
        let id = &data.id;
        let dir = &data.bundle;

        let start = start_container(id, dir).unwrap().wait().unwrap();
        if !start.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        // terminal is absent (= false) in the process.json; --tty must not override it.
        let process_json = json!({
            "cwd": "/",
            "args": ["sh", "-c", "if [ -t 1 ]; then echo TTY; else echo NOT_TTY; fi"],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "user": { "uid": 0, "gid": 0 }
        });
        let process_path = dir.join("tty-flag-process.json");
        if let Err(e) = fs::write(
            &process_path,
            serde_json::to_vec_pretty(&process_json).unwrap(),
        ) {
            return TestResult::Failed(anyhow!("failed to write process.json: {e}"));
        }

        let output =
            match build_exec_command(id, dir, &[OsStr::new("--tty")], Some(&process_path), &[])
                .stdin(Stdio::null())
                .output()
            {
                Ok(o) => o,
                Err(e) => return TestResult::Failed(anyhow!("failed to run exec: {e:?}")),
            };

        let stdout = String::from_utf8_lossy(&output.stdout);
        if saw_line(&stdout, "NOT_TTY") {
            TestResult::Passed
        } else {
            TestResult::Failed(anyhow!(
                "--tty must be ignored when --process is given (runc semantics): \
                 stdout={:?} status={:?} stderr={}",
                stdout,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    })
}

// Foreground exec must propagate the host terminal size to the exec'd PTY (like runc's
// initial resize). We give youki a real tty of a known size and read `stty size` inside.
pub(crate) fn terminal_exec_terminal_size_test() -> TestResult {
    test_outside_container(&sleeper_spec(), &|data| {
        test_result!(check_container_created(&data));
        let id = &data.id;
        let dir = &data.bundle;

        let start = start_container(id, dir).unwrap().wait().unwrap();
        if !start.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let process_json = json!({
            "terminal": true,
            "cwd": "/",
            "args": ["sh", "-c", poll_size_script("EXEC_SIZE", "19 73")],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "user": { "uid": 0, "gid": 0 }
        });
        let process_path = dir.join("terminal-size-process.json");
        if let Err(e) = fs::write(
            &process_path,
            serde_json::to_vec_pretty(&process_json).unwrap(),
        ) {
            return TestResult::Failed(anyhow!("failed to write process.json: {e}"));
        }

        let pty = match sized_pty(19, 73) {
            Ok(pty) => pty,
            Err(e) => return TestResult::Failed(anyhow!("failed to open test pty: {e}")),
        };
        let mut child = match spawn_on_pty(
            build_exec_command(id, dir, &[OsStr::new("")], Some(&process_path), &[]),
            pty.slave,
        ) {
            Ok(child) => child,
            Err(e) => return TestResult::Failed(anyhow!("failed to spawn exec: {e:?}")),
        };

        let reader = drain_master(pty.master);
        let status = match wait_timeout(&mut child, Duration::from_secs(30)) {
            Ok(status) => status,
            Err(e) => return TestResult::Failed(anyhow!("failed to wait for exec: {e:?}")),
        };
        let output = reader.join().unwrap_or_default();

        let marker = "EXEC_SIZE=19 73";
        if saw_line(&output, marker) {
            TestResult::Passed
        } else {
            TestResult::Failed(anyhow!(
                "host terminal size (19x73) not propagated to the exec PTY: \
                 expected {:?}, output={:?} status={:?}",
                marker,
                output,
                status
            ))
        }
    })
}
