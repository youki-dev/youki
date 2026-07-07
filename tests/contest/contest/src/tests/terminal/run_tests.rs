use std::fs;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::time::Duration;

use anyhow::anyhow;
use nix::sys::signal::{Signal, kill};
use nix::sys::termios::{self, LocalFlags};
use nix::unistd::Pid;
use test_framework::TestResult;

use super::{
    console_size_spec, drain_master, poll_size_script, read_master_for, recv_pty_master,
    run_command, runtime_command, saw_line, set_winsize, sized_pty, spawn_on_pty, terminal_spec,
    wait_timeout,
};
use crate::utils::{generate_uuid, prepare_bundle, set_config};

// process.terminal=true + no console socket => the container gets a real tty.
// Every foreground test brings its own host pty: runc refuses to run a
// foreground terminal container when the caller has no terminal at all.
pub(crate) fn terminal_no_console_socket_test() -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();
    set_config(
        &bundle,
        &terminal_spec("if [ -t 1 ]; then echo TTY; else echo NOT_TTY; fi"),
    )
    .unwrap();

    let pty = match sized_pty(24, 80) {
        Ok(pty) => pty,
        Err(e) => return TestResult::Failed(anyhow!("failed to open test pty: {e}")),
    };
    let mut child = match spawn_on_pty(run_command(bundle.as_ref(), &id), pty.slave) {
        Ok(child) => child,
        Err(e) => return TestResult::Failed(anyhow!("failed to spawn container: {e:?}")),
    };

    let reader = drain_master(pty.master);
    let status = wait_timeout(&mut child, Duration::from_secs(30));
    let output = reader.join().unwrap_or_default();

    if saw_line(&output, "NOT_TTY") {
        return TestResult::Failed(anyhow!(
            "container stdout was not a tty despite process.terminal=true"
        ));
    }
    if saw_line(&output, "TTY") {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "missing tty marker: output={:?} status={:?}",
            output,
            status
        ))
    }
}

// Host input is bridged into the container's PTY: a line fed to the host pty
// reaches the container's `read`.
pub(crate) fn terminal_stdin_bridge_test() -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();
    set_config(&bundle, &terminal_spec("read line; echo \"GOT:$line\"")).unwrap();

    let pty = match sized_pty(24, 80) {
        Ok(pty) => pty,
        Err(e) => return TestResult::Failed(anyhow!("failed to open test pty: {e}")),
    };
    let mut child = match spawn_on_pty(run_command(bundle.as_ref(), &id), pty.slave) {
        Ok(child) => child,
        Err(e) => return TestResult::Failed(anyhow!("failed to spawn container: {e:?}")),
    };

    let mut writer = match pty.master.try_clone() {
        Ok(fd) => fs::File::from(fd),
        Err(e) => return TestResult::Failed(anyhow!("failed to dup pty master: {e}")),
    };
    let reader = drain_master(pty.master);
    if let Err(e) = writer.write_all(b"hello\n") {
        return TestResult::Failed(anyhow!("failed to write to the pty: {e:?}"));
    }

    let status = wait_timeout(&mut child, Duration::from_secs(30));
    let output = reader.join().unwrap_or_default();
    if saw_line(&output, "GOT:hello") {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "stdin was not bridged to the container: output={:?} status={:?}",
            output,
            status
        ))
    }
}

// process.consoleSize sets the PTY size. Checked via the console-socket path:
// a foreground tty would immediately be resized to the host terminal size,
// by youki and runc alike.
pub(crate) fn terminal_console_size_test() -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();
    // Non-canonical size so a stray 80x24/24x80 default cannot fake a pass.
    let (height, width): (u64, u64) = (17, 71);
    set_config(
        &bundle,
        &console_size_spec("echo \"CONSOLE_SIZE=$(stty size)\"", height, width),
    )
    .unwrap();

    let socket_path = bundle.as_ref().join("console.sock");
    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(e) => return TestResult::Failed(anyhow!("failed to bind console socket: {e}")),
    };
    let cleanup = || {
        let _ = runtime_command(bundle.as_ref(), "delete")
            .arg("-f")
            .arg(&id)
            .output();
    };

    let create = match runtime_command(bundle.as_ref(), "create")
        .arg(&id)
        .arg("--bundle")
        .arg(bundle.as_ref().join("bundle"))
        .arg("--console-socket")
        .arg(&socket_path)
        .output()
    {
        Ok(output) => output,
        Err(e) => return TestResult::Failed(anyhow!("failed to run create: {e:?}")),
    };
    if !create.status.success() {
        return TestResult::Failed(anyhow!(
            "create failed with status {:?}, stderr: {}",
            create.status,
            String::from_utf8_lossy(&create.stderr)
        ));
    }

    let master = match recv_pty_master(&listener) {
        Ok(master) => master,
        Err(e) => {
            cleanup();
            return TestResult::Failed(anyhow!("failed to receive the pty master: {e}"));
        }
    };

    let start = match runtime_command(bundle.as_ref(), "start").arg(&id).output() {
        Ok(output) => output,
        Err(e) => {
            cleanup();
            return TestResult::Failed(anyhow!("failed to run start: {e:?}"));
        }
    };
    if !start.status.success() {
        cleanup();
        return TestResult::Failed(anyhow!(
            "start failed with status {:?}, stderr: {}",
            start.status,
            String::from_utf8_lossy(&start.stderr)
        ));
    }

    let output = read_master_for(master, Duration::from_secs(10));
    cleanup();

    let marker = format!("CONSOLE_SIZE={height} {width}");
    if saw_line(&output, &marker) {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "process.consoleSize not applied to PTY: expected {:?} in {:?}",
            marker,
            output
        ))
    }
}

// SIGWINCH to youki must propagate the new host terminal size to the container PTY.
pub(crate) fn terminal_run_sigwinch_test() -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();
    set_config(
        &bundle,
        &terminal_spec(&poll_size_script("WINCH_SIZE", "31 91")),
    )
    .unwrap();

    let pty = match sized_pty(19, 73) {
        Ok(pty) => pty,
        Err(e) => return TestResult::Failed(anyhow!("failed to open test pty: {e}")),
    };
    let mut child = match spawn_on_pty(run_command(bundle.as_ref(), &id), pty.slave) {
        Ok(child) => child,
        Err(e) => return TestResult::Failed(anyhow!("failed to spawn container: {e:?}")),
    };

    // Resize the host pty and notify youki; repeat in case the first signal
    // fires before youki's signal mask is in place.
    let pid = Pid::from_raw(child.id() as i32);
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(700));
        set_winsize(&pty.master, 31, 91);
        let _ = kill(pid, Signal::SIGWINCH);
    }

    let reader = drain_master(pty.master);
    let status = wait_timeout(&mut child, Duration::from_secs(30));
    let output = reader.join().unwrap_or_default();
    if saw_line(&output, "WINCH_SIZE=31 91") {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "SIGWINCH resize not propagated to the container PTY: output={:?} status={:?}",
            output,
            status
        ))
    }
}

// The container's exit status must become youki's exit status in foreground mode.
pub(crate) fn terminal_run_exit_code_test() -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();
    set_config(&bundle, &terminal_spec("exit 7")).unwrap();

    let pty = match sized_pty(24, 80) {
        Ok(pty) => pty,
        Err(e) => return TestResult::Failed(anyhow!("failed to open test pty: {e}")),
    };
    let mut child = match spawn_on_pty(run_command(bundle.as_ref(), &id), pty.slave) {
        Ok(child) => child,
        Err(e) => return TestResult::Failed(anyhow!("failed to spawn container: {e:?}")),
    };

    let status = match wait_timeout(&mut child, Duration::from_secs(30)) {
        Ok(status) => status,
        Err(e) => return TestResult::Failed(anyhow!("failed to wait for container: {e:?}")),
    };
    if status.code() == Some(7) {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "expected youki to exit with the container's status 7, got {:?}",
            status
        ))
    }
}

// After youki exits, the host terminal must be restored from raw mode to its original termios.
pub(crate) fn terminal_raw_restore_test() -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();
    set_config(&bundle, &terminal_spec("echo hi")).unwrap();

    let pty = match sized_pty(24, 80) {
        Ok(pty) => pty,
        Err(e) => return TestResult::Failed(anyhow!("failed to open test pty: {e}")),
    };
    let mut child = match spawn_on_pty(run_command(bundle.as_ref(), &id), pty.slave) {
        Ok(child) => child,
        Err(e) => return TestResult::Failed(anyhow!("failed to spawn container: {e:?}")),
    };

    let status = wait_timeout(&mut child, Duration::from_secs(30));
    let term = match termios::tcgetattr(&pty.master) {
        Ok(term) => term,
        Err(e) => return TestResult::Failed(anyhow!("failed to read back termios: {e}")),
    };
    if term
        .local_flags
        .contains(LocalFlags::ECHO | LocalFlags::ICANON)
    {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "host terminal left in raw mode after exit: {:?} status={:?}",
            term.local_flags,
            status
        ))
    }
}

// Everything the container writes must reach the host, including the tail written right
// before exit (larger than the 64KiB PTY buffer, so it exercises the relay and final drain).
pub(crate) fn terminal_large_output_test() -> TestResult {
    let id = generate_uuid().to_string();
    let bundle = prepare_bundle().unwrap();
    set_config(
        &bundle,
        &terminal_spec(
            "awk 'BEGIN { for (i = 0; i < 102400; i++) printf \"x\"; print \"\" }'; echo BULK_DONE",
        ),
    )
    .unwrap();

    let pty = match sized_pty(24, 80) {
        Ok(pty) => pty,
        Err(e) => return TestResult::Failed(anyhow!("failed to open test pty: {e}")),
    };
    let mut child = match spawn_on_pty(run_command(bundle.as_ref(), &id), pty.slave) {
        Ok(child) => child,
        Err(e) => return TestResult::Failed(anyhow!("failed to spawn container: {e:?}")),
    };

    let reader = drain_master(pty.master);
    let status = wait_timeout(&mut child, Duration::from_secs(30));
    let output = reader.join().unwrap_or_default();

    let xs = output.chars().filter(|&c| c == 'x').count();
    if xs == 102400 && saw_line(&output, "BULK_DONE") {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "container output lost in the bridge: got {} of 102400 bytes, done-marker={} status={:?}",
            xs,
            saw_line(&output, "BULK_DONE"),
            status
        ))
    }
}
