mod exec_tests;
mod run_tests;

use std::fs;
use std::io::{ErrorKind, IoSliceMut, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::libc;
use nix::pty::{OpenptyResult, Winsize, openpty};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
use oci_spec::runtime::{BoxBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup};

use crate::utils::get_runtime_path;

fn terminal_spec(command: &str) -> Spec {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .terminal(true)
                .args(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    command.to_string(),
                ])
                .build()
                .expect("error in creating process config"),
        )
        .build()
        .unwrap()
}

fn console_size_spec(command: &str, height: u64, width: u64) -> Spec {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .terminal(true)
                .console_size(
                    BoxBuilder::default()
                        .height(height)
                        .width(width)
                        .build()
                        .expect("error in creating console size"),
                )
                .args(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    command.to_string(),
                ])
                .build()
                .expect("error in creating process config"),
        )
        .build()
        .unwrap()
}

fn runtime_command(bundle_root: &Path, subcommand: &str) -> Command {
    let mut command = Command::new(get_runtime_path());
    command
        .arg("--root")
        .arg(bundle_root.join("runtime"))
        .arg(subcommand);
    command
}

fn run_command(bundle_root: &Path, id: &str) -> Command {
    let mut command = runtime_command(bundle_root, "run");
    command
        .arg(id)
        .arg("--bundle")
        .arg(bundle_root.join("bundle"));
    command
}

// PTY output uses \r\n (doubled when it crosses two PTYs), so trim trailing \r.
fn saw_line(stdout: &str, marker: &str) -> bool {
    stdout
        .lines()
        .any(|line| line.trim_end_matches('\r') == marker)
}

// Shell that polls `stty size` (~5s) until `want` appears, then echoes "<marker>=<last size>".
// The resize races with the container's startup, and on a 0x0 PTY busybox `stty size`
// prints nothing (GNU prints "0 0"), hence the polling.
fn poll_size_script(marker: &str, want: &str) -> String {
    format!(
        "i=0; s=; while [ $i -lt 50 ]; do \
         s=$(stty size 2>/dev/null); \
         [ \"$s\" = \"{want}\" ] && break; \
         sleep 0.1 2>/dev/null || sleep 1; i=$((i+1)); done; \
         echo \"{marker}=$s\""
    )
}

fn sized_pty(rows: u16, cols: u16) -> nix::Result<OpenptyResult> {
    let winsize = Some(Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    });
    openpty(&winsize, None)
}

fn set_winsize(fd: &impl AsRawFd, rows: u16, cols: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
}

// Spawn with all stdio on the pty slave. The slave is consumed so that no slave fd
// stays behind in the test process and the master read can hit EIO after exit.
fn spawn_on_pty(mut command: Command, slave: OwnedFd) -> std::io::Result<Child> {
    let stdin = slave.try_clone()?;
    let stdout = slave.try_clone()?;
    command
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(slave))
        .spawn()
}

// Kill the child if it does not exit in time so a regression fails instead of hanging the suite.
fn wait_timeout(child: &mut Child, timeout: Duration) -> std::io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            return child.wait();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// Receive the PTY master sent by the runtime over the console socket (SCM_RIGHTS).
fn recv_pty_master(listener: &UnixListener) -> Result<OwnedFd> {
    let (stream, _) = listener.accept()?;
    let mut buf = [0u8; 4096];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
    let msg = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::empty(),
    )?;
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg
            && let Some(&fd) = fds.first()
        {
            // SAFETY: the fd was just received via SCM_RIGHTS, so we own it.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }
    Err(anyhow!("no fd received on the console socket"))
}

// Read the master until EOF or the deadline (the container may stay alive on failure).
fn read_master_for(master: OwnedFd, timeout: Duration) -> String {
    let _ = fcntl(master.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK));
    let mut file = fs::File::from(master);
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while Instant::now() < deadline {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

// Drain the PTY master until every slave fd closes (the master read then hits EIO).
fn drain_master(master: OwnedFd) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut master = fs::File::from(master);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match master.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    })
}

pub fn get_terminal_test() -> TestGroup {
    let mut tg = TestGroup::new("terminal");
    tg.add(vec![
        Box::new(Test::new(
            "terminal_no_console_socket",
            Box::new(run_tests::terminal_no_console_socket_test),
        )),
        Box::new(Test::new(
            "terminal_stdin_bridge",
            Box::new(run_tests::terminal_stdin_bridge_test),
        )),
        Box::new(Test::new(
            "terminal_console_size",
            Box::new(run_tests::terminal_console_size_test),
        )),
        Box::new(Test::new(
            "terminal_run_sigwinch",
            Box::new(run_tests::terminal_run_sigwinch_test),
        )),
        Box::new(Test::new(
            "terminal_run_exit_code",
            Box::new(run_tests::terminal_run_exit_code_test),
        )),
        Box::new(Test::new(
            "terminal_raw_restore",
            Box::new(run_tests::terminal_raw_restore_test),
        )),
        Box::new(Test::new(
            "terminal_large_output",
            Box::new(run_tests::terminal_large_output_test),
        )),
        Box::new(Test::new(
            "terminal_exec_no_console_socket",
            Box::new(exec_tests::terminal_exec_no_console_socket_test),
        )),
        Box::new(Test::new(
            "terminal_exec_terminal_size",
            Box::new(exec_tests::terminal_exec_terminal_size_test),
        )),
        Box::new(Test::new(
            "terminal_exec_tty_flag",
            Box::new(exec_tests::terminal_exec_tty_flag_test),
        )),
        Box::new(Test::new(
            "terminal_exec_tty_flag_with_process_json",
            Box::new(exec_tests::terminal_exec_tty_flag_with_process_json_test),
        )),
    ]);
    tg
}
