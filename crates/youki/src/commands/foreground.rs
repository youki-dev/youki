use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::thread::JoinHandle;

use anyhow::{Context, Result};
use nix::sys::signal::{self, kill};
use nix::sys::signalfd::SigSet;
use nix::sys::termios::{self, Termios};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use nix::{libc, unistd};

struct RawTerminalGuard {
    original: Termios,
}

impl RawTerminalGuard {
    fn new() -> Result<Option<Self>> {
        let stdin = io::stdin();
        if !unistd::isatty(stdin.as_raw_fd())? {
            return Ok(None);
        }

        let stdin_fd = stdin.as_fd();
        let original =
            termios::tcgetattr(stdin_fd).with_context(|| "failed to get terminal attributes")?;
        let mut raw = original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&stdin, termios::SetArg::TCSANOW, &raw)
            .with_context(|| "failed to set raw terminal attributes")?;

        Ok(Some(Self { original }))
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        // There is nothing we can do if this fails, so ignore the error.
        let _ = termios::tcsetattr(io::stdin(), termios::SetArg::TCSANOW, &self.original);
    }
}

// Bridge host stdio <-> the container's PTY master; returns the PTY->stdout relay's join handle.
fn io_bridge(master: OwnedFd) -> Result<JoinHandle<()>> {
    let master_clone = master
        .try_clone()
        .with_context(|| "failed to duplicate pty master fd")?;

    // host stdin -> PTY master (detached; blocks on stdin until exit).
    std::thread::spawn(move || {
        let mut master_file = File::from(master);
        // Errors are ignored: when the container exits, the PTY master
        // returns EIO, which is the normal way to exit this loop.
        let _ = io::copy(&mut io::stdin(), &mut master_file);
    });

    // PTY master -> host stdout (joined on drop to flush the last bytes).
    let output = std::thread::spawn(move || {
        let mut master_file = File::from(master_clone);
        if let Ok(stdout_fd) = io::stdout().as_fd().try_clone_to_owned() {
            let mut out = File::from(stdout_fd);
            let _ = io::copy(&mut master_file, &mut out);
        }
    });

    Ok(output)
}

/// Foreground console state. On drop it drains the PTY->stdout relay (so the last output is not
/// lost) and restores the terminal, so hold it for the whole lifetime — never bind it to `_`.
struct ConsoleBridge {
    raw: Option<RawTerminalGuard>,
    output: Option<JoinHandle<()>>,
    // A dup of the PTY master kept so SIGWINCH can resize the container terminal.
    resize: OwnedFd,
}

impl ConsoleBridge {
    /// Propagate the host terminal's current window size to the container PTY master.
    fn resize_to_host(&self) {
        let stdin = io::stdin();
        if !unistd::isatty(stdin.as_raw_fd()).unwrap_or(false) {
            return;
        }

        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(stdin.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) } < 0 {
            return;
        }
        unsafe { libc::ioctl(self.resize.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
    }
}

impl Drop for ConsoleBridge {
    fn drop(&mut self) {
        // Restore the terminal first so a stuck relay cannot leave it in raw mode.
        drop(self.raw.take());
        // The relay ends when every PTY slave closes (container exit) and the master read hits EIO.
        if let Some(output) = self.output.take() {
            let _ = output.join();
        }
    }
}

/// With a PTY master, raw-mode the host terminal and bridge host stdio <-> the PTY.
fn attach_console(master: Option<OwnedFd>) -> Result<Option<ConsoleBridge>> {
    match master {
        Some(master) => {
            let raw = RawTerminalGuard::new()?;
            let resize = master
                .try_clone()
                .with_context(|| "failed to duplicate pty master fd")?;
            let output = io_bridge(master)?;
            Ok(Some(ConsoleBridge {
                raw,
                output: Some(output),
                resize,
            }))
        }
        None => Ok(None),
    }
}

// handle_foreground will match the `runc` behavior running the foreground mode.
// The youki main process will wait and reap the container init process. The
// youki main process also forwards most of the signals to the container init
// process.
#[tracing::instrument(level = "trace")]
pub(crate) fn handle_foreground(init_pid: Pid, pty_master_fd: Option<OwnedFd>) -> Result<i32> {
    tracing::trace!("waiting for container init process to exit");

    // We mask all signals here and forward most of the signals to the container
    // init process.
    let signal_set = SigSet::all();
    signal_set
        .thread_block()
        .with_context(|| "failed to call pthread_sigmask")?;

    // With a PTY master, raw-mode the host terminal (restored on drop) and bridge stdio.
    let console = attach_console(pty_master_fd)?;
    if let Some(console) = &console {
        console.resize_to_host();
    }

    if let Some(status) = reap_children(init_pid)? {
        return Ok(status);
    }

    loop {
        match signal_set
            .wait()
            .with_context(|| "failed to call sigwait")?
        {
            signal::SIGCHLD => {
                // Reap all child until either container init process exits or
                // no more child to be reaped. Once the container init process
                // exits we can then return.
                tracing::trace!("reaping child processes");
                if let Some(status) = reap_children(init_pid)? {
                    return Ok(status);
                }
            }
            signal::SIGURG => {
                // In `runc`, SIGURG is used by go runtime and should not be forwarded to
                // the container process. Here, we just ignore the signal.
            }
            signal::SIGWINCH => {
                if let Some(console) = &console {
                    console.resize_to_host();
                }
            }
            signal => {
                tracing::trace!(?signal, "forwarding signal");
                // There is nothing we can do if we fail to forward the signal.
                let _ = kill(init_pid, Some(signal)).map_err(|err| {
                    tracing::warn!(
                        ?err,
                        ?signal,
                        "failed to forward signal to container init process",
                    );
                });
            }
        }
    }
}

fn reap_children(init_pid: Pid) -> Result<Option<i32>> {
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG))? {
            WaitStatus::Exited(pid, status) => {
                if pid.eq(&init_pid) {
                    return Ok(Some(status));
                }

                // Else, some random child process exited, ignoring...
            }
            WaitStatus::Signaled(pid, signal, _) => {
                if pid.eq(&init_pid) {
                    return Ok(Some(signal as i32));
                }

                // Else, some random child process exited, ignoring...
            }
            WaitStatus::StillAlive => {
                // No more child to reap.
                return Ok(None);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nix::sys::signal::Signal::{SIGINT, SIGKILL};
    use nix::sys::wait;
    use nix::unistd;

    use super::*;

    #[test]
    fn test_foreground_forward_sig() -> Result<()> {
        // To set up the test correctly, we need to run the test in dedicated
        // process, so the rust unit test runtime and other unit tests will not
        // mess with the signal handling. We use `sigkill` as a simple way to
        // make sure the signal is properly forwarded. In this test, P0 is the
        // rust process that runs this unit test (in a thread). P1 mocks youki
        // main and P2 mocks the container init process
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                // Inside P0
                //
                // We need to make sure that the child process has entered into
                // the signal forwarding loops. There is no way to 100% sync
                // that the child has executed the for loop waiting to forward
                // the signal. There are sync mechanisms with condvar or
                // channels to make it as close to calling the handle_foreground
                // function as possible, but still have a tiny (highly unlikely
                // but probable) window that a race can still happen. So instead
                // we just wait for 1 second for everything to settle. In
                // general, I don't like sleep in tests to avoid race condition,
                // but I'd rather not over-engineer this now. We can revisit
                // this later if the test becomes flaky.
                std::thread::sleep(Duration::from_secs(1));
                // Send the `sigint` signal to P1 who will forward the signal
                // to P2. P2 will then exit and send a sigchld to P1. P1 will
                // then reap P2 and exits. In P0, we can then reap P1.
                kill(child, SIGINT)?;
                wait::waitpid(child, None)?;
            }
            unistd::ForkResult::Child => {
                // Inside P1. Fork P2 as mock container init process and run
                // signal handler process inside.
                match unsafe { unistd::fork()? } {
                    unistd::ForkResult::Parent { child } => {
                        // Inside P1.
                        let _ = handle_foreground(child, None).map_err(|err| {
                            // Since we are in a child process, we want to use trace to log the error.
                            let _ = tracing_subscriber::fmt()
                                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                                .try_init();
                            tracing::error!(?err, "failed to handle foreground");
                            err
                        });
                        std::process::exit(0);
                    }
                    unistd::ForkResult::Child => {
                        let mut signal_set = SigSet::empty();
                        signal_set.add(SIGINT);
                        signal_set.thread_block()?;
                        signal_set.wait()?;
                        std::process::exit(0);
                    }
                };
            }
        };

        Ok(())
    }

    #[test]
    fn test_foreground_already_exited_child() -> Result<()> {
        // The container process can exit before handle_foreground blocks
        // signals; the SIGCHLD is then delivered and discarded, so sigwait
        // alone would block forever. handle_foreground must reap the zombie
        // that is already there. P0 = test, P1 = mock youki, P2 = mock init.
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                // Inside P0. P1 must finish on its own; kill it if it hangs.
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    match wait::waitpid(child, Some(WaitPidFlag::WNOHANG))? {
                        WaitStatus::StillAlive => {
                            if std::time::Instant::now() > deadline {
                                let _ = kill(child, SIGKILL);
                                let _ = wait::waitpid(child, None);
                                panic!("handle_foreground hung on a pre-exited child");
                            }
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        status => {
                            assert_eq!(status, WaitStatus::Exited(child, 0));
                            break;
                        }
                    }
                }
            }
            unistd::ForkResult::Child => {
                // Inside P1. P2 exits immediately; sleep long enough that its
                // SIGCHLD is delivered (and discarded) before handle_foreground.
                match unsafe { unistd::fork() } {
                    Ok(unistd::ForkResult::Parent { child }) => {
                        std::thread::sleep(Duration::from_millis(500));
                        let code = match handle_foreground(child, None) {
                            Ok(_) => 0,
                            Err(_) => 1,
                        };
                        std::process::exit(code);
                    }
                    Ok(unistd::ForkResult::Child) => std::process::exit(0),
                    Err(_) => std::process::exit(1),
                }
            }
        };

        Ok(())
    }

    #[test]
    fn test_foreground_exit() -> Result<()> {
        // The setup is similar to `handle_foreground`, but instead of
        // forwarding signal, the container init process will exit. Again, we
        // use `sleep` to simulate the conditions to avoid fine grained
        // synchronization for now.
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                // Inside P0
                std::thread::sleep(Duration::from_secs(1));
                wait::waitpid(child, None)?;
            }
            unistd::ForkResult::Child => {
                // Inside P1. Fork P2 as mock container init process and run
                // signal handler process inside.
                match unsafe { unistd::fork()? } {
                    unistd::ForkResult::Parent { child } => {
                        // Inside P1.
                        handle_foreground(child, None)?;
                        wait::waitpid(child, None)?;
                    }
                    unistd::ForkResult::Child => {
                        // Inside P2. The process exits after 1 second.
                        std::thread::sleep(Duration::from_secs(1));
                    }
                };
            }
        };

        Ok(())
    }
}
