use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::{Context, Result};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::eventfd::{EfdFlags, EventFd};
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

// Owns the PTY output thread and the eventfd used to wake it during foreground shutdown.
struct OutputRelay {
    stop: Arc<EventFd>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for OutputRelay {
    fn drop(&mut self) {
        let _ = self.stop.arm();

        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// Bridge host stdio with the container PTY and return a stoppable output relay.
fn io_bridge(master: OwnedFd) -> Result<OutputRelay> {
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

    // PTY master -> host stdout. The relay is explicitly stopped and joined on drop.
    let stop = Arc::new(
        EventFd::from_flags(EfdFlags::EFD_CLOEXEC)
            .with_context(|| "failed to create output relay eventfd")?,
    );
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        let mut master_file = File::from(master_clone);

        let Ok(stdout_fd) = io::stdout().as_fd().try_clone_to_owned() else {
            return;
        };
        let mut out = File::from(stdout_fd);

        let _ = relay_output(&mut master_file, &mut out, &thread_stop).map_err(|err| {
            tracing::warn!(?err, "failed to relay output from pty master to stdout");
        });
    });

    Ok(OutputRelay {
        stop,
        thread: Some(thread),
    })
}

// Relay PTY output until the master closes or the owning foreground process requests shutdown.
fn relay_output(master: &mut File, out: &mut File, stop: &EventFd) -> io::Result<()> {
    let mut buffer = [0_u8; 8192];

    loop {
        let (master_events, stop_events) = {
            let mut fds = [
                PollFd::new(master.as_fd(), PollFlags::POLLIN),
                PollFd::new(stop.as_fd(), PollFlags::POLLIN),
            ];

            poll(&mut fds, PollTimeout::NONE)?;

            (
                fds[0].revents().unwrap_or(PollFlags::empty()),
                fds[1].revents().unwrap_or(PollFlags::empty()),
            )
        };

        if master_events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            match master.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(read) => out.write_all(&buffer[..read])?,
                Err(err) if err.raw_os_error() == Some(libc::EIO) => return Ok(()),
                Err(err) => return Err(err),
            }
        }

        if stop_events.contains(PollFlags::POLLIN) {
            drain_pending_output(master, out, &mut buffer)?;
            return Ok(());
        }
    }
}

// Drain output while the PTY master is immediately readable. The zero timeout avoids waiting for
// a descendant that keeps the PTY slave open after the queued output has been consumed.
fn drain_pending_output(master: &mut File, out: &mut File, buffer: &mut [u8]) -> io::Result<()> {
    loop {
        let master_events = {
            let mut fds = [PollFd::new(master.as_fd(), PollFlags::POLLIN)];

            poll(&mut fds, PollTimeout::ZERO)?;

            fds[0].revents().unwrap_or(PollFlags::empty())
        };

        if !master_events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            return Ok(());
        }

        match master.read(buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => out.write_all(&buffer[..read])?,
            Err(err) if err.raw_os_error() == Some(libc::EIO) => return Ok(()),
            Err(err) => return Err(err),
        }
    }
}

/// Foreground console state. On drop it drains the PTY->stdout relay (so the last output is not
/// lost) and restores the terminal, so hold it for the whole lifetime — never bind it to `_`.
struct ConsoleBridge {
    raw: Option<RawTerminalGuard>,
    output: Option<OutputRelay>,
    // A dup of the PTY master kept so SIGWINCH can resize the container terminal.
    resize: OwnedFd,
}

impl ConsoleBridge {
    /// Propagate the host terminal's current window size to the container PTY master.
    /// Does nothing when the host stdin is not a TTY (there is no size to propagate).
    fn resize_to_host(&self) -> Result<()> {
        let stdin = io::stdin();
        if !unistd::isatty(stdin.as_raw_fd()).unwrap_or(false) {
            return Ok(());
        }

        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(stdin.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) } < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| "failed to get host terminal size");
        }
        if unsafe { libc::ioctl(self.resize.as_raw_fd(), libc::TIOCSWINSZ, &ws) } < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| "failed to set container pty size");
        }

        Ok(())
    }
}

impl Drop for ConsoleBridge {
    fn drop(&mut self) {
        // Restore the host terminal before waiting for the output relay to finish.
        drop(self.raw.take());
        // Dropping the relay signals its eventfd, drains queued output, and joins its thread.
        drop(self.output.take());
    }
}

/// With a PTY master, raw-mode the host terminal and bridge host stdio <-> the PTY.
fn setup_console_bridge(master: Option<OwnedFd>) -> Result<Option<ConsoleBridge>> {
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
pub(crate) fn handle_foreground(init_pid: Pid, foreground_pty_fd: Option<OwnedFd>) -> Result<i32> {
    tracing::trace!("waiting for container init process to exit");

    // We mask all signals here and forward most of the signals to the container
    // init process.
    let signal_set = SigSet::all();
    signal_set
        .thread_block()
        .with_context(|| "failed to call pthread_sigmask")?;

    // With a PTY master, raw-mode the host terminal (restored on drop) and bridge stdio.
    let console = setup_console_bridge(foreground_pty_fd)?;
    if let Some(console) = &console {
        // Resize failure is not fatal; the container just keeps its default size.
        let _ = console.resize_to_host().map_err(|err| {
            tracing::warn!(?err, "failed to resize container terminal");
        });
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
                    // Resize failure is not fatal; the container just keeps its old size.
                    let _ = console.resize_to_host().map_err(|err| {
                        tracing::warn!(?err, "failed to resize container terminal");
                    });
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
