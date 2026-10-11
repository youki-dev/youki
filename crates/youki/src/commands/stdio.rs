use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use libcontainer::container::builder::ContainerBuilder;
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::libc;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::eventfd::{EfdFlags, EventFd};
use nix::unistd::{self, Gid, Pid, Uid, pipe2};
use oci_spec::runtime::{LinuxIdMapping, LinuxIdMappingBuilder, LinuxNamespaceType, Spec};

// Pipe endpoint ownership (arrows show the intended data flow):
//
//             HostStdio                     ContainerStdio
// stdin:      write end  -----------------> read end
// stdout:     read end   <----------------- write end
// stderr:     read end   <----------------- write end
fn create_stdio_pipes() -> nix::Result<(HostStdio, ContainerStdio)> {
    let (stdin_read, stdin_write) = pipe2(OFlag::O_CLOEXEC)?;
    let (stdout_read, stdout_write) = pipe2(OFlag::O_CLOEXEC)?;
    let (stderr_read, stderr_write) = pipe2(OFlag::O_CLOEXEC)?;

    Ok((
        HostStdio {
            stdin: stdin_write,
            stdout: stdout_read,
            stderr: stderr_read,
        },
        ContainerStdio {
            stdin: stdin_read,
            stdout: stdout_write,
            stderr: stderr_write,
        },
    ))
}

/// Creates the stdio pipes and gives the container ends to `uid` and `gid`.
pub(crate) fn create_stdio_pipes_owned_by(
    uid: Uid,
    gid: Gid,
) -> nix::Result<(HostStdio, ContainerStdio)> {
    let (host, container) = create_stdio_pipes()?;
    match container.set_owner(uid, gid) {
        Ok(()) => {}
        // Rootless youki cannot chown to a subordinate UID. The pipes
        // stay owned by youki: relaying still works, but the container
        // user may not reopen them, as with inherited stdio.
        Err(Errno::EPERM) => tracing::warn!(
            %uid,
            %gid,
            "cannot chown the stdio pipes to the container user"
        ),
        Err(err) => return Err(err),
    }
    Ok((host, container))
}

pub(crate) struct HostStdio {
    stdin: OwnedFd,
    stdout: OwnedFd,
    stderr: OwnedFd,
}

impl HostStdio {
    /// Starts relaying between the pipes and youki's own stdio.
    ///
    /// Callers must block all signals first: the relay threads inherit this
    /// thread's mask and must not receive signals meant for the container.
    pub(crate) fn start_relay(self) -> io::Result<StdioRelay> {
        let stop = Arc::new(EventFd::from_flags(EfdFlags::EFD_CLOEXEC)?);
        let youki_stdin = io::stdin().as_fd().try_clone_to_owned()?;
        let youki_stdout = io::stdout().as_fd().try_clone_to_owned()?;
        let youki_stderr = io::stderr().as_fd().try_clone_to_owned()?;

        start_input_relay(youki_stdin, self.stdin);
        Ok(StdioRelay {
            stdout: Some(start_output_relay(
                self.stdout,
                youki_stdout,
                Arc::clone(&stop),
            )),
            stderr: Some(start_output_relay(
                self.stderr,
                youki_stderr,
                Arc::clone(&stop),
            )),
            stop,
        })
    }
}

/// Keep this guard alive while the container runs. Dropping it wakes both output
/// threads, drains the available output, and waits for the threads to finish.
pub(crate) struct StdioRelay {
    stop: Arc<EventFd>,
    stdout: Option<thread::JoinHandle<io::Result<()>>>,
    stderr: Option<thread::JoinHandle<io::Result<()>>>,
}

impl Drop for StdioRelay {
    fn drop(&mut self) {
        // Neither reader consumes this event, so both threads observe the stop request.
        let _ = self.stop.write(1);
        for (stream, handle) in [("stdout", &mut self.stdout), ("stderr", &mut self.stderr)] {
            if let Some(handle) = handle.take() {
                match handle.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => tracing::warn!(stream, ?err, "stdio relay failed"),
                    Err(_) => tracing::warn!(stream, "stdio relay thread panicked"),
                }
            }
        }
    }
}

pub(crate) struct ContainerStdio {
    stdin: OwnedFd,
    stdout: OwnedFd,
    stderr: OwnedFd,
}

impl ContainerStdio {
    pub(crate) fn apply_to(self, builder: ContainerBuilder) -> ContainerBuilder {
        builder
            .with_stdin(self.stdin)
            .with_stdout(self.stdout)
            .with_stderr(self.stderr)
    }

    pub(crate) fn set_owner(&self, uid: Uid, gid: Gid) -> nix::Result<()> {
        for fd in [&self.stdin, &self.stdout, &self.stderr] {
            unistd::fchown(fd, Some(uid), Some(gid))?;
        }
        Ok(())
    }
}

/// Returns the host IDs that should own the stdio pipes: the process user and
/// the container root group, which is what runc ends up with. Returns `None`
/// when the container joins a user namespace through a path other than
/// `/proc/<pid>/ns/user`, because youki does not read its mappings yet.
pub(crate) fn pipe_owner(spec: &Spec) -> Result<Option<(Uid, Gid)>> {
    let uid = spec
        .process()
        .as_ref()
        .map_or(0, |process| process.user().uid());
    let user_ns = spec
        .linux()
        .as_ref()
        .and_then(|linux| linux.namespaces().as_ref())
        .and_then(|namespaces| {
            namespaces
                .iter()
                .find(|ns| ns.typ() == LinuxNamespaceType::User)
        });

    let (uid_mappings, gid_mappings) = match user_ns.map(|ns| ns.path()) {
        // Without a user namespace, container IDs are host IDs.
        None => return Ok(Some((Uid::from_raw(uid), Gid::from_raw(0)))),
        // A new user namespace uses the mappings in config.json.
        Some(None) => {
            let linux = spec.linux().as_ref().context("missing linux")?;
            (
                linux
                    .uid_mappings()
                    .clone()
                    .context("missing UID mappings")?,
                linux
                    .gid_mappings()
                    .clone()
                    .context("missing GID mappings")?,
            )
        }
        // A joined user namespace uses the mappings of a process inside it.
        Some(Some(path)) => {
            return match proc_pid(path) {
                Some(pid) => pipe_owner_from_proc(pid, uid).map(Some),
                None => Ok(None),
            };
        }
    };

    let host_uid = map_to_host_id(uid, &uid_mappings).context("container UID is not mapped")?;
    let host_gid = map_to_host_id(0, &gid_mappings).context("container root GID is not mapped")?;
    Ok(Some((Uid::from_raw(host_uid), Gid::from_raw(host_gid))))
}

/// Returns the host IDs that should own the stdio pipes, like [`pipe_owner`],
/// using the ID mappings of `pid`. `pid` must be in the container's user
/// namespace, such as the init of a running container. No special case is
/// needed without a user namespace: the mappings are then the identity mapping.
pub(crate) fn pipe_owner_from_proc(pid: Pid, uid_in_container: u32) -> Result<(Uid, Gid)> {
    let uid = host_id_from_proc(pid, uid_in_container, "uid_map")?;
    let gid = host_id_from_proc(pid, 0, "gid_map")?;
    Ok((Uid::from_raw(uid), Gid::from_raw(gid)))
}

/// Maps a container ID to the host ID through `/proc/<pid>/<file>`.
fn host_id_from_proc(pid: Pid, id_in_container: u32, file: &str) -> Result<u32> {
    let mappings = read_id_mappings(pid, file)?;
    map_to_host_id(id_in_container, &mappings)
        .with_context(|| format!("container ID {id_in_container} is not mapped in {file}"))
}

fn map_to_host_id(id_in_container: u32, mappings: &[LinuxIdMapping]) -> Option<u32> {
    mappings.iter().find_map(|m| {
        let offset = id_in_container.checked_sub(m.container_id())?;
        if offset < m.size() {
            m.host_id().checked_add(offset)
        } else {
            None
        }
    })
}

/// Extracts `<pid>` from a `/proc/<pid>/ns/user` path.
fn proc_pid(path: &Path) -> Option<Pid> {
    let pid = path
        .to_str()?
        .strip_prefix("/proc/")?
        .strip_suffix("/ns/user")?;
    pid.parse().ok().filter(|pid| *pid > 0).map(Pid::from_raw)
}

/// Reads `/proc/<pid>/uid_map` or `/proc/<pid>/gid_map`.
fn read_id_mappings(pid: Pid, file: &str) -> Result<Vec<LinuxIdMapping>> {
    let path = format!("/proc/{pid}/{file}");
    let text = fs::read_to_string(&path).with_context(|| format!("failed to read {path}"))?;
    text.lines()
        .map(|line| {
            let fields = line
                .split_whitespace()
                .map(str::parse)
                .collect::<Result<Vec<u32>, _>>()
                .with_context(|| format!("invalid ID mapping: {line}"))?;
            let &[container_id, host_id, size] = fields.as_slice() else {
                anyhow::bail!("invalid ID mapping: {line}");
            };
            Ok(LinuxIdMappingBuilder::default()
                .container_id(container_id)
                .host_id(host_id)
                .size(size)
                .build()?)
        })
        .collect()
}

/// Copies youki's stdin into the container. The thread is never joined because
/// youki's stdin may not reach EOF, for example when it is a terminal. When it
/// does, dropping `writer` closes the pipe and the container sees EOF.
fn start_input_relay(reader: OwnedFd, writer: OwnedFd) {
    let mut reader = File::from(reader);
    let mut writer = File::from(writer);
    thread::spawn(move || io::copy(&mut reader, &mut writer));
}

fn start_output_relay(
    reader: OwnedFd,
    writer: OwnedFd,
    stop: Arc<EventFd>,
) -> thread::JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        let mut reader = File::from(reader);
        let mut writer = File::from(writer);
        relay_output(&mut reader, &mut writer, &stop)
    })
}

/// Relays pipe or PTY output until the source closes or `stop` is signaled.
pub(crate) fn relay_output(source: &mut File, out: &mut File, stop: &EventFd) -> io::Result<()> {
    let mut buffer = [0_u8; 8192];

    loop {
        let (source_events, stop_events) = {
            let mut fds = [
                PollFd::new(source.as_fd(), PollFlags::POLLIN),
                PollFd::new(stop.as_fd(), PollFlags::POLLIN),
            ];

            poll(&mut fds, PollTimeout::NONE)?;

            (
                fds[0].revents().unwrap_or(PollFlags::empty()),
                fds[1].revents().unwrap_or(PollFlags::empty()),
            )
        };

        if source_events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            match source.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(read) => out.write_all(&buffer[..read])?,
                Err(err) if err.raw_os_error() == Some(libc::EIO) => return Ok(()),
                Err(err) => return Err(err),
            }
        }

        if stop_events.contains(PollFlags::POLLIN) {
            drain_pending_output(source, out, &mut buffer)?;
            return Ok(());
        }
    }
}

/// Drains output while the source is immediately readable. The zero timeout
/// avoids waiting for a descendant that keeps the other end open after the
/// queued output has been consumed.
fn drain_pending_output(source: &mut File, out: &mut File, buffer: &mut [u8]) -> io::Result<()> {
    loop {
        let source_events = {
            let mut fds = [PollFd::new(source.as_fd(), PollFlags::POLLIN)];

            poll(&mut fds, PollTimeout::ZERO)?;

            fds[0].revents().unwrap_or(PollFlags::empty())
        };

        if !source_events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            return Ok(());
        }

        match source.read(buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => out.write_all(&buffer[..read])?,
            Err(err) if err.raw_os_error() == Some(libc::EIO) => return Ok(()),
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    // Descendants of init may keep the container's stdio open after init exits.
    // Dropping the relay must still stop both output threads without waiting
    // for EOF, and flush what was already written.
    #[test]
    fn drop_drains_outputs_without_eof() -> Result<()> {
        let stop = Arc::new(EventFd::from_flags(EfdFlags::EFD_CLOEXEC)?);
        // Relay into temp files instead of changing the test process's stdio.
        let spawn_relay = |reader: OwnedFd, mut capture: File| {
            let stop = Arc::clone(&stop);
            thread::spawn(move || relay_output(&mut File::from(reader), &mut capture, &stop))
        };
        let (stdout_reader, stdout_writer) = pipe2(OFlag::O_CLOEXEC)?;
        let (stderr_reader, stderr_writer) = pipe2(OFlag::O_CLOEXEC)?;
        let mut stdout_writer = File::from(stdout_writer);
        let mut stderr_writer = File::from(stderr_writer);
        let mut stdout_capture = tempfile::tempfile()?;
        let mut stderr_capture = tempfile::tempfile()?;
        stdout_writer.write_all(b"last stdout")?;
        stderr_writer.write_all(b"last stderr")?;
        let relay = StdioRelay {
            stdout: Some(spawn_relay(stdout_reader, stdout_capture.try_clone()?)),
            stderr: Some(spawn_relay(stderr_reader, stderr_capture.try_clone()?)),
            stop,
        };

        let (dropped_tx, dropped_rx) = mpsc::channel();
        let dropper = thread::spawn(move || {
            drop(relay);
            let _ = dropped_tx.send(());
        });
        let stopped = dropped_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        // Close the writers before asserting, so a broken stop does not leave
        // the relay threads blocked forever.
        drop(stdout_writer);
        drop(stderr_writer);
        dropper.join().expect("drop thread panicked");
        assert!(stopped, "relay waited for EOF after being dropped");

        for (capture, expected) in [
            (&mut stdout_capture, b"last stdout"),
            (&mut stderr_capture, b"last stderr"),
        ] {
            let mut actual = Vec::new();
            capture.seek(SeekFrom::Start(0))?;
            capture.read_to_end(&mut actual)?;
            assert_eq!(actual, expected);
        }
        Ok(())
    }
}
