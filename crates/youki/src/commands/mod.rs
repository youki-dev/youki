use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use libcgroups::common::AnyCgroupManager;
use libcontainer::container::Container;
use nix::sys::signal::{self, kill};
use nix::sys::signalfd::SigSet;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

pub mod checkpoint;
pub mod completion;
pub mod create;
pub mod delete;
pub mod events;
pub mod exec;
pub mod features;
pub mod info;
pub mod kill;
pub mod list;
pub mod pause;
pub mod ps;
pub mod restore;
pub mod resume;
pub mod run;
pub mod spec_json;
pub mod start;
pub mod state;
pub mod update;

fn construct_container_root<P: AsRef<Path>>(root_path: P, container_id: &str) -> Result<PathBuf> {
    // resolves relative paths, symbolic links etc. and get complete path
    let root_path = fs::canonicalize(&root_path).with_context(|| {
        format!(
            "failed to canonicalize {} for container {}",
            root_path.as_ref().display(),
            container_id
        )
    })?;
    // the state of the container is stored in a directory named after the container id
    Ok(root_path.join(container_id))
}

fn load_container<P: AsRef<Path>>(root_path: P, container_id: &str) -> Result<Container> {
    let container_root = construct_container_root(root_path, container_id)?;
    if !container_root.exists() {
        bail!("container {} does not exist.", container_id)
    }

    Container::load(container_root)
        .with_context(|| format!("could not load state for container {container_id}"))
}

fn container_exists<P: AsRef<Path>>(root_path: P, container_id: &str) -> Result<bool> {
    let container_root = construct_container_root(root_path, container_id)?;
    Ok(container_root.exists())
}

fn create_cgroup_manager<P: AsRef<Path>>(
    root_path: P,
    container_id: &str,
) -> Result<AnyCgroupManager> {
    let container = load_container(root_path, container_id)?;
    Ok(libcgroups::common::create_cgroup_manager(
        libcgroups::common::CgroupConfig {
            cgroup_path: container.spec()?.cgroup_path,
            systemd_cgroup: container.systemd(),
            container_name: container.id().to_string(),
        },
    )?)
}

// handle_foreground will match the `runc` behavior running the foreground mode.
// The youki main process will wait and reap the container init process. The
// youki main process also forwards most of the signals to the container init
// process.
#[tracing::instrument(level = "trace")]
pub(crate) fn handle_foreground(init_pid: Pid) -> Result<i32> {
    tracing::trace!("waiting for container init process to exit");
    // We mask all signals here and forward most of the signals to the container
    // init process.
    let signal_set = SigSet::all();
    signal_set
        .thread_block()
        .with_context(|| "failed to call pthread_sigmask")?;
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
                loop {
                    match waitpid(None, Some(WaitPidFlag::WNOHANG))? {
                        WaitStatus::Exited(pid, status) => {
                            if pid.eq(&init_pid) {
                                return Ok(status);
                            }

                            // Else, some random child process exited, ignoring...
                        }
                        WaitStatus::Signaled(pid, signal, _) => {
                            if pid.eq(&init_pid) {
                                return Ok(signal as i32);
                            }

                            // Else, some random child process exited, ignoring...
                        }
                        WaitStatus::StillAlive => {
                            // No more child to reap.
                            break;
                        }
                        _ => {}
                    }
                }
            }
            signal::SIGURG => {
                // In `runc`, SIGURG is used by go runtime and should not be forwarded to
                // the container process. Here, we just ignore the signal.
            }
            signal::SIGWINCH => {
                // TODO: resize the terminal
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nix::sys::signal::Signal::SIGINT;
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
                        let _ = handle_foreground(child).map_err(|err| {
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
                        handle_foreground(child)?;
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
