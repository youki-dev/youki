use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Seek, Write};
use std::path::Path;
use std::str::{self, Utf8Error};
use std::thread;
use std::time::Duration;

use super::controller::Controller;
use crate::common::{ControllerOpt, FreezerState, WrapIoResult, WrappedIoError};

const CGROUP_FREEZE: &str = "cgroup.freeze";
const CGROUP_EVENTS: &str = "cgroup.events";

#[derive(thiserror::Error, Debug)]
pub enum V2FreezerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("freezer not supported: {0}")]
    NotSupported(WrappedIoError),
    #[error("expected \"cgroup.freeze\" to be in state {expected:?} but was in {actual:?}")]
    ExpectedToBe {
        expected: FreezerState,
        actual: FreezerState,
    },
    #[error("unexpected \"cgroup.freeze\" state: {state}")]
    UnknownState { state: String },
    #[error("timeout of {0} ms reached waiting for the cgroup to freeze")]
    Timeout(u128),
    #[error("invalid utf8: {0}")]
    InvalidUtf8(#[from] Utf8Error),
}

pub struct Freezer {}

impl Controller for Freezer {
    type Error = V2FreezerError;

    fn apply(controller_opt: &ControllerOpt, cgroup_path: &Path) -> Result<(), Self::Error> {
        if let Some(freezer_state) = controller_opt.freezer_state {
            Self::apply(freezer_state, cgroup_path)?;
        }

        Ok(())
    }
}

impl Freezer {
    fn apply(freezer_state: FreezerState, path: &Path) -> Result<(), V2FreezerError> {
        let state_str = match freezer_state {
            FreezerState::Undefined => return Ok(()),
            FreezerState::Frozen => "1",
            FreezerState::Thawed => "0",
        };

        let target = path.join(CGROUP_FREEZE);
        match OpenOptions::new().create(false).write(true).open(&target) {
            Err(err) => {
                if freezer_state == FreezerState::Frozen {
                    return Err(V2FreezerError::NotSupported(WrappedIoError::Open {
                        err,
                        path: target,
                    }));
                }
                return Ok(());
            }
            Ok(mut file) => file
                .write_all(state_str.as_bytes())
                .wrap_write(target, state_str)?,
        };

        // confirm that the cgroup did actually change states.
        let actual_state = Self::read_freezer_state(path)?;
        if !actual_state.eq(&freezer_state) {
            return Err(V2FreezerError::ExpectedToBe {
                expected: freezer_state,
                actual: actual_state,
            });
        }

        Ok(())
    }

    pub fn read_freezer_state(path: &Path) -> Result<FreezerState, V2FreezerError> {
        let target = path.join(CGROUP_FREEZE);
        let mut buf = [0; 1];
        let result = OpenOptions::new()
            .create(false)
            .read(true)
            .open(&target)
            .and_then(|mut file| file.read_exact(&mut buf));

        if result.is_err() {
            return Ok(FreezerState::Undefined);
        }

        let state = str::from_utf8(&buf)?;
        match state {
            "0" => Ok(FreezerState::Thawed),
            "1" => Self::wait_frozen(path),
            _ => Err(V2FreezerError::UnknownState {
                state: state.into(),
            }),
        }
    }

    // wait_frozen polls cgroup.events until it sees "frozen 1" in it.
    fn wait_frozen(path: &Path) -> Result<FreezerState, V2FreezerError> {
        let path = path.join(CGROUP_EVENTS);
        let f = OpenOptions::new()
            .create(false)
            .read(true)
            .open(&path)
            .wrap_open(&path)?;
        let mut f = BufReader::new(f);

        let wait_time = Duration::from_millis(10);
        let max_iter = 1000;
        let mut iter = 0;
        let mut line = String::new();

        loop {
            if iter == max_iter {
                return Err(V2FreezerError::Timeout(wait_time.as_millis() * max_iter));
            }
            line.clear();
            let num_bytes = f.read_line(&mut line).wrap_read(&path)?;
            if num_bytes == 0 {
                break;
            }
            if line.starts_with("frozen ") {
                if line.starts_with("frozen 1") {
                    if iter > 1 {
                        tracing::debug!("frozen after {} retries", iter)
                    }
                    return Ok(FreezerState::Frozen);
                }
                iter += 1;
                thread::sleep(wait_time);
                f.rewind().wrap_other(&path)?;
            }
        }

        Ok(FreezerState::Undefined)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::common::FreezerState;
    use crate::test::set_fixture;

    #[test]
    fn test_set_freezer_state() {
        let tmp = Arc::new(tempfile::tempdir().unwrap());
        set_fixture(tmp.path(), CGROUP_FREEZE, "").expect("Set fixure for freezer state");
        set_fixture(tmp.path(), CGROUP_EVENTS, "populated 0\nfrozen 0")
            .expect("Set fixure for freezer state");

        // set Frozen state.
        {
            // use another thread to update events file async.
            let p = Arc::clone(&tmp);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                set_fixture(p.path(), CGROUP_EVENTS, "populated 0\nfrozen 1")
                    .expect("Set fixure for freezer state");
            });
            let freezer_state = FreezerState::Frozen;
            Freezer::apply(freezer_state, tmp.path()).expect("Set freezer state");

            let state_content =
                std::fs::read_to_string(tmp.path().join(CGROUP_FREEZE)).expect("Read to string");
            assert_eq!("1", state_content);
        }

        // set Thawed state.
        {
            let freezer_state = FreezerState::Thawed;
            Freezer::apply(freezer_state, tmp.path()).expect("Set freezer state");

            let state_content =
                std::fs::read_to_string(tmp.path().join(CGROUP_FREEZE)).expect("Read to string");
            assert_eq!("0", state_content);
        }

        // set Undefined state.
        {
            let old_state_content =
                std::fs::read_to_string(tmp.path().join(CGROUP_FREEZE)).expect("Read to string");
            let freezer_state = FreezerState::Undefined;
            Freezer::apply(freezer_state, tmp.path()).expect("Set freezer state");

            let state_content =
                std::fs::read_to_string(tmp.path().join(CGROUP_FREEZE)).expect("Read to string");
            assert_eq!(old_state_content, state_content);
        }
    }

    #[test]
    fn test_set_freezer_state_error() {
        let tmp = tempfile::tempdir().unwrap();
        set_fixture(tmp.path(), CGROUP_FREEZE, "").expect("Set fixure for freezer state");
        set_fixture(tmp.path(), CGROUP_EVENTS, "").expect("Set fixure for freezer state");

        // events file does not contain "frozen 1"
        {
            let freezer_state = FreezerState::Frozen;
            let r = Freezer::apply(freezer_state, tmp.path());
            assert!(r.is_err());
        }
    }
}
