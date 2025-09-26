use std::cell::RefCell;
use std::convert::Infallible;

use nix::unistd::Pid;

use crate::common::{CgroupManager, ControllerOpt, FreezerState};
use crate::stats::Stats;

#[derive(Debug)]
pub struct TestManager {
    add_task_args: RefCell<Vec<Pid>>,
    pub apply_called: RefCell<bool>,
}

impl Default for TestManager {
    fn default() -> Self {
        Self {
            add_task_args: RefCell::new(vec![]),
            apply_called: RefCell::new(false),
        }
    }
}

impl CgroupManager for TestManager {
    type Error = Infallible;

    fn add_task(&self, pid: Pid) -> Result<(), Infallible> {
        self.add_task_args.borrow_mut().push(pid);
        Ok(())
    }

    // NOTE: The argument cannot be stored due to lifetime.
    fn apply(&self, _controller_opt: &ControllerOpt) -> Result<(), Infallible> {
        *self.apply_called.borrow_mut() = true;
        Ok(())
    }

    fn remove(&self) -> Result<(), Infallible> {
        unimplemented!()
    }

    fn freeze(&self, _state: FreezerState) -> Result<(), Infallible> {
        unimplemented!()
    }

    fn get_freezer_state(&self) -> Result<FreezerState, Self::Error> {
        unimplemented!()
    }

    fn stats(&self) -> Result<Stats, Infallible> {
        unimplemented!()
    }

    fn get_all_pids(&self) -> Result<Vec<Pid>, Infallible> {
        unimplemented!()
    }
}

impl TestManager {
    pub fn get_add_task_args(&self) -> Vec<Pid> {
        self.add_task_args.borrow_mut().clone()
    }

    pub fn apply_called(&self) -> bool {
        *self.apply_called.borrow_mut()
    }
}
