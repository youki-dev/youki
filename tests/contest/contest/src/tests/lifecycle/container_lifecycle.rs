use std::thread::sleep;
use std::time::Duration;

use test_framework::{TestResult, TestableGroup};

use super::util::criu_installed;
use super::{checkpoint, create, delete, exec, kill, start, state};
use crate::utils::{generate_uuid, prepare_bundle};

// By experimenting, somewhere around 50 is enough for youki process
// to get the kill signal and shut down
// here we add a little buffer time as well
const SLEEP_TIME: Duration = Duration::from_millis(75);

pub struct ContainerLifecycle {
    project_path: tempfile::TempDir,
    container_id: String,
}

impl Default for ContainerLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl ContainerLifecycle {
    pub fn new() -> Self {
        let id = generate_uuid();
        let bundle_dir = prepare_bundle().unwrap();
        ContainerLifecycle {
            project_path: bundle_dir,
            container_id: id.to_string(),
        }
    }

    pub fn create(&self) -> TestResult {
        create::create(self.project_path.path(), &self.container_id).into()
    }

    #[allow(dead_code)]
    pub fn exec(&self, cmd: Vec<&str>, expected_output: Option<&str>) -> TestResult {
        exec::exec(
            self.project_path.path(),
            &self.container_id,
            cmd,
            expected_output,
        )
        .into()
    }

    pub fn start(&self) -> TestResult {
        start::start(self.project_path.path(), &self.container_id).into()
    }

    pub fn state(&self) -> TestResult {
        state::state(self.project_path.path(), &self.container_id).into()
    }

    pub fn kill(&self) -> TestResult {
        let ret = kill::kill(self.project_path.path(), &self.container_id);
        // sleep a little, so the youki process actually gets the signal and shuts down
        // otherwise, the tester moves on to next tests before the youki has gotten signal, and delete test can fail
        sleep(SLEEP_TIME);
        ret.into()
    }

    pub fn delete(&self) -> TestResult {
        delete::delete(self.project_path.path(), &self.container_id).into()
    }

    pub fn checkpoint_leave_running(&self) -> TestResult {
        if !criu_installed() {
            return TestResult::Skipped;
        }

        checkpoint::checkpoint_leave_running(self.project_path.path(), &self.container_id)
    }

    pub fn checkpoint_leave_running_work_path_tmp(&self) -> TestResult {
        if !criu_installed() {
            return TestResult::Skipped;
        }

        checkpoint::checkpoint_leave_running_work_path_tmp(
            self.project_path.path(),
            &self.container_id,
        )
    }
}

impl TestableGroup for ContainerLifecycle {
    fn get_name(&self) -> &'static str {
        "lifecycle"
    }

    fn parallel(&self) -> bool {
        true
    }

    fn run_all(&self) -> Vec<(&'static str, TestResult)> {
        vec![
            ("create", self.create()),
            ("start", self.start()),
            // ("exec", self.exec(vec!["echo", "Hello"], Some("Hello\n"))),
            (
                "checkpoint and leave running with --work-path /tmp",
                self.checkpoint_leave_running_work_path_tmp(),
            ),
            (
                "checkpoint and leave running",
                self.checkpoint_leave_running(),
            ),
            ("kill", self.kill()),
            ("state", self.state()),
            ("delete", self.delete()),
        ]
    }

    fn run_selected(&self, selected: &[&str]) -> Vec<(&'static str, TestResult)> {
        let mut ret = Vec::new();
        for name in selected {
            match *name {
                "create" => ret.push(("create", self.create())),
                "start" => ret.push(("start", self.start())),
                "checkpoint_leave_running_work_path_tmp" => ret.push((
                    "checkpoint and leave running with --work-path /tmp",
                    self.checkpoint_leave_running_work_path_tmp(),
                )),
                "checkpoint_leave_running" => ret.push((
                    "checkpoint and leave running",
                    self.checkpoint_leave_running(),
                )),
                "kill" => ret.push(("kill", self.kill())),
                "state" => ret.push(("state", self.state())),
                "delete" => ret.push(("delete", self.delete())),
                _ => eprintln!("No test named {name} in lifecycle"),
            };
        }
        ret
    }
}
