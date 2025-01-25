use tempfile::TempDir;
use test_framework::{TestResult, TestableGroup};

use super::{create, delete, kill};
use crate::utils::{generate_uuid, prepare_bundle};

pub struct ContainerCreate {
    project_path: TempDir,
    container_id: String,
}

impl Default for ContainerCreate {
    fn default() -> Self {
        Self::new()
    }
}

impl ContainerCreate {
    pub fn new() -> Self {
        let id = generate_uuid();
        let temp_dir = prepare_bundle().unwrap();
        ContainerCreate {
            project_path: temp_dir,
            container_id: id.to_string(),
        }
    }

    // runtime should not create container with empty id
    fn create_empty_id(&self) -> TestResult {
        match create::create(self.project_path.path(), "") {
            Ok(()) => TestResult::Failed(anyhow::anyhow!(
                "container should not have been created with empty id, but was created."
            )),
            Err(_) => TestResult::Passed,
        }
    }

    // runtime should create container with valid id
    fn create_valid_id(&self) -> TestResult {
        match create::create(self.project_path.path(), &self.container_id) {
            Ok(_) => {
                let _ = kill::kill(self.project_path.path(), &self.container_id);
                let _ = delete::delete(self.project_path.path(), &self.container_id);
                TestResult::Passed
            }
            Err(err) => {
                TestResult::Failed(err.context(
                    "container should have been created with valid id, but was not created.",
                ))
            }
        }
    }

    // runtime should not create container with is that already exists
    fn create_duplicate_id(&self) -> TestResult {
        let id = generate_uuid().to_string();
        // First create which should be successful
        if let Err(err) = create::create(self.project_path.path(), &id) {
            return TestResult::Failed(
                err.context(
                    "container should have been created with valid id, but was not created",
                ),
            );
        }
        // Second create which should fail
        let ret = create::create(self.project_path.path(), &id);
        // Clean up the container from the first create. No error handling since
        // there is nothing we can do.
        let _ = kill::kill(self.project_path.path(), &id);
        let _ = delete::delete(self.project_path.path(), &id);
        match ret {
            Ok(()) => TestResult::Failed(anyhow::anyhow!(
                "container should not have been created with same id, but was created."
            )),
            Err(_) => TestResult::Passed,
        }
    }
}

impl TestableGroup for ContainerCreate {
    fn get_name(&self) -> &'static str {
        "create"
    }

    fn parallel(&self) -> bool {
        true
    }

    fn run_all(&self) -> Vec<(&'static str, TestResult)> {
        vec![
            ("empty_id", self.create_empty_id()),
            ("valid_id", self.create_valid_id()),
            ("duplicate_id", self.create_duplicate_id()),
        ]
    }

    fn run_selected(&self, selected: &[&str]) -> Vec<(&'static str, TestResult)> {
        let mut ret = Vec::new();
        for name in selected {
            match *name {
                "empty_id" => ret.push(("empty_id", self.create_empty_id())),
                "valid_id" => ret.push(("valid_id", self.create_valid_id())),
                "duplicate_id" => ret.push(("duplicate_id", self.create_duplicate_id())),
                _ => eprintln!("No test named {name} in lifecycle"),
            };
        }
        ret
    }
}
