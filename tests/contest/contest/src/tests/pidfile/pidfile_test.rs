use std::fs::File;

use anyhow::anyhow;
use test_framework::{Test, TestGroup, TestResult};
use uuid::Uuid;

use crate::utils::{
    create_container, delete_container, generate_uuid, get_state, kill_container, prepare_bundle,
    CreateOptions, State,
};

#[inline]
fn cleanup(id: &Uuid, bundle: &tempfile::TempDir) {
    let str_id = id.to_string();
    kill_container(&str_id, bundle).unwrap().wait().unwrap();
    delete_container(&str_id, bundle).unwrap().wait().unwrap();
}

fn test_pidfile() -> TestResult {
    // create id for the container and pidfile
    let container_id = generate_uuid();

    // create temp dir for bundle and for storing the pid
    let bundle = prepare_bundle().unwrap();
    let pidfile_dir = tempfile::tempdir().unwrap();
    let pidfile_path = pidfile_dir.as_ref().join("pidfile");
    let _ = File::create(&pidfile_path).unwrap();

    // start the container
    create_container(
        &container_id.to_string(),
        &bundle,
        &CreateOptions::default().with_extra_args(&["--pid-file".as_ref(), pidfile_path.as_ref()]),
    )
    .unwrap()
    .wait()
    .unwrap();

    let (out, err) = get_state(&container_id.to_string(), &bundle).unwrap();

    if !err.is_empty() {
        cleanup(&container_id, &bundle);
        return TestResult::Failed(anyhow!("error in state : {}", err));
    }

    let state: State = serde_json::from_str(&out).unwrap();

    if state.id != container_id.to_string() {
        cleanup(&container_id, &bundle);
        return TestResult::Failed(anyhow!(
            "error in state : id not matched ,expected {} got {}",
            container_id,
            state.id
        ));
    }

    if state.status != "created" {
        cleanup(&container_id, &bundle);
        return TestResult::Failed(anyhow!(
            "error in state : status not matched ,expected 'created' got {}",
            state.status
        ));
    }

    // get pid from the pidfile
    let pidfile: i32 = std::fs::read_to_string(pidfile_dir.as_ref().join("pidfile"))
        .unwrap()
        .parse()
        .unwrap();

    // get pid from the state
    if state.pid.unwrap() != pidfile {
        cleanup(&container_id, &bundle);
        return TestResult::Failed(anyhow!(
            "error : pid not matched ,expected {} as per state, but got {} from pidfile instead",
            state.pid.unwrap(),
            pidfile
        ));
    }

    cleanup(&container_id, &bundle);
    TestResult::Passed
}

pub fn get_pidfile_test() -> TestGroup {
    let pidfile = Test::new("pidfile", Box::new(test_pidfile));
    let mut tg = TestGroup::new("pidfile");
    tg.add(vec![Box::new(pidfile)]);
    tg
}
