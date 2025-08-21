use anyhow::anyhow;
use test_framework::{test_result, TestResult};

use crate::utils::test_utils::{
    check_container_created, exec_container, pause_container, resume_container, start_container,
    test_outside_container,
};

pub(crate) fn ignore_paused_test() -> TestResult {
    let spec = test_result!(super::create_spec());

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let pause_result = pause_container(id, dir).unwrap().wait().unwrap();
        if !pause_result.success() {
            return TestResult::Failed(anyhow!("container pause failed"));
        }

        let id2 = id.clone();
        let dir2 = dir.to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let _ = resume_container(&id2, &dir2).unwrap().wait();
        });

        let (stdout, _) = exec_container(
            id,
            dir,
            &[
                "--ignore-paused",
                "echo",
                "ya I can be executed in a pause state without error!",
            ],
            None,
        )
        .expect("exec failed");
        if !stdout.contains("ya I can be executed in a pause state without error!") {
            return TestResult::Failed(anyhow!("unexpected output: {}", stdout));
        }

        TestResult::Passed
    })
}
