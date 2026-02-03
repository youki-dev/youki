use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail};
use oci_spec::runtime::{Hook, HookBuilder, HooksBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_utils::{CreateOptions, LifecycleStatus, start_container};
use crate::utils::{
    create_container, delete_container, generate_uuid, prepare_bundle, set_config, wait_for_state,
};

const STATE_WAIT_TIMEOUT_SECS: u64 = 5;
const STATE_POLL_INTERVAL_MILLIS: u64 = 100;

fn get_hook_output_path(bundle: &tempfile::TempDir) -> PathBuf {
    bundle.as_ref().join("bundle").join("rootfs").join("output")
}

fn delete_hook_output_file(path: &PathBuf) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => bail!("failed to remove output file: {}", e),
    }
}

fn write_log_hook(content: &str, host_output_file_path: &str) -> Hook {
    HookBuilder::default()
        .path("/bin/sh")
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo '{content}' >> {host_output_file_path}",),
        ])
        .build()
        .expect("could not build hook")
}

fn get_spec(host_output_file: &str) -> Spec {
    let write_format = |content: &str| write_log_hook(content, host_output_file);

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["true".to_string()])
                .build()
                .unwrap(),
        )
        .hooks(
            HooksBuilder::default()
                .prestart(vec![
                    write_format("pre-start1 called"),
                    write_format("pre-start2 called"),
                ])
                .create_runtime(vec![
                    write_format("create-runtime1 called"),
                    write_format("create-runtime2 called"),
                ])
                .create_container(vec![
                    write_format("create-container1 called"),
                    write_format("create-container2 called"),
                ])
                .start_container(vec![
                    write_format("start-container1 called"),
                    write_format("start-container2 called"),
                ])
                .poststart(vec![
                    write_format("post-start1 called"),
                    write_format("post-start2 called"),
                ])
                .poststop(vec![
                    write_format("post-stop1 called"),
                    write_format("post-stop2 called"),
                ])
                .build()
                .expect("could not build hooks"),
        )
        .build()
        .unwrap()
}

fn get_test(test_name: &'static str) -> Test {
    Test::new(
        test_name,
        Box::new(move || {
            let id = generate_uuid();
            let id_str = id.to_string();
            let bundle = prepare_bundle().unwrap();
            let host_output_file = get_hook_output_path(&bundle);
            let host_output_file_str = host_output_file.to_str().unwrap();

            let spec = get_spec(host_output_file_str);

            set_config(&bundle, &spec).unwrap();
            create_container(&id_str, &bundle, &CreateOptions::default())
                .unwrap()
                .wait()
                .unwrap();
            wait_for_state(
                &id_str,
                bundle.path(),
                LifecycleStatus::Created,
                std::time::Duration::from_secs(STATE_WAIT_TIMEOUT_SECS),
                std::time::Duration::from_millis(STATE_POLL_INTERVAL_MILLIS),
            )
            .unwrap();
            start_container(&id_str, &bundle).unwrap().wait().unwrap();
            delete_container(&id_str, &bundle).unwrap().wait().unwrap();
            wait_for_state(
                &id_str,
                bundle.path(),
                LifecycleStatus::Stopped,
                std::time::Duration::from_secs(STATE_WAIT_TIMEOUT_SECS),
                std::time::Duration::from_millis(STATE_POLL_INTERVAL_MILLIS),
            )
            .unwrap();
            let log = fs::read_to_string(&host_output_file).expect("cannot read output file");
            delete_hook_output_file(&host_output_file).unwrap();
            let expected = "pre-start1 called\n\
                    pre-start2 called\n\
                    create-runtime1 called\n\
                    create-runtime2 called\n\
                    create-container1 called\n\
                    create-container2 called\n\
                    post-start1 called\n\
                    post-start2 called\n\
                    post-stop1 called\n\
                    post-stop2 called\n";
            if log != expected {
                return TestResult::Failed(anyhow!(
                    "error: hooks must be called in the listed order.\n\
                    got:\n{log}\n\
                    expected:\n{expected}"
                ));
            }
            TestResult::Passed
        }),
    )
}

pub fn get_hooks_tests() -> TestGroup {
    let mut tg = TestGroup::new("hooks");
    tg.add(vec![Box::new(get_test("hooks"))]);
    tg
}
