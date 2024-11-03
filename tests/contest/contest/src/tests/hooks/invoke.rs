use std::fs::File;
use std::io::Read;

use anyhow::anyhow;
use oci_spec::runtime::{Hook, HookBuilder, HooksBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_utils::{start_container, CreateOptions};
use crate::utils::{create_container, delete_container, generate_uuid, prepare_bundle, set_config};

const HOOK_OUTPUT_FILE: &str = "output";

fn create_hook_output_file() {
    std::fs::File::create(HOOK_OUTPUT_FILE).expect("fail to create hook output file");
}

fn delete_hook_output_file() {
    std::fs::remove_file(HOOK_OUTPUT_FILE).expect("fail to remove hook output file");
}

fn write_log_hook(content: &str) -> Hook {
    let output = std::fs::canonicalize(HOOK_OUTPUT_FILE).unwrap();
    let output = output.to_str().unwrap();
    HookBuilder::default()
        .path("/bin/sh")
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo '{content}' >> {output}",),
        ])
        .build()
        .expect("could not build hook")
}

fn get_spec() -> Spec {
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
                    write_log_hook("pre-start1 called"),
                    write_log_hook("pre-start2 called"),
                ])
                .poststart(vec![
                    write_log_hook("post-start1 called"),
                    write_log_hook("post-start2 called"),
                ])
                .poststop(vec![
                    write_log_hook("post-stop1 called"),
                    write_log_hook("post-stop2 called"),
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
            create_hook_output_file();
            let spec = get_spec();
            let id = generate_uuid();
            let id_str = id.to_string();
            let bundle = prepare_bundle().unwrap();
            set_config(&bundle, &spec).unwrap();
            create_container(&id_str, &bundle, &CreateOptions::default())
                .unwrap()
                .wait()
                .unwrap();
            start_container(&id_str, &bundle).unwrap().wait().unwrap();
            delete_container(&id_str, &bundle).unwrap().wait().unwrap();
            let log = {
                let mut output = File::open("output").expect("cannot open hook log");
                let mut log = String::new();
                output
                    .read_to_string(&mut log)
                    .expect("fail to read hook log");
                log
            };
            delete_hook_output_file();
            if log != "pre-start1 called\npre-start2 called\npost-start1 called\npost-start2 called\npost-stop1 called\npost-stop2 called\n" {
                return TestResult::Failed(anyhow!(
                        "error : hooks must be called in the listed order, {log:?}"
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
