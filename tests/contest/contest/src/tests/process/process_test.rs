use std::fs;

use anyhow::{bail, Context, Ok, Result};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use test_framework::{test_result, Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec() -> Result<Spec> {
    let mut process = ProcessBuilder::default()
        .args(vec!["runtimetest".to_string(), "process".to_string()])
        .cwd("/test")
        .build()
        .expect("error in creating process config");
    let mut env = process.env().clone().unwrap();
    env.push("testa=valuea".to_string());
    env.push("testb=123".to_string());
    process.set_env(Some(env));

    let spec = SpecBuilder::default()
        .process(process)
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

fn process_test() -> TestResult {
    let spec = test_result!(create_spec());

    test_inside_container(spec, &CreateOptions::default(), &|bundle| {
        match fs::create_dir(bundle.join("test")) {
            Result::Ok(_) => { /*This is expected*/ }
            Err(e) => {
                bail!(e)
            }
        }

        Ok(())
    })
}

pub fn get_process_test() -> TestGroup {
    let mut process_test_group = TestGroup::new("process");

    let test = Test::new("process_test", Box::new(process_test));
    process_test_group.add(vec![Box::new(test)]);

    process_test_group
}
