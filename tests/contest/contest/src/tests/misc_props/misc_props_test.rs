use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use serde_json::Value;
use test_framework::{ConditionalTest, TestGroup, TestResult};

use crate::utils::{CreateOptions, is_runtime_runc, test_inside_container};

fn create_spec() -> Result<Spec> {
    let spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["/bin/sh".into(), "-c".into(), "true".into()])
                .build()
                .context("build process")?,
        )
        .build()
        .context("failed to build spec")?;
    Ok(spec)
}

fn host_config_path_from_rootfs(rootfs: &Path) -> Result<std::path::PathBuf> {
    let bundle_dir = rootfs.parent().context("no parent for rootfs")?;
    Ok(bundle_dir.join("config.json"))
}

fn write_top_level_str(path: &Path, key: &str, value: &str) -> Result<()> {
    let s = fs::read_to_string(path)?;
    let mut v: Value = serde_json::from_str(&s)?;
    if let Value::Object(map) = &mut v {
        map.insert(key.to_string(), Value::String(value.to_string()));
        fs::write(path, serde_json::to_vec_pretty(&v)?)?;
        Ok(())
    } else {
        bail!("config.json is not a JSON object");
    }
}

fn annotations_unknown_key_ignored_test() -> TestResult {
    let mut spec = create_spec().unwrap();

    let mut ann = spec.annotations().clone().unwrap_or_default();
    ann.insert("org.youki.misc-props.unknown".to_string(), String::new());
    spec.set_annotations(Some(ann));

    test_inside_container(&spec, &CreateOptions::default(), &|_rootfs| Ok(()))
}

fn unknown_top_level_property_ignored_test() -> TestResult {
    let spec = create_spec().unwrap();

    test_inside_container(&spec, &CreateOptions::default(), &|rootfs| {
        let host_cfg = host_config_path_from_rootfs(rootfs)?;
        write_top_level_str(&host_cfg, "unknown", "value")
    })
}

fn invalid_oci_version_must_error_test() -> TestResult {
    let spec = create_spec().unwrap();

    let res = test_inside_container(&spec, &CreateOptions::default(), &|rootfs| {
        let host_cfg = host_config_path_from_rootfs(rootfs)?;
        write_top_level_str(&host_cfg, "ociVersion", "invalid")
    });

    match res {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!(
            "expected invalid ociVersion to fail, but container started successfully"
        )),
        other => other,
    }
}

pub fn get_misc_props_test() -> TestGroup {
    let mut misc_props_group = TestGroup::new("set_misc_props");

    let annotations_unknown_key_ignored_test = ConditionalTest::new(
        "annotations_unknown_key_ignored_test",
        Box::new(|| true),
        Box::new(annotations_unknown_key_ignored_test),
    );

    let unknown_top_level_property_ignored_test = ConditionalTest::new(
        "unknown_top_level_property_ignored_test",
        Box::new(|| true),
        Box::new(unknown_top_level_property_ignored_test),
    );

    // runc does not perform strict ociVersion validation,
    // so this negative test is skipped on runc.
    // youki does validate spec.version as 1.x.y, so we run this test on youki.
    let invalid_oci_version_must_error_test = ConditionalTest::new(
        "invalid_oci_version_must_error_test",
        Box::new(|| !is_runtime_runc()),
        Box::new(invalid_oci_version_must_error_test),
    );

    misc_props_group.add(vec![
        Box::new(annotations_unknown_key_ignored_test),
        Box::new(unknown_top_level_property_ignored_test),
        Box::new(invalid_oci_version_must_error_test),
    ]);
    misc_props_group
}
