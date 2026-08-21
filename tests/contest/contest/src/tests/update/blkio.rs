use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use oci_spec::runtime::{
    LinuxBlockIoBuilder, LinuxResources, LinuxResourcesBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{TestResult, test_result};

use super::update_container_and_wait;
use crate::utils::test_utils::check_container_created;
use crate::utils::{
    start_container, test_outside_container, update_container, update_container_with_stdin,
};

const INITIAL_WEIGHT: u16 = 100;
const UPDATED_WEIGHT: u16 = 500;

fn create_spec(cgroup_name: &str, resources: Option<LinuxResources>) -> Result<Spec> {
    let mut spec = SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "1000".to_string()])
                .build()?,
        )
        .build()
        .context("failed to build spec")?;

    if let Some(linux) = spec.linux_mut() {
        linux.set_cgroups_path(Some(Path::new("/runtime-test").join(cgroup_name)));
        linux.set_resources(resources);
    }

    Ok(spec)
}

fn convert_blkio_weight_to_io_weight(weight: u16) -> u64 {
    1 + (u64::from(weight) - 10) * 9999 / 990
}

// Both files may prefix the default weight with "default" and may contain
// per-device entries, so match the expected numeric value among the tokens.
fn check_blkio_weight(cgroup_path: &Path, weight: u16) -> Result<()> {
    let bfq_path = cgroup_path.join("io.bfq.weight");
    let (path, expected) = if bfq_path.exists() {
        (bfq_path, weight.to_string())
    } else {
        (
            cgroup_path.join("io.weight"),
            convert_blkio_weight_to_io_weight(weight).to_string(),
        )
    };

    let content =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    if !content.split_whitespace().any(|token| token == expected) {
        bail!(
            "{}: expected weight {}, got {:?}",
            path.display(),
            expected,
            content
        );
    }

    Ok(())
}

fn expect_update_failure(id: &str, dir: &Path, weight: &str) -> Result<()> {
    let status = update_container(id, dir, &["--blkio-weight", weight])
        .unwrap()
        .wait()
        .unwrap();

    if status.success() {
        bail!("expected --blkio-weight {weight} to fail, but it succeeded");
    }

    Ok(())
}

// "update cgroup blkio weight"
pub(crate) fn update_blkio_weight_test() -> TestResult {
    const CGROUP_NAME: &str = "update_blkio_weight";
    let block_io = test_result!(
        LinuxBlockIoBuilder::default()
            .weight(INITIAL_WEIGHT)
            .build()
            .context("failed to build blockio resources")
    );

    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .block_io(block_io)
            .build()
            .context("failed to build resources spec")
    );
    let spec = test_result!(create_spec(CGROUP_NAME, Some(resources)));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));

        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }
        let cgroup_path = Path::new("/sys/fs/cgroup/runtime-test").join(CGROUP_NAME);

        // check the initial value was properly set
        test_result!(check_blkio_weight(&cgroup_path, INITIAL_WEIGHT));

        // Update blkio weight via CLI flag.
        test_result!(update_container_and_wait(
            id,
            dir,
            &["--blkio-weight", "500"],
        ));
        test_result!(check_blkio_weight(&cgroup_path, UPDATED_WEIGHT));

        // Revert to the test initial value via json on stdin
        let json = serde_json::json!({ "blockIO": { "weight": INITIAL_WEIGHT } }).to_string();
        let update_result = update_container_with_stdin(id, dir, &["-r", "-"], &json)
            .unwrap()
            .wait()
            .unwrap();
        if !update_result.success() {
            return TestResult::Failed(anyhow!("update blkio weight via stdin failed"));
        }
        test_result!(check_blkio_weight(&cgroup_path, INITIAL_WEIGHT));

        // Out of range values must be rejected and leave the weight unchanged.
        test_result!(expect_update_failure(id, dir, "2000"));
        test_result!(check_blkio_weight(&cgroup_path, INITIAL_WEIGHT));

        TestResult::Passed
    })
}
