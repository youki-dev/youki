use anyhow::{Context, Result};
use libcontainer::process::intel_rdt::find_resctrl_mount_point;
use oci_spec::runtime::{LinuxBuilder, LinuxIntelRdt, Spec, SpecBuilder};
use test_framework::{TestResult, test_result};

use crate::utils::test_outside_container;
use crate::utils::test_utils::check_container_created;

fn create_spec(
    maybe_l3_cache: Option<&str>,
    maybe_mem_bw: Option<&str>,
    maybe_clos_id: Option<&str>,
    enable_monitoring: Option<bool>,
) -> Result<Spec> {
    let mut intel_rdt = LinuxIntelRdt::default();
    intel_rdt.set_l3_cache_schema(maybe_l3_cache.map(|x| x.to_owned()));
    intel_rdt.set_mem_bw_schema(maybe_mem_bw.map(|x| x.to_owned()));
    intel_rdt.set_clos_id(maybe_clos_id.map(|x| x.to_owned()));
    intel_rdt.set_enable_monitoring(enable_monitoring);

    // Create the Linux Spec
    let linux_spec = LinuxBuilder::default()
        .intel_rdt(intel_rdt)
        .build()
        .context("failed to build linux spec")?;

    // Create the top level Spec
    let spec = SpecBuilder::default()
        .linux(linux_spec)
        .build()
        .context("failed to build spec")?;

    Ok(spec)
}

pub fn test_intel_rdt() -> TestResult {
    let cases = vec![
        test_result!(create_spec(Some("L3:0=fff"), Some("MB:0=70"), None, None)),
        test_result!(create_spec(Some("L3:0=fff"), None, None, None)),
        test_result!(create_spec(None, Some("MB:0=70"), None, None)),
        test_result!(create_spec(None, None, None, None)),
        test_result!(create_spec(None, None, None, Some(true))),
        test_result!(create_spec(
            Some("L3:0=fff"),
            Some("MB:0=70"),
            None,
            Some(true)
        )),
        test_result!(create_spec(Some("L3:0=fff"), None, None, Some(true))),
        test_result!(create_spec(None, Some("MB:0=70"), None, Some(true))),
    ];

    for spec in cases.into_iter() {
        let spec_clone = spec.clone();
        let test_result = test_outside_container(&spec, &|data| {
            test_result!(check_container_created(&data));

            // If enable_monitoring is true, verify the mon_groups directory exists
            if let Some(linux) = spec_clone.linux()
                && let Some(intel_rdt) = linux.intel_rdt()
                && let Some(true) = intel_rdt.enable_monitoring()
            {
                let mount_point = find_resctrl_mount_point().unwrap();
                let container_id = &data.id;
                let clos_id = intel_rdt.clos_id().as_deref().unwrap_or(container_id);
                let mon_dir = mount_point
                    .join(clos_id)
                    .join("mon_groups")
                    .join(container_id);
                if !mon_dir.exists() {
                    return TestResult::Failed(anyhow::anyhow!(
                        "Monitoring directory does not exist: {:?}",
                        mon_dir
                    ));
                }
            }

            TestResult::Passed
        });
        if let TestResult::Failed(_) = test_result {
            return test_result;
        }
    }

    TestResult::Passed
}

pub fn can_run() -> bool {
    // Ensure the resctrl pseudo-filesystem is mounted.
    let res = find_resctrl_mount_point();
    res.is_ok()
}
