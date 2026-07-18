pub mod absolute_network;
pub mod relative_network;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use oci_spec::runtime::Spec;

use crate::utils::test_utils::CGROUP_ROOT;

// check for available network cgroup mount points paths, as the network controller can be multiple mount points
// see issue:#39 for discussion
fn check_network_cgroup_paths() -> Result<(&'static str, &'static str)> {
    let net_cls_net_prio_independent = Path::new("/sys/fs/cgroup/net_cls/net_cls.classid").exists()
        && Path::new("/sys/fs/cgroup/net_prio/net_prio.ifpriomap").exists();
    let net_cls_net_prio = Path::new("/sys/fs/cgroup/net_cls,net_prio/net_cls.classid").exists()
        && Path::new("/sys/fs/cgroup/net_cls,net_prio/net_prio.ifpriomap").exists();
    let net_prio_net_cls = Path::new("/sys/fs/cgroup/net_prio,net_cls/net_cls.classid").exists()
        && Path::new("/sys/fs/cgroup/net_prio,net_cls/net_prio.ifpriomap").exists();

    if net_cls_net_prio_independent {
        Ok(("net_cls", "net_prio"))
    } else if net_cls_net_prio {
        Ok(("net_cls,net_prio", "net_cls,net_prio"))
    } else if net_prio_net_cls {
        Ok(("net_prio,net_cls", "net_prio,net_cls"))
    } else {
        Err(anyhow!("Required cgroup paths do not exist"))
    }
}

// validates the Network structure parsed from /sys/fs/cgroup/net_cls,net_prio with the spec
fn validate_network(cgroup_name: &str, spec: &Spec) -> Result<()> {
    let (net_cls_base, net_prio_base) = check_network_cgroup_paths()?;
    let net_cls_path = PathBuf::from(CGROUP_ROOT)
        .join(net_cls_base)
        .join(cgroup_name.trim_start_matches('/'))
        .join("net_cls.classid");
    let net_prio_path = PathBuf::from(CGROUP_ROOT)
        .join(net_prio_base)
        .join(cgroup_name.trim_start_matches('/'))
        .join("net_prio.ifpriomap");

    let resources = spec.linux().as_ref().unwrap().resources().as_ref().unwrap();
    let spec_network = resources.network().as_ref().unwrap();

    // Validate net_cls.classid
    let classid_content = fs::read_to_string(&net_cls_path)
        .with_context(|| format!("failed to read {:?}", net_cls_path))?;
    let expected_classid = spec_network.class_id().unwrap();
    let actual_classid: u32 = classid_content
        .trim()
        .parse()
        .with_context(|| format!("could not parse {:?}", classid_content.trim()))?;
    if expected_classid != actual_classid {
        bail!(
            "expected {:?} to contain a classid of {}, but the classid was {}",
            net_cls_path,
            expected_classid,
            actual_classid
        );
    }

    // Validate net_prio.ifpriomap
    let ifpriomap_content = fs::read_to_string(&net_prio_path)
        .with_context(|| format!("failed to read {:?}", net_prio_path))?;
    let expected_priorities = spec_network.priorities().as_ref().unwrap();
    for priority in expected_priorities {
        let expected_entry = format!("{} {}", priority.name(), priority.priority());
        if !ifpriomap_content.contains(&expected_entry) {
            bail!(
                "expected {:?} to contain an entry '{}', but it was not found",
                net_prio_path,
                expected_entry
            );
        }
    }

    Ok(())
}
