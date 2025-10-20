use std::fs;

use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{
    LinuxBuilder, LinuxMemoryPolicyBuilder, MemoryPolicyFlagType, MemoryPolicyModeType,
    ProcessBuilder, Spec, SpecBuilder,
};
use serde_json::json;
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn spec_with_runtimetest(
    args_token: &str,
    mp: Option<(MemoryPolicyModeType, &str, Vec<MemoryPolicyFlagType>)>,
) -> Result<Spec> {
    let mut linux = LinuxBuilder::default();

    if let Some((mode, nodes, flags)) = mp {
        let mp = LinuxMemoryPolicyBuilder::default()
            .mode(mode)
            .nodes(nodes.to_string())
            .flags(flags)
            .build()?;
        linux = linux.memory_policy(mp);
    }

    SpecBuilder::default()
        .linux(linux.build()?)
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), args_token.to_string()])
                .build()?,
        )
        .build()
        .context("failed to build spec")
}

fn interleave_without_flags() -> TestResult {
    let spec = match spec_with_runtimetest(
        "memory_policy",
        Some((MemoryPolicyModeType::MpolInterleave, "0", vec![])),
    ) {
        Ok(s) => s,
        Err(e) => return TestResult::Failed(e),
    };

    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn bind_static() -> TestResult {
    let spec = match spec_with_runtimetest(
        "memory_policy",
        Some((
            MemoryPolicyModeType::MpolBind,
            "0",
            vec![MemoryPolicyFlagType::MpolFStaticNodes],
        )),
    ) {
        Ok(s) => s,
        Err(e) => return TestResult::Failed(e),
    };

    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn preferred_relative() -> TestResult {
    let spec = match spec_with_runtimetest(
        "memory_policy",
        Some((
            MemoryPolicyModeType::MpolPreferred,
            "0",
            vec![MemoryPolicyFlagType::MpolFRelativeNodes],
        )),
    ) {
        Ok(s) => s,
        Err(e) => return TestResult::Failed(e),
    };

    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn default_with_missing_nodes_ok() -> TestResult {
    let spec = match spec_with_runtimetest(
        "memory_policy",
        Some((MemoryPolicyModeType::MpolDefault, "", vec![])),
    ) {
        Ok(s) => s,
        Err(e) => return TestResult::Failed(e),
    };
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn invalid_mode_string() -> TestResult {
    let spec = match spec_with_runtimetest("memory_policy", None) {
        Ok(s) => s,
        Err(e) => return TestResult::Failed(e),
    };

    let res = test_inside_container(&spec, &CreateOptions::default(), &|bundle| {
        let cfg_path = bundle.join("config.json");
        let mut v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&cfg_path)?).context("parse config.json")?;
        v["linux"]["memoryPolicy"] = json!({
            "mode": "INTERLEAVE",
            "nodes": "0"
        });
        fs::write(&cfg_path, serde_json::to_vec_pretty(&v)?)?;
        Ok(())
    });
    match res {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!(
            "expected error for invalid memory policy mode, found none"
        )),
        TestResult::Skipped => TestResult::Skipped,
    }
}

fn invalid_flag_string() -> TestResult {
    let spec = match spec_with_runtimetest("memory_policy", None) {
        Ok(s) => s,
        Err(e) => return TestResult::Failed(e),
    };

    let res = test_inside_container(&spec, &CreateOptions::default(), &|bundle| {
        let cfg_path = bundle.join("config.json");
        let mut v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&cfg_path)?).context("parse config.json")?;
        v["linux"]["memoryPolicy"] = json!({
            "mode": "MPOL_PREFERRED",
            "nodes": "0",
            "flags": ["MPOL_F_RELATIVE_NODES", "badflag"]
        });
        fs::write(&cfg_path, serde_json::to_vec_pretty(&v)?)?;
        Ok(())
    });

    match res {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!(
            "expected error for invalid memory policy flag, found none"
        )),
        TestResult::Skipped => TestResult::Skipped,
    }
}

fn missing_mode_but_nodes_present() -> TestResult {
    let spec = match spec_with_runtimetest("memory_policy", None) {
        Ok(s) => s,
        Err(e) => return TestResult::Failed(e),
    };

    let res = test_inside_container(&spec, &CreateOptions::default(), &|bundle| {
        let cfg_path = bundle.join("config.json");
        let mut v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&cfg_path)?).context("parse config.json")?;
        v["linux"]["memoryPolicy"] = json!({ "nodes": "0-7" });
        fs::write(&cfg_path, serde_json::to_vec_pretty(&v)?)?;
        Ok(())
    });

    match res {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => {
            TestResult::Failed(anyhow!("expected error for missing mode, found none"))
        }
        TestResult::Skipped => TestResult::Skipped,
    }
}

fn syscall_invalid_arguments() -> TestResult {
    let spec = match spec_with_runtimetest("memory_policy", None) {
        Ok(s) => s,
        Err(e) => return TestResult::Failed(e),
    };

    let res = test_inside_container(&spec, &CreateOptions::default(), &|bundle| {
        let cfg_path = bundle.join("config.json");
        let mut v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&cfg_path)?).context("parse config.json")?;
        v["linux"]["memoryPolicy"] = json!({
            "mode": "MPOL_DEFAULT",
            "nodes": "0-7",
            "flags": ["MPOL_F_NUMA_BALANCING", "MPOL_F_STATIC_NODES", "MPOL_F_RELATIVE_NODES"]
        });
        fs::write(&cfg_path, serde_json::to_vec_pretty(&v)?)?;
        Ok(())
    });

    match res {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!(
            "expected error for invalid set_mempolicy args, found none"
        )),
        TestResult::Skipped => TestResult::Skipped,
    }
}

fn bind_way_too_large_node_number() -> TestResult {
    let spec = match spec_with_runtimetest("memory_policy", None) {
        Ok(s) => s,
        Err(e) => return TestResult::Failed(e),
    };

    let res = test_inside_container(&spec, &CreateOptions::default(), &|bundle| {
        let cfg_path = bundle.join("config.json");
        let mut v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&cfg_path)?).context("parse config.json")?;
        v["linux"]["memoryPolicy"] = json!({
            "mode": "MPOL_BIND",
            "nodes": "0-9876543210",
            "flags": []
        });
        fs::write(&cfg_path, serde_json::to_vec_pretty(&v)?)?;
        Ok(())
    });

    match res {
        TestResult::Failed(_) => TestResult::Passed,
        TestResult::Passed => TestResult::Failed(anyhow!(
            "expected error for invalid memory policy node, found none"
        )),
        TestResult::Skipped => TestResult::Skipped,
    }
}

pub fn get_linux_memory_policy_tests() -> TestGroup {
    let mut tg = TestGroup::new("memory_policy");

    tg.add(vec![
        Box::new(Test::new(
            "interleave_without_flags",
            Box::new(interleave_without_flags),
        )),
        Box::new(Test::new("bind_static", Box::new(bind_static))),
        Box::new(Test::new(
            "preferred_relative",
            Box::new(preferred_relative),
        )),
    ]);

    tg.add(vec![
        Box::new(Test::new(
            "default_with_missing_nodes_ok",
            Box::new(default_with_missing_nodes_ok),
        )),
        Box::new(Test::new(
            "invalid_mode_string",
            Box::new(invalid_mode_string),
        )),
        Box::new(Test::new(
            "invalid_flag_string",
            Box::new(invalid_flag_string),
        )),
        Box::new(Test::new(
            "missing_mode_but_nodes_present",
            Box::new(missing_mode_but_nodes_present),
        )),
        Box::new(Test::new(
            "syscall_invalid_arguments",
            Box::new(syscall_invalid_arguments),
        )),
        Box::new(Test::new(
            "bind_way_too_large_node_number",
            Box::new(bind_way_too_large_node_number),
        )),
    ]);

    tg
}
