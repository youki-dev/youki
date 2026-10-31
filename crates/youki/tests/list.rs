use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use libcontainer::container::state::{ContainerStatus, State};
use serde_json::{Value, json};

fn list(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_youki"))
        .arg("--root")
        .arg(root)
        .arg("list")
        .args(args)
        .output()
        .unwrap()
}

fn fixture(root: &Path, id: &str, annotations: HashMap<String, String>) -> std::path::PathBuf {
    let bundle = root.parent().unwrap().join(format!("bundle-{id}"));
    fs::create_dir(&bundle).unwrap();
    fs::write(bundle.join("config.json"), r#"{"root":{"path":"rootfs"}}"#).unwrap();
    let dir = root.join(id);
    fs::create_dir(&dir).unwrap();
    let mut state = State::new(id, ContainerStatus::Stopped, None, bundle.clone());
    state.annotations = Some(annotations);
    state.save(&dir).unwrap();
    fs::write(
        dir.join("youki_config.json"),
        serde_json::to_vec(&json!({
            "hooks": null,
            "cgroup_path": "/test",
            "rootfs": bundle.join("rootfs"),
        }))
        .unwrap(),
    )
    .unwrap();
    bundle
}

#[test]
fn quiet_empty_root_has_no_header() {
    let root = tempfile::tempdir().unwrap();
    let output = list(root.path(), &["--quiet"]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
}

#[test]
fn quiet_lists_only_ids_without_reading_bundle_configs() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    fs::create_dir(&root).unwrap();
    for id in ["alpha", "beta"] {
        let bundle = fixture(&root, id, HashMap::new());
        fs::remove_file(bundle.join("config.json")).unwrap();
    }
    let output = list(&root, &["-q"]);
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        text.lines().collect::<BTreeSet<_>>(),
        BTreeSet::from(["alpha", "beta"])
    );
}

#[test]
fn json_empty_root_is_an_array() {
    let root = tempfile::tempdir().unwrap();
    let output = list(root.path(), &["--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!([])
    );
}

#[test]
fn json_includes_stopped_container_metadata_and_escapes_annotations() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    fs::create_dir(&root).unwrap();
    let annotation = "quote\" newline\nbackslash\\";
    let bundle = fixture(
        &root,
        "alpha",
        HashMap::from([("note".into(), annotation.into())]),
    );
    let output = list(&root, &["--format=json"]);
    assert!(output.status.success(), "{output:?}");
    let values: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(values.len(), 1);
    let entry = &values[0];
    assert_eq!(entry["id"], "alpha");
    assert_eq!(entry["pid"], 0);
    assert_eq!(entry["status"], "stopped");
    assert_eq!(entry["bundle"], bundle.to_str().unwrap());
    assert_eq!(entry["rootfs"], bundle.join("rootfs").to_str().unwrap());
    assert_eq!(entry["annotations"]["note"], annotation);
    assert!(entry["owner"].as_str().is_some_and(|name| !name.is_empty()));
    assert!(entry["ociVersion"].as_str().is_some());
}

#[test]
fn invalid_format_is_rejected_but_quiet_takes_precedence() {
    let root = tempfile::tempdir().unwrap();
    let invalid = list(root.path(), &["--format", "invalid"]);
    assert!(!invalid.status.success(), "{invalid:?}");
    let quiet = list(root.path(), &["--format", "invalid", "--quiet"]);
    assert!(quiet.status.success(), "{quiet:?}");
    assert!(quiet.stdout.is_empty(), "{quiet:?}");
}

#[test]
fn default_table_keeps_its_existing_header() {
    let root = tempfile::tempdir().unwrap();
    let output = list(root.path(), &[]);
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        text.split_whitespace().collect::<Vec<_>>(),
        ["ID", "PID", "STATUS", "BUNDLE", "CREATED", "CREATOR"]
    );
}

#[test]
fn all_formats_list_containers_in_id_order() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    fs::create_dir(&root).unwrap();
    for id in ["gamma", "alpha", "beta"] {
        fixture(&root, id, HashMap::new());
    }

    for args in [&["--quiet"][..], &["--format", "table"][..]] {
        let output = list(&root, args);
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        let ids: Vec<_> = text
            .lines()
            .skip(usize::from(args[0] == "--format"))
            .map(|line| line.split_whitespace().next().unwrap())
            .collect();
        assert_eq!(ids, ["alpha", "beta", "gamma"]);
    }

    let output = list(&root, &["--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let entries: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let ids: Vec<_> = entries
        .iter()
        .map(|entry| entry["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["alpha", "beta", "gamma"]);
}

#[test]
fn table_uses_lowercase_status() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    fs::create_dir(&root).unwrap();
    fixture(&root, "alpha", HashMap::new());
    let output = list(&root, &["--format", "table"]);
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    let row = text.lines().nth(1).unwrap();
    assert_eq!(row.split_whitespace().nth(1), Some("stopped"));
}

#[test]
fn json_uses_recorded_rootfs_after_bundle_config_changes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    fs::create_dir(&root).unwrap();
    let bundle = fixture(&root, "alpha", HashMap::new());
    fs::write(bundle.join("config.json"), r#"{"root":{"path":"changed"}}"#).unwrap();

    let output = list(&root, &["--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let entries: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        entries[0]["rootfs"],
        bundle.join("rootfs").to_str().unwrap()
    );
}

#[test]
fn json_uses_recorded_rootfs_after_bundle_config_removal() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    fs::create_dir(&root).unwrap();
    let bundle = fixture(&root, "alpha", HashMap::new());
    fs::remove_file(bundle.join("config.json")).unwrap();

    let output = list(&root, &["--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let entries: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        entries[0]["rootfs"],
        bundle.join("rootfs").to_str().unwrap()
    );
}

#[test]
fn json_omits_unknown_rootfs_for_legacy_containers() {
    for missing_config in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        fs::create_dir(&root).unwrap();
        let bundle = fixture(&root, "alpha", HashMap::new());
        let config = root.join("alpha/youki_config.json");
        if missing_config {
            fs::remove_file(config).unwrap();
        } else {
            fs::write(config, r#"{"hooks":null,"cgroup_path":"/legacy"}"#).unwrap();
        }
        fs::remove_file(bundle.join("config.json")).unwrap();

        let output = list(&root, &["--format", "json"]);
        assert!(output.status.success(), "{output:?}");
        let entries: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(entries[0]["id"], "alpha");
        assert!(entries[0].get("rootfs").is_none());
    }
}
