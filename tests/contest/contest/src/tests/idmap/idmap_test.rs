use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nix::mount::{MntFlags, umount2};
#[cfg(target_os = "linux")]
use nix::mount::{MsFlags, mount};
use nix::unistd::{Gid, Uid, chown};
use oci_spec::runtime::{
    LinuxBuilder, LinuxIdMapping, LinuxIdMappingBuilder, LinuxNamespace, LinuxNamespaceBuilder,
    LinuxNamespaceType, Mount, MountBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder,
    get_default_mounts,
};
use tempfile::TempDir;
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::tests::lifecycle::ContainerLifecycle;
use crate::utils::test_utils::CreateOptions;
use crate::utils::{State, get_runtimetest_path, get_state, set_config, test_inside_container};

const USERNS_HOST_ID: u32 = 100_000;
const USERNS_SIZE: u32 = 65_536;
const STATE_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

// This file mirrors runc/tests/integration/idmap.bats. Keep get_idmap_test()
// in the same order as the BATS @test blocks so the port can be reviewed
// by reading both files top-to-bottom.

fn id_mapping(container_id: u32, host_id: u32, size: u32) -> Result<LinuxIdMapping> {
    LinuxIdMappingBuilder::default()
        .container_id(container_id)
        .host_id(host_id)
        .size(size)
        .build()
        .context("failed to build id mapping")
}

fn id_mappings(container_id: u32, host_id: u32, size: u32) -> Result<Vec<LinuxIdMapping>> {
    Ok(vec![id_mapping(container_id, host_id, size)?])
}

fn id_mappings_from_tuples(mappings: &[(u32, u32, u32)]) -> Result<Vec<LinuxIdMapping>> {
    mappings
        .iter()
        .map(|(container_id, host_id, size)| id_mapping(*container_id, *host_id, *size))
        .collect()
}

fn userns_mappings(host_id: u32) -> Result<Vec<LinuxIdMapping>> {
    id_mappings(0, host_id, USERNS_SIZE)
}

// runc helper: setup_idmap_userns
fn create_linux_config(use_userns: bool, userns_host_id: u32) -> Result<oci_spec::runtime::Linux> {
    let mut builder = LinuxBuilder::default().readonly_paths(vec![]);
    if use_userns {
        let mut namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces();
        namespaces.push(
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::User)
                .build()
                .context("failed to build user namespace")?,
        );
        builder = builder
            .namespaces(namespaces)
            .uid_mappings(userns_mappings(userns_host_id)?)
            .gid_mappings(userns_mappings(userns_host_id)?);
    }
    builder.build().context("failed to build linux config")
}

fn create_linux_config_joining_userns(userns_path: PathBuf) -> Result<oci_spec::runtime::Linux> {
    let mut namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces();
    namespaces.retain(|namespace| namespace.typ() != LinuxNamespaceType::User);
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .path(userns_path)
            .build()
            .context("failed to build joined user namespace")?,
    );

    LinuxBuilder::default()
        .readonly_paths(vec![])
        .namespaces(namespaces)
        .build()
        .context("failed to build linux config")
}

fn create_idmap_spec_with_linux(
    mounts: Vec<Mount>,
    case: &str,
    linux: oci_spec::runtime::Linux,
) -> Result<Spec> {
    let mut all_mounts = get_default_mounts();
    all_mounts.extend(mounts);

    SpecBuilder::default()
        .mounts(all_mounts)
        .root(
            RootBuilder::default()
                .readonly(false)
                .build()
                .context("failed to build root")?,
        )
        .linux(linux)
        .process(
            ProcessBuilder::default()
                .args(vec![
                    "runtimetest".to_string(),
                    "idmap".to_string(),
                    case.to_string(),
                ])
                .build()
                .context("failed to build process")?,
        )
        .build()
        .context("failed to build spec")
}

fn create_idmap_spec(
    mounts: Vec<Mount>,
    case: &str,
    use_userns: bool,
    userns_host_id: u32,
) -> Result<Spec> {
    create_idmap_spec_with_linux(
        mounts,
        case,
        create_linux_config(use_userns, userns_host_id)?,
    )
}

fn create_userns_holder_spec() -> Result<Spec> {
    // This container only needs to keep a user namespace alive. In principle
    // `sleep` would be enough, as in runc's test, but contest's bundled rootfs
    // is a fixed x86_64 artifact. On aarch64 local environments such as Apple
    // Silicon Lima, rootfs binaries like /bin/sleep cannot run. Use the
    // current-arch runtimetest binary copied into the rootfs instead.
    create_idmap_spec(vec![], "target_userns_sleep", true, USERNS_HOST_ID)
}

fn build_bind_mount(
    source: &Path,
    destination: &str,
    options: &[&str],
    uid_mappings: Option<Vec<LinuxIdMapping>>,
    gid_mappings: Option<Vec<LinuxIdMapping>>,
) -> Result<Mount> {
    let mut builder = MountBuilder::default()
        .destination(PathBuf::from(destination))
        .typ("bind")
        .source(source)
        .options(
            options
                .iter()
                .map(|option| option.to_string())
                .collect::<Vec<_>>(),
        );

    if let Some(uid_mappings) = uid_mappings {
        builder = builder.uid_mappings(uid_mappings);
    }
    if let Some(gid_mappings) = gid_mappings {
        builder = builder.gid_mappings(gid_mappings);
    }

    builder.build().context("failed to build bind mount")
}

// runc helper: setup_idmap_basic_mount
fn build_basic_idmapped_bind_mount(
    source: &Path,
    destination: &str,
    options: &[&str],
    uid_host_id: u32,
    gid_host_id: u32,
    size: u32,
) -> Result<Mount> {
    build_bind_mount(
        source,
        destination,
        options,
        Some(id_mappings(0, uid_host_id, size)?),
        Some(id_mappings(0, gid_host_id, size)?),
    )
}

// runc helper: setup_idmap_single_mount
fn build_idmapped_bind_mount(
    source: &Path,
    destination: &str,
    options: &[&str],
    uid_mapping: (u32, u32, u32),
    gid_mapping: (u32, u32, u32),
) -> Result<Mount> {
    build_bind_mount(
        source,
        destination,
        options,
        Some(id_mappings(uid_mapping.0, uid_mapping.1, uid_mapping.2)?),
        Some(id_mappings(gid_mapping.0, gid_mapping.1, gid_mapping.2)?),
    )
}

fn build_idmapped_bind_mount_with_mappings(
    source: &Path,
    destination: &str,
    options: &[&str],
    uid_mappings: &[(u32, u32, u32)],
    gid_mappings: &[(u32, u32, u32)],
) -> Result<Mount> {
    build_bind_mount(
        source,
        destination,
        options,
        Some(id_mappings_from_tuples(uid_mappings)?),
        Some(id_mappings_from_tuples(gid_mappings)?),
    )
}

// runc helpers: setup_host_bind_mount + setup_idmap_single_mount for tree cases
fn build_tree_idmapped_bind_mount(
    source: &Path,
    destination: &str,
    options: &[&str],
) -> Result<Mount> {
    build_bind_mount(
        source,
        destination,
        options,
        Some(vec![
            id_mapping(100, 101000, 3)?,
            id_mapping(200, 102000, 3)?,
            id_mapping(300, 103000, 3)?,
        ]),
        Some(vec![
            id_mapping(210, 101100, 10)?,
            id_mapping(220, 102200, 10)?,
            id_mapping(230, 103300, 10)?,
        ]),
    )
}

// runc setup(): prepare source-* files and chown them.
fn write_owned_file(path: &Path, uid: u32, gid: u32) -> Result<()> {
    fs::write(path, b"idmap test\n")
        .with_context(|| format!("failed to write {}", path.display()))?;
    chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .with_context(|| format!("failed to chown {}", path.display()))
}

fn setup_single_owned_file(source: &Path, uid: u32, gid: u32) -> Result<()> {
    fs::create_dir_all(source).with_context(|| format!("failed to create {}", source.display()))?;
    write_owned_file(&source.join("foo.txt"), uid, gid)
}

fn setup_owned_files(source: &Path, files: &[(u32, u32); 3]) -> Result<()> {
    fs::create_dir_all(source).with_context(|| format!("failed to create {}", source.display()))?;
    for (name, (uid, gid)) in ["foo.txt", "bar.txt", "baz.txt"]
        .into_iter()
        .zip(files.iter())
    {
        write_owned_file(&source.join(name), *uid, *gid)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_mount(source: &Path, target: &Path) -> Result<()> {
    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| {
        format!(
            "failed to bind mount {} on {}",
            source.display(),
            target.display()
        )
    })
}

fn setup_owned_bind_mount_tree(
    mount_tree: &Path,
    top_files: &[(u32, u32); 3],
    child1_files: &[(u32, u32); 3],
    child2_files: &[(u32, u32); 3],
) -> Result<()> {
    fs::create_dir_all(mount_tree)
        .with_context(|| format!("failed to create {}", mount_tree.display()))?;
    setup_owned_files(mount_tree, top_files)?;

    let parent = mount_tree
        .parent()
        .context("mount tree source must have a parent directory")?;
    let child1_source = parent.join("source-multi1");
    let child2_source = parent.join("source-multi2");
    setup_owned_files(&child1_source, child1_files)?;
    setup_owned_files(&child2_source, child2_files)?;

    let multi1 = mount_tree.join("multi1");
    let multi2 = mount_tree.join("multi2");
    fs::create_dir_all(&multi1)?;
    fs::create_dir_all(&multi2)?;
    bind_mount(&child1_source, &multi1)?;
    bind_mount(&child2_source, &multi2)
}

fn setup_runc_idmap_tree(source: &Path) -> Result<()> {
    setup_owned_bind_mount_tree(
        source,
        &[(100, 211), (200, 222), (300, 233)],
        &[(100, 211), (101, 222), (102, 233)],
        &[(200, 211), (201, 222), (202, 233)],
    )
}

fn cleanup_tree(source: &Path) {
    for dir in ["multi1", "multi2"] {
        let mountpoint = source.join(dir);
        if let Err(err) = umount2(&mountpoint, MntFlags::MNT_DETACH) {
            eprintln!(
                "failed to cleanup idmap test mount {}: {err}",
                mountpoint.display()
            );
        }
    }
}

fn run_idmap_case<F>(case: &str, spec: Spec, setup: F) -> TestResult
where
    F: Fn() -> Result<()>,
{
    test_inside_container(&spec, &CreateOptions::default(), &|rootfs| {
        if let Some(mounts) = spec.mounts() {
            for mount in mounts {
                let relative_destination = mount
                    .destination()
                    .strip_prefix("/")
                    .unwrap_or_else(|_| mount.destination());
                fs::create_dir_all(rootfs.join(relative_destination)).with_context(|| {
                    format!(
                        "failed to create mount destination {:?}",
                        mount.destination()
                    )
                })?;
            }
        }
        setup().with_context(|| format!("failed to setup idmap case {case}"))
    })
}

fn require_passed(result: TestResult, context: &str) -> Result<()> {
    match result {
        TestResult::Passed => Ok(()),
        TestResult::Skipped => anyhow::bail!("{context}: skipped"),
        TestResult::Failed(err) => Err(err).with_context(|| context.to_string()),
    }
}

fn container_state(container: &ContainerLifecycle) -> Result<State> {
    let (stdout, stderr) =
        get_state(container.id(), container.project_path()).context("failed to get state")?;
    if !stderr.is_empty() {
        anyhow::bail!("failed to get container state: {stderr}");
    }
    serde_json::from_str(&stdout).context("failed to parse container state")
}

struct UsernsHolderContainer {
    container: ContainerLifecycle,
    pid: i32,
}

impl UsernsHolderContainer {
    fn userns_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/{}/ns/user", self.pid))
    }
}

impl Drop for UsernsHolderContainer {
    fn drop(&mut self) {
        let _ = self.container.kill();
        let _ = self.container.delete();
    }
}

fn start_userns_holder_container() -> Result<UsernsHolderContainer> {
    let container = ContainerLifecycle::new();
    let spec = create_userns_holder_spec()?;
    set_config(container.project_path(), &spec).context("failed to set target userns config")?;

    spec.save(
        container
            .project_path()
            .join("bundle")
            .join("rootfs")
            .join("config.json"),
    )
    .context("failed to save target userns spec inside rootfs")?;
    // The userns holder uses the same runtimetest-based process args as the
    // other idmap cases, so its rootfs also needs the runtimetest binary. If
    // this holder is changed to match runc's "sleep infinity" setup directly,
    // this copy is no longer needed.
    std::fs::copy(
        get_runtimetest_path(),
        container
            .project_path()
            .join("bundle")
            .join("rootfs")
            .join("bin")
            .join("runtimetest"),
    )
    .context("failed to copy runtimetest into target userns bundle")?;

    require_passed(
        container.create(),
        "failed to create target userns container",
    )?;
    require_passed(
        container.wait_for_state("created", STATE_WAIT_TIMEOUT),
        "target userns container did not reach created state",
    )?;
    require_passed(container.start(), "failed to start target userns container")?;
    require_passed(
        container.wait_for_state("running", STATE_WAIT_TIMEOUT),
        "target userns container did not reach running state",
    )?;

    let state = container_state(&container).context("failed to get target userns state")?;
    let pid = state
        .pid
        .context("target userns state did not include a pid")?;

    Ok(UsernsHolderContainer { container, pid })
}

fn run_single_file_idmapped_bind_case(case: &'static str, use_userns: bool) -> TestResult {
    let tmp = test_result!(TempDir::new().context("failed to create tempdir"));
    let source = tmp.path().join("mount-1");
    let mount = test_result!(build_basic_idmapped_bind_mount(
        &source,
        "/tmp/mount-1",
        &["bind"],
        USERNS_HOST_ID,
        USERNS_HOST_ID,
        USERNS_SIZE,
    ));
    let spec = test_result!(create_idmap_spec(
        vec![mount],
        case,
        use_userns,
        USERNS_HOST_ID
    ));
    run_idmap_case(case, spec, || setup_single_owned_file(&source, 0, 0))
}

fn run_relative_destination_idmapped_bind_case() -> TestResult {
    let tmp = test_result!(TempDir::new().context("failed to create tempdir"));
    let source = tmp.path().join("mount-1");
    let mount = test_result!(build_basic_idmapped_bind_mount(
        &source,
        "tmp/mount-1",
        &["bind"],
        USERNS_HOST_ID,
        USERNS_HOST_ID,
        USERNS_SIZE,
    ));
    let spec = test_result!(create_idmap_spec(
        vec![mount],
        "idmap_mount_with_relative_path_userns",
        true,
        USERNS_HOST_ID
    ));
    run_idmap_case("idmap_mount_with_relative_path_userns", spec, || {
        setup_single_owned_file(&source, 0, 0)
    })
}

fn run_joined_userns_implied_idmap_case() -> TestResult {
    let tmp = test_result!(TempDir::new().context("failed to create tempdir"));
    let source = tmp.path().join("mount-tree");
    let mount = test_result!(build_bind_mount(
        &source,
        "/tmp/mount-tree",
        &["rbind", "idmap"],
        None,
        None,
    ));
    let target = test_result!(start_userns_holder_container());
    let linux = test_result!(create_linux_config_joining_userns(target.userns_path()));
    let spec = test_result!(create_idmap_spec_with_linux(
        vec![mount],
        "idmap_mount_idmap_flag_implied_mapping_userns_join_userns",
        linux,
    ));
    let result = run_idmap_case(
        "idmap_mount_idmap_flag_implied_mapping_userns_join_userns",
        spec,
        || setup_runc_idmap_tree(&source),
    );
    cleanup_tree(&source);
    result
}

fn run_propagation_idmapped_bind_case() -> TestResult {
    let tmp = test_result!(TempDir::new().context("failed to create tempdir"));
    let source = tmp.path().join("mount-1");
    let mount = test_result!(build_basic_idmapped_bind_mount(
        &source,
        "/tmp/mount-1",
        &["bind", "shared"],
        USERNS_HOST_ID,
        USERNS_HOST_ID,
        USERNS_SIZE,
    ));
    let spec = test_result!(create_idmap_spec(
        vec![mount],
        "idmap_mount_with_propagation_flag_userns",
        true,
        USERNS_HOST_ID,
    ));
    run_idmap_case("idmap_mount_with_propagation_flag_userns", spec, || {
        setup_single_owned_file(&source, 0, 0)
    })
}

fn run_idmapped_and_plain_bind_case(case: &'static str, use_userns: bool) -> TestResult {
    let tmp = test_result!(TempDir::new().context("failed to create tempdir"));
    let source = tmp.path().join("mount-1");
    let idmapped = test_result!(build_basic_idmapped_bind_mount(
        &source,
        "/tmp/mount-1",
        &["bind"],
        USERNS_HOST_ID,
        USERNS_HOST_ID,
        USERNS_SIZE,
    ));
    let plain = test_result!(build_bind_mount(
        &source,
        "/tmp/bind-mount-1",
        &["bind"],
        None,
        None
    ));
    let spec = test_result!(create_idmap_spec(
        vec![idmapped, plain],
        case,
        use_userns,
        USERNS_HOST_ID,
    ));
    run_idmap_case(case, spec, || setup_single_owned_file(&source, 0, 0))
}

fn run_two_idmapped_binds_same_mapping_case() -> TestResult {
    let tmp = test_result!(TempDir::new().context("failed to create tempdir"));
    let source1 = tmp.path().join("mount-1");
    let source2 = tmp.path().join("mount-2");
    let idmapped1 = test_result!(build_basic_idmapped_bind_mount(
        &source1,
        "/tmp/mount-1",
        &["bind"],
        USERNS_HOST_ID,
        USERNS_HOST_ID,
        USERNS_SIZE,
    ));
    let plain1 = test_result!(build_bind_mount(
        &source1,
        "/tmp/bind-mount-1",
        &["bind"],
        None,
        None,
    ));
    let plain2 = test_result!(build_bind_mount(
        &source2,
        "/tmp/bind-mount-2",
        &["bind"],
        None,
        None,
    ));
    let idmapped2 = test_result!(build_basic_idmapped_bind_mount(
        &source2,
        "/tmp/mount-2",
        &["bind"],
        USERNS_HOST_ID,
        USERNS_HOST_ID,
        USERNS_SIZE,
    ));
    let spec = test_result!(create_idmap_spec(
        vec![idmapped1, plain1, plain2, idmapped2],
        "two_idmap_mounts_same_mapping_with_two_bind_mounts_userns",
        true,
        USERNS_HOST_ID,
    ));
    run_idmap_case(
        "two_idmap_mounts_same_mapping_with_two_bind_mounts_userns",
        spec,
        || {
            setup_single_owned_file(&source1, 0, 0)?;
            setup_single_owned_file(&source2, 1, 1)
        },
    )
}

fn run_same_source_different_mappings_case(case: &'static str, use_userns: bool) -> TestResult {
    let tmp = test_result!(TempDir::new().context("failed to create tempdir"));
    let source = tmp.path().join("multi1");
    let source_symlink = tmp.path().join("multi1-symlink");
    let mount1 = test_result!(build_idmapped_bind_mount(
        &source,
        "/tmp/mount-multi1",
        &["bind"],
        (100, 100000, 100),
        (200, 100000, 100),
    ));
    let mount2 = test_result!(build_idmapped_bind_mount(
        &source,
        "/tmp/mount-multi1-alt",
        &["bind"],
        (100, 101000, 100),
        (200, 102000, 100),
    ));
    let mount3 = test_result!(build_idmapped_bind_mount(
        &source_symlink,
        "/tmp/mount-multi1-alt-sym",
        &["bind"],
        (100, 102000, 100),
        (200, 103000, 100),
    ));
    let spec = test_result!(create_idmap_spec(
        vec![mount1, mount2, mount3],
        case,
        use_userns,
        USERNS_HOST_ID,
    ));
    run_idmap_case(case, spec, || {
        setup_owned_files(&source, &[(100, 211), (101, 222), (102, 233)])?;
        symlink(&source, &source_symlink).with_context(|| {
            format!(
                "failed to symlink {} to {}",
                source_symlink.display(),
                source.display()
            )
        })
    })
}

fn run_multiple_sources_different_mappings_case(
    case: &'static str,
    use_userns: bool,
) -> TestResult {
    let tmp = test_result!(TempDir::new().context("failed to create tempdir"));
    let source1 = tmp.path().join("multi1");
    let source2 = tmp.path().join("multi2");
    let source3 = tmp.path().join("multi3");
    let userns_offset = if use_userns { USERNS_HOST_ID } else { 0 };
    let mount1 = test_result!(build_idmapped_bind_mount(
        &source1,
        "/tmp/mount-multi1",
        &["bind"],
        (100, userns_offset + 1100, 3),
        (200, userns_offset + 1900, 50),
    ));
    let mount2 = test_result!(build_idmapped_bind_mount(
        &source2,
        "/tmp/mount-multi2",
        &["bind"],
        (200, userns_offset + 2200, 3),
        (200, userns_offset + 2900, 100),
    ));
    let mount3 = test_result!(build_idmapped_bind_mount(
        &source3,
        "/tmp/mount-multi3",
        &["bind"],
        (5000000, userns_offset + 3000, 1000),
        (6000000, userns_offset + 3000, 500),
    ));
    let spec = test_result!(create_idmap_spec(
        vec![mount1, mount2, mount3],
        case,
        use_userns,
        USERNS_HOST_ID
    ));
    run_idmap_case(case, spec, || {
        setup_owned_files(&source1, &[(100, 211), (101, 222), (102, 233)])?;
        setup_owned_files(&source2, &[(200, 211), (201, 222), (202, 233)])?;
        setup_owned_files(
            &source3,
            &[(5000528, 6000491), (5000133, 6000337), (5000999, 6000444)],
        )
    })
}

fn run_complicated_mapping_case(case: &'static str, use_userns: bool) -> TestResult {
    let tmp = test_result!(TempDir::new().context("failed to create tempdir"));
    let source = tmp.path().join("multi1");
    let userns_offset = if use_userns { USERNS_HOST_ID } else { 0 };
    let mount = test_result!(build_idmapped_bind_mount_with_mappings(
        &source,
        "/tmp/mount-multi1",
        &["bind"],
        &[
            (100, userns_offset + 1000, 1),
            (101, userns_offset + 2000, 1),
            (102, userns_offset + 3000, 1),
        ],
        &[
            (210, userns_offset + 1100, 10),
            (220, userns_offset + 2200, 10),
            (230, userns_offset + 3300, 10),
        ],
    ));
    let spec = test_result!(create_idmap_spec(
        vec![mount],
        case,
        use_userns,
        USERNS_HOST_ID
    ));
    run_idmap_case(case, spec, || {
        setup_owned_files(&source, &[(100, 211), (101, 222), (102, 233)])
    })
}

fn run_tree_idmapped_bind_case(
    case: &'static str,
    options: &[&'static str],
    use_userns: bool,
) -> TestResult {
    let tmp = test_result!(TempDir::new().context("failed to create tempdir"));
    let source = tmp.path().join("mount-tree");
    let mount = test_result!(build_tree_idmapped_bind_mount(
        &source,
        "/tmp/mount-tree",
        options,
    ));
    let spec = test_result!(create_idmap_spec(
        vec![mount],
        case,
        use_userns,
        USERNS_HOST_ID
    ));
    let result = run_idmap_case(case, spec, || setup_runc_idmap_tree(&source));
    cleanup_tree(&source);
    result
}

fn run_implied_mapping_tree_case(case: &'static str, option: &'static str) -> TestResult {
    let tmp = test_result!(TempDir::new().context("failed to create tempdir"));
    let source = tmp.path().join("mount-tree");
    let mount = test_result!(build_bind_mount(
        &source,
        "/tmp/mount-tree",
        &["rbind", option],
        None,
        None
    ));
    let spec = test_result!(create_idmap_spec(vec![mount], case, true, USERNS_HOST_ID));
    let result = run_idmap_case(case, spec, || setup_runc_idmap_tree(&source));
    cleanup_tree(&source);
    result
}

pub fn get_idmap_test() -> TestGroup {
    let mut test_group = TestGroup::new("idmap");
    test_group.set_nonparallel();

    test_group.add(vec![
        // runc: simple idmap mount [userns]
        Box::new(Test::new(
            "simple_idmap_mount_userns",
            Box::new(|| run_single_file_idmapped_bind_case("simple_idmap_mount_userns", true)),
        )),
        // runc: simple idmap mount [no userns]
        Box::new(Test::new(
            "simple_idmap_mount_no_userns",
            Box::new(|| run_single_file_idmapped_bind_case("simple_idmap_mount_no_userns", false)),
        )),
        // runc: write to an idmap mount [userns]
        Box::new(Test::new(
            "write_to_an_idmap_mount_userns",
            Box::new(|| run_single_file_idmapped_bind_case("write_to_an_idmap_mount_userns", true)),
        )),
        // runc: write to an idmap mount [no userns]
        Box::new(Test::new(
            "write_to_an_idmap_mount_no_userns",
            Box::new(|| {
                run_single_file_idmapped_bind_case("write_to_an_idmap_mount_no_userns", false)
            }),
        )),
        // runc: idmap mount with propagation flag [userns]
        Box::new(Test::new(
            "idmap_mount_with_propagation_flag_userns",
            Box::new(run_propagation_idmapped_bind_case),
        )),
        // runc: idmap mount with relative path [userns]
        Box::new(Test::new(
            "idmap_mount_with_relative_path_userns",
            Box::new(run_relative_destination_idmapped_bind_case),
        )),
        // runc: idmap mount with bind mount [userns]
        Box::new(Test::new(
            "idmap_mount_with_bind_mount_userns",
            Box::new(|| {
                run_idmapped_and_plain_bind_case("idmap_mount_with_bind_mount_userns", true)
            }),
        )),
        // runc: idmap mount with bind mount [no userns]
        Box::new(Test::new(
            "idmap_mount_with_bind_mount_no_userns",
            Box::new(|| {
                run_idmapped_and_plain_bind_case("idmap_mount_with_bind_mount_no_userns", false)
            }),
        )),
        // runc: two idmap mounts (same mapping) with two bind mounts [userns]
        Box::new(Test::new(
            "two_idmap_mounts_same_mapping_with_two_bind_mounts_userns",
            Box::new(run_two_idmapped_binds_same_mapping_case),
        )),
        // runc: same idmap mount (different mappings) [userns]
        Box::new(Test::new(
            "same_idmap_mount_different_mappings_userns",
            Box::new(|| {
                run_same_source_different_mappings_case(
                    "same_idmap_mount_different_mappings_userns",
                    true,
                )
            }),
        )),
        // runc: same idmap mount (different mappings) [no userns]
        Box::new(Test::new(
            "same_idmap_mount_different_mappings_no_userns",
            Box::new(|| {
                run_same_source_different_mappings_case(
                    "same_idmap_mount_different_mappings_no_userns",
                    false,
                )
            }),
        )),
        // runc: multiple idmap mounts (different mappings) [userns]
        Box::new(Test::new(
            "multiple_idmap_mounts_different_mappings_userns",
            Box::new(|| {
                run_multiple_sources_different_mappings_case(
                    "multiple_idmap_mounts_different_mappings_userns",
                    true,
                )
            }),
        )),
        // runc: multiple idmap mounts (different mappings) [no userns]
        Box::new(Test::new(
            "multiple_idmap_mounts_different_mappings_no_userns",
            Box::new(|| {
                run_multiple_sources_different_mappings_case(
                    "multiple_idmap_mounts_different_mappings_no_userns",
                    false,
                )
            }),
        )),
        // runc: idmap mount (complicated mapping) [userns]
        Box::new(Test::new(
            "idmap_mount_complicated_mapping_userns",
            Box::new(|| {
                run_complicated_mapping_case("idmap_mount_complicated_mapping_userns", true)
            }),
        )),
        // runc: idmap mount (complicated mapping) [no userns]
        Box::new(Test::new(
            "idmap_mount_complicated_mapping_no_userns",
            Box::new(|| {
                run_complicated_mapping_case("idmap_mount_complicated_mapping_no_userns", false)
            }),
        )),
        // runc: idmap mount (non-recursive idmap) [userns]
        Box::new(Test::new(
            "idmap_mount_non_recursive_idmap_userns",
            Box::new(|| {
                run_tree_idmapped_bind_case(
                    "idmap_mount_non_recursive_idmap_userns",
                    &["rbind"],
                    true,
                )
            }),
        )),
        // runc: idmap mount (non-recursive idmap) [no userns]
        Box::new(Test::new(
            "idmap_mount_non_recursive_idmap_no_userns",
            Box::new(|| {
                run_tree_idmapped_bind_case(
                    "idmap_mount_non_recursive_idmap_no_userns",
                    &["rbind"],
                    false,
                )
            }),
        )),
        // runc: idmap mount (idmap flag) [userns]
        Box::new(Test::new(
            "idmap_mount_idmap_flag_userns",
            Box::new(|| {
                run_tree_idmapped_bind_case(
                    "idmap_mount_idmap_flag_userns",
                    &["rbind", "idmap"],
                    true,
                )
            }),
        )),
        // runc: idmap mount (idmap flag) [no userns]
        Box::new(Test::new(
            "idmap_mount_idmap_flag_no_userns",
            Box::new(|| {
                run_tree_idmapped_bind_case(
                    "idmap_mount_idmap_flag_no_userns",
                    &["rbind", "idmap"],
                    false,
                )
            }),
        )),
        // runc: idmap mount (ridmap flag) [userns]
        Box::new(Test::new(
            "idmap_mount_ridmap_flag_userns",
            Box::new(|| {
                run_tree_idmapped_bind_case(
                    "idmap_mount_ridmap_flag_userns",
                    &["rbind", "ridmap"],
                    true,
                )
            }),
        )),
        // runc: idmap mount (ridmap flag) [no userns]
        Box::new(Test::new(
            "idmap_mount_ridmap_flag_no_userns",
            Box::new(|| {
                run_tree_idmapped_bind_case(
                    "idmap_mount_ridmap_flag_no_userns",
                    &["rbind", "ridmap"],
                    false,
                )
            }),
        )),
        // runc: idmap mount (idmap flag, implied mapping) [userns]
        Box::new(Test::new(
            "idmap_mount_idmap_flag_implied_mapping_userns",
            Box::new(|| {
                run_implied_mapping_tree_case(
                    "idmap_mount_idmap_flag_implied_mapping_userns",
                    "idmap",
                )
            }),
        )),
        // runc: idmap mount (ridmap flag, implied mapping) [userns]
        Box::new(Test::new(
            "idmap_mount_ridmap_flag_implied_mapping_userns",
            Box::new(|| {
                run_implied_mapping_tree_case(
                    "idmap_mount_ridmap_flag_implied_mapping_userns",
                    "ridmap",
                )
            }),
        )),
        // runc: idmap mount (idmap flag, implied mapping, userns join) [userns]
        Box::new(Test::new(
            "idmap_mount_idmap_flag_implied_mapping_userns_join_userns",
            Box::new(run_joined_userns_implied_idmap_case),
        )),
    ]);

    test_group
}
