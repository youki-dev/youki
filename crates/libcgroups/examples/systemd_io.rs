use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::Result;
use nix::unistd::Pid;
use libcgroups::common::{CgroupConfig, CgroupManager, ControllerOpt, create_cgroup_manager};
use oci_spec::runtime::{
    LinuxBlockIoBuilder, LinuxMemoryBuilder, LinuxResourcesBuilder, LinuxThrottleDeviceBuilder,
};
fn main() -> Result<()> {
    let cfg = CgroupConfig {
        cgroup_path: PathBuf::from("system.slice:youki:test"),
        systemd_cgroup: true,
        container_name: "test".to_owned(),
    };
    let manager = create_cgroup_manager(cfg)?;
    let mem_limit = 256 * 1024 * 1024;
    let rate: u64 = 1000;
    let memory_resource = LinuxMemoryBuilder::default().limit(mem_limit).build()?;
    let device = LinuxThrottleDeviceBuilder::default()
        .major(259)
        .minor(0)
        .rate(rate)
        .build()?;
    let blkio = LinuxBlockIoBuilder::default()
        .throttle_read_bps_device(vec![device])
        .build()?;
    let resources = LinuxResourcesBuilder::default()
        .memory(memory_resource)
        .block_io(blkio)
        .build()?;
    let opts = ControllerOpt {
        resources: &resources,
        disable_oom_killer: false,
        oom_score_adj: None,
        freezer_state: None,
    };

    let pid = Pid::from_raw(std::process::id() as i32);
    manager.add_task(pid)?;
    manager.apply(&opts)?;

    println!("Cgroup created and properties applied.");
    println!("Launching interactive shell... (type exit to continue)");
    // use 'dd if=/dev/zero of=/tmp/test.bin bs=1M count=1024 oflag=direct' to test the read write speed
    // or check using 'systemctl --show youki-test.scope'
    Command::new("sh")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn shell")
        .wait()
        .expect("Shell process failed");

    println!("Shell exited. Removing cgroup...");

    manager.remove()?;
    Ok(())
}
