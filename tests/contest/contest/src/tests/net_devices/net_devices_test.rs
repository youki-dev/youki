use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, anyhow};
use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, LinuxNetDevice, LinuxNetDeviceBuilder,
    ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_utils::{
    CreateOptions, check_container_created, exec_container, start_container,
};
use crate::utils::{test_inside_container, test_outside_container};

fn create_unique_name(prefix: &str) -> String {
    let random_part: u16 = rand::random();
    format!("{}{}", prefix, random_part)
}

fn create_netns(name: &str) -> Result<()> {
    // Ensure /run/netns mount propagation is shared before creating netns
    // This is needed in case previous tests changed mount propagation to private
    let _ = std::process::Command::new("mount")
        .args(vec!["--make-shared", "/"])
        .output();

    let output = std::process::Command::new("ip")
        .args(vec!["netns", "add", name])
        .output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "Failed to create netns: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

fn cleanup_netns(name: &str) -> Result<()> {
    // Ensure /run/netns mount propagation is shared before deleting netns
    // This is needed in case previous tests changed mount propagation to private
    let _ = std::process::Command::new("mount")
        .args(vec!["--make-shared", "/"])
        .output();

    let output = std::process::Command::new("ip")
        .args(vec!["netns", "del", name])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "Failed to cleanup netns: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn create_dummy_device(name: &str) -> Result<()> {
    let output = std::process::Command::new("ip")
        .args(vec!["link", "add", name, "type", "dummy"])
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "Failed to create dummy device: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn delete_dummy_device(name: &str) -> Result<()> {
    let output = std::process::Command::new("ip")
        .args(vec!["link", "del", name])
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "Failed to delete dummy device: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// RAII guard for dummy network devices that automatically cleans up on drop
struct DummyDevice {
    name: String,
}

impl DummyDevice {
    fn create(name: String) -> Result<Self> {
        create_dummy_device(&name)?;
        Ok(Self { name })
    }
}

impl Drop for DummyDevice {
    fn drop(&mut self) {
        let _ = delete_dummy_device(&self.name);
    }
}

/// RAII guard for network namespaces that automatically cleans up on drop
struct NetNamespace {
    name: String,
}

impl NetNamespace {
    fn create(name: String) -> Result<Self> {
        create_netns(&name)?;
        Ok(Self { name })
    }
}

impl Drop for NetNamespace {
    fn drop(&mut self) {
        let _ = cleanup_netns(&self.name);
    }
}

fn check_device_exists(name: &str) -> Result<bool> {
    let out = std::process::Command::new("ip")
        .args(vec!["link", "show", name])
        .output()?;
    Ok(out.status.success())
}

fn create_spec(net_devices: HashMap<String, LinuxNetDevice>) -> Spec {
    SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .net_devices(net_devices)
                .build()
                .unwrap(),
        )
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "net_devices".to_string()])
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

fn create_spec_without_runtimetest(net_devices: HashMap<String, LinuxNetDevice>) -> Spec {
    SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .net_devices(net_devices)
                .build()
                .unwrap(),
        )
        .process(
            ProcessBuilder::default()
                .args(vec!["sleep".to_string(), "infinity".to_string()])
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

fn create_spec_with_netns(net_devices: HashMap<String, LinuxNetDevice>, netns: String) -> Spec {
    let mut spec = SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .net_devices(net_devices)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Get default namespaces and retain all except network
    let mut namespaces = spec
        .linux()
        .as_ref()
        .and_then(|l| l.namespaces().as_ref())
        .cloned()
        .unwrap_or_default();

    // Remove existing network namespace if any
    namespaces.retain(|ns| ns.typ() != LinuxNamespaceType::Network);

    // Add network namespace with custom path
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Network)
            .path(netns)
            .build()
            .unwrap(),
    );

    // Update spec with modified namespaces
    if let Some(linux) = spec.linux_mut() {
        linux.set_namespaces(Some(namespaces));
    }

    spec
}

fn check_net_device() -> TestResult {
    let device_name = create_unique_name("dummy");

    if let Err(e) = create_dummy_device(&device_name) {
        return TestResult::Failed(anyhow!("Failed to create dummy device: {}", e));
    }

    let mut net_devices = HashMap::new();
    net_devices.insert(device_name.clone(), LinuxNetDevice::default());
    let spec = create_spec(net_devices);
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()));

    match check_device_exists(&device_name) {
        Ok(true) => {
            if let Err(e) = delete_dummy_device(&device_name) {
                return TestResult::Failed(anyhow!("Failed to delete device: {}", e));
            }
            TestResult::Failed(anyhow!("The device still exists after test"))
        }
        Ok(false) => TestResult::Passed,
        Err(e) => {
            if let Err(e) = delete_dummy_device(&device_name) {
                return TestResult::Failed(anyhow!("Failed to delete device: {}", e));
            }
            TestResult::Failed(anyhow!("Failed to check device: {}", e))
        }
    }
}

fn check_net_device_rename() -> TestResult {
    let device_name = create_unique_name("rename");
    let device_name_rename = create_unique_name("renamed");

    if let Err(e) = create_dummy_device(&device_name) {
        return TestResult::Failed(anyhow!("Failed to create dummy device: {}", e));
    }

    let mut net_devices = HashMap::new();
    net_devices.insert(
        device_name.clone(),
        LinuxNetDeviceBuilder::default()
            .name(&device_name_rename)
            .build()
            .unwrap(),
    );
    let spec = create_spec(net_devices);
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()));

    match check_device_exists(&device_name) {
        Ok(true) => {
            if let Err(e) = delete_dummy_device(&device_name) {
                return TestResult::Failed(anyhow!("Failed to delete device: {}", e));
            }
            TestResult::Failed(anyhow!("The device still exists after test"))
        }
        Ok(false) => TestResult::Passed,
        Err(e) => {
            if let Err(e) = delete_dummy_device(&device_name) {
                return TestResult::Failed(anyhow!("Failed to delete device: {}", e));
            }
            TestResult::Failed(anyhow!("Failed to check device: {}", e))
        }
    }
}

fn check_net_devices() -> TestResult {
    let device_name1 = create_unique_name("dummy");
    let device_name2 = create_unique_name("dummy");

    let _device1 = match DummyDevice::create(device_name1.clone()) {
        Ok(dev) => dev,
        Err(e) => return TestResult::Failed(anyhow!("Failed to create dummy device: {}", e)),
    };

    let _device2 = match DummyDevice::create(device_name2.clone()) {
        Ok(dev) => dev,
        Err(e) => return TestResult::Failed(anyhow!("Failed to create dummy device: {}", e)),
    };

    let mut net_devices = HashMap::new();
    net_devices.insert(device_name1.clone(), LinuxNetDevice::default());
    net_devices.insert(device_name2.clone(), LinuxNetDevice::default());
    let spec = create_spec(net_devices);
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()));

    let mut result = TestResult::Passed;

    match check_device_exists(&device_name1) {
        Ok(true) => {
            result = TestResult::Failed(anyhow!("The device1 still exists after test"));
        }
        Ok(false) => {}
        Err(e) => {
            result = TestResult::Failed(anyhow!("Failed to check device1: {}", e));
        }
    }

    match check_device_exists(&device_name2) {
        Ok(true) => {
            if let TestResult::Passed = result {
                result = TestResult::Failed(anyhow!("The device2 still exists after test"));
            }
        }
        Ok(false) => {}
        Err(e) => {
            if let TestResult::Passed = result {
                result = TestResult::Failed(anyhow!("Failed to check device2: {}", e));
            }
        }
    }

    // Devices will be automatically cleaned up when _device1 and _device2 go out of scope

    result
}

fn check_empty_net_devices() -> TestResult {
    let device_name = create_unique_name("empty");

    let mut net_devices = HashMap::new();
    net_devices.insert(device_name.clone(), LinuxNetDevice::default());
    let spec = create_spec(net_devices);
    let result = test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()));

    // If the container creation succeeds, we expect an error since the masked paths does not support symlinks.
    if let TestResult::Passed = result {
        TestResult::Failed(anyhow!(
            "expected error in container creation with invalid net device, found no error"
        ))
    } else {
        TestResult::Passed
    }
}

fn check_back_device() -> TestResult {
    let netns_name = create_unique_name("back");
    let device_name = create_unique_name("back");

    let mut net_devices = HashMap::new();
    net_devices.insert(
        device_name.clone(),
        LinuxNetDeviceBuilder::default()
            .name(&device_name)
            .build()
            .unwrap(),
    );

    let _netns = match NetNamespace::create(netns_name.clone()) {
        Ok(ns) => ns,
        Err(e) => return TestResult::Failed(anyhow!("Failed to create netns: {}", e)),
    };

    let _device = match DummyDevice::create(device_name.clone()) {
        Ok(dev) => dev,
        Err(e) => return TestResult::Failed(anyhow!("Failed to create dummy device: {}", e)),
    };

    let spec = create_spec_with_netns(
        net_devices,
        Path::new("/run/netns")
            .join(&netns_name)
            .to_str()
            .unwrap()
            .to_string(),
    );
    let test_result = test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        TestResult::Passed
    });
    if let TestResult::Failed(_) = test_result {
        return test_result;
    }

    // Move the device back to the original namespace
    let move_result = std::process::Command::new("ip")
        .args(vec![
            "netns",
            "exec",
            &netns_name,
            "ip",
            "link",
            "set",
            "dev",
            &device_name,
            "netns",
            "1",
        ])
        .output();

    if let Err(e) = move_result {
        // Try to delete the device from the namespace before cleaning up
        let _ = std::process::Command::new("ip")
            .args(vec![
                "netns",
                "exec",
                &netns_name,
                "ip",
                "link",
                "del",
                &device_name,
            ])
            .output();
        return TestResult::Failed(anyhow!("Failed to move device back: {}", e));
    }

    // Check that the device exists
    if let Err(e) = check_device_exists(&device_name) {
        return TestResult::Failed(anyhow!("Failed to check device: {}", e));
    }

    // Cleanup will happen automatically when _device and _netns go out of scope

    TestResult::Passed
}

fn check_address() -> TestResult {
    let device_name = create_unique_name("addr");
    const DUMMY_ADDRESS: &str = "244.178.44.111/24";

    let mut net_devices = HashMap::new();
    net_devices.insert(
        device_name.clone(),
        LinuxNetDeviceBuilder::default()
            .name(&device_name)
            .build()
            .unwrap(),
    );

    if let Err(e) = create_dummy_device(&device_name) {
        return TestResult::Failed(anyhow!("Failed to create dummy device: {}", e));
    }

    // Add address to the device
    if let Err(e) = std::process::Command::new("ip")
        .args(vec!["addr", "add", DUMMY_ADDRESS, "dev", &device_name])
        .output()
    {
        return TestResult::Failed(anyhow!("Failed to add address: {}", e));
    }

    let spec = create_spec_without_runtimetest(net_devices);
    let test_result = test_outside_container(&spec, &|data| {
        let id = &data.id;
        let dir = &data.bundle;

        let start_result = start_container(id, dir).unwrap().wait().unwrap();
        if !start_result.success() {
            return TestResult::Failed(anyhow!("container start failed"));
        }

        let (stdout, _) = exec_container(id, dir, &["ip", "addr"], None).expect("exec failed");

        if !stdout.contains(&device_name) || !stdout.contains(DUMMY_ADDRESS) {
            return TestResult::Failed(anyhow!("unexpected : {}", stdout));
        }

        TestResult::Passed
    });
    if let TestResult::Failed(_) = test_result {
        return test_result;
    }

    TestResult::Passed
}

pub fn get_net_devices_test() -> TestGroup {
    let mut test_group = TestGroup::new("net_devices");
    test_group.set_nonparallel();
    let net_device_test = Test::new("net_device", Box::new(check_net_device));
    let net_device_rename_test = Test::new("net_device_rename", Box::new(check_net_device_rename));
    let net_devices_test = Test::new("net_devices", Box::new(check_net_devices));
    let empty_net_devices_test = Test::new("empty_net_devices", Box::new(check_empty_net_devices));
    let back_device_test = Test::new("back_device", Box::new(check_back_device));
    let address_test = Test::new("address", Box::new(check_address));
    test_group.add(vec![
        Box::new(net_device_test),
        Box::new(net_device_rename_test),
        Box::new(net_devices_test),
        Box::new(empty_net_devices_test),
        Box::new(back_device_test),
        Box::new(address_test),
    ]);

    test_group
}
