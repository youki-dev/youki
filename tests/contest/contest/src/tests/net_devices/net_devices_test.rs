use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Result, anyhow};
use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, LinuxNetDevice, LinuxNetDeviceBuilder,
    ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_utils::{CreateOptions, check_container_created};
use crate::utils::{test_inside_container, test_outside_container};

static NETNS_COUNTER: AtomicUsize = AtomicUsize::new(0);
static DEVICE_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn create_unique_netns_name(prefix: &str) -> String {
    let count = NETNS_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{}-{}", prefix, count)
}

pub fn create_unique_device_name(prefix: &str) -> String {
    let count = DEVICE_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{}-{}", prefix, count)
}

fn create_netns(name: &str) -> Result<()> {
    std::process::Command::new("ip")
        .args(vec!["netns", "add", name])
        .output()?;
    Ok(())
}

fn cleanup_netns(name: &str) -> Result<()> {
    std::process::Command::new("ip")
        .args(vec!["netns", "del", name])
        .output()?;
    Ok(())
}

fn create_dummy_device(name: &str) -> Result<()> {
    std::process::Command::new("ip")
        .args(vec!["link", "add", name, "type", "dummy"])
        .output()?;
    Ok(())
}

fn delete_dummy_device(name: &str) -> Result<()> {
    std::process::Command::new("ip")
        .args(vec!["link", "del", name])
        .output()?;
    Ok(())
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

fn create_spec_with_netns(net_devices: HashMap<String, LinuxNetDevice>, netns: String) -> Spec {
    SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .namespaces(vec![
                    LinuxNamespaceBuilder::default()
                        .typ(LinuxNamespaceType::Network)
                        .path(netns)
                        .build()
                        .unwrap(),
                ])
                .net_devices(net_devices)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

fn check_net_device() -> TestResult {
    let device_name = create_unique_device_name("dummy");

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
    let device_name = create_unique_device_name("dummy-rename");
    let device_name_rename = create_unique_device_name("dummy-renamed");

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
    let device_name1 = create_unique_device_name("dummy1");
    let device_name2 = create_unique_device_name("dummy2");

    if let Err(e) = create_dummy_device(&device_name1) {
        return TestResult::Failed(anyhow!("Failed to create dummy device: {}", e));
    }

    if let Err(e) = create_dummy_device(&device_name2) {
        return TestResult::Failed(anyhow!("Failed to create dummy device: {}", e));
    }

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

    // cleanup both devices regardless of test result
    let _ = delete_dummy_device(&device_name1);
    let _ = delete_dummy_device(&device_name2);

    result
}

fn check_empty_net_devices() -> TestResult {
    let device_name = create_unique_device_name("dummy-empty");

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
    let netns_name = create_unique_netns_name("netns-back");
    let device_name = create_unique_device_name("dummy-back");

    let mut net_devices = HashMap::new();
    net_devices.insert(
        device_name.clone(),
        LinuxNetDeviceBuilder::default()
            .name(&device_name)
            .build()
            .unwrap(),
    );

    if let Err(e) = create_netns(&netns_name) {
        return TestResult::Failed(anyhow!("Failed to create netns: {}", e));
    }

    if let Err(e) = create_dummy_device(&device_name) {
        return TestResult::Failed(anyhow!("Failed to create dummy device: {}", e));
    }

    let spec = create_spec_with_netns(
        net_devices,
        Path::new("/var/run/netns")
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
    if let Err(e) = std::process::Command::new("ip")
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
        .output()
    {
        return TestResult::Failed(anyhow!("Failed to move device back: {}", e));
    }

    // Check that the device exists
    if let Err(e) = check_device_exists(&device_name) {
        return TestResult::Failed(anyhow!("Failed to check device: {}", e));
    }

    if let Err(e) = delete_dummy_device(&device_name) {
        return TestResult::Failed(anyhow!("Failed to delete device: {}", e));
    }

    if let Err(e) = cleanup_netns(&netns_name) {
        return TestResult::Failed(anyhow!("Failed to cleanup netns: {}", e));
    }

    TestResult::Passed
}

fn check_address() -> TestResult {
    let netns_name = create_unique_netns_name("netns-address");
    let device_name = create_unique_device_name("dummy-address");
    const DUMMY_ADDRESS: &str = "244.178.44.111/24";

    let mut net_devices = HashMap::new();
    net_devices.insert(
        device_name.clone(),
        LinuxNetDeviceBuilder::default()
            .name(&device_name)
            .build()
            .unwrap(),
    );

    if let Err(e) = create_netns(&netns_name) {
        return TestResult::Failed(anyhow!("Failed to create netns: {}", e));
    }

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

    let spec = create_spec_with_netns(
        net_devices,
        Path::new("/var/run/netns")
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

    // Check that the address was added
    let out = match std::process::Command::new("ip")
        .args(vec!["netns", "exec", &netns_name, "ip", "addr"])
        .output()
    {
        Ok(out) => out,
        Err(e) => return TestResult::Failed(anyhow!("Failed to check address: {}", e)),
    };
    let out = match String::from_utf8(out.stdout) {
        Ok(out) => out,
        Err(e) => return TestResult::Failed(anyhow!("Failed to parse output: {}", e)),
    };
    if !out.contains(&device_name) || !out.contains(DUMMY_ADDRESS) {
        return TestResult::Failed(anyhow!("Address not found in output"));
    }

    if let Err(e) = cleanup_netns(&netns_name) {
        return TestResult::Failed(anyhow!("Failed to cleanup netns: {}", e));
    }

    TestResult::Passed
}

pub fn get_net_devices_test() -> TestGroup {
    let mut test_group = TestGroup::new("net_devices");
    let net_device_test = Test::new("net_device", Box::new(check_net_device));
    let net_device_rename_test = Test::new("net_device_rename", Box::new(check_net_device_rename));
    let net_devices_test = Test::new("net_devices", Box::new(check_net_devices));
    let empty_net_devices_test = Test::new("empty_net_devices", Box::new(check_empty_net_devices));
    let back_device_test = Test::new("back_device", Box::new(check_back_device));
    let address_test = Test::new("address", Box::new(check_address));
    test_group.add(vec![Box::new(net_device_test)]);
    test_group.add(vec![Box::new(net_device_rename_test)]);
    test_group.add(vec![Box::new(net_devices_test)]);
    test_group.add(vec![Box::new(empty_net_devices_test)]);
    test_group.add(vec![Box::new(back_device_test)]);
    test_group.add(vec![Box::new(address_test)]);

    test_group
}
