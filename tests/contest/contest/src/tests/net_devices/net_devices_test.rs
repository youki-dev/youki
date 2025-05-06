use std::collections::HashMap;
use std::path::Path;

use anyhow::anyhow;
use futures::stream::TryStreamExt;
use ipnetwork::IpNetwork;
use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, LinuxNetDevice, LinuxNetDeviceBuilder,
    ProcessBuilder, Spec, SpecBuilder,
};
use rtnetlink::{new_connection, LinkDummy, NetworkNamespace};
use test_framework::{test_result, Test, TestGroup, TestResult};
use tokio::runtime::Runtime;

use crate::utils::test_utils::{check_container_created, CreateOptions};
use crate::utils::{test_inside_container, test_outside_container};

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
                .namespaces(vec![LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Network)
                    .path(netns)
                    .build()
                    .unwrap()])
                .net_devices(net_devices)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

fn check_net_device() -> TestResult {
    const DUMMY_DEVICE: &str = "dummy";
    let mut net_devices = HashMap::new();
    net_devices.insert(DUMMY_DEVICE.to_string(), LinuxNetDevice::default());
    let spec = create_spec(net_devices);
    test_inside_container(&spec, &CreateOptions::default(), &|_| {
        let rt = Runtime::new().unwrap();

        let res = rt.block_on(async {
            let (connection, handle, _) = new_connection().unwrap();
            tokio::spawn(connection);

            handle
                .link()
                .add(LinkDummy::new(DUMMY_DEVICE).build())
                .execute()
                .await
        });

        assert!(res.is_ok());

        Ok(())
    })
}

fn check_net_device_rename() -> TestResult {
    const DUMMY_DEVICE: &str = "dummy-rename";
    const DUMMY_DEVICE_RENAMED: &str = "dummy1-renamed";
    let mut net_devices = HashMap::new();
    net_devices.insert(
        DUMMY_DEVICE.to_string(),
        LinuxNetDeviceBuilder::default()
            .name(DUMMY_DEVICE_RENAMED)
            .build()
            .unwrap(),
    );
    let spec = create_spec(net_devices);
    test_inside_container(&spec, &CreateOptions::default(), &|_| {
        let rt = Runtime::new().unwrap();

        let res = rt.block_on(async {
            let (connection, handle, _) = new_connection().unwrap();
            tokio::spawn(connection);

            handle
                .link()
                .add(LinkDummy::new(DUMMY_DEVICE).build())
                .execute()
                .await
        });

        assert!(res.is_ok());

        Ok(())
    })
}

fn check_net_devices() -> TestResult {
    const DUMMY_DEVICE1: &str = "dummy1";
    const DUMMY_DEVICE2: &str = "dummy2";
    let mut net_devices = HashMap::new();
    net_devices.insert(DUMMY_DEVICE1.to_string(), LinuxNetDevice::default());
    net_devices.insert(DUMMY_DEVICE2.to_string(), LinuxNetDevice::default());
    let spec = create_spec(net_devices);
    test_inside_container(&spec, &CreateOptions::default(), &|_| {
        let rt = Runtime::new().unwrap();

        let res = rt.block_on(async {
            let (connection, handle, _) = new_connection().unwrap();
            tokio::spawn(connection);

            handle
                .link()
                .add(LinkDummy::new(DUMMY_DEVICE1).build())
                .execute()
                .await?;

            handle
                .link()
                .add(LinkDummy::new(DUMMY_DEVICE2).build())
                .execute()
                .await
        });

        assert!(res.is_ok());

        Ok(())
    })
}

fn check_empty_net_devices() -> TestResult {
    const DUMMY_DEVICE: &str = "dummy-empty";
    let mut net_devices = HashMap::new();
    net_devices.insert(DUMMY_DEVICE.to_string(), LinuxNetDevice::default());
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
    const NETNS_NAME: &str = "netns-back";
    const DUMMY_DEVICE: &str = "dummy-back";

    let mut net_devices = HashMap::new();
    net_devices.insert(
        DUMMY_DEVICE.to_string(),
        LinuxNetDeviceBuilder::default()
            .name(DUMMY_DEVICE.to_string())
            .build()
            .unwrap(),
    );

    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);

        NetworkNamespace::add(NETNS_NAME.to_string()).await.unwrap();

        handle
            .link()
            .add(LinkDummy::new(DUMMY_DEVICE).build())
            .execute()
            .await
    })
    .unwrap();

    let spec = create_spec_with_netns(
        net_devices,
        Path::new("/var/run/netns")
            .join(NETNS_NAME)
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
    std::process::Command::new("ip")
        .args(vec![
            "netns",
            "exec",
            NETNS_NAME,
            "ip",
            "link",
            "set",
            "dev",
            DUMMY_DEVICE,
            "netns",
            "1",
        ])
        .output()
        .unwrap();

    rt.block_on(async {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);

        let mut links = handle
            .link()
            .get()
            .match_name(DUMMY_DEVICE.to_string())
            .execute();

        let link = match links.try_next().await {
            Ok(link) => link.unwrap(),
            Err(err) => panic!("error while retrieving link: {}", err),
        };

        // clean up
        handle
            .link()
            .del(link.header.index)
            .execute()
            .await
            .unwrap_or_else(|_| panic!("Failed to delete link"));

        NetworkNamespace::del(NETNS_NAME.to_string()).await.unwrap();
    });

    TestResult::Passed
}

fn check_address() -> TestResult {
    const NETNS_NAME: &str = "netns-address";
    const DUMMY_DEVICE: &str = "dummy-address";
    const DUMMY_ADDRESS: &str = "244.178.44.111/24";
    let mut net_devices = HashMap::new();
    net_devices.insert(
        DUMMY_DEVICE.to_string(),
        LinuxNetDeviceBuilder::default()
            .name(DUMMY_DEVICE.to_string())
            .build()
            .unwrap(),
    );
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);

        NetworkNamespace::add(NETNS_NAME.to_string()).await.unwrap();

        handle
            .link()
            .add(LinkDummy::new(DUMMY_DEVICE).build())
            .execute()
            .await?;

        let mut links = handle
            .link()
            .get()
            .match_name(DUMMY_DEVICE.to_string())
            .execute();

        let link = links.try_next().await?.unwrap();
        let ip: IpNetwork = DUMMY_ADDRESS.parse().unwrap();
        handle
            .address()
            .add(link.header.index, ip.ip(), ip.prefix())
            .execute()
            .await
    })
    .unwrap();

    let spec = create_spec_with_netns(
        net_devices,
        Path::new("/var/run/netns")
            .join(NETNS_NAME)
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
    let out = std::process::Command::new("ip")
        .args(vec!["netns", "exec", NETNS_NAME, "ip", "addr"])
        .output()
        .unwrap();
    let out = String::from_utf8(out.stdout).unwrap();
    assert!(out.contains(DUMMY_DEVICE));
    assert!(out.contains(DUMMY_ADDRESS));

    rt.block_on(async {
        let (connection, _, _) = new_connection().unwrap();
        tokio::spawn(connection);

        NetworkNamespace::del(NETNS_NAME.to_string()).await.unwrap();
    });

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
