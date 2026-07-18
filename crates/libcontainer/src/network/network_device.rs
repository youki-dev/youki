use std::os::fd::RawFd;

use netlink_packet_route::address::{AddressHeaderFlags, AddressScope};
use oci_spec::runtime::LinuxNetDevice;

use super::Result;
use super::address::AddressClient;
use super::link::LinkClient;
use super::wrapper::create_network_client;
use crate::network::cidr::CidrAddress;

/// Resolves the final name for a network device.
/// If the device has a configured name (non-empty), use it; otherwise use the original name.
pub fn resolve_device_name<'a>(device: &'a LinuxNetDevice, original_name: &'a str) -> &'a str {
    device
        .name()
        .as_ref()
        .filter(|d| !d.is_empty())
        .map_or(original_name, |d| d)
}

/// dev_change_netns allows to move a device given by name to a network namespace given by netns_fd
/// and optionally change the device name.
/// The device name will be kept the same if device.Name is None or an empty string.
/// This function ensures that the move and rename operations occur atomically.
/// It preserves existing interface attributes, including IP addresses.
pub fn dev_change_net_namespace(
    name: &str,
    netns_fd: RawFd,
    device: &LinuxNetDevice,
) -> Result<Vec<CidrAddress>> {
    tracing::debug!(
        "attaching network device {} to network namespace fd {}",
        name,
        netns_fd
    );

    let mut link_client = LinkClient::new(create_network_client())?;
    let mut addr_client = AddressClient::new(create_network_client())?;

    let new_name = resolve_device_name(device, name);

    let link = link_client.get_by_name(name)?;

    let index = link.header.index;

    // Set the interface link state to DOWN before modifying attributes like namespace or name.
    // This prevents potential conflicts or disruptions on the host network during the transition,
    // particularly if other host components depend on this specific interface or its properties.
    link_client.set_down(index)?;

    // Get the existing IP addresses on the interface.
    let addrs = addr_client.get_by_index(index)?;

    link_client
        .set_ns_fd(index, new_name, netns_fd)
        .map_err(|err| {
            tracing::error!(?err, "failed to set_ns_fd");
            err
        })?;

    // Filter addresses before sending to init process:
    // Only include IP addresses with global scope and permanent flag.
    let cidr_addrs: Vec<CidrAddress> = addrs
        .iter()
        .filter(|addr| {
            // Only move IP addresses with global scope because those are not host-specific, auto-configured,
            // or have limited network scope, making them unsuitable inside the container namespace.
            // Ref: https://www.ietf.org/rfc/rfc3549.txt
            if addr.header.scope != AddressScope::Universe {
                tracing::debug!(
                    "skipping address with scope {:?} from network device {}",
                    addr.header.scope,
                    new_name
                );
                return false;
            }

            // Only move permanent IP addresses configured by the user, dynamic addresses are excluded because
            // their validity may rely on the original network namespace's context and they may have limited
            // lifetimes and are not guaranteed to be available in a new namespace.
            // Ref: https://www.ietf.org/rfc/rfc3549.txt
            if !addr.header.flags.contains(AddressHeaderFlags::Permanent) {
                tracing::debug!(
                    "skipping non-permanent address from network device {}",
                    new_name
                );
                return false;
            }

            true
        })
        .map(CidrAddress::from)
        .collect();

    Ok(cidr_addrs)
}

/// Core logic for setting up addresses in the new network namespace
/// This function is extracted to make it testable without system calls
///
/// Note: The addresses passed to this function are already filtered in the main process
/// to include only global scope and permanent addresses.
pub fn setup_addresses_in_network_namespace(
    addrs: &[CidrAddress],
    link_index: u32,
    new_name: &str,
    addr_client: &mut AddressClient,
) -> Result<()> {
    // Re-add the original IP addresses to the interface in the new namespace.
    // The kernel removes IP addresses when an interface is moved between network namespaces.
    for addr in addrs {
        tracing::debug!(
            "adding address {:?}/{} to network device {}",
            addr.address,
            addr.prefix_len,
            new_name
        );
        addr_client.add(link_index, addr.address, addr.prefix_len)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use netlink_packet_route::RouteNetlinkMessage;
    use netlink_packet_route::address::{AddressAttribute, AddressMessage};

    use super::*;
    use crate::network::address::AddressClient;
    use crate::network::fake::FakeNetlinkClient;
    use crate::network::wrapper::ClientWrapper;

    #[test]
    fn test_setup_addresses_in_network_namespace() {
        let mut fake_client = FakeNetlinkClient::new();

        let mut addr_msg = AddressMessage::default();
        addr_msg.header.scope = AddressScope::Universe;
        addr_msg.header.prefix_len = 24;
        addr_msg.header.flags = AddressHeaderFlags::Permanent;
        addr_msg
            .attributes
            .push(AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 1,
            ))));

        let responses = vec![RouteNetlinkMessage::NewAddress(addr_msg.clone())];
        fake_client.set_expected_responses(responses);

        let mut addr_client = AddressClient::new(ClientWrapper::Fake(fake_client)).unwrap();

        let addrs = [addr_msg];
        let serializable_addrs: Vec<CidrAddress> = addrs.iter().map(CidrAddress::from).collect();
        let result =
            setup_addresses_in_network_namespace(&serializable_addrs, 5, "eth1", &mut addr_client);
        assert!(result.is_ok());

        // Verify the call was tracked
        if let Some(send_calls) = addr_client.get_send_calls() {
            assert_eq!(send_calls.len(), 1);
        } else {
            panic!("Expected Fake client");
        }
    }

    #[test]
    fn test_resolve_device_name_with_name() {
        let device = LinuxNetDevice::default()
            .set_name(Some("eth0".to_string()))
            .clone();
        let original = "veth0";

        let result = resolve_device_name(&device, original);
        assert_eq!(result, "eth0");
    }

    #[test]
    fn test_resolve_device_name_with_empty_name() {
        let device = LinuxNetDevice::default()
            .set_name(Some("".to_string()))
            .clone();
        let original = "veth0";

        let result = resolve_device_name(&device, original);
        assert_eq!(result, "veth0");
    }

    #[test]
    fn test_resolve_device_name_without_name() {
        let device = LinuxNetDevice::default();
        let original = "veth0";

        let result = resolve_device_name(&device, original);
        assert_eq!(result, "veth0");
    }
}
