use std::fs::File;
use std::os::fd::AsRawFd;

use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressMessage, AddressScope};
use oci_spec::runtime::LinuxNetDevice;

use super::address::AddressClient;
use super::link::LinkClient;
use super::wrapper::create_network_client;
use super::Result;
use crate::network::serialize::SerializableAddress;

/// dev_change_netns allows to move a device given by name to a network namespace given by nsPath
/// and optionally change the device name.
/// The device name will be kept the same if device.Name is None or an empty string.
/// This function ensures that the move and rename operations occur atomically.
/// It preserves existing interface attributes, including IP addresses.
pub fn dev_change_net_namespace(
    name: String,
    netns_path: String,
    device: &LinuxNetDevice,
) -> Result<Vec<SerializableAddress>> {
    tracing::debug!(
        "attaching network device {} to network namespace {}",
        name,
        netns_path
    );

    let mut link_client = LinkClient::new(create_network_client())?;
    let mut addr_client = AddressClient::new(create_network_client())?;

    let netns_file = File::open(netns_path)?;

    let new_name = device
        .name()
        .as_ref()
        .filter(|d| !d.is_empty())
        .map_or(name.clone(), |d| d.to_string());

    let link = link_client.get_by_name(&name)?;

    let index = link.header.index;

    // Set the interface link state to DOWN before modifying attributes like namespace or name.
    // This prevents potential conflicts or disruptions on the host network during the transition,
    // particularly if other host components depend on this specific interface or its properties.
    link_client.set_down(index)?;

    // Get the existing IP addresses on the interface.
    let addrs = addr_client.get_by_index(index)?;

    link_client
        .set_ns_fd(index, &new_name, netns_file.as_raw_fd())
        .map_err(|err| {
            tracing::error!(?err, "failed to set_ns_fd");
            err
        })?;

    let serialize_addrs: Vec<SerializableAddress> =
        addrs.iter().map(SerializableAddress::from).collect();

    Ok(serialize_addrs)
}

pub fn setup_network_device(
    name: String,
    net_dev: &LinuxNetDevice,
    serialize_addrs: Vec<SerializableAddress>,
) -> Result<()> {
    let mut link_client = LinkClient::new(create_network_client())?;
    let mut addr_client = AddressClient::new(create_network_client())?;

    let new_name = net_dev
        .name()
        .as_ref()
        .filter(|d| !d.is_empty())
        .map_or(name.clone(), |d| d.to_string());

    let ns_link = link_client.get_by_name(&new_name)?;
    let ns_index = ns_link.header.index;

    setup_addresses_in_namespace(serialize_addrs, &new_name, ns_index, &mut addr_client)?;

    link_client.set_up(ns_index)?;
    Ok(())
}

/// Core logic for setting up addresses in the new namespace
/// This function is extracted to make it testable without system calls
pub fn setup_addresses_in_namespace(
    addrs: Vec<SerializableAddress>,
    new_name: &str,
    ns_index: u32,
    addr_client: &mut AddressClient,
) -> Result<()> {
    // Re-add the original IP addresses to the interface in the new namespace.
    // The kernel removes IP addresses when an interface is moved between network namespaces.
    for addr in addrs {
        let addr = AddressMessage::from(&addr);
        tracing::debug!(
            "processing address {:?} from network device {}",
            addr.clone(),
            new_name
        );
        let mut ip_opts = None;
        let mut flags_opts = None;
        // Only move IP addresses with global scope because those are not host-specific, auto-configured,
        // or have limited network scope, making them unsuitable inside the container namespace.
        // Ref: https://www.ietf.org/rfc/rfc3549.txt
        if addr.header.scope != AddressScope::Universe {
            tracing::debug!(
                "skipping address {:?} from network device {}",
                addr.clone(),
                new_name
            );
            continue;
        }
        for attr in &addr.attributes {
            match attr {
                AddressAttribute::Flags(flags) => flags_opts = Some(*flags),
                AddressAttribute::Address(ip) => ip_opts = Some(*ip),
                _ => {}
            }
        }

        // Only move permanent IP addresses configured by the user, dynamic addresses are excluded because
        // their validity may rely on the original network namespace's context and they may have limited
        // lifetimes and are not guaranteed to be available in a new namespace.
        // Ref: https://www.ietf.org/rfc/rfc3549.txt
        if let Some(flag) = flags_opts {
            if !flag.contains(AddressFlags::Permanent) {
                tracing::debug!(
                    "skipping address {:?} from network device {}",
                    addr.clone(),
                    new_name
                );
                continue;
            }
        }
        if let Some(ip) = ip_opts {
            // Remove the interface attribute of the original address
            // to avoid issues when the interface is renamed.
            addr_client.add(ns_index, ip, addr.header.prefix_len)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use netlink_packet_route::address::AddressMessage;
    use netlink_packet_route::RouteNetlinkMessage;

    use super::*;
    use crate::network::address::AddressClient;
    use crate::network::fake::FakeNetlinkClient;
    use crate::network::wrapper::ClientWrapper;

    #[test]
    fn test_setup_addresses_in_namespace() {
        let mut fake_client = FakeNetlinkClient::new();

        let mut addr_msg = AddressMessage::default();
        addr_msg.header.scope = AddressScope::Universe;
        addr_msg.header.prefix_len = 24;
        addr_msg
            .attributes
            .push(AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 1,
            ))));
        addr_msg
            .attributes
            .push(AddressAttribute::Flags(AddressFlags::Permanent));

        let responses = vec![RouteNetlinkMessage::NewAddress(addr_msg.clone())];
        fake_client.set_expected_responses(responses);

        let mut addr_client = AddressClient::new(ClientWrapper::Fake(fake_client)).unwrap();

        let addrs = [addr_msg];
        let serializable_addrs: Vec<SerializableAddress> =
            addrs.iter().map(SerializableAddress::from).collect();
        let result = setup_addresses_in_namespace(serializable_addrs, "eth1", 1, &mut addr_client);
        assert!(result.is_ok());

        // Verify the call was tracked
        if let Some(send_calls) = addr_client.get_send_calls() {
            assert_eq!(send_calls.len(), 1);
        } else {
            panic!("Expected Fake client");
        }
    }

    #[test]
    fn test_setup_addresses_in_namespace_skip_non_universe_scope() {
        let fake_client = FakeNetlinkClient::new();

        let mut addr_msg = AddressMessage::default();
        addr_msg.header.scope = AddressScope::Host; // Non-universe scope
        addr_msg.header.prefix_len = 24;
        addr_msg
            .attributes
            .push(AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 1,
            ))));

        let mut addr_client = AddressClient::new(ClientWrapper::Fake(fake_client)).unwrap();

        let addrs = [addr_msg];
        let serializable_addrs: Vec<SerializableAddress> =
            addrs.iter().map(SerializableAddress::from).collect();
        let result = setup_addresses_in_namespace(serializable_addrs, "eth1", 1, &mut addr_client);
        assert!(result.is_ok());

        // Verify the call was tracked
        if let Some(send_calls) = addr_client.get_send_calls() {
            assert_eq!(send_calls.len(), 0);
        } else {
            panic!("Expected Fake client");
        }
    }

    #[test]
    fn test_setup_addresses_in_namespace_skip_non_permanent() {
        let mut fake_client = FakeNetlinkClient::new();

        let mut addr_msg = AddressMessage::default();
        addr_msg.header.scope = AddressScope::Universe;
        addr_msg.header.prefix_len = 24;
        addr_msg
            .attributes
            .push(AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 1,
            ))));
        addr_msg
            .attributes
            .push(AddressAttribute::Flags(AddressFlags::empty())); // Non-permanent

        let responses = vec![RouteNetlinkMessage::NewAddress(addr_msg.clone())];
        fake_client.set_expected_responses(responses);

        let mut addr_client = AddressClient::new(ClientWrapper::Fake(fake_client)).unwrap();

        let addrs = [addr_msg];
        let serializable_addrs: Vec<SerializableAddress> =
            addrs.iter().map(SerializableAddress::from).collect();
        let result = setup_addresses_in_namespace(serializable_addrs, "eth1", 1, &mut addr_client);
        assert!(result.is_ok());

        // Verify the call was tracked
        if let Some(send_calls) = addr_client.get_send_calls() {
            assert_eq!(send_calls.len(), 0);
        } else {
            panic!("Expected Fake client");
        }
    }
}
