use std::net::IpAddr;

use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidrAddress {
    pub prefix_len: u8,
    pub address: IpAddr,
}

impl From<&AddressMessage> for CidrAddress {
    fn from(msg: &AddressMessage) -> Self {
        let address =
            parse_ip_address(msg).expect("AddressMessage without IFA_LOCAL or IFA_ADDRESS");
        CidrAddress {
            prefix_len: msg.header.prefix_len,
            address,
        }
    }
}

/// Parses the IP address from an AddressMessage following libnl conventions.
///
/// From libnl addr.c:
/// - IPv6 sends the local address as IFA_ADDRESS with no IFA_LOCAL
/// - IPv4 sends both IFA_LOCAL and IFA_ADDRESS, with IFA_ADDRESS being the peer address if they differ
/// - For IPv6 Point-to-Point addresses, IFA_LOCAL should also be handled
///
/// Priority:
/// 1. If IFA_LOCAL exists, use it (this handles IPv4 and IPv6 PtP correctly)
/// 2. Otherwise, fall back to IFA_ADDRESS (this handles regular IPv6)
fn parse_ip_address(addr: &AddressMessage) -> Option<IpAddr> {
    // First, try to find IFA_LOCAL
    let local = addr.attributes.iter().find_map(|attr| match attr {
        AddressAttribute::Local(ip) => Some(*ip),
        _ => None,
    });

    // If IFA_LOCAL exists, use it
    if let Some(ip) = local {
        return Some(ip);
    }

    // Otherwise, fall back to IFA_ADDRESS
    addr.attributes.iter().find_map(|attr| match attr {
        AddressAttribute::Address(ip) => Some(*ip),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use netlink_packet_route::AddressFamily;
    use netlink_packet_route::address::{AddressFlags, AddressMessage, AddressScope};

    use super::*;

    #[test]
    fn test_address_message_to_cidr() {
        let mut msg = AddressMessage::default();
        msg.header.index = 10;
        msg.header.prefix_len = 24;
        msg.header.family = AddressFamily::Inet;
        msg.header.scope = AddressScope::Universe;
        let ip = "192.168.1.1".parse().unwrap();
        msg.attributes.push(AddressAttribute::Address(ip));
        msg.attributes
            .push(AddressAttribute::Flags(AddressFlags::Permanent));

        let cidr = CidrAddress::from(&msg);
        assert_eq!(cidr.prefix_len, 24);
        assert_eq!(cidr.address, ip);
    }

    #[test]
    fn test_parse_ip_address_with_local() {
        // Test IPv4 with IFA_LOCAL (typical IPv4 case)
        let mut addr_msg = AddressMessage::default();
        addr_msg
            .attributes
            .push(AddressAttribute::Local(IpAddr::V4(Ipv4Addr::new(
                10, 0, 0, 1,
            ))));
        addr_msg
            .attributes
            .push(AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
                10, 0, 0, 2,
            ))));

        let result = parse_ip_address(&addr_msg);
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_parse_ip_address_without_local() {
        // Test IPv6 without IFA_LOCAL (typical IPv6 case)
        let mut addr_msg = AddressMessage::default();
        addr_msg
            .attributes
            .push(AddressAttribute::Address(IpAddr::V6(
                std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            )));

        let result = parse_ip_address(&addr_msg);
        assert_eq!(
            result,
            Some(IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
            )))
        );
    }

    #[test]
    fn test_parse_ip_address_ipv6_with_local() {
        // Test IPv6 PtP with IFA_LOCAL
        let mut addr_msg = AddressMessage::default();
        addr_msg.attributes.push(AddressAttribute::Local(IpAddr::V6(
            std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        )));
        addr_msg
            .attributes
            .push(AddressAttribute::Address(IpAddr::V6(
                std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            )));

        let result = parse_ip_address(&addr_msg);
        assert_eq!(
            result,
            Some(IpAddr::V6(std::net::Ipv6Addr::new(
                0xfe80, 0, 0, 0, 0, 0, 0, 1
            )))
        );
    }

    #[test]
    fn test_parse_ip_address_no_attributes() {
        // Test with no address attributes
        let addr_msg = AddressMessage::default();

        let result = parse_ip_address(&addr_msg);
        assert_eq!(result, None);
    }
}
