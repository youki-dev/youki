use serde::{Serialize, Deserialize};
use std::net::IpAddr;
use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressMessage, AddressHeader, AddressScope};
use netlink_packet_route::{AddressFamily};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableAddress {
    pub index: u32,
    pub prefix_len: u8,
    pub family: u8,
    pub scope: u8,
    pub address: Option<IpAddr>,
    pub flags: Option<u32>,
}

impl From<&AddressMessage> for SerializableAddress {
    fn from(msg: &AddressMessage) -> Self {
        let mut address = None;
        let mut flags = None;
        for attr in &msg.attributes {
            match attr {
                AddressAttribute::Address(ip) => address = Some(*ip),
                AddressAttribute::Flags(f) => flags = Some(f.bits()),
                _ => {}
            }
        }
        SerializableAddress {
            index: msg.header.index,
            prefix_len: msg.header.prefix_len,
            family: u8::from(msg.header.family),
            scope: u8::from(msg.header.scope),
            address,
            flags,
        }
    }
}

impl From<&SerializableAddress> for AddressMessage {
    fn from(sa: &SerializableAddress) -> Self {
        let mut attrs = Vec::new();
        if let Some(ip) = sa.address {
            attrs.push(AddressAttribute::Address(ip));
        }
        if let Some(flags) = sa.flags {
            attrs.push(AddressAttribute::Flags(AddressFlags::from_bits_truncate(flags)));
        }
        let mut header = AddressHeader::default();
        header.index = sa.index;
        header.prefix_len = sa.prefix_len;
        header.family = AddressFamily::from(sa.family);
        header.scope = AddressScope::from(sa.scope);

        let mut msg = AddressMessage::default();
        msg.header = header;
        msg.attributes = attrs;

        msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::address::AddressScope;
    use netlink_packet_route::AddressFamily;

    #[test]
    fn test_address_message_to_serializable() {
        let mut msg = AddressMessage::default();
        msg.header.index = 10;
        msg.header.prefix_len = 24;
        msg.header.family = AddressFamily::Inet;
        msg.header.scope = AddressScope::Universe;
        let ip = "192.168.1.1".parse().unwrap();
        msg.attributes.push(AddressAttribute::Address(ip));
        msg.attributes.push(AddressAttribute::Flags(AddressFlags::Permanent));

        // AddressMessage -> SerializableAddress
        let serializable = SerializableAddress::from(&msg);

        assert_eq!(serializable.index, 10);
        assert_eq!(serializable.prefix_len, 24);
        assert_eq!(serializable.family, u8::from(AddressFamily::Inet));
        assert_eq!(serializable.scope, u8::from(AddressScope::Universe));
        assert_eq!(serializable.address, Some(ip));
        assert_eq!(serializable.flags, Some(AddressFlags::Permanent.bits()));
    }

    #[test]
    fn test_serializable_to_address_message() {
        let ip = "192.168.1.1".parse().unwrap();
        let serializable = SerializableAddress {
            index: 10,
            prefix_len: 24,
            family: u8::from(AddressFamily::Inet),
            scope: u8::from(AddressScope::Universe),
            address: Some(ip),
            flags: Some(AddressFlags::Permanent.bits()),
        };

        // SerializableAddress -> AddressMessage
        let msg = AddressMessage::from(&serializable);

        assert_eq!(msg.header.index, 10);
        assert_eq!(msg.header.prefix_len, 24);
        assert_eq!(msg.header.family, AddressFamily::Inet);
        assert_eq!(msg.header.scope, AddressScope::Universe);

        let mut found_ip = false;
        let mut found_flags = false;
        for attr in &msg.attributes {
            match attr {
                AddressAttribute::Address(a) => {
                    assert_eq!(*a, ip);
                    found_ip = true;
                }
                AddressAttribute::Flags(f) => {
                    assert!(f.contains(AddressFlags::Permanent));
                    found_flags = true;
                }
                _ => {}
            }
        }
        assert!(found_ip, "Address attribute not found");
        assert!(found_flags, "Flags attribute not found");
    }
}

