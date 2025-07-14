use std::net::{IpAddr, Ipv4Addr};

use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};

use crate::network::traits::{Client, NetlinkMessageHandler};
use crate::network::wrapper::ClientWrapper;
use crate::network::{NetlinkResponse, NetworkError, Result};

/// Handler for Address messages in Netlink communication.
///
/// This handler processes Netlink messages related to network addresses
/// and converts them into AddressMessage responses.
pub struct AddressMessageHandler {
    target_index: Option<u32>,
}

impl AddressMessageHandler {
    pub fn new() -> Self {
        Self { target_index: None }
    }

    pub fn with_index(index: u32) -> Self {
        Self {
            target_index: Some(index),
        }
    }
}

impl Default for AddressMessageHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl NetlinkMessageHandler for AddressMessageHandler {
    type Response = AddressMessage;

    fn handle_payload(
        &self,
        payload: NetlinkPayload<RouteNetlinkMessage>,
    ) -> Result<NetlinkResponse<Self::Response>> {
        match payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr)) => {
                if let Some(target_index) = self.target_index {
                    if addr.header.index == target_index {
                        Ok(NetlinkResponse::Success(addr))
                    } else {
                        Ok(NetlinkResponse::None)
                    }
                } else {
                    Ok(NetlinkResponse::Success(addr))
                }
            }
            NetlinkPayload::Error(e) => match e.code {
                None => Ok(NetlinkResponse::Success(AddressMessage::default())),
                Some(code) => Ok(NetlinkResponse::Error(code.get())),
            },
            NetlinkPayload::Done(_) => Ok(NetlinkResponse::Done),
            _ => Err(NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Unexpected message type: {:?}", payload),
            ))),
        }
    }
}

/// Client for managing network addresses.
///
/// This client provides methods for querying and modifying network address properties
/// through Netlink communication.
pub struct AddressClient {
    client: ClientWrapper,
}

impl AddressClient {
    /// Creates a new AddressClient instance.
    ///
    /// # Returns
    ///
    /// A Result containing either a new AddressClient or an IO error
    pub fn new(client: ClientWrapper) -> Result<Self> {
        Ok(Self { client })
    }

    /// Retrieves all addresses associated with a network interface.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the network interface
    ///
    /// # Returns
    ///
    /// A Result containing either a vector of AddressMessages or an error
    pub fn get_by_index(&mut self, index: u32) -> Result<Vec<AddressMessage>> {
        let mut message = AddressMessage::default();
        message.header.index = index;

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::GetAddress(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
        req.finalize();

        let handler = AddressMessageHandler::with_index(index);

        self.client.send_and_receive_multiple(&req, handler)
    }

    /// Adds a new address to a network interface.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the network interface
    /// * `address` - The IP address to add
    /// * `prefix_len` - The prefix length of the address
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure of the operation
    pub fn add(&mut self, index: u32, address: IpAddr, prefix_len: u8) -> Result<()> {
        let message = self.create_address_request(index, address, prefix_len)?;

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewAddress(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
        req.finalize();

        let handler = AddressMessageHandler::new();

        self.client.send_and_receive(&req, handler)?;
        Ok(())
    }

    /// Creates an address request message.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the network interface
    /// * `address` - The IP address to add
    /// * `prefix_len` - The prefix length of the address
    ///
    /// # Returns
    ///
    /// A Result containing either the created AddressMessage or an error
    /// ref: https://github.com/rust-netlink/rtnetlink/blob/v0.17.0/src/addr/add.rs#L27-L73
    fn create_address_request(
        &self,
        index: u32,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<AddressMessage> {
        let mut message = AddressMessage::default();
        message.header.prefix_len = prefix_len;
        message.header.index = index;
        message.header.family = match address {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };

        if address.is_multicast() {
            if let IpAddr::V6(a) = address {
                message.attributes.push(AddressAttribute::Multicast(a));
            }
        } else {
            message.attributes.push(AddressAttribute::Address(address));
            message.attributes.push(AddressAttribute::Local(address));

            if let IpAddr::V4(a) = address {
                if prefix_len == 32 {
                    message.attributes.push(AddressAttribute::Broadcast(a));
                } else {
                    let ip_addr = u32::from(a);
                    let brd =
                        Ipv4Addr::from(((0xffff_ffff_u32) >> u32::from(prefix_len)) | ip_addr);
                    message.attributes.push(AddressAttribute::Broadcast(brd));
                };
            }
        }

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::fake::FakeNetlinkClient;
    use crate::network::wrapper::create_network_client;

    #[test]
    fn test_address_message_handler_success() {
        let handler = AddressMessageHandler::new();
        let mut addr_msg = AddressMessage::default();
        addr_msg.header.index = 1;
        addr_msg
            .attributes
            .push(AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 1,
            ))));

        let payload =
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr_msg.clone()));
        let result = handler.handle_payload(payload);

        assert!(result.is_ok());
        match result.unwrap() {
            NetlinkResponse::Success(response) => {
                assert_eq!(response.header.index, 1);
                assert_eq!(response.attributes.len(), 1);
            }
            _ => panic!("Expected Success response"),
        }
    }

    #[test]
    fn test_address_message_handler_errorcode_zero() {
        let handler = AddressMessageHandler::new();
        let mut error_msg = netlink_packet_core::ErrorMessage::default();
        error_msg.code = std::num::NonZeroI32::new(0);
        let error_payload = NetlinkPayload::Error(error_msg);
        let result = handler.handle_payload(error_payload);

        assert!(result.is_ok());
        match result.unwrap() {
            NetlinkResponse::Success(_) => {}
            _ => panic!("Expected Success response"),
        }
    }

    #[test]
    fn test_address_message_handler_error() {
        let handler = AddressMessageHandler::new();
        let mut error_msg = netlink_packet_core::ErrorMessage::default();
        error_msg.code = std::num::NonZeroI32::new(1);
        let error_payload = NetlinkPayload::Error(error_msg);
        let result = handler.handle_payload(error_payload);

        assert!(result.is_ok());
        match result.unwrap() {
            NetlinkResponse::Error(code) => {
                assert_eq!(code, 1);
            }
            _ => panic!("Expected Error response"),
        }
    }

    #[test]
    fn test_address_message_handler_done() {
        let handler = AddressMessageHandler::new();
        let done_payload = NetlinkPayload::Done(netlink_packet_core::DoneMessage::default());
        let result = handler.handle_payload(done_payload);

        assert!(result.is_ok());
        match result.unwrap() {
            NetlinkResponse::Done => {}
            _ => panic!("Expected Done response"),
        }
    }

    #[test]
    fn test_address_message_handler_unexpected() {
        let handler = AddressMessageHandler::new();
        let unexpected_payload = NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(
            netlink_packet_route::link::LinkMessage::default(),
        ));
        let result = handler.handle_payload(unexpected_payload);

        assert!(result.is_err());
    }

    #[test]
    fn test_address_client_new() {
        let result = AddressClient::new(create_network_client());
        assert!(result.is_ok());
    }

    #[test]
    fn test_address_client_get_by_index_failure() {
        let mut fake_client = FakeNetlinkClient::new();
        fake_client.set_failure("Get by index failed".to_string());

        let mut addr_client = AddressClient::new(ClientWrapper::Fake(fake_client)).unwrap();
        let result = addr_client.get_by_index(1);

        assert!(result.is_err());
    }

    #[test]
    fn test_address_client_get_by_index_without_response() {
        let fake_client = FakeNetlinkClient::new();
        let mut addr_client = AddressClient::new(ClientWrapper::Fake(fake_client)).unwrap();
        let result = addr_client.get_by_index(1);

        // Should failed without response
        assert!(result.is_err());
    }

    #[test]
    fn test_address_client_get_by_index_with_multiple_responses() {
        let mut fake_client = FakeNetlinkClient::new();

        // Set up multiple responses
        let mut addr1 = AddressMessage::default();
        addr1.header.index = 1;
        addr1
            .attributes
            .push(AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 1,
            ))));

        let mut addr2 = AddressMessage::default();
        addr2.header.index = 1;
        addr2
            .attributes
            .push(AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 2,
            ))));

        let responses = vec![
            RouteNetlinkMessage::NewAddress(addr1),
            RouteNetlinkMessage::NewAddress(addr2),
        ];
        fake_client.set_expected_responses(responses);

        let mut addr_client = AddressClient::new(ClientWrapper::Fake(fake_client)).unwrap();
        let result = addr_client.get_by_index(1);

        // Should succeed with multiple responses
        assert!(result.is_ok());
        let responses = result.unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].header.index, 1);
        assert_eq!(responses[1].header.index, 1);
    }

    #[test]
    fn test_address_client_get_by_index_success() {
        let mut fake_client = FakeNetlinkClient::new();

        let responses = vec![RouteNetlinkMessage::NewAddress(AddressMessage::default())];
        fake_client.set_expected_responses(responses);

        let client_wrapper = ClientWrapper::Fake(fake_client);
        let mut addr_client = AddressClient::new(client_wrapper).unwrap();

        let result = addr_client.get_by_index(42);
        assert!(result.is_ok());

        // Verify the call was tracked
        if let ClientWrapper::Fake(fake_client) = &mut addr_client.client {
            let send_calls = fake_client.get_send_calls();
            assert_eq!(send_calls.len(), 1);

            // Verify the message details
            if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetAddress(addr)) =
                &send_calls[0].payload
            {
                assert_eq!(addr.header.index, 42);
            } else {
                panic!("Expected GetAddress message");
            }

            // Verify the netlink flags
            let expected_flags = NLM_F_REQUEST | NLM_F_DUMP;
            assert_eq!(send_calls[0].header.flags, expected_flags);
        } else {
            panic!("Expected Fake client");
        }
    }

    #[test]
    fn test_address_client_add_failure() {
        let mut fake_client = FakeNetlinkClient::new();
        fake_client.set_failure("Add address failed".to_string());

        let mut addr_client = AddressClient::new(ClientWrapper::Fake(fake_client)).unwrap();
        let result = addr_client.add(1, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 24);

        assert!(result.is_err());
    }

    #[test]
    fn test_address_client_add_success() {
        let mut fake_client = FakeNetlinkClient::new();

        let responses = vec![RouteNetlinkMessage::NewAddress(AddressMessage::default())];
        fake_client.set_expected_responses(responses);

        let client_wrapper = ClientWrapper::Fake(fake_client);
        let mut addr_client = AddressClient::new(client_wrapper).unwrap();

        let result = addr_client.add(42, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 16);
        assert!(result.is_ok());

        // Verify the call was tracked
        if let ClientWrapper::Fake(fake_client) = &mut addr_client.client {
            let send_calls = fake_client.get_send_calls();
            assert_eq!(send_calls.len(), 1);

            // Verify the message details
            if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr)) =
                &send_calls[0].payload
            {
                assert_eq!(addr.header.index, 42);
                assert_eq!(addr.header.prefix_len, 16);
                assert_eq!(addr.header.family, AddressFamily::Inet);
                assert_eq!(addr.attributes.len(), 3); // Address, Local, Broadcast

                // Check for Address attribute
                let mut found_address = false;
                for attr in &addr.attributes {
                    if let AddressAttribute::Address(ip) = attr {
                        assert_eq!(*ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
                        found_address = true;
                        break;
                    }
                }
                assert!(found_address, "Address attribute not found");
            } else {
                panic!("Expected NewAddress message");
            }

            // Verify the netlink flags
            let expected_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
            assert_eq!(send_calls[0].header.flags, expected_flags);
        } else {
            panic!("Expected Fake client");
        }
    }

    #[test]
    fn test_address_client_add_with_different_parameters() {
        let mut fake_client = FakeNetlinkClient::new();
        let responses = vec![RouteNetlinkMessage::NewAddress(AddressMessage::default())];
        fake_client.set_expected_responses(responses);

        let client_wrapper = ClientWrapper::Fake(fake_client);
        let mut addr_client = AddressClient::new(client_wrapper).unwrap();

        // Test with different parameters
        let test_cases = vec![
            (1, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 24),
            (10, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 16),
            (
                100,
                IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                64,
            ),
        ];
        let test_cases_clone = test_cases.clone();

        for (index, address, prefix_len) in test_cases {
            let result = addr_client.add(index, address, prefix_len);
            assert!(
                result.is_ok(),
                "add failed for index {}, address {:?}, prefix_len {}",
                index,
                address,
                prefix_len
            );
        }

        // Verify all calls were tracked
        if let ClientWrapper::Fake(fake_client) = &mut addr_client.client {
            let send_calls = fake_client.get_send_calls();
            assert_eq!(send_calls.len(), test_cases_clone.len());

            for (i, (index, address, prefix_len)) in test_cases_clone.iter().enumerate() {
                if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr)) =
                    &send_calls[i].payload
                {
                    assert_eq!(addr.header.index, *index);
                    assert_eq!(addr.header.prefix_len, *prefix_len);

                    // Check address family
                    let expected_family = match address {
                        IpAddr::V4(_) => AddressFamily::Inet,
                        IpAddr::V6(_) => AddressFamily::Inet6,
                    };
                    assert_eq!(addr.header.family, expected_family);

                    // Check for Address attribute
                    let mut found_address = false;
                    for attr in &addr.attributes {
                        if let AddressAttribute::Address(ip) = attr {
                            assert_eq!(*ip, *address);
                            found_address = true;
                            break;
                        }
                    }
                    assert!(
                        found_address,
                        "Address attribute not found for index {}",
                        index
                    );
                } else {
                    panic!("Expected NewAddress message for index {}", index);
                }
            }
        } else {
            panic!("Expected Fake client");
        }
    }

    #[test]
    fn test_create_address_request_ipv4() {
        let addr_client = AddressClient::new(create_network_client()).unwrap();
        let result =
            addr_client.create_address_request(1, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 24);

        assert!(result.is_ok());
        let message = result.unwrap();
        assert_eq!(message.header.index, 1);
        assert_eq!(message.header.prefix_len, 24);
        assert_eq!(message.header.family, AddressFamily::Inet);
        assert_eq!(message.attributes.len(), 3); // Address, Local, Broadcast
    }

    #[test]
    fn test_create_address_request_ipv6() {
        let addr_client = AddressClient::new(create_network_client()).unwrap();
        let result = addr_client.create_address_request(
            1,
            IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            64,
        );

        assert!(result.is_ok());
        let message = result.unwrap();
        assert_eq!(message.header.index, 1);
        assert_eq!(message.header.prefix_len, 64);
        assert_eq!(message.header.family, AddressFamily::Inet6);
        assert_eq!(message.attributes.len(), 2); // Address, Local
    }
}
