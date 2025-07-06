use std::os::fd::RawFd;

use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use netlink_packet_route::RouteNetlinkMessage;

use crate::network::netlink::{
    Client, ClientWrapper, NetlinkMessageHandler, NetlinkResponse, NetworkError,
};

type Result<T> = std::result::Result<T, NetworkError>;

/// Handler for Link messages in Netlink communication.
///
/// This handler processes Netlink messages related to network interfaces (links)
/// and converts them into LinkMessage responses.
pub struct LinkMessageHandler;

impl NetlinkMessageHandler for LinkMessageHandler {
    type Response = LinkMessage;

    fn handle_payload(
        &self,
        payload: NetlinkPayload<RouteNetlinkMessage>,
    ) -> Result<NetlinkResponse<Self::Response>> {
        match payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
                Ok(NetlinkResponse::Success(link))
            }
            NetlinkPayload::Error(e) => match e.code {
                // According to netlink(7), when e.code is 0, it indicates success (acknowledgement)
                // rather than an error. This is used for ACK messages where the operation succeeded.
                // See: https://www.man7.org/linux/man-pages/man7/netlink.7.html
                None => Ok(NetlinkResponse::Success(LinkMessage::default())),
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

/// Client for managing network interfaces (links).
///
/// This client provides methods for querying and modifying network interface properties
/// through Netlink communication.
pub struct LinkClient {
    client: ClientWrapper,
}

impl LinkClient {
    /// Creates a new LinkClient instance.
    ///
    /// # Returns
    ///
    /// A Result containing either a new LinkClient or an IO error
    pub fn new(client: ClientWrapper) -> Result<Self> {
        Ok(Self { client })
    }

    /// Retrieves a network interface by its name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the network interface to retrieve
    ///
    /// # Returns
    ///
    /// A Result containing either the LinkMessage for the interface or an error
    pub fn get_by_name(&mut self, name: &str) -> Result<LinkMessage> {
        let mut message = LinkMessage::default();
        message
            .attributes
            .push(LinkAttribute::IfName(name.to_string()));

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::GetLink(message));
        req.header.flags = NLM_F_REQUEST;
        req.finalize();

        self.client.send_and_receive(&req, LinkMessageHandler)
    }

    /// Sets a network interface to the up state.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the network interface to modify
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure of the operation
    pub fn set_up(&mut self, index: u32) -> Result<()> {
        let mut message = LinkMessage::default();
        message.header.index = index;

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::SetLink(message));
        if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::SetLink(ref mut link)) =
            req.payload
        {
            link.header.change_mask |= LinkFlags::Up;
            link.header.flags |= LinkFlags::Up;
        }
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
        req.finalize();

        self.client.send_and_receive(&req, LinkMessageHandler)?;
        Ok(())
    }

    /// Sets a network interface to the down state.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the network interface to modify
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure of the operation
    pub fn set_down(&mut self, index: u32) -> Result<()> {
        let mut message = LinkMessage::default();
        message.header.index = index;

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::SetLink(message));
        if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::SetLink(ref mut link)) =
            req.payload
        {
            link.header.change_mask |= LinkFlags::Up;
            link.header.flags.remove(LinkFlags::Up);
        }
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
        req.finalize();

        self.client.send_and_receive(&req, LinkMessageHandler)?;
        Ok(())
    }

    /// Moves a network interface to a different network namespace.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the network interface to move
    /// * `new_name` - The new name for the interface in the target namespace
    /// * `ns_path` - The file descriptor of the target network namespace
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure of the operation
    pub fn set_ns_fd(&mut self, index: u32, new_name: &str, ns_path: RawFd) -> Result<()> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        message
            .attributes
            .push(LinkAttribute::IfName(new_name.to_string()));
        message.attributes.push(LinkAttribute::NetNsFd(ns_path));

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::SetLink(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
        req.finalize();

        self.client.send_and_receive(&req, LinkMessageHandler)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::netlink::{
        create_network_client, ClientWrapper, FakeNetlinkClient, NetlinkResponse,
    };

    #[test]
    fn test_link_message_handler_success() {
        let handler = LinkMessageHandler;
        let mut link_msg = LinkMessage::default();
        link_msg.header.index = 1;
        link_msg
            .attributes
            .push(LinkAttribute::IfName("eth0".to_string()));

        let payload = NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link_msg.clone()));
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
    fn test_link_message_handler_errorcode_zero() {
        let handler = LinkMessageHandler;
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
    fn test_link_message_handler_error() {
        let handler = LinkMessageHandler;
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
    fn test_link_message_handler_done() {
        let handler = LinkMessageHandler;
        let done_payload = NetlinkPayload::Done(netlink_packet_core::DoneMessage::default());
        let result = handler.handle_payload(done_payload);

        assert!(result.is_ok());
        match result.unwrap() {
            NetlinkResponse::Done => {}
            _ => panic!("Expected Done response"),
        }
    }

    #[test]
    fn test_link_message_handler_unexpected() {
        let handler = LinkMessageHandler;
        let unexpected_payload = NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(
            netlink_packet_route::address::AddressMessage::default(),
        ));
        let result = handler.handle_payload(unexpected_payload);

        assert!(result.is_err());
    }

    #[test]
    fn test_link_client_new() {
        let result = LinkClient::new(create_network_client());

        assert!(result.is_ok());
    }

    #[test]
    fn test_link_client_get_by_name_without_response() {
        let fake_client = FakeNetlinkClient::new();
        let mut link_client = LinkClient::new(ClientWrapper::Fake(fake_client)).unwrap();
        let result = link_client.get_by_name("eth0");

        // Should failed without LinkMessage
        assert!(result.is_err());
    }

    #[test]
    fn test_link_client_get_by_name_with_response() {
        let mut fake_client = FakeNetlinkClient::new();

        // Set up multiple responses
        let mut link1 = LinkMessage::default();
        link1.header.index = 1;
        link1
            .attributes
            .push(LinkAttribute::IfName("eth0".to_string()));

        let responses = vec![RouteNetlinkMessage::NewLink(link1)];
        fake_client.set_expected_responses(responses);

        let mut link_client = LinkClient::new(ClientWrapper::Fake(fake_client)).unwrap();
        let result = link_client.get_by_name("eth0");

        // Should succeed with the first matching response
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.header.index, 1);
        assert_eq!(response.attributes.len(), 1);
    }

    #[test]
    fn test_link_client_set_up_failure() {
        let mut fake_client = FakeNetlinkClient::new();
        fake_client.set_failure("Set up failed".to_string());

        let client_wrapper = ClientWrapper::Fake(fake_client);
        let mut link_client = LinkClient::new(client_wrapper).unwrap();

        let result = link_client.set_up(1);
        assert!(result.is_err());
    }

    #[test]
    fn test_link_client_set_up_success() {
        let mut fake_client = FakeNetlinkClient::new();

        // Set up a successful response (ACK with code 0)
        let mut error_msg = netlink_packet_core::ErrorMessage::default();
        error_msg.code = std::num::NonZeroI32::new(0);
        let responses = vec![RouteNetlinkMessage::NewLink(LinkMessage::default())];
        fake_client.set_expected_responses(responses);

        let client_wrapper = ClientWrapper::Fake(fake_client);
        let mut link_client = LinkClient::new(client_wrapper).unwrap();

        let result = link_client.set_up(42);
        assert!(result.is_ok());

        // Verify the call was tracked
        if let ClientWrapper::Fake(fake_client) = &mut link_client.client {
            let send_calls = fake_client.get_send_calls();
            assert_eq!(send_calls.len(), 1);

            // Verify the message details
            if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::SetLink(link)) =
                &send_calls[0].payload
            {
                assert_eq!(link.header.index, 42);
                assert!(link.header.flags.contains(LinkFlags::Up));
                assert!(link.header.change_mask.contains(LinkFlags::Up));
            } else {
                panic!("Expected SetLink message");
            }

            // Verify the netlink flags
            let expected_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
            assert_eq!(send_calls[0].header.flags, expected_flags);
        } else {
            panic!("Expected Fake client");
        }
    }

    #[test]
    fn test_link_client_set_down_failure() {
        let mut fake_client = FakeNetlinkClient::new();
        fake_client.set_failure("Set down failed".to_string());

        let client_wrapper = ClientWrapper::Fake(fake_client);
        let mut link_client = LinkClient::new(client_wrapper).unwrap();

        let result = link_client.set_down(1);
        assert!(result.is_err());
    }

    #[test]
    fn test_link_client_set_down_success() {
        let mut fake_client = FakeNetlinkClient::new();

        let responses = vec![RouteNetlinkMessage::NewLink(LinkMessage::default())];
        fake_client.set_expected_responses(responses);

        let client_wrapper = ClientWrapper::Fake(fake_client);
        let mut link_client = LinkClient::new(client_wrapper).unwrap();

        let result = link_client.set_down(42);
        assert!(result.is_ok());

        // Verify the call was tracked
        if let ClientWrapper::Fake(fake_client) = &mut link_client.client {
            let send_calls = fake_client.get_send_calls();
            assert_eq!(send_calls.len(), 1);

            // Verify the message details
            if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::SetLink(link)) =
                &send_calls[0].payload
            {
                assert_eq!(link.header.index, 42);
                assert!(!link.header.flags.contains(LinkFlags::Up));
                assert!(link.header.change_mask.contains(LinkFlags::Up));
            } else {
                panic!("Expected SetLink message");
            }

            // Verify the netlink flags
            let expected_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
            assert_eq!(send_calls[0].header.flags, expected_flags);
        } else {
            panic!("Expected Fake client");
        }
    }

    #[test]
    fn test_link_client_set_ns_fd_failure() {
        let mut fake_client = FakeNetlinkClient::new();
        fake_client.set_failure("Set namespace failed".to_string());

        let client_wrapper = ClientWrapper::Fake(fake_client);
        let mut link_client = LinkClient::new(client_wrapper).unwrap();

        let result = link_client.set_ns_fd(1, "veth0", 123);
        assert!(result.is_err());
    }

    #[test]
    fn test_link_client_set_ns_fd_success() {
        let mut fake_client = FakeNetlinkClient::new();

        let responses = vec![RouteNetlinkMessage::NewLink(LinkMessage::default())];
        fake_client.set_expected_responses(responses);

        let client_wrapper = ClientWrapper::Fake(fake_client);
        let mut link_client = LinkClient::new(client_wrapper).unwrap();

        let result = link_client.set_ns_fd(42, "new_veth", 456);
        assert!(result.is_ok());

        // Verify the call was tracked
        if let ClientWrapper::Fake(fake_client) = &mut link_client.client {
            let send_calls = fake_client.get_send_calls();
            assert_eq!(send_calls.len(), 1);

            // Verify the message details
            if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::SetLink(link)) =
                &send_calls[0].payload
            {
                assert_eq!(link.header.index, 42);
                assert_eq!(link.attributes.len(), 2);

                // Check for IfName attribute
                let mut found_ifname = false;
                let mut found_netns_fd = false;
                for attr in &link.attributes {
                    match attr {
                        LinkAttribute::IfName(name) => {
                            assert_eq!(name, "new_veth");
                            found_ifname = true;
                        }
                        LinkAttribute::NetNsFd(fd) => {
                            assert_eq!(*fd, 456);
                            found_netns_fd = true;
                        }
                        _ => {}
                    }
                }
                assert!(found_ifname, "IfName attribute not found");
                assert!(found_netns_fd, "NetNsFd attribute not found");
            } else {
                panic!("Expected SetLink message");
            }

            // Verify the netlink flags
            let expected_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
            assert_eq!(send_calls[0].header.flags, expected_flags);
        } else {
            panic!("Expected Fake client");
        }
    }
}
