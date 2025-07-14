use std::collections::VecDeque;

use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;

use super::traits::{Client, NetlinkMessageHandler};
use super::{NetlinkResponse, NetworkError, Result};

pub enum FakeResponse {
    Success(RouteNetlinkMessage),
    Error(String),
}

/// Fake implementation of NetlinkClient for testing.
///
/// This fake client allows you to predefine responses for specific requests,
/// making it easy to test different scenarios without requiring actual
/// network operations.
pub struct FakeNetlinkClient {
    send_calls: Vec<NetlinkMessage<RouteNetlinkMessage>>,
    expected_responses: VecDeque<FakeResponse>,
}

impl FakeNetlinkClient {
    /// Creates a new FakeNetlinkClient instance.
    pub fn new() -> Self {
        Self {
            send_calls: Vec::new(),
            expected_responses: VecDeque::new(),
        }
    }

    /// Sets the fake to fail with a specific error message.
    ///
    /// # Arguments
    ///
    /// * `error_message` - The error message to return
    pub fn set_failure(&mut self, error_message: String) {
        self.expected_responses
            .push_back(FakeResponse::Error(error_message));
    }

    /// Sets multiple expected responses for multiple message handlers.
    ///
    /// # Arguments
    ///
    /// * `responses` - Vector of RouteNetlinkMessage responses to return
    pub fn set_expected_responses(&mut self, responses: Vec<RouteNetlinkMessage>) {
        for response in responses {
            self.expected_responses
                .push_back(FakeResponse::Success(response));
        }
    }

    /// Gets the list of send calls made to this fake.
    pub fn get_send_calls(&self) -> &[NetlinkMessage<RouteNetlinkMessage>] {
        &self.send_calls
    }

    /// Clears the send calls history.
    pub fn clear_send_calls(&mut self) {
        self.send_calls.clear();
    }
}

impl Default for FakeNetlinkClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Client for FakeNetlinkClient {
    fn send(&mut self, req: &NetlinkMessage<RouteNetlinkMessage>) -> Result<()> {
        self.send_calls.push(req.clone());
        Ok(())
    }

    fn receive<T, H>(&mut self, handler: H) -> Result<T>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        if let Some(resp) = self.expected_responses.pop_front() {
            match resp {
                FakeResponse::Success(msg) => {
                    let payload = NetlinkPayload::InnerMessage(msg);
                    match handler.handle_payload(payload) {
                        Ok(NetlinkResponse::Success(response)) => Ok(response),
                        Ok(NetlinkResponse::Error(code)) => {
                            Err(NetworkError::IO(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Netlink error: {}", code),
                            )))
                        }
                        Ok(NetlinkResponse::Done) => Err(NetworkError::IO(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Unexpected done message",
                        ))),
                        Ok(NetlinkResponse::None) => Err(NetworkError::IO(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Unexpected none message",
                        ))),
                        Err(e) => Err(e),
                    }
                }
                FakeResponse::Error(msg) => Err(NetworkError::IO(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    msg,
                ))),
            }
        } else {
            Err(NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No fake response set",
            )))
        }
    }

    fn receive_multiple<T, H>(&mut self, handler: H) -> Result<Vec<T>>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        let mut responses = Vec::new();
        while let Some(resp) = self.expected_responses.pop_front() {
            match resp {
                FakeResponse::Success(msg) => {
                    let payload = NetlinkPayload::InnerMessage(msg);
                    match handler.handle_payload(payload) {
                        Ok(NetlinkResponse::Success(response)) => responses.push(response),
                        Ok(NetlinkResponse::Error(code)) => {
                            return Err(NetworkError::IO(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Netlink error: {}", code),
                            )))
                        }
                        Ok(NetlinkResponse::Done) => break,
                        Ok(NetlinkResponse::None) => continue,
                        Err(e) => return Err(e),
                    }
                }
                FakeResponse::Error(msg) => {
                    return Err(NetworkError::IO(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        msg,
                    )))
                }
            }
        }
        Ok(responses)
    }

    fn send_and_receive<T, H>(
        &mut self,
        req: &NetlinkMessage<RouteNetlinkMessage>,
        handler: H,
    ) -> Result<T>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        self.send(req)?;
        self.receive(handler)
    }

    fn send_and_receive_multiple<T, H>(
        &mut self,
        req: &NetlinkMessage<RouteNetlinkMessage>,
        handler: H,
    ) -> Result<Vec<T>>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        self.send(req)?;
        self.receive_multiple(handler)
    }
}
