use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;

use super::traits::{Client, NetlinkMessageHandler};
use super::{NetlinkResponse, NetworkError, Result};

/// Fake implementation of NetlinkClient for testing.
///
/// This fake client allows you to predefine responses for specific requests,
/// making it easy to test different scenarios without requiring actual
/// network operations.
pub struct FakeNetlinkClient {
    send_calls: Vec<NetlinkMessage<RouteNetlinkMessage>>,
    should_fail: bool,
    fail_error: Option<String>,
    expected_responses: Vec<RouteNetlinkMessage>,
}

impl FakeNetlinkClient {
    /// Creates a new FakeNetlinkClient instance.
    pub fn new() -> Self {
        Self {
            send_calls: Vec::new(),
            should_fail: false,
            fail_error: None,
            expected_responses: Vec::new(),
        }
    }

    /// Sets the fake to fail with a specific error message.
    ///
    /// # Arguments
    ///
    /// * `error_message` - The error message to return
    pub fn set_failure(&mut self, error_message: String) {
        self.should_fail = true;
        self.fail_error = Some(error_message);
    }

    /// Sets multiple expected responses for multiple message handlers.
    ///
    /// # Arguments
    ///
    /// * `responses` - Vector of RouteNetlinkMessage responses to return
    pub fn set_expected_responses(&mut self, responses: Vec<RouteNetlinkMessage>) {
        self.expected_responses = responses;
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
        if self.should_fail {
            return Err(NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                self.fail_error
                    .clone()
                    .unwrap_or_else(|| "Fake failure".to_string()),
            )));
        }

        self.send_calls.push(req.clone());
        Ok(())
    }

    fn receive<T, H>(&mut self, handler: H) -> Result<T>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        if self.should_fail {
            return Err(NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                self.fail_error
                    .clone()
                    .unwrap_or_else(|| "Fake failure".to_string()),
            )));
        }

        // Try to handle responses from expected_responses
        for response in &self.expected_responses {
            let payload = NetlinkPayload::InnerMessage(response.clone());
            match handler.handle_payload(payload) {
                Ok(NetlinkResponse::Success(response)) => return Ok(response),
                Ok(NetlinkResponse::Error(code)) => {
                    return Err(NetworkError::IO(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Netlink error: {}", code),
                    )))
                }
                Ok(NetlinkResponse::Done) => {
                    return Err(NetworkError::IO(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Unexpected done message",
                    )))
                }
                Ok(NetlinkResponse::None) => {
                    return Err(NetworkError::IO(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Unexpected none message",
                    )))
                }
                Err(_) => {
                    // If handler doesn't accept this response type, try the next one
                    continue;
                }
            }
        }

        // For other handler types, return a generic error
        Err(NetworkError::IO(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Fake receive not implemented for this handler type",
        )))
    }

    fn receive_multiple<T, H>(&mut self, handler: H) -> Result<Vec<T>>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        if self.should_fail {
            return Err(NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                self.fail_error
                    .clone()
                    .unwrap_or_else(|| "Fake failure".to_string()),
            )));
        }

        let mut responses = Vec::new();

        // Try to handle responses from expected_responses
        for response in &self.expected_responses {
            let payload = NetlinkPayload::InnerMessage(response.clone());
            match handler.handle_payload(payload) {
                Ok(NetlinkResponse::Success(response)) => responses.push(response),
                Ok(NetlinkResponse::Error(code)) => {
                    return Err(NetworkError::IO(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Netlink error: {}", code),
                    )))
                }
                Ok(NetlinkResponse::Done) => return Ok(responses),
                Ok(NetlinkResponse::None) => {}
                Err(_) => {
                    // If handler doesn't accept this response type, try the next one
                    continue;
                }
            }
        }

        // If we have responses, return them
        if !responses.is_empty() {
            return Ok(responses);
        }

        //
        Err(NetworkError::IO(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Fake receive_multiple not implemented for this handler type",
        )))
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
