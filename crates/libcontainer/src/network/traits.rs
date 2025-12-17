use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;

use super::{NetlinkResponse, Result};

/// Trait for handling Netlink message payloads.
///
/// This trait defines how different types of Netlink messages should be processed
/// and converted into appropriate response types.
pub trait NetlinkMessageHandler {
    /// The type of response that this handler produces
    type Response;

    /// Process a Netlink payload and convert it into a response.
    ///
    /// # Arguments
    ///
    /// * `payload` - The Netlink payload to process
    ///
    /// # Returns
    ///
    /// A Result containing either a NetlinkResponse or an IO error
    fn handle_payload(
        &self,
        payload: NetlinkPayload<RouteNetlinkMessage>,
    ) -> Result<NetlinkResponse<Self::Response>>;
}

/// Trait for Netlink client operations.
///
/// This trait abstracts the Netlink communication, allowing for easy mocking in tests.
pub trait Client {
    /// Sends a Netlink message.
    ///
    /// # Arguments
    ///
    /// * `req` - The Netlink message to send
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure of the send operation
    fn send(&mut self, req: &NetlinkMessage<RouteNetlinkMessage>) -> Result<()>;

    /// Receives and processes a Netlink message.
    ///
    /// # Arguments
    ///
    /// * `handler` - The handler to process the received message
    ///
    /// # Returns
    ///
    /// A Result containing either the processed response or an error
    fn receive<T, H>(&mut self, handler: H) -> Result<T>
    where
        H: NetlinkMessageHandler<Response = T>;

    /// Receives and processes multiple Netlink messages.
    ///
    /// # Arguments
    ///
    /// * `handler` - The handler to process the received messages
    ///
    /// # Returns
    ///
    /// A Result containing either a vector of processed responses or an error
    fn receive_multiple<T, H>(&mut self, handler: H) -> Result<Vec<T>>
    where
        H: NetlinkMessageHandler<Response = T>;

    /// Sends a Netlink message and receives a single response.
    ///
    /// # Arguments
    ///
    /// * `req` - The Netlink message to send
    /// * `handler` - The handler to process the received message
    ///
    /// # Returns
    ///
    /// A Result containing either the processed response or an error
    fn send_and_receive<T, H>(
        &mut self,
        req: &NetlinkMessage<RouteNetlinkMessage>,
        handler: H,
    ) -> Result<T>
    where
        H: NetlinkMessageHandler<Response = T>;

    /// Sends a Netlink message and receives multiple responses.
    ///
    /// # Arguments
    ///
    /// * `req` - The Netlink message to send
    /// * `handler` - The handler to process the received messages
    ///
    /// # Returns
    ///
    /// A Result containing either a vector of processed responses or an error
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
