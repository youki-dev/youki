use netlink_packet_core::NetlinkMessage;
use netlink_packet_route::RouteNetlinkMessage;

use super::client::NetlinkClient;
use super::fake::FakeNetlinkClient;
use super::traits::{Client, NetlinkMessageHandler};
use super::{NetworkError, Result};

/// Enum wrapper for different client types
/// The `Client` trait contains generic methods, which makes it impossible to use as a trait object.
/// Therefore, we define `ClientWrapper` as an enum-based dynamic dispatch to handle this.
pub enum ClientWrapper {
    /// Real NetlinkClient instance for production use
    Client(NetlinkClient),
    /// Error state when NetlinkClient initialization failed
    ErrorState,
    /// Fake client for testing purposes
    Fake(FakeNetlinkClient),
}

impl Client for ClientWrapper {
    fn send(&mut self, req: &NetlinkMessage<RouteNetlinkMessage>) -> Result<()> {
        match self {
            ClientWrapper::Client(client) => client.send(req),
            ClientWrapper::ErrorState => Err(NetworkError::ClientInitializeError),
            ClientWrapper::Fake(client) => client.send(req),
        }
    }

    fn receive<T, H>(&mut self, handler: H) -> Result<T>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        match self {
            ClientWrapper::Client(client) => client.receive(handler),
            ClientWrapper::ErrorState => Err(NetworkError::ClientInitializeError),
            ClientWrapper::Fake(client) => client.receive(handler),
        }
    }

    fn receive_multiple<T, H>(&mut self, handler: H) -> Result<Vec<T>>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        match self {
            ClientWrapper::Client(client) => client.receive_multiple(handler),
            ClientWrapper::ErrorState => Err(NetworkError::ClientInitializeError),
            ClientWrapper::Fake(client) => client.receive_multiple(handler),
        }
    }

    fn send_and_receive<T, H>(
        &mut self,
        req: &NetlinkMessage<RouteNetlinkMessage>,
        handler: H,
    ) -> Result<T>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        match self {
            ClientWrapper::Client(client) => client.send_and_receive(req, handler),
            ClientWrapper::ErrorState => Err(NetworkError::ClientInitializeError),
            ClientWrapper::Fake(client) => client.send_and_receive(req, handler),
        }
    }

    fn send_and_receive_multiple<T, H>(
        &mut self,
        req: &NetlinkMessage<RouteNetlinkMessage>,
        handler: H,
    ) -> Result<Vec<T>>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        match self {
            ClientWrapper::Client(client) => client.send_and_receive_multiple(req, handler),
            ClientWrapper::ErrorState => Err(NetworkError::ClientInitializeError),
            ClientWrapper::Fake(client) => client.send_and_receive_multiple(req, handler),
        }
    }
}

impl Default for ClientWrapper {
    fn default() -> Self {
        if cfg!(test) {
            ClientWrapper::Fake(FakeNetlinkClient::new())
        } else {
            // If NetlinkClient initialization fails, we store the error state
            // instead of panicking. The error will be returned when the client is used.
            match NetlinkClient::new() {
                Ok(client) => ClientWrapper::Client(client),
                Err(_) => ClientWrapper::ErrorState,
            }
        }
    }
}

pub fn create_network_client() -> ClientWrapper {
    ClientWrapper::default()
}
