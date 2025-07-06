use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::Socket;

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, NetworkError>;

/// Represents a response from a Netlink operation.
///
/// This enum encapsulates the possible outcomes of a Netlink operation:
/// - Success: The operation completed successfully with a response of type T
/// - Error: The operation failed with an error code
/// - Done: The operation completed with no more data to process
#[derive(Debug)]
pub enum NetlinkResponse<T> {
    Success(T),
    Error(i32),
    Done,
}

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

/// Base client for Netlink communication.
///
/// This client provides the core functionality for sending and receiving Netlink messages.
/// It manages the underlying socket connection and provides methods for message handling.
pub struct NetlinkClient {
    socket: Socket,
}

impl NetlinkClient {
    /// Creates a new NetlinkClient instance.
    ///
    /// # Returns
    ///
    /// A Result containing either a new NetlinkClient or an IO error
    pub fn new() -> Result<Self> {
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        Ok(Self { socket })
    }
}

impl Client for NetlinkClient {
    fn send(&mut self, req: &NetlinkMessage<RouteNetlinkMessage>) -> Result<()> {
        let mut send_buf = vec![0; req.header.length as usize];
        req.serialize(&mut send_buf[..]);
        self.socket.send(&send_buf[..], 0)?;
        Ok(())
    }

    fn receive<T, H>(&mut self, handler: H) -> Result<T>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        let mut receive_buf = vec![0u8; 4096];
        let n_received = self.socket.recv(&mut &mut receive_buf[..], 0)?;
        let bytes = &receive_buf[..n_received];

        let rx_packet = <NetlinkMessage<RouteNetlinkMessage>>::deserialize(bytes).map_err(|e| {
            NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Deserialization error: {}", e),
            ))
        })?;

        match handler.handle_payload(rx_packet.payload)? {
            NetlinkResponse::Success(response) => Ok(response),
            NetlinkResponse::Error(code) => Err(NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Netlink error: {}", code),
            ))),
            NetlinkResponse::Done => Err(NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Unexpected done message",
            ))),
        }
    }

    fn receive_multiple<T, H>(&mut self, handler: H) -> Result<Vec<T>>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        let mut receive_buf = vec![0u8; 4096];
        let mut responses = Vec::new();
        let mut offset = 0;

        loop {
            let n_received = self.socket.recv(&mut &mut receive_buf[..], 0)?;
            loop {
                let bytes = &receive_buf[offset..];
                let rx_packet =
                    <NetlinkMessage<RouteNetlinkMessage>>::deserialize(bytes).map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Deserialization error: {}", e),
                        )
                    })?;

                match handler.handle_payload(rx_packet.payload)? {
                    NetlinkResponse::Success(response) => responses.push(response),
                    NetlinkResponse::Error(code) => {
                        return Err(NetworkError::IO(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Netlink error: code={}", code),
                        )))
                    }
                    NetlinkResponse::Done => return Ok(responses),
                }

                offset += rx_packet.header.length as usize;
                if offset == n_received || rx_packet.header.length == 0 {
                    offset = 0;
                    break;
                }
            }
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

/// Enum wrapper for different client types
/// The `Client` trait contains generic methods, which makes it impossible to use as a trait object.
/// Therefore, we define `ClientWrapper` as an enum-based dynamic dispatch to handle this.
pub enum ClientWrapper {
    Client(NetlinkClient),
    Fake(FakeNetlinkClient),
}

impl Client for ClientWrapper {
    fn send(&mut self, req: &NetlinkMessage<RouteNetlinkMessage>) -> Result<()> {
        match self {
            ClientWrapper::Client(client) => client.send(req),
            ClientWrapper::Fake(client) => client.send(req),
        }
    }

    fn receive<T, H>(&mut self, handler: H) -> Result<T>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        match self {
            ClientWrapper::Client(client) => client.receive(handler),
            ClientWrapper::Fake(client) => client.receive(handler),
        }
    }

    fn receive_multiple<T, H>(&mut self, handler: H) -> Result<Vec<T>>
    where
        H: NetlinkMessageHandler<Response = T>,
    {
        match self {
            ClientWrapper::Client(client) => client.receive_multiple(handler),
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
            ClientWrapper::Fake(client) => client.send_and_receive_multiple(req, handler),
        }
    }
}

impl Default for ClientWrapper {
    fn default() -> Self {
        if cfg!(test) {
            ClientWrapper::Fake(FakeNetlinkClient::new())
        } else {
            ClientWrapper::Client(
                NetlinkClient::new().unwrap_or_else(|_| panic!("Failed to create NetlinkClient")),
            )
        }
    }
}

pub fn create_network_client() -> ClientWrapper {
    ClientWrapper::default()
}
