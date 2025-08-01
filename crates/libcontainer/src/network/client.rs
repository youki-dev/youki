use netlink_packet_core::NetlinkMessage;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::Socket;

use super::traits::{Client, NetlinkMessageHandler};
use super::{NetlinkResponse, NetworkError, Result};

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
            NetlinkResponse::None => Err(NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Unexpected none message",
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
                    NetlinkResponse::None => {}
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
