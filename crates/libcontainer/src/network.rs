use std::fs::File;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressMessage, AddressScope};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::Socket;
use nix::sched::{setns, CloneFlags};
use oci_spec::runtime::LinuxNetDevice;

type Result<T> = std::result::Result<T, NetworkError>;

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
}

/// Represents a response from a Netlink operation.
///
/// This enum encapsulates the possible outcomes of a Netlink operation:
/// - Success: The operation completed successfully with a response of type T
/// - Error: The operation failed with an error code
/// - Done: The operation completed with no more data to process
#[derive(Debug)]
enum NetlinkResponse<T> {
    Success(T),
    Error(i32),
    Done,
}

/// Trait for handling Netlink message payloads.
///
/// This trait defines how different types of Netlink messages should be processed
/// and converted into appropriate response types.
trait NetlinkMessageHandler {
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

/// Handler for Link messages in Netlink communication.
///
/// This handler processes Netlink messages related to network interfaces (links)
/// and converts them into LinkMessage responses.
struct LinkMessageHandler;

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

/// Handler for Address messages in Netlink communication.
///
/// This handler processes Netlink messages related to network addresses
/// and converts them into AddressMessage responses.
struct AddressMessageHandler;

impl NetlinkMessageHandler for AddressMessageHandler {
    type Response = AddressMessage;

    fn handle_payload(
        &self,
        payload: NetlinkPayload<RouteNetlinkMessage>,
    ) -> Result<NetlinkResponse<Self::Response>> {
        match payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr)) => {
                Ok(NetlinkResponse::Success(addr))
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

/// Base client for Netlink communication.
///
/// This client provides the core functionality for sending and receiving Netlink messages.
/// It manages the underlying socket connection and provides methods for message handling.
struct NetlinkClient {
    socket: Socket,
}

impl NetlinkClient {
    /// Creates a new NetlinkClient instance.
    ///
    /// # Returns
    ///
    /// A Result containing either a new NetlinkClient or an IO error
    fn new() -> Result<Self> {
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        Ok(Self { socket })
    }

    /// Sends a Netlink message.
    ///
    /// # Arguments
    ///
    /// * `req` - The Netlink message to send
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure of the send operation
    fn send(&mut self, req: &NetlinkMessage<RouteNetlinkMessage>) -> Result<()> {
        let mut send_buf = vec![0; req.header.length as usize];
        req.serialize(&mut send_buf[..]);
        self.socket.send(&send_buf[..], 0)?;
        Ok(())
    }

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
        H: NetlinkMessageHandler<Response = T>,
    {
        self.send(req)?;
        self.receive(handler)
    }

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

/// Client for managing network interfaces (links).
///
/// This client provides methods for querying and modifying network interface properties
/// through Netlink communication.
struct LinkClient {
    client: NetlinkClient,
}

impl LinkClient {
    /// Creates a new LinkClient instance.
    ///
    /// # Returns
    ///
    /// A Result containing either a new LinkClient or an IO error
    fn new() -> Result<Self> {
        Ok(Self {
            client: NetlinkClient::new()?,
        })
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
    fn get_by_name(&mut self, name: &str) -> Result<LinkMessage> {
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
    fn set_up(&mut self, index: u32) -> Result<()> {
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
    fn set_down(&mut self, index: u32) -> Result<()> {
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
    fn set_ns_fd(&mut self, index: u32, new_name: &str, ns_path: RawFd) -> Result<()> {
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

/// Client for managing network addresses.
///
/// This client provides methods for querying and modifying network address properties
/// through Netlink communication.
struct AddressClient {
    client: NetlinkClient,
}

impl AddressClient {
    /// Creates a new AddressClient instance.
    ///
    /// # Returns
    ///
    /// A Result containing either a new AddressClient or an IO error
    fn new() -> Result<Self> {
        Ok(Self {
            client: NetlinkClient::new()?,
        })
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
    fn get_by_index(&mut self, index: u32) -> Result<Vec<AddressMessage>> {
        let mut message = AddressMessage::default();
        message.header.index = index;

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::GetAddress(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
        req.finalize();

        self.client
            .send_and_receive_multiple(&req, AddressMessageHandler)
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
    fn add(&mut self, index: u32, address: IpAddr, prefix_len: u8) -> Result<()> {
        let message = self.create_address_request(index, address, prefix_len)?;

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewAddress(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
        req.finalize();

        self.client.send_and_receive(&req, AddressMessageHandler)?;
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

/// dev_change_netns allows to move a device given by name to a network namespace given by nsPath
/// and optionally change the device name.
/// The device name will be kept the same if device.Name is the zero value.
/// This function ensures that the move and rename operations occur atomically.
/// It preserves existing interface attributes, including IP addresses.
pub fn dev_change_net_namespace(
    name: String,
    netns_path: String,
    device: LinuxNetDevice,
) -> Result<()> {
    tracing::debug!(
        "attaching network device {} to network namespace {}",
        name,
        netns_path
    );

    let mut link_client = LinkClient::new()?;
    let mut addr_client = AddressClient::new()?;

    let netns_file = File::open(netns_path)?;
    let origin_netns_file = File::open("/proc/self/ns/net")?;

    let new_name = device
        .name()
        .as_ref()
        .filter(|d| !d.is_empty())
        .map_or(name.clone(), |d| d.to_string());

    let link = link_client.get_by_name(&name)?;

    let index = link.header.index;

    // Set the interface link state to DOWN before modifying attributes like namespace or name.
    // This prevents potential conflicts or disruptions on the host network during the transition,
    // particularly if other host components depend on this specific interface or its properties.
    link_client.set_down(index)?;

    // Get the existing IP addresses on the interface.
    let addrs = addr_client.get_by_index(index)?;

    link_client.set_ns_fd(index, &new_name, netns_file.as_raw_fd())?;

    let thread_handle = std::thread::spawn({
        move || -> Result<()> {
            setns(
                unsafe { BorrowedFd::borrow_raw(netns_file.as_raw_fd()) },
                CloneFlags::CLONE_NEWNET,
            )?;

            let mut link_client = LinkClient::new()?;
            let mut addr_client = AddressClient::new()?;

            let ns_link = link_client.get_by_name(&new_name)?;
            let ns_index = ns_link.header.index;

            // Re-add the original IP addresses to the interface in the new namespace.
            // The kernel removes IP addresses when an interface is moved between network namespaces.
            for addr in addrs {
                tracing::debug!(
                    "processing address {:?} from network device {}",
                    addr.clone(),
                    name
                );
                let mut ip_opts = None;
                let mut flags_opts = None;
                // Only move IP addresses with global scope because those are not host-specific, auto-configured,
                // or have limited network scope, making them unsuitable inside the container namespace.
                // Ref: https://www.ietf.org/rfc/rfc3549.txt
                if addr.header.scope != AddressScope::Universe {
                    tracing::debug!(
                        "skipping address {:?} from network device {}",
                        addr.clone(),
                        name
                    );
                    continue;
                }
                for attr in &addr.attributes {
                    match attr {
                        AddressAttribute::Flags(flags) => flags_opts = Some(*flags),
                        AddressAttribute::Address(ip) => ip_opts = Some(*ip),
                        _ => {}
                    }
                }

                // Only move permanent IP addresses configured by the user, dynamic addresses are excluded because
                // their validity may rely on the original network namespace's context and they may have limited
                // lifetimes and are not guaranteed to be available in a new namespace.
                // Ref: https://www.ietf.org/rfc/rfc3549.txt
                if let Some(flag) = flags_opts {
                    if !flag.contains(AddressFlags::Permanent) {
                        tracing::debug!(
                            "skipping address {:?} from network device {}",
                            addr.clone(),
                            name
                        );
                        continue;
                    }
                }
                if let Some(ip) = ip_opts {
                    // Remove the interface attribute of the original address
                    // to avoid issues when the interface is renamed.
                    addr_client.add(ns_index, ip, addr.header.prefix_len)?;
                }
            }

            link_client.set_up(ns_index)?;

            setns(
                unsafe { BorrowedFd::borrow_raw(origin_netns_file.as_raw_fd()) },
                CloneFlags::CLONE_NEWNET,
            )?;
            Ok(())
        }
    });

    thread_handle
        .join()
        .map_err(|e| {
            NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Thread join error: {:?}", e),
            ))
        })?
        .map_err(|e| {
            NetworkError::IO(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Thread execution error: {:?}", e),
            ))
        })?;

    Ok(())
}
