use std::collections::HashMap;
use std::io::IoSlice;
use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use nix::errno::Errno;
use nix::sys::socket;
use nix::sys::time::TimeVal;

use super::client::SystemdClient;
use super::message::*;
use super::proxy::Proxy;
use super::utils::{DbusError, Result, SystemdClientError};
use crate::systemd::dbus_native::serialize::{DbusSerialize, Structure, Variant};

// systemd exposes a private socket for direct communication without a dbus daemon.
// Used as fallback when the standard system bus socket is unavailable, matching runc behavior.
// See: https://github.com/coreos/go-systemd/blob/main/dbus/dbus.go (NewSystemdConnectionContext)
const SYSTEMD_PRIVATE_SOCKET: &str = "/run/systemd/private";

/// Per-recv() timeout applied for the lifetime of every dbus connection,
/// covering both the auth handshake and all subsequent method calls.
///
/// Without a timeout, recv() blocks indefinitely when systemd is slow to
/// respond (e.g. cluster boot with many simultaneous container starts).
/// When SO_RCVTIMEO fires, recv() returns EAGAIN, which Manager::new()
/// catches and retries by reconnecting from scratch with exponential backoff.
///
/// Note: runc uses go-systemd's context.TODO() for dbus calls, which has no
/// deadline, leaving the same indefinite-block risk open (runc issue #3904).
/// This SO_RCVTIMEO approach is youki's equivalent fix.
const RECV_TIMEOUT_SECS: i64 = 10;

/// NOTE that this is meant for a single-threaded use, and concurrent
/// usage can cause errors, primarily because then the message received over
/// socket can be out of order and we need to manager buffer and check with message counter
/// which message is for which request etc etc
// Client is a wrapper providing higher level API and abatraction around dbus.
// For more information see https://www.freedesktop.org/wiki/Software/systemd/dbus/
pub struct DbusConnection {
    /// Is the socket system level or session specific
    #[allow(dead_code)]
    system: bool,
    /// socket fd
    socket: i32,
    /// name id assigned by dbus for the connection
    id: Option<String>,
    /// counter for messages
    // This must be atomic, so that we can take non-mutable reference to self
    // and still increment this
    msg_ctr: AtomicU32,
}

#[inline(always)]
fn uid_to_hex_str(uid: u32) -> String {
    let temp: Vec<_> = uid
        .to_string()
        .chars()
        .map(|c| format!("{:x}", c as u8))
        .collect();
    temp.join("")
}

fn parse_dbus_address(env_value: String) -> Result<String> {
    // as per spec, the env var can have multiple addresses separated by ;
    let addr_list: Vec<_> = env_value.split(';').collect();
    for addr in addr_list {
        if let Some(s) = addr.strip_prefix("unix:path=") {
            if !std::path::PathBuf::from(s).exists() {
                continue;
            }
            return Ok(s.to_owned());
        }

        if let Some(s) = addr.strip_prefix("unix:abstract=") {
            return Ok(s.to_owned());
        }
    }
    // we do not support unix:runtime=
    Err(DbusError::BusAddressError(format!("no valid bus path found in list {}", env_value)).into())
}

fn get_session_bus_address() -> Result<String> {
    if let Ok(s) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        return parse_dbus_address(s);
    }

    if let Ok(mut s) = std::env::var("XDG_RUNTIME_DIR") {
        s.push_str("/bus");
        if !std::path::PathBuf::from(&s).exists() {
            return Err(DbusError::BusAddressError(format!(
                "session bus address {} does not exist",
                s
            ))
            .into());
        }
        return Ok(s);
    }

    Err(
        DbusError::BusAddressError("could not find dbus session bus address from env".into())
            .into(),
    )
}

fn get_system_bus_address() -> Result<String> {
    if let Ok(s) = std::env::var("DBUS_SYSTEM_BUS_ADDRESS") {
        return parse_dbus_address(s);
    }
    // as per dbus spec https://dbus.freedesktop.org/doc/dbus-specification.html#message-bus-types-system
    // there are multiple service files which we should try searching and finding bus address from
    // but we will instead just support the following, which is supposed to be
    // well known anyways according to spec
    Ok("/var/run/dbus/system_bus_socket".into())
}

fn get_actual_uid() -> Result<u32> {
    let output = std::process::Command::new("busctl")
        .arg("--user")
        .arg("--no-pager")
        .arg("status")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| DbusError::BusctlError(format!("error in running busctl {:?}", e)))?
        .wait_with_output()
        .map_err(|e| DbusError::BusctlError(format!("error from busctl execution {:?}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let found =
        stdout
            .lines()
            .find(|s| s.starts_with("OwnerUID="))
            .ok_or(DbusError::BusctlError(
                "could not find OwnerUID from busctl".into(),
            ))?;

    let uid = found
        .trim_start_matches("OwnerUID=")
        .parse::<u32>()
        .map_err(DbusError::UidError)?;
    Ok(uid)
}

impl DbusConnection {
    /// Open a new dbus connection to the given address, authenticate, and register with the daemon.
    pub fn new(addr: &str, uid: u32, system: bool) -> Result<Self> {
        let mut conn = Self::connect(addr, system)?;
        conn.auth(uid)?;
        conn.hello()?;
        Ok(conn)
    }

    pub fn new_system() -> Result<Self> {
        // Try the standard system bus first (DBUS_SYSTEM_BUS_ADDRESS or well-known path).
        // and_then chains address lookup + connection so either failure falls through.
        let standard = get_system_bus_address().and_then(|addr| Self::new(&addr, 0, true));
        match standard {
            Ok(conn) => return Ok(conn),
            Err(ref e) => tracing::debug!("standard system bus unavailable: {}", e),
        }

        // Fallback: connect directly to systemd without a dbus daemon (root only).
        // /run/systemd/private is created by systemd itself and exists even when
        // dbus-daemon is not installed, e.g. in kind nodes.
        // Any error from the standard bus (including EACCES) falls through to this path,
        // matching go-systemd's NewSystemdConnectionContext() behavior.
        // register() must be skipped because systemd does not implement org.freedesktop.DBus.Hello.
        if nix::unistd::getuid().is_root() && std::path::Path::new(SYSTEMD_PRIVATE_SOCKET).exists()
        {
            tracing::debug!(
                "falling back to systemd private socket {}",
                SYSTEMD_PRIVATE_SOCKET
            );
            return Self::new_direct(SYSTEMD_PRIVATE_SOCKET, true);
        }

        Err(DbusError::BusAddressError(
            "could not connect to system bus or systemd private socket".into(),
        )
        .into())
    }

    pub fn new_session() -> Result<Self> {
        let addr = get_session_bus_address()?;
        let uid = get_actual_uid()?;
        Self::new(&addr, uid, false)
    }

    /// Create a Unix socket and connect it to the given dbus address.
    fn connect(addr: &str, system: bool) -> Result<Self> {
        // NOTE: DbusConnection should own an OwnedFd instead of ManuallyDrop + RawFd
        // so that fd ownership is explicit and Drop does not need to close manually.
        // Tracked in https://github.com/youki-dev/youki/issues/3629
        let socket = std::mem::ManuallyDrop::new(socket::socket(
            socket::AddressFamily::Unix,
            socket::SockType::Stream,
            socket::SockFlag::empty(),
            None,
        )?);

        let unix_addr = socket::UnixAddr::new(addr)?;
        socket::connect(socket.as_raw_fd(), &unix_addr)?;

        // Set SO_RCVTIMEO so that every recv() on this socket times out instead
        // of blocking indefinitely.  See RECV_TIMEOUT_SECS for rationale.
        socket::setsockopt(
            &socket.as_fd(),
            socket::sockopt::ReceiveTimeout,
            &TimeVal::new(RECV_TIMEOUT_SECS, 0),
        )?;

        Ok(Self {
            socket: socket.as_raw_fd(),
            msg_ctr: AtomicU32::new(0),
            id: None,
            system,
        })
    }

    /// Perform the dbus SASL AUTH EXTERNAL / BEGIN exchange.
    /// Must be called immediately after connect(), before any method calls.
    fn auth(&mut self, uid: u32) -> Result<()> {
        let mut buf = [0; 64];

        // dbus connection always start with a 0 byte sent as first thing
        socket::send(self.socket, &[0], socket::MsgFlags::empty())?;

        let msg = format!("AUTH EXTERNAL {}\r\n", uid_to_hex_str(uid));

        // then we send our auth with uid
        socket::send(self.socket, msg.as_bytes(), socket::MsgFlags::empty())?;

        // we get the reply and check if all went well or not
        socket::recv(self.socket, &mut buf, socket::MsgFlags::empty())?;

        let reply: Vec<u8> = buf.iter().filter(|v| **v != 0).copied().collect();

        // we can use _lossy as we know dbus communication is always ascii
        let reply = String::from_utf8_lossy(&reply);

        // successful auth reply starts with 'ok'
        if !reply.starts_with("OK") {
            return Err(DbusError::AuthenticationErr(format!(
                "Authentication failed, got message : {}",
                reply
            ))
            .into());
        }

        // we must send the BEGIN before starting any actual communication
        // we can also send AGREE_UNIX_FD before this if we need to deal with sending/receiving
        // fds over the connection, but because youki doesn't need it, we can skip that
        socket::send(
            self.socket,
            "BEGIN\r\n".as_bytes(),
            socket::MsgFlags::empty(),
        )?;

        Ok(())
    }

    /// Send the Hello method call to register this connection with the dbus daemon.
    /// Hello allocates a unique name (e.g. ":1.42") for this connection on the bus.
    /// Must be called after connect() + auth() when connecting to a dbus daemon.
    /// Must NOT be called when connecting directly to systemd via /run/systemd/private,
    /// since systemd does not implement org.freedesktop.DBus.Hello.
    fn hello(&mut self) -> Result<()> {
        // First thing any dbus client must do after authentication
        // is to do a hello method call, in order to get a name allocated
        // if we do any other method call, the connection is assumed to be
        // invalid and auto disconnected
        let headers = vec![
            Header {
                kind: HeaderKind::Path,
                value: HeaderValue::String("/org/freedesktop/DBus".to_string()),
            },
            Header {
                kind: HeaderKind::Destination,
                value: HeaderValue::String("org.freedesktop.DBus".to_string()),
            },
            Header {
                kind: HeaderKind::Interface,
                value: HeaderValue::String("org.freedesktop.DBus".to_string()),
            },
            Header {
                kind: HeaderKind::Member,
                value: HeaderValue::String("Hello".to_string()),
            },
        ];

        let res = self.send_message(MessageType::MethodCall, headers, vec![])?;

        let res: Vec<_> = res
            .into_iter()
            .filter(|m| m.preamble.mtype == MessageType::MethodReturn)
            .collect();

        let res = res.first().ok_or(DbusError::AuthenticationErr(format!(
            "expected Hello call to have reply, found no reply message, got {:?} instead",
            res
        )))?;
        let mut ctr = 0;
        let id = String::deserialize(&res.body, &mut ctr)?;
        self.id = Some(id);

        Ok(())
    }

    /// Connect directly to /run/systemd/private without going through a dbus daemon.
    /// uid is always root (0) because /run/systemd/private is only accessible by root,
    /// and callers must verify this before calling.
    fn new_direct(addr: &str, system: bool) -> Result<Self> {
        // connect() + auth() perform socket setup and AUTH/BEGIN.
        // hello() is intentionally skipped here because systemd does not implement
        // org.freedesktop.DBus.Hello.
        // self.id remains None; send_message already handles None by omitting the Sender header.
        let mut conn = Self::connect(addr, system)?;
        conn.auth(0)?;
        Ok(conn)
    }

    /// Read exactly `buf.len()` bytes from the socket, retrying on EINTR.
    fn read_exact(&self, buf: &mut [u8]) -> Result<()> {
        let mut total = 0;
        while total < buf.len() {
            match socket::recv(self.socket, &mut buf[total..], socket::MsgFlags::empty()) {
                Ok(0) => {
                    return Err(DbusError::ConnectionError(
                        "connection closed unexpectedly".into(),
                    )
                    .into());
                }
                Ok(n) => total += n,
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Read exactly one complete dbus message from the socket.
    ///
    /// ```text
    /// byte  0     : BYTE   endianness flag ('l' = little-endian, 'B' = big-endian)
    /// byte  1     : BYTE   message type (1=MethodCall 2=MethodReturn 3=Error 4=Signal)
    /// byte  2     : BYTE   flags
    /// byte  3     : BYTE   major protocol version
    /// bytes 4-7   : UINT32 length in bytes of the message body
    /// bytes 8-11  : UINT32 serial of this message
    /// bytes 12-15 : UINT32 length in bytes of the header fields array
    /// bytes 16+   : ARRAY  header fields a(yv), padded to 8-byte boundary
    /// ...         : body   (body_len bytes)
    /// ```
    /// See: https://dbus.freedesktop.org/doc/dbus-specification.html#message-format
    ///
    /// Reads the fixed header first to extract body_len and header_array_len,
    /// then reads the exact remainder with no heuristics.
    fn read_one_message(&self) -> Result<Vec<u8>> {
        let mut fixed = [0u8; 16];
        self.read_exact(&mut fixed)?;

        // byte 0 is the endianness flag; Linux/systemd always sends little-endian ('l').
        let body_len = u32::from_le_bytes(fixed[4..8].try_into().unwrap()) as usize;
        let header_array_len = u32::from_le_bytes(fixed[12..16].try_into().unwrap()) as usize;
        let aligned_header_len = (header_array_len + 7) & !7;

        let mut rest = vec![0u8; aligned_header_len + body_len];
        self.read_exact(&mut rest)?;

        let mut msg_bytes = fixed.to_vec();
        msg_bytes.extend_from_slice(&rest);
        Ok(msg_bytes)
    }

    /// function to send message of given type with given headers and body
    /// over the dbus connection. The caller must specify the destination, interface etc.etc.
    /// in the headers, this function will only take care of sending the message and
    /// returning the received messages. Note that the caller must check if any error
    /// message was returned or not, this will not check that, the returned Err
    /// indicates error in sending/receiving message
    pub fn send_message(
        &self,
        mtype: MessageType,
        mut headers: Vec<Header>,
        body: Vec<u8>,
    ) -> Result<Vec<Message>> {
        if let Some(s) = &self.id {
            headers.push(Header {
                kind: HeaderKind::Sender,
                value: HeaderValue::String(s.clone()),
            });
        }

        let message = Message::new(mtype, self.get_msg_id(), headers, body);
        let serialized = message.serialize();

        socket::sendmsg::<()>(
            self.socket,
            &[IoSlice::new(&serialized)],
            &[],
            socket::MsgFlags::empty(),
            None,
        )?;

        let mut ret = Vec::new();

        // Read one complete message per iteration. Signals do not terminate
        // the loop; only MethodReturn or Error ends the wait.
        loop {
            let msg_bytes = self.read_one_message()?;
            let mut ctr = 0;
            let msg = Message::deserialize(&msg_bytes, &mut ctr)?;

            // For non-method-call sends (e.g. AUTH handshake) one read suffices.
            if mtype != MessageType::MethodCall {
                ret.push(msg);
                break;
            }

            let is_final = msg.preamble.mtype == MessageType::MethodReturn
                || msg.preamble.mtype == MessageType::Error;
            ret.push(msg);

            if is_final {
                break;
            }
            // Signal or other unsolicited message — keep reading.
        }
        Ok(ret)
    }

    /// function to manage the message counter
    fn get_msg_id(&self) -> u32 {
        let old_ctr = self.msg_ctr.fetch_add(1, Ordering::SeqCst);
        old_ctr + 1
    }

    /// Create a proxy for given destination and path
    pub fn proxy(&self, destination: &str, path: &str) -> Proxy<'_> {
        Proxy::new(self, destination, path)
    }

    fn create_proxy(&self) -> Proxy<'_> {
        self.proxy("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
    }
}

impl SystemdClient for DbusConnection {
    fn is_system(&self) -> bool {
        self.system
    }

    fn transient_unit_exists(&self, unit_name: &str) -> bool {
        let mut proxy = self.create_proxy();
        proxy.get_unit(unit_name).is_ok()
    }

    /// start_transient_unit is a higher level API for starting a unit
    /// for a specific container under systemd.
    /// See https://www.freedesktop.org/wiki/Software/systemd/dbus for more details.
    fn start_transient_unit(
        &self,
        container_name: &str,
        pid: u32,
        parent: &str,
        unit_name: &str,
    ) -> Result<()> {
        // To view and introspect the methods under the 'org.freedesktop.systemd1' destination
        // and object path under it use the following command:
        // `gdbus introspect --system --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1`
        let proxy = self.create_proxy();

        // To align with runc, youki will always add the following properties to its container units:
        // - CPUAccounting=true
        // - IOAccounting=true (BlockIOAccounting for cgroup v1)
        // - MemoryAccounting=true
        // - TasksAccounting=true
        // see https://github.com/opencontainers/runc/blob/6023d635d725a74c6eaa11ab7f3c870c073badd2/docs/systemd.md#systemd-cgroup-driver
        // for more details.
        let mut properties: Vec<(&str, Variant)> = Vec::with_capacity(6);
        properties.push((
            "Description",
            Variant::String(format!("youki container {container_name}")),
        ));

        // if we create a slice, the parent is defined via a Wants=
        // otherwise, we use Slice=
        if unit_name.ends_with("slice") {
            properties.push(("Wants", Variant::String(parent.to_owned())));
        } else {
            properties.push(("Slice", Variant::String(parent.to_owned())));
            properties.push(("Delegate", Variant::Bool(true)));
        }

        properties.push(("MemoryAccounting", Variant::Bool(true)));
        properties.push(("CPUAccounting", Variant::Bool(true)));
        properties.push(("IOAccounting", Variant::Bool(true)));
        properties.push(("TasksAccounting", Variant::Bool(true)));

        properties.push(("DefaultDependencies", Variant::Bool(false)));
        properties.push(("PIDs", Variant::ArrayU32(vec![pid])));

        tracing::debug!("Starting transient unit: {:?}", properties);
        let props = properties
            .into_iter()
            .map(|(k, v)| Structure::new(k.into(), v))
            .collect();
        proxy
            .start_transient_unit(unit_name, "replace", props, vec![])
            .map_err(|err| SystemdClientError::FailedTransient {
                err: Box::new(err),
                unit_name: unit_name.into(),
                parent: parent.into(),
            })?;
        Ok(())
    }

    fn stop_transient_unit(&self, unit_name: &str) -> Result<()> {
        let proxy = self.create_proxy();

        proxy
            .stop_unit(unit_name, "replace")
            .map_err(|err| SystemdClientError::FailedStop {
                err: Box::new(err),
                unit_name: unit_name.into(),
            })?;
        Ok(())
    }

    fn set_unit_properties(
        &self,
        unit_name: &str,
        properties: &HashMap<&str, Variant>,
    ) -> Result<()> {
        let proxy = self.create_proxy();

        let props: Vec<Structure<Variant>> = properties
            .iter()
            .map(|(k, v)| Structure::new(k.to_string(), v.clone()))
            .collect();

        proxy
            .set_unit_properties(unit_name, true, props)
            .map_err(|err| SystemdClientError::FailedProperties {
                err: Box::new(err),
                unit_name: unit_name.into(),
            })?;
        Ok(())
    }

    fn systemd_version(&self) -> std::result::Result<u32, SystemdClientError> {
        let proxy = self.create_proxy();

        let version = proxy
            .version()?
            .chars()
            .skip_while(|c| c.is_alphabetic())
            .take_while(|c| c.is_numeric())
            .collect::<String>()
            .parse::<u32>()
            .map_err(SystemdClientError::SystemdVersion)?;

        Ok(version)
    }

    fn control_cgroup_root(&self) -> std::result::Result<PathBuf, SystemdClientError> {
        let proxy = self.create_proxy();

        let cgroup_root = proxy.control_group()?;
        Ok(PathBuf::from(&cgroup_root))
    }
    fn add_process_to_unit(&self, unit_name: &str, subcgroup: &str, pid: u32) -> Result<()> {
        let proxy = self.create_proxy();
        proxy.attach_process(unit_name, subcgroup, pid)
    }
}

#[cfg(test)]
impl DbusConnection {
    /// Construct a DbusConnection wrapping an already-connected fd, for unit tests.
    fn for_test(fd: i32) -> Self {
        Self {
            system: false,
            socket: fd,
            id: None,
            msg_ctr: AtomicU32::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};
    use nix::unistd::getuid;

    use super::super::utils::Result;
    use super::{DbusConnection, SystemdClientError, uid_to_hex_str};

    #[test]
    fn test_uid_to_hex_str() {
        let uid0 = uid_to_hex_str(0);
        assert_eq!(uid0, "30");
        let uid1000 = uid_to_hex_str(1000);
        assert_eq!(uid1000, "31303030");
    }

    #[test]
    #[cfg(feature = "systemd")]
    fn test_dbus_connection_new() {
        let uid: u32 = getuid().into();

        let dbus_pipe_path = format!("/run/user/{}/bus", uid);

        let conn = DbusConnection::new(&dbus_pipe_path, uid, false);
        assert!(conn.is_ok());

        let invalid_conn = DbusConnection::new(&dbus_pipe_path, uid.wrapping_add(1), false);
        assert!(invalid_conn.is_err());
    }

    #[test]
    #[cfg(feature = "systemd")]
    fn test_dbus_function_calls() -> Result<()> {
        use crate::systemd::dbus_native::serialize::Variant;

        let uid: u32 = getuid().into();

        let dbus_pipe_path = format!("/run/user/{}/bus", uid);

        let conn = DbusConnection::new(&dbus_pipe_path, uid, false)?;

        let proxy = conn.proxy("org.freedesktop.systemd1", "/org/freedesktop/systemd1");

        let body = (
            "org.freedesktop.systemd1.Manager".to_string(),
            "Version".to_string(),
        );
        let t = proxy.method_call::<_, Variant>(
            "org.freedesktop.DBus.Properties",
            "Get",
            Some(body),
        )?;
        assert!(matches!(t, Variant::String(_)));

        let body = (
            "org.freedesktop.systemd1.Manager".to_string(),
            "ControlGroup".to_string(),
        );
        let t = proxy.method_call::<_, Variant>(
            "org.freedesktop.DBus.Properties",
            "Get",
            Some(body),
        )?;
        assert!(matches!(t, Variant::String(_)));

        Ok(())
    }

    #[test]
    #[cfg(feature = "systemd")]
    fn test_dbus_function_calls_errors() {
        use crate::systemd::dbus_native::utils::DbusError;

        let uid: u32 = getuid().into();

        let dbus_pipe_path = format!("/run/user/{}/bus", uid);

        let conn = DbusConnection::new(&dbus_pipe_path, uid, false).unwrap();

        let proxy = conn.proxy("org.freedesktop.systemd1", "/org/freedesktop/systemd1");
        let body = (
            "org.freedesktop.systemd1.Manager".to_string(),
            "ControlGroup".to_string(),
        );

        // invalid return type, this call returns variant<String>
        let res = proxy.method_call::<_, u16>("org.freedesktop.DBus.Properties", "Get", Some(body));
        assert!(res.is_err());
        assert!(matches!(
            res,
            Err(SystemdClientError::DBus(DbusError::DeserializationError(_)))
        ));

        let body = (
            "org.freedesktop.systemd1.Manager".to_string(),
            "ControlGroup".to_string(),
        );

        // invalid interface
        let res = proxy.method_call::<_, u16>("org.freedesktop.DBus.Property_", "Get", Some(body));
        assert!(res.is_err());
        assert!(matches!(
            res,
            Err(SystemdClientError::DBus(DbusError::MethodCallErr(_)))
        ))
    }

    #[test]
    fn test_read_exact() {
        let (a, b) = socket::socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();

        let data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        socket::send(a.as_raw_fd(), &data, socket::MsgFlags::empty()).unwrap();

        let conn = DbusConnection::for_test(b.as_raw_fd());
        let mut buf = [0u8; 10];
        conn.read_exact(&mut buf).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn test_read_one_message() {
        // Serialized MethodReturn message captured from real dbus traffic.
        // body_len=12, header_array_len=63 (aligned to 64), total=92 bytes.
        let msg_bytes: &[u8] = b"l\x02\x00\x01\x0c\x00\x00\x00\xff\xff\xff\xff?\x00\x00\x00\x05\x01u\x00\x01\x00\x00\x00\x07\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x06\x01s\x00\x07\x00\x00\x00:1.2072\x00\x08\x01g\x00\x01s\x00\x00\x07\x00\x00\x00:1.2072\x00";

        let (a, b) = socket::socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();

        socket::send(a.as_raw_fd(), msg_bytes, socket::MsgFlags::empty()).unwrap();

        let conn = DbusConnection::for_test(b.as_raw_fd());
        let received = conn.read_one_message().unwrap();
        assert_eq!(received, msg_bytes);
    }

    #[test]
    fn test_read_one_message_respects_boundaries() {
        // Two messages written back-to-back; each read_one_message call must
        // return exactly one, with no bytes stolen from the next.
        //
        // Signal: body_len=12, header_array_len=143 (aligned to 144), total=172 bytes.
        let signal_bytes: &[u8] = b"l\x04\x00\x01\x0c\x00\x00\x00\xff\xff\xff\xff\x8f\x00\x00\x00\x07\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x06\x01s\x00\x07\x00\x00\x00:1.2072\x00\x01\x01o\x00\x15\x00\x00\x00/org/freedesktop/DBus\x00\x00\x00\x02\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x03\x01s\x00\x0c\x00\x00\x00NameAcquired\x00\x00\x00\x00\x08\x01g\x00\x01s\x00\x00\x07\x00\x00\x00:1.2072\x00";
        // MethodReturn: body_len=12, header_array_len=63 (aligned to 64), total=92 bytes.
        let reply_bytes: &[u8] = b"l\x02\x00\x01\x0c\x00\x00\x00\xff\xff\xff\xff?\x00\x00\x00\x05\x01u\x00\x01\x00\x00\x00\x07\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x06\x01s\x00\x07\x00\x00\x00:1.2072\x00\x08\x01g\x00\x01s\x00\x00\x07\x00\x00\x00:1.2072\x00";

        let (a, b) = socket::socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();

        let mut combined = signal_bytes.to_vec();
        combined.extend_from_slice(reply_bytes);
        socket::send(a.as_raw_fd(), &combined, socket::MsgFlags::empty()).unwrap();

        let conn = DbusConnection::for_test(b.as_raw_fd());

        let first = conn.read_one_message().unwrap();
        assert_eq!(first, signal_bytes);

        let second = conn.read_one_message().unwrap();
        assert_eq!(second, reply_bytes);
    }
}
