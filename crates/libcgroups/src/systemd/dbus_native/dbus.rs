use std::collections::HashMap;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use nix::errno::Errno;
use nix::sys::socket;

use super::client::SystemdClient;
use super::message::*;
use super::proxy::Proxy;
use super::utils::{DbusError, Result, SystemdClientError};
use crate::systemd::dbus_native::serialize::{DbusSerialize, Structure, Variant};

const REPLY_BUF_SIZE: usize = 128; // seems good enough tradeoff between extra size and repeated calls

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
    /// Open a new dbus connection to given address
    /// authenticating as user with given uid
    pub fn new(addr: &str, uid: u32, system: bool) -> Result<Self> {
        // Use ManuallyDrop to keep the socket open.
        let socket = std::mem::ManuallyDrop::new(socket::socket(
            socket::AddressFamily::Unix,
            socket::SockType::Stream,
            socket::SockFlag::empty(),
            None,
        )?);

        let addr = socket::UnixAddr::new(addr)?;
        socket::connect(socket.as_raw_fd(), &addr)?;
        let mut dbus = Self {
            socket: socket.as_raw_fd(),
            msg_ctr: AtomicU32::new(0),
            id: None,
            system,
        };
        dbus.authenticate(uid)?;
        Ok(dbus)
    }

    pub fn new_system() -> Result<Self> {
        let addr = get_system_bus_address()?;
        Self::new(&addr, 0, true)
    }

    pub fn new_session() -> Result<Self> {
        let addr = get_session_bus_address()?;
        let uid = get_actual_uid()?;
        Self::new(&addr, uid, false)
    }

    /// Authenticates with dbus using given uid via external strategy
    /// Must be called on any connection before doing any other communication
    fn authenticate(&mut self, uid: u32) -> Result<()> {
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

    /// Helper function to get complete message in chunks
    /// over the socket. This will loop and collect all of the message
    /// chunks into a single vector
    fn receive_complete_response(&self) -> Result<Vec<u8>> {
        let mut ret = Vec::with_capacity(512);
        loop {
            let mut reply: [u8; REPLY_BUF_SIZE] = [0_u8; REPLY_BUF_SIZE];
            let mut reply_buffer = [IoSliceMut::new(&mut reply[0..])];

            let reply_res = socket::recvmsg::<()>(
                self.socket,
                &mut reply_buffer,
                None,
                socket::MsgFlags::empty(),
            );

            let reply_rcvd = match reply_res {
                Ok(msg) => msg,
                Err(Errno::EAGAIN) => continue,
                Err(e) => return Err(e.into()),
            };
            let received_byte_count = reply_rcvd.bytes;

            ret.extend_from_slice(&reply[0..received_byte_count]);

            if received_byte_count < REPLY_BUF_SIZE {
                // if received byte count is less than buffer size, then we got all
                break;
            }
        }
        Ok(ret)
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

        // it is possible that while receiving messages, we get some extra/previous message
        // for method calls, we need to have an error or method return type message, so
        // we keep looping until we get either of these. see https://github.com/containers/youki/issues/2826
        // for more detailed analysis.
        loop {
            let reply = self.receive_complete_response()?;

            // note that a single received response can contain multiple
            // messages, so we must deserialize it piece by piece
            let mut buf = &reply[..];

            while !buf.is_empty() {
                let mut ctr = 0;
                let msg = Message::deserialize(&buf[ctr..], &mut ctr)?;
                // we reset the buf, because I couldn't figure out how the adjust_counter function
                // should should be changed to work correctly with non-zero start counter, and this solved that issue
                buf = &buf[ctr..];
                ret.push(msg);
            }

            // in Youki, we only ever do method call apart from initial auth
            // in case it is, we don't really have a specific message to look
            // out of, so we take the buffer and break
            if mtype != MessageType::MethodCall {
                break;
            }

            // check if any of the received message is method return or error type
            let return_message_count = ret
                .iter()
                .filter(|m| {
                    m.preamble.mtype == MessageType::MethodReturn
                        || m.preamble.mtype == MessageType::Error
                })
                .count();

            if return_message_count > 0 {
                break;
            }
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
mod tests {
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
    fn test_dbus_connection_auth() {
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
}
