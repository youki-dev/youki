use super::dbus::DbusConnection;
use super::message::*;
use super::serialize::{DbusSerialize, Structure, Variant};
use super::utils::{DbusError, Result};

/// Structure to conveniently communicate with
/// given destination and path for method calls
pub struct Proxy<'conn> {
    conn: &'conn DbusConnection,
    dest: String,
    path: String,
}

// helper method to check compatibility between
// actual signature of received reply and expected signature
// we have to do this, as we don't have dedicated type
// for object path
fn check_signature_compatibility(actual: &str, expected: &str) -> bool {
    if actual == expected {
        return true;
    }
    // we don't consider signature (g) here as :
    // 1. length encoding is different than string, so cannot be deserialized by String::deserialize
    // 2. currently we don't expect any method to return signature, so we can get away with this
    if expected == "s" && matches!(actual, "s" | "o") {
        return true;
    }

    false
}

impl<'conn> Proxy<'conn> {
    /// create a new proxy for given destination and path over given connection
    pub fn new(conn: &'conn DbusConnection, dest: &str, path: &str) -> Self {
        Self {
            conn,
            dest: dest.into(),
            path: path.into(),
        }
    }

    /// Do a method call for given interface and member by sending given body
    /// If no body is to be sent, set it as `None`
    pub fn method_call<Body: DbusSerialize, Output: DbusSerialize>(
        &self,
        interface: &str,
        member: &str,
        body: Option<Body>,
    ) -> Result<Output> {
        tracing::trace!("dbus call at interface {} member {}", interface, member);
        let mut headers = Vec::with_capacity(4);

        // create necessary headers
        headers.push(Header {
            kind: HeaderKind::Path,
            value: HeaderValue::String(self.path.clone()),
        });
        headers.push(Header {
            kind: HeaderKind::Destination,
            value: HeaderValue::String(self.dest.clone()),
        });
        headers.push(Header {
            kind: HeaderKind::Interface,
            value: HeaderValue::String(interface.to_string()),
        });
        headers.push(Header {
            kind: HeaderKind::Member,
            value: HeaderValue::String(member.to_string()),
        });

        let mut serialized_body = vec![];

        // if there is some body, serialize it, and set the
        // body signature header accordingly
        if let Some(v) = body {
            headers.push(Header {
                kind: HeaderKind::BodySignature,
                value: HeaderValue::String(Body::get_signature()),
            });
            v.serialize(&mut serialized_body);
        }

        // send the message and get response
        let reply_messages =
            self.conn
                .send_message(MessageType::MethodCall, headers, serialized_body)?;

        // check if there is any error message
        let error_message: Vec<_> = reply_messages
            .iter()
            .filter(|m| m.preamble.mtype == MessageType::Error)
            .collect();

        // if any error, return error
        if !error_message.is_empty() {
            let msg = error_message[0];
            if msg.body.is_empty() {
                // this should rarely be the case
                return Err(DbusError::MethodCallErr("Unknown Dbus Error".into()).into());
            } else {
                // in error message, first item of the body (if present) is always a string
                // indicating the error
                let mut ctr = 0;
                let msg = String::deserialize(&msg.body, &mut ctr)?;
                return Err(DbusError::MethodCallErr(msg).into());
            }
        }

        // we basically ignore all type of messages apart from method return
        let reply: Vec<_> = reply_messages
            .iter()
            .filter(|m| m.preamble.mtype == MessageType::MethodReturn)
            .collect();

        // we are only going to consider first reply, cause... so.
        // realistically there should only be at most one method return type of message
        // for a method call
        let reply = reply.first().ok_or(DbusError::MethodCallErr(format!(
            "expected to get a reply for method call, got {:?} instead",
            reply_messages
        )))?;

        let headers = &reply.headers;
        let expected_signature = Output::get_signature();

        // get the signature header
        let signature_header: Vec<_> = headers
            .iter()
            .filter(|h| h.kind == HeaderKind::BodySignature)
            .collect();

        // This is also something that should never happen
        // we just check this defensively
        if signature_header.is_empty() && !reply.body.is_empty() {
            return Err(DbusError::MethodCallErr(
                "Body non empty, but body signature header missing".to_string(),
            )
            .into());
        }

        if expected_signature == *"" {
            // This is for the case when there is no body, i.e. Output = ()
            // we must do this as the signature header will be
            // absent in that case, so instead we choose to
            // parse and return early
            // This is a bit hacky, but works
            let mut ctr = 0;
            return Output::deserialize(&[], &mut ctr);
        }

        let actual_signature = match &signature_header[0].value {
            HeaderValue::String(s) => s,
            _ => unreachable!("body signature header will always be string type"),
        };

        // check that signature returned and type we are trying to deserialize
        // match as expected
        if !check_signature_compatibility(actual_signature, &expected_signature) {
            return Err(DbusError::DeserializationError(format!(
                "reply signature mismatch : expected {}, found {} : \n{:?}",
                expected_signature, actual_signature, reply.body
            ))
            .into());
        }

        let mut ctr = 0;
        Output::deserialize(&reply.body, &mut ctr)
    }

    pub fn get_unit(&mut self, name: &str) -> Result<String> {
        self.method_call(
            "org.freedesktop.systemd1.Manager",
            "GetUnit",
            Some(name.to_string()),
        )
    }

    // Note that because we do not listen to the jobRemoved signal
    // similar to runc, it is possible that when this method returns
    // the unit is not yet started, however, because we do expect a reply
    // (according to message flags we send), it is possible that dbus only returns
    // after unit is started. Need to investigate more
    pub fn start_transient_unit(
        &self,
        name: &str,
        mode: &str,
        properties: Vec<Structure<Variant>>,
        aux: Vec<Structure<Vec<Structure<Variant>>>>,
    ) -> Result<String> {
        self.method_call(
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
            Some((name, mode, properties, aux)),
        )
    }

    pub fn stop_unit(&self, name: &str, mode: &str) -> Result<String> {
        self.method_call(
            "org.freedesktop.systemd1.Manager",
            "StopUnit",
            Some((name, mode)),
        )
    }

    pub fn set_unit_properties(
        &self,
        name: &str,
        runtime: bool,
        properties: Vec<Structure<Variant>>,
    ) -> Result<()> {
        self.method_call(
            "org.freedesktop.systemd1.Manager",
            "SetUnitProperties",
            Some((name, runtime, properties)),
        )
    }

    pub fn version(&self) -> Result<String> {
        let t = self.method_call::<_, Variant>(
            "org.freedesktop.DBus.Properties",
            "Get",
            Some(("org.freedesktop.systemd1.Manager", "Version")),
        )?;
        match t {
            Variant::String(s) => Ok(s),
            v => panic!("version expected string variant, got {:?} instead", v),
        }
    }

    pub fn control_group(&self) -> Result<String> {
        let t = self.method_call::<_, Variant>(
            "org.freedesktop.DBus.Properties",
            "Get",
            Some((
                "org.freedesktop.systemd1.Manager".to_string(),
                "ControlGroup".to_string(),
            )),
        )?;
        match t {
            Variant::String(s) => Ok(s),
            v => panic!("control group expected string variant, got {:?} instead", v),
        }
    }
    pub fn attach_process(&self, name: &str, cgroup: &str, pid: u32) -> Result<()> {
        self.method_call::<_, ()>(
            "org.freedesktop.systemd1.Manager",
            "AttachProcessesToUnit",
            Some((name, cgroup, vec![pid])),
        )
    }
}
