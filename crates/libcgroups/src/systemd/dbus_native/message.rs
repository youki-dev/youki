use super::utils::{DbusError, Result, adjust_padding, align_counter};

#[derive(Debug)]
/// Indicates the endian of message
pub enum Endian {
    Little,
    Big, // we do not support this unless explicitly requested in youki's issues
}

impl Endian {
    fn to_byte(&self) -> u8 {
        match self {
            Self::Big => b'b',
            Self::Little => b'l',
        }
    }
    fn from_byte(byte: u8) -> Self {
        match byte {
            b'l' => Self::Little,
            b'b' => Self::Big,
            _ => panic!("invalid endian {}", byte),
        }
    }
}

/// Represents the type of header data
// there are others, but these are the only once we need
#[derive(Debug, PartialEq, Eq)]
pub enum HeaderSignature {
    Object,
    U32,
    String,
    Signature,
}

impl HeaderSignature {
    fn to_byte(&self) -> u8 {
        match self {
            Self::Object => b'o',
            Self::Signature => b'g',
            Self::String => b's',
            Self::U32 => b'u',
        }
    }
    fn from_byte(byte: u8) -> Self {
        match byte {
            b'o' => Self::Object,
            b'g' => Self::Signature,
            b's' => Self::String,
            b'u' => Self::U32,
            _ => panic!("unexpected signature {}", byte),
        }
    }
}

/// Type of message
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MessageType {
    MethodCall,
    MethodReturn,
    Error,
    Signal, // we will ignore this for all intents and purposes
}

/// Represents the kind of header
#[derive(Debug, PartialEq, Eq)]
pub enum HeaderKind {
    Path,
    Interface,
    Member,
    ErrorName,
    ReplySerial,
    Destination,
    Sender,
    BodySignature,
    UnixFd, // we will not use this, just for the sake of completion
}

impl HeaderKind {
    fn signature(&self) -> HeaderSignature {
        match &self {
            Self::Path => HeaderSignature::Object,
            Self::ReplySerial => HeaderSignature::U32,
            Self::BodySignature => HeaderSignature::Signature, // this is also encoded as string, but we need special handling for how its length is encoded
            Self::UnixFd => HeaderSignature::U32,
            _ => HeaderSignature::String, // rest all are encoded as string
        }
    }
}

// This is separated from header kind, because I wanted
// HeaderKind to be u8 like directly comparable, passable thing
#[derive(Debug, PartialEq, Eq)]
pub enum HeaderValue {
    String(String),
    U32(u32),
}

impl HeaderValue {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::String(s) => {
                let mut t: Vec<u8> = s.as_bytes().into();
                t.push(0); // null byte terminator
                t
            }
            Self::U32(v) => v.to_le_bytes().into(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::String(s) => s.len(), // we don't consider terminating null byte in length
            Self::U32(_) => 4,          // u32 is encoded as 4 bytes
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: HeaderKind,
    pub value: HeaderValue,
}

impl Header {
    /// Parses a single header from given u8 vec,
    /// assuming the header to start from given counter point
    fn parse(buf: &[u8], ctr: &mut usize) -> Result<Self> {
        let header_kind = match buf[*ctr] {
            1 => HeaderKind::Path,
            2 => HeaderKind::Interface,
            3 => HeaderKind::Member,
            4 => HeaderKind::ErrorName,
            5 => HeaderKind::ReplySerial,
            6 => HeaderKind::Destination,
            7 => HeaderKind::Sender,
            8 => HeaderKind::BodySignature,
            9 => HeaderKind::UnixFd,
            v => {
                // should not occur unless we mess up parsing somewhere else
                return Err(DbusError::DeserializationError(format!(
                    "found invalid header kind value : {}",
                    v
                ))
                .into());
            }
        };

        // account for the header_kind byte
        *ctr += 1;

        // length of signature is always < 255, i.e. stored in 1 byte
        let signature_length = buf[*ctr] as usize;
        *ctr += 1;

        // we only support string, u32 signature and object,
        // all of which have signature length of 1 byte
        if signature_length != 1 {
            return Err(DbusError::IncompleteImplementation(
                "complex header type not supported".into(),
            )
            .into());
        }

        let actual_signature = HeaderSignature::from_byte(buf[*ctr]);

        // we can simply += 1, but I think this is more sensible
        *ctr += signature_length;

        let expected_signature = header_kind.signature();

        if actual_signature != expected_signature {
            return Err(DbusError::DeserializationError(format!(
                "header signature mismatch, expected {:?}, found {:?}",
                expected_signature, actual_signature
            ))
            .into());
        }

        *ctr += 1; // accounting for extra null byte that is always there

        let value = match expected_signature {
            HeaderSignature::U32 => {
                if buf.len() < *ctr + 4 {
                    return Err(DbusError::DeserializationError(
                        "incomplete response : partial header value".into(),
                    )
                    .into());
                }
                let ret = HeaderValue::U32(u32::from_le_bytes(
                    buf[*ctr..*ctr + 4].try_into().unwrap(), // we can unwrap here as we know 4 byte buffer will satisfy [u8;4]
                ));
                *ctr += 4;
                ret
            }
            // both are encoded as string
            HeaderSignature::Object | HeaderSignature::String => {
                if buf.len() < *ctr + 4 {
                    return Err(DbusError::DeserializationError(
                        "incomplete response : partial header value length".into(),
                    )
                    .into());
                }
                let len = u32::from_le_bytes(buf[*ctr..*ctr + 4].try_into().unwrap()) as usize;
                *ctr += 4;
                if buf.len() < *ctr + len {
                    return Err(DbusError::DeserializationError(
                        "incomplete response : partial header value".into(),
                    )
                    .into());
                }
                let string = String::from_utf8(buf[*ctr..*ctr + len].into()).unwrap();
                *ctr += len + 1; // +1 to account for null
                HeaderValue::String(string)
            }
            // only difference here is that length is 1 byte, not 4 bytes
            HeaderSignature::Signature => {
                let len = buf[*ctr] as usize;
                *ctr += 1;
                if buf.len() < *ctr + len {
                    return Err(DbusError::DeserializationError(
                        "incomplete response : partial header value".into(),
                    )
                    .into());
                }
                let signature = String::from_utf8(buf[*ctr..*ctr + len].into()).unwrap();
                *ctr += len + 1; //+1 to account for null byte
                HeaderValue::String(signature)
            }
        };
        Ok(Self {
            kind: header_kind,
            value,
        })
    }
}

/// Message preamble of initial 4 bytes
#[derive(Debug)]
pub struct Preamble {
    endian: Endian,
    pub mtype: MessageType,
    flags: u8,
    version: u8,
}

impl Preamble {
    fn new(mtype: MessageType) -> Self {
        Self {
            endian: Endian::Little, // we don't support big endian until requested
            mtype,
            flags: 0,   // until we need some flags to be used, this is fixed
            version: 1, // this is fixed until dbus releases a new major version
        }
    }
}

/// Represents a complete message transported over dbus connection
#[derive(Debug)]
pub struct Message {
    /// Initial 4 byte preamble needed for all messages
    pub preamble: Preamble,
    /// Serial ID of message
    pub serial: u32,
    // Message headers
    pub headers: Vec<Header>,
    /// Actual body, serialized
    pub body: Vec<u8>,
}

impl Message {
    /// create a new message structure
    pub fn new(mtype: MessageType, serial: u32, headers: Vec<Header>, body: Vec<u8>) -> Self {
        let preamble = Preamble::new(mtype);
        Self {
            preamble,
            serial,
            headers,
            body,
        }
    }
}

// NOTE that this does not add padding after last header, because we need
// non-padded header length
// the 8-byte alignment must be done separately after this
fn serialize_headers(headers: &[Header]) -> Vec<u8> {
    let mut ret = vec![];

    for header in headers {
        // all headers are always 8 byte aligned
        adjust_padding(&mut ret, 8);

        let header_kind: u8 = match &header.kind {
            HeaderKind::Path => 1,
            HeaderKind::Interface => 2,
            HeaderKind::Member => 3,
            HeaderKind::ErrorName => 4,
            HeaderKind::ReplySerial => 5,
            HeaderKind::Destination => 6,
            HeaderKind::Sender => 7,
            HeaderKind::BodySignature => 8,
            HeaderKind::UnixFd => 9,
        };

        let header_signature: u8 = header.kind.signature().to_byte();

        let signature_length = 1; // signature length is always 1 byte, and for all our headers, it is going to be 1

        // header preamble
        ret.extend_from_slice(&[header_kind, signature_length, header_signature, 0]);

        let header_value_length = header.value.len() as u32;

        // add header value length
        match &header.kind {
            HeaderKind::BodySignature => {
                // signature length is always 1 byte
                ret.push(header_value_length as u8);
            }
            HeaderKind::ReplySerial | HeaderKind::UnixFd => {
                /* do nothing as u32 does not need length appended*/
            }
            _ => {
                ret.extend_from_slice(&header_value_length.to_le_bytes());
            }
        }

        ret.extend_from_slice(&header.value.as_bytes());
    }

    ret
}

/// deserializes multiple headers from given array
fn deserialize_headers(buf: &[u8]) -> Result<Vec<Header>> {
    let mut ret = Vec::new();

    let mut ctr = 0;
    // headers are always aligned at 8 byte boundary
    align_counter(&mut ctr, 8);
    while ctr < buf.len() {
        let header = Header::parse(buf, &mut ctr)?;
        align_counter(&mut ctr, 8);
        ret.push(header);
    }
    Ok(ret)
}

impl Message {
    /// Serialize the given message into u8 vec
    pub fn serialize(mut self) -> Vec<u8> {
        let mtype = match self.preamble.mtype {
            MessageType::MethodCall => 1,
            MessageType::MethodReturn => 2,
            MessageType::Error => 3,
            MessageType::Signal => 4,
        };

        // preamble
        // Endian, message type, flags, dbus spec version
        let mut message: Vec<u8> = vec![
            self.preamble.endian.to_byte(),
            mtype,
            self.preamble.flags,
            self.preamble.version,
        ];

        // set body length
        message.extend_from_slice(&(self.body.len() as u32).to_le_bytes());

        // set id
        message.extend_from_slice(&self.serial.to_le_bytes());

        let serialized_headers = serialize_headers(&self.headers);

        // header length -  to be calculated without padding
        message.extend_from_slice(&(serialized_headers.len() as u32).to_le_bytes());
        // actual headers
        message.extend_from_slice(&serialized_headers);

        // padding to 8 byte boundary
        adjust_padding(&mut message, 8);

        // body
        message.append(&mut self.body);

        // no padding after body

        message
    }

    /// deserialize a single message from given buffer, assumed to start from given counter value
    pub fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        let endian = Endian::from_byte(buf[*counter]);

        if !matches!(endian, Endian::Little) {
            return Err(
                DbusError::IncompleteImplementation("big endian not supported".into()).into(),
            );
        }

        let mtype = match buf[*counter + 1] {
            1 => MessageType::MethodCall,
            2 => MessageType::MethodReturn,
            3 => MessageType::Error,
            4 => MessageType::Signal,
            v => {
                return Err(
                    DbusError::DeserializationError(format!("invalid message type {}", v)).into(),
                );
            }
        };

        let _flags = buf[*counter + 2]; // we basically ignore flags
        let version = buf[*counter + 3];

        if version != 1 {
            return Err(DbusError::IncompleteImplementation(
                "only dbus protocol v1 is supported".into(),
            )
            .into());
        }

        *counter += 4; // account for preamble bytes

        let preamble = Preamble::new(mtype);

        if buf.len() < *counter + 4 {
            return Err(DbusError::DeserializationError(
                "incomplete response : partial body length".into(),
            )
            .into());
        }
        let body_length =
            u32::from_le_bytes(buf[*counter..*counter + 4].try_into().unwrap()) as usize;
        *counter += 4;

        if buf.len() < *counter + 4 {
            return Err(DbusError::DeserializationError(
                "incomplete response : partial header serial".into(),
            )
            .into());
        }

        let serial = u32::from_le_bytes(buf[*counter..*counter + 4].try_into().unwrap());
        *counter += 4;

        if buf.len() < *counter + 4 {
            return Err(DbusError::DeserializationError(
                "incomplete response : partial header header array length".into(),
            )
            .into());
        }
        let header_array_length =
            u32::from_le_bytes(buf[*counter..*counter + 4].try_into().unwrap()) as usize;
        *counter += 4;

        if buf.len() < *counter + header_array_length {
            return Err(DbusError::DeserializationError(
                "incomplete response : partial header array".into(),
            )
            .into());
        }
        let headers = deserialize_headers(&buf[*counter..*counter + header_array_length])?;
        *counter += header_array_length;
        align_counter(counter, 8);

        if buf.len() < *counter + body_length {
            return Err(DbusError::DeserializationError(
                "incomplete response : partial body value".into(),
            )
            .into());
        }

        // we do not deserialize body here, and instead let the caller do it as needed
        // that way we don't have do deal with checking if the message sent id error or validating the body signature etc
        let body = Vec::from(&buf[*counter..*counter + body_length]);
        *counter += body_length;

        Ok(Self {
            preamble,
            serial,
            headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::serialize::DbusSerialize;
    use super::{Header, HeaderKind, HeaderValue, Message, MessageType, Result};
    use crate::systemd::dbus_native::serialize::{Structure, Variant};
    // The hardcoded serialized values are captured from
    // original dbus library communication
    // and manually decoded.
    // see https://github.com/YJDoc2/dbus_native/tree/2d0dbc78d067c508ccc96343673b122f0a0cb48a/raw-decoded
    #[test]
    fn test_method_call_deserialize() -> Result<()> {
        let serialized = b"l\x01\x00\x019\x00\x00\x00\x02\x00\x00\x00\xa0\x00\x00\x00\x01\x01o\x00\x19\x00\x00\x00/org/freedesktop/systemd1\x00\x00\x00\x00\x00\x00\x00\x03\x01s\x00\x03\x00\x00\x00Get\x00\x00\x00\x00\x00\x07\x01s\x00\x07\x00\x00\x00:1.1309\x00\x06\x01s\x00\x18\x00\x00\x00org.freedesktop.systemd1\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01s\x00\x1f\x00\x00\x00org.freedesktop.DBus.Properties\x00\x08\x01g\x00\x02ss\x00 \x00\x00\x00org.freedesktop.systemd1.Manager\x00\x00\x00\x00\x0c\x00\x00\x00ControlGroup\x00";

        let mut counter = 0;

        let res = Message::deserialize(serialized, &mut counter)?;
        assert_eq!(res.preamble.mtype, MessageType::MethodCall);

        let expected_headers = vec![
            Header {
                kind: HeaderKind::Path,
                value: HeaderValue::String("/org/freedesktop/systemd1".into()),
            },
            Header {
                kind: HeaderKind::Member,
                value: HeaderValue::String("Get".into()),
            },
            Header {
                kind: HeaderKind::Sender,
                value: HeaderValue::String(":1.1309".into()),
            },
            Header {
                kind: HeaderKind::Destination,
                value: HeaderValue::String("org.freedesktop.systemd1".into()),
            },
            Header {
                kind: HeaderKind::Interface,
                value: HeaderValue::String("org.freedesktop.DBus.Properties".into()),
            },
            Header {
                kind: HeaderKind::BodySignature,
                value: HeaderValue::String("ss".into()),
            },
        ];
        assert_eq!(res.headers, expected_headers);

        let mut counter = 0;
        let body = <(String, String)>::deserialize(&res.body, &mut counter)?;
        assert_eq!(body.0, "org.freedesktop.systemd1.Manager");
        assert_eq!(body.1, "ControlGroup");

        let mut body = vec![];
        (
            "org.freedesktop.systemd1.Manager".to_string(),
            "ControlGroup".to_string(),
        )
            .serialize(&mut body);

        let msg = Message::new(MessageType::MethodCall, 2, expected_headers, body);
        let actual_serialized = msg.serialize();

        assert_eq!(
            Vec::from_iter(serialized.iter().copied()),
            actual_serialized
        );

        Ok(())
    }

    #[test]
    fn test_method_reply_deserialize() -> Result<()> {
        let serialized = b"l\x02\x00\x01\x0c\x00\x00\x00\xff\xff\xff\xff?\x00\x00\x00\x05\x01u\x00\x01\x00\x00\x00\x07\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x06\x01s\x00\x07\x00\x00\x00:1.2072\x00\x08\x01g\x00\x01s\x00\x00\x07\x00\x00\x00:1.2072\x00";

        let mut counter = 0;

        let res = Message::deserialize(serialized, &mut counter)?;
        assert_eq!(res.preamble.mtype, MessageType::MethodReturn);

        let expected_headers = vec![
            Header {
                kind: HeaderKind::ReplySerial,
                value: HeaderValue::U32(1),
            },
            Header {
                kind: HeaderKind::Sender,
                value: HeaderValue::String("org.freedesktop.DBus".into()),
            },
            Header {
                kind: HeaderKind::Destination,
                value: HeaderValue::String(":1.2072".into()),
            },
            Header {
                kind: HeaderKind::BodySignature,
                value: HeaderValue::String("s".into()),
            },
        ];
        assert_eq!(res.headers, expected_headers);

        let mut counter = 0;
        let body = String::deserialize(&res.body, &mut counter)?;
        assert_eq!(body, ":1.2072");

        let mut body = vec![];
        String::from(":1.2072").serialize(&mut body);

        let msg = Message::new(MessageType::MethodReturn, u32::MAX, expected_headers, body);
        let actual_serialized = msg.serialize();

        assert_eq!(
            Vec::from_iter(serialized.iter().copied()),
            actual_serialized
        );

        Ok(())
    }

    // we don't support signals, but just checking if serialize-deserialize works
    #[test]
    fn test_signal_deserialize() -> Result<()> {
        let serialized = b"l\x04\x00\x01\x0c\x00\x00\x00\xff\xff\xff\xff\x8f\x00\x00\x00\x07\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x06\x01s\x00\x07\x00\x00\x00:1.2072\x00\x01\x01o\x00\x15\x00\x00\x00/org/freedesktop/DBus\x00\x00\x00\x02\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x03\x01s\x00\x0c\x00\x00\x00NameAcquired\x00\x00\x00\x00\x08\x01g\x00\x01s\x00\x00\x07\x00\x00\x00:1.2072\x00";

        let mut counter = 0;

        let res = Message::deserialize(serialized, &mut counter)?;
        assert_eq!(res.preamble.mtype, MessageType::Signal);

        let expected_headers = vec![
            Header {
                kind: HeaderKind::Sender,
                value: HeaderValue::String("org.freedesktop.DBus".into()),
            },
            Header {
                kind: HeaderKind::Destination,
                value: HeaderValue::String(":1.2072".into()),
            },
            Header {
                kind: HeaderKind::Path,
                value: HeaderValue::String("/org/freedesktop/DBus".into()),
            },
            Header {
                kind: HeaderKind::Interface,
                value: HeaderValue::String("org.freedesktop.DBus".into()),
            },
            Header {
                kind: HeaderKind::Member,
                value: HeaderValue::String("NameAcquired".into()),
            },
            Header {
                kind: HeaderKind::BodySignature,
                value: HeaderValue::String("s".into()),
            },
        ];
        assert_eq!(res.headers, expected_headers);

        let mut counter = 0;
        let body = String::deserialize(&res.body, &mut counter)?;
        assert_eq!(body, ":1.2072");

        let mut body = vec![];
        String::from(":1.2072").serialize(&mut body);

        let msg = Message::new(MessageType::Signal, u32::MAX, expected_headers, body);
        let actual_serialized = msg.serialize();

        assert_eq!(
            Vec::from_iter(serialized.iter().copied()),
            actual_serialized
        );

        Ok(())
    }

    #[test]
    fn test_no_body_deserialize() -> Result<()> {
        let serialized = b"l\x01\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00n\x00\x00\x00\x01\x01o\x00\x15\x00\x00\x00/org/freedesktop/DBus\x00\x00\x00\x06\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x02\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x03\x01s\x00\x05\x00\x00\x00Hello\x00\x00\x00";

        let mut counter = 0;

        let res = Message::deserialize(serialized, &mut counter)?;
        assert_eq!(res.preamble.mtype, MessageType::MethodCall);

        let expected_headers = vec![
            Header {
                kind: HeaderKind::Path,
                value: HeaderValue::String("/org/freedesktop/DBus".into()),
            },
            Header {
                kind: HeaderKind::Destination,
                value: HeaderValue::String("org.freedesktop.DBus".into()),
            },
            Header {
                kind: HeaderKind::Interface,
                value: HeaderValue::String("org.freedesktop.DBus".into()),
            },
            Header {
                kind: HeaderKind::Member,
                value: HeaderValue::String("Hello".into()),
            },
        ];
        assert_eq!(res.headers, expected_headers);

        assert!(res.body.is_empty());

        let msg = Message::new(MessageType::MethodCall, 1, expected_headers, vec![]);
        let actual_serialized = msg.serialize();

        assert_eq!(
            Vec::from_iter(serialized.iter().copied()),
            actual_serialized
        );

        Ok(())
    }

    #[test]
    fn test_error_message_deserialize() -> Result<()> {
        let serialized = b"l\x03\x00\x01\x16\x00\x00\x00\xff\xff\xff\xffw\x00\x00\x00\x05\x01u\x00\x03\x00\x00\x00\x07\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x04\x01s\x00+\x00\x00\x00org.freedesktop.DBus.Error.UnknownInterface\x00\x00\x00\x00\x00\x08\x01g\x00\x01s\x00\x00\x06\x01s\x00\x06\x00\x00\x00:1.868\x00\x00\x11\x00\x00\x00Invalid interface\x00";

        let mut counter = 0;

        let res = Message::deserialize(serialized, &mut counter)?;
        assert_eq!(res.preamble.mtype, MessageType::Error);

        let expected_headers = vec![
            Header {
                kind: HeaderKind::ReplySerial,
                value: HeaderValue::U32(3),
            },
            Header {
                kind: HeaderKind::Sender,
                value: HeaderValue::String("org.freedesktop.DBus".into()),
            },
            Header {
                kind: HeaderKind::ErrorName,
                value: HeaderValue::String("org.freedesktop.DBus.Error.UnknownInterface".into()),
            },
            Header {
                kind: HeaderKind::BodySignature,
                value: HeaderValue::String("s".into()),
            },
            Header {
                kind: HeaderKind::Destination,
                value: HeaderValue::String(":1.868".into()),
            },
        ];
        assert_eq!(res.headers, expected_headers);

        let mut counter = 0;
        let body = String::deserialize(&res.body, &mut counter)?;
        assert_eq!(body, "Invalid interface");

        let mut body = vec![];
        String::from("Invalid interface").serialize(&mut body);

        let msg = Message::new(MessageType::Error, u32::MAX, expected_headers, body);
        let actual_serialized = msg.serialize();

        assert_eq!(
            Vec::from_iter(serialized.iter().copied()),
            actual_serialized
        );

        Ok(())
    }

    #[test]
    fn test_vector_payload_deserialize() -> Result<()> {
        let serialized = b"l\x01\x00\x01\xc8\x01\x00\x00\x03\x00\x00\x00\xc6\x00\x00\x00\x01\x01o\x00\x19\x00\x00\x00\x2forg\x2ffreedesktop\x2fsystemd1\x00\x00\x00\x00\x00\x00\x00\x03\x01s\x00\x12\x00\x00\x00StartTransientUnit\x00\x00\x00\x00\x00\x00\x07\x01s\x00\x07\x00\x00\x00\x3a1\x2e1021\x00\x06\x01s\x00\x18\x00\x00\x00org\x2efreedesktop\x2esystemd1\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01s\x00\x20\x00\x00\x00org\x2efreedesktop\x2esystemd1\x2eManager\x00\x00\x00\x00\x00\x00\x00\x00\x08\x01g\x00\x10ssa\x28sv\x29a\x28sa\x28sv\x29\x29\x00\x00\x00M\x00\x00\x00libpod\x2d57f5869eaf80cee986095eebd1e0fbbbd148527f67d94f1fbe958f5bab8112f7\x2escope\x00\x00\x00\x07\x00\x00\x00replace\x00X\x01\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00Description\x00\x01s\x00\x00P\x00\x00\x00youki\x20container\x2057f5869eaf80cee986095eebd1e0fbbbd148527f67d94f1fbe958f5bab8112f7\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00Slice\x00\x01s\x00\x00\x00\x00\x0a\x00\x00\x00user\x2eslice\x00\x00\x08\x00\x00\x00Delegate\x00\x01b\x00\x01\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00MemoryAccounting\x00\x01b\x00\x01\x00\x00\x00\x00\x00\x00\x00\x0d\x00\x00\x00CPUAccounting\x00\x01b\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00IOAccounting\x00\x01b\x00\x01\x00\x00\x00\x0f\x00\x00\x00TasksAccounting\x00\x01b\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00DefaultDependencies\x00\x01b\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00PIDs\x00\x02au\x00\x00\x00\x00\x04\x00\x00\x007g\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        let mut counter = 0;

        let res = Message::deserialize(serialized, &mut counter)?;
        assert_eq!(res.preamble.mtype, MessageType::MethodCall);

        let expected_headers = vec![
            Header {
                kind: HeaderKind::Path,
                value: HeaderValue::String("/org/freedesktop/systemd1".into()),
            },
            Header {
                kind: HeaderKind::Member,
                value: HeaderValue::String("StartTransientUnit".into()),
            },
            Header {
                kind: HeaderKind::Sender,
                value: HeaderValue::String(":1.1021".into()),
            },
            Header {
                kind: HeaderKind::Destination,
                value: HeaderValue::String("org.freedesktop.systemd1".into()),
            },
            Header {
                kind: HeaderKind::Interface,
                value: HeaderValue::String("org.freedesktop.systemd1.Manager".into()),
            },
            Header {
                kind: HeaderKind::BodySignature,
                value: HeaderValue::String("ssa(sv)a(sa(sv))".into()),
            },
        ];
        assert_eq!(res.headers, expected_headers);

        let mut counter = 0;

        let (name, mode, props, aux) = <(
            String,
            String,
            Vec<Structure<Variant>>,
            Vec<Structure<Vec<Structure<Variant>>>>,
        )>::deserialize(&res.body, &mut counter)?;

        let expected_name =
            "libpod-57f5869eaf80cee986095eebd1e0fbbbd148527f67d94f1fbe958f5bab8112f7.scope"
                .to_string();

        assert_eq!(name, expected_name);

        let expected_mode = "replace".to_string();
        assert_eq!(mode, expected_mode);

        let expected_aux = vec![];
        assert_eq!(aux, expected_aux);

        let expected_props = vec![Structure::new(
            "Description".into(),
            Variant::String(
                "youki container 57f5869eaf80cee986095eebd1e0fbbbd148527f67d94f1fbe958f5bab8112f7"
                    .into(),
            ),
        ),
        Structure::new("Slice".into(), Variant::String("user.slice".into())),
        Structure::new("Delegate".into(), Variant::Bool(true)),
        Structure::new("MemoryAccounting".into(), Variant::Bool(true)),
        Structure::new("CPUAccounting".into(), Variant::Bool(true)),
        Structure::new("IOAccounting".into(), Variant::Bool(true)),
        Structure::new("TasksAccounting".into(), Variant::Bool(true)),
        Structure::new("DefaultDependencies".into(), Variant::Bool(false)),
        Structure::new("PIDs".into(),Variant::ArrayU32(vec![26423]))
        ];

        assert_eq!(props, expected_props);

        let mut body = vec![];
        (expected_name, expected_mode, expected_props, expected_aux).serialize(&mut body);

        let msg = Message::new(MessageType::MethodCall, 3, expected_headers, body);
        let actual_serialized = msg.serialize();

        assert_eq!(
            Vec::from_iter(serialized.iter().copied()),
            actual_serialized
        );

        Ok(())
    }
}
