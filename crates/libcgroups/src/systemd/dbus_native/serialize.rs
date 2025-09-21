use super::utils::{adjust_padding, align_counter, DbusError, Result};

/// This indicates that given type can be serialized as dbus
/// message body, and has methods needed for that
pub trait DbusSerialize: std::fmt::Debug {
    /// Provide signature for the given type in the dbus signature format
    fn get_signature() -> String
    where
        Self: Sized;

    fn get_alignment() -> usize;
    /// Serialize the given type into given buffer
    /// This needs to adjust padding before starting serialization, but must not
    /// pad after last byte of serialized value
    fn serialize(&self, buf: &mut Vec<u8>);
    /// Deserialize the type from given buffer
    /// The trait implementation must adjust the counter to required padding boundary
    /// before starting deserialization, as the counter can be unaligned for the given type.
    /// The caller must have verified that the buffer actually
    /// contains the given type's value, so this method does not need to do that.
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self>
    where
        Self: Sized;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Variant {
    // D-Bus data type
    // s
    String(String),
    // b
    Bool(bool),
    // t
    U64(u64),
    // au
    ArrayU32(Vec<u32>),
    // at
    ArrayU64(Vec<u64>),
    // a(st)
    ArrayStructU64(Vec<Structure<u64>>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Structure<T: DbusSerialize> {
    key: String,
    val: T,
}

impl<T: DbusSerialize> Structure<T> {
    pub fn new(key: String, val: T) -> Self {
        Self { key, val }
    }
}

impl DbusSerialize for () {
    fn get_signature() -> String {
        String::new()
    }
    fn get_alignment() -> usize {
        1
    }
    fn serialize(&self, _: &mut Vec<u8>) {}
    // for (), we have to ignore body , so we simply clear it out
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        *counter = buf.len();
        Ok(())
    }
}

impl<T1: DbusSerialize, T2: DbusSerialize> DbusSerialize for (T1, T2) {
    fn get_signature() -> String {
        format!("{}{}", T1::get_signature(), T2::get_signature())
    }
    fn get_alignment() -> usize {
        T1::get_alignment()
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        self.0.serialize(buf);
        self.1.serialize(buf);
    }
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        let t1 = T1::deserialize(buf, counter)?;
        let t2 = T2::deserialize(buf, counter)?;
        Ok((t1, t2))
    }
}

impl<T1: DbusSerialize, T2: DbusSerialize, T3: DbusSerialize, T4: DbusSerialize> DbusSerialize
    for (T1, T2, T3, T4)
{
    fn get_signature() -> String {
        format!(
            "{}{}{}{}",
            T1::get_signature(),
            T2::get_signature(),
            T3::get_signature(),
            T4::get_signature()
        )
    }
    fn get_alignment() -> usize {
        T1::get_alignment()
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        self.0.serialize(buf);
        self.1.serialize(buf);
        self.2.serialize(buf);
        self.3.serialize(buf);
    }
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        let t1 = T1::deserialize(buf, counter)?;
        let t2 = T2::deserialize(buf, counter)?;
        let t3 = T3::deserialize(buf, counter)?;
        let t4 = T4::deserialize(buf, counter)?;
        Ok((t1, t2, t3, t4))
    }
}

impl<T1: DbusSerialize, T2: DbusSerialize, T3: DbusSerialize> DbusSerialize for (T1, T2, T3) {
    fn get_signature() -> String {
        format!(
            "{}{}{}",
            T1::get_signature(),
            T2::get_signature(),
            T3::get_signature(),
        )
    }
    fn get_alignment() -> usize {
        T1::get_alignment()
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        self.0.serialize(buf);
        self.1.serialize(buf);
        self.2.serialize(buf);
    }
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        let t1 = T1::deserialize(buf, counter)?;
        let t2 = T2::deserialize(buf, counter)?;
        let t3 = T3::deserialize(buf, counter)?;
        Ok((t1, t2, t3))
    }
}

impl DbusSerialize for &str {
    fn get_signature() -> String {
        "s".to_string()
    }
    fn get_alignment() -> usize {
        String::get_alignment()
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        adjust_padding(buf, 4);
        let length = self.len() as u32;
        buf.extend_from_slice(&length.to_le_bytes());

        buf.extend_from_slice(self.as_bytes());
        buf.push(0); // needs to be null terminated
    }
    fn deserialize(_: &[u8], _: &mut usize) -> Result<Self> {
        Err(
            DbusError::IncompleteImplementation("&str does not support deserialization".into())
                .into(),
        )
    }
}

impl DbusSerialize for String {
    fn get_signature() -> String {
        "s".to_string()
    }
    fn get_alignment() -> usize {
        4 // string length is u32
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        adjust_padding(buf, 4);
        let length = self.len() as u32;
        buf.extend_from_slice(&length.to_le_bytes());

        buf.extend_from_slice(self.as_bytes());
        buf.push(0); // needs to be null terminated
    }
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        align_counter(counter, 4);
        if buf.len() < *counter + 4 {
            return Err(DbusError::DeserializationError(
                "incomplete string response : missing length".into(),
            )
            .into());
        }
        let length = u32::from_le_bytes(buf[*counter..*counter + 4].try_into().unwrap()) as usize;
        *counter += 4;
        if buf.len() < *counter + length {
            return Err(DbusError::DeserializationError(
                "incomplete string response : missing partial string".into(),
            )
            .into());
        }
        let ret = String::from_utf8((&buf[*counter..*counter + length]).into()).unwrap();
        *counter += length + 1; // +1 accounting for null
        Ok(ret)
    }
}

impl DbusSerialize for bool {
    fn get_signature() -> String {
        "b".to_string()
    }
    fn get_alignment() -> usize {
        4
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        adjust_padding(buf, 4);
        let val: u32 = match self {
            true => 1,
            false => 0,
        };
        buf.extend_from_slice(&val.to_le_bytes());
    }
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        align_counter(counter, 4);
        if buf.len() < *counter + 4 {
            return Err(DbusError::DeserializationError(
                "incomplete bool response : partial response".into(),
            )
            .into());
        }
        let ret = u32::from_le_bytes(buf[*counter..*counter + 4].try_into().unwrap());
        *counter += 4;
        Ok(ret != 0)
    }
}

impl DbusSerialize for u8 {
    fn get_signature() -> String {
        "y".to_string()
    }
    fn get_alignment() -> usize {
        1
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        adjust_padding(buf, 1);
        buf.extend_from_slice(&self.to_le_bytes());
    }
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        align_counter(counter, 1);
        if buf.len() < *counter + 1 {
            return Err(DbusError::DeserializationError(
                "incomplete u8 response : partial response".into(),
            )
            .into());
        }
        let ret = u8::from_le_bytes(buf[*counter..*counter + 1].try_into().unwrap());
        *counter += 1;
        Ok(ret)
    }
}

impl DbusSerialize for u16 {
    fn get_signature() -> String {
        "q".to_string()
    }
    fn get_alignment() -> usize {
        2
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        adjust_padding(buf, 2);
        buf.extend_from_slice(&self.to_le_bytes());
    }
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        align_counter(counter, 2);
        if buf.len() < *counter + 2 {
            return Err(DbusError::DeserializationError(
                "incomplete u16 response : partial response".into(),
            )
            .into());
        }
        let ret = u16::from_le_bytes(buf[*counter..*counter + 2].try_into().unwrap());
        *counter += 2;
        Ok(ret)
    }
}

impl DbusSerialize for u32 {
    fn get_signature() -> String {
        "u".to_string()
    }
    fn get_alignment() -> usize {
        4
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        adjust_padding(buf, 4);
        buf.extend_from_slice(&self.to_le_bytes());
    }
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        align_counter(counter, 4);
        if buf.len() < *counter + 4 {
            return Err(DbusError::DeserializationError(
                "incomplete u32 response : partial response".into(),
            )
            .into());
        }
        let ret = u32::from_le_bytes(buf[*counter..*counter + 4].try_into().unwrap());
        *counter += 4;
        Ok(ret)
    }
}

impl DbusSerialize for u64 {
    fn get_signature() -> String {
        "t".to_string()
    }
    fn get_alignment() -> usize {
        8
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        adjust_padding(buf, 8);
        buf.extend_from_slice(&self.to_le_bytes());
    }
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        align_counter(counter, 8);
        if buf.len() < *counter + 8 {
            return Err(DbusError::DeserializationError(
                "incomplete u64 response : partial response".into(),
            )
            .into());
        }
        let ret = u64::from_le_bytes(buf[*counter..*counter + 8].try_into().unwrap());
        *counter += 8;
        Ok(ret)
    }
}

impl<T: DbusSerialize> DbusSerialize for Vec<T> {
    fn get_signature() -> String {
        let sub_type = T::get_signature();
        format!("a{}", sub_type)
    }
    fn get_alignment() -> usize {
        4 // for the length u32
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        adjust_padding(buf, 4);

        let mut temp_buf = Vec::new();
        for elem in self.iter() {
            elem.serialize(&mut temp_buf);
        }
        let len = temp_buf.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        let align = T::get_alignment();
        adjust_padding(buf, align);
        buf.extend_from_slice(&temp_buf);
    }
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        align_counter(counter, 4);

        if buf.len() < *counter + 4 {
            return Err(DbusError::DeserializationError(
                "incomplete array response : partial length".into(),
            )
            .into());
        }

        let length_in_bytes =
            u32::from_le_bytes(buf[*counter..*counter + 4].try_into().unwrap()) as usize;
        *counter += 4;

        let end = *counter + length_in_bytes;

        if buf.len() < end {
            return Err(DbusError::DeserializationError(
                "incomplete array response : partial elements".into(),
            )
            .into());
        }

        let mut ret = Vec::new();

        while *counter < end {
            let elem = T::deserialize(buf, counter)?;
            ret.push(elem);
        }
        Ok(ret)
    }
}

impl<T: DbusSerialize> DbusSerialize for Structure<T> {
    fn get_signature() -> String {
        let val_sign = T::get_signature();
        format!("(s{})", val_sign)
    }
    fn get_alignment() -> usize {
        8
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        adjust_padding(buf, 8);
        self.key.serialize(buf);
        self.val.serialize(buf);
    }
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        align_counter(counter, 8);
        let key = String::deserialize(buf, counter)?;
        let val = T::deserialize(buf, counter)?;
        Ok(Self { key, val })
    }
}

impl DbusSerialize for Variant {
    fn get_signature() -> String {
        "v".to_string()
    }
    fn get_alignment() -> usize {
        1 // the signature comes first, which is 1 aligned
    }
    fn serialize(&self, buf: &mut Vec<u8>) {
        // no alignment needed, as variant is 1-align
        match self {
            Self::String(s) => {
                let sub_type = String::get_signature();
                let signature_length = sub_type.len() as u8; // signature length must be < 256
                buf.push(signature_length);
                buf.extend_from_slice(sub_type.as_bytes());
                buf.push(0);
                s.serialize(buf);
            }
            Self::ArrayU32(v) => {
                let sub_type = <Vec<u32>>::get_signature();
                let signature_length = sub_type.len() as u8; // signature length must be < 256
                buf.push(signature_length);
                buf.extend_from_slice(sub_type.as_bytes());
                buf.push(0);
                v.serialize(buf);
            }
            Self::ArrayU64(v) => {
                let sub_type = <Vec<u64>>::get_signature();
                let signature_length = sub_type.len() as u8; // signature length must be < 256
                buf.push(signature_length);
                buf.extend_from_slice(sub_type.as_bytes());
                buf.push(0);
                v.serialize(buf);
            }
            Self::Bool(b) => {
                let sub_type = bool::get_signature();
                let signature_length = sub_type.len() as u8; // signature length must be < 256
                buf.push(signature_length);
                buf.extend_from_slice(sub_type.as_bytes());
                buf.push(0);
                b.serialize(buf);
            }
            Self::U64(v) => {
                let sub_type = u64::get_signature();
                let signature_length = sub_type.len() as u8; // signature length must be < 256
                buf.push(signature_length);
                buf.extend_from_slice(sub_type.as_bytes());
                buf.push(0);
                v.serialize(buf);
            }
            Self::ArrayStructU64(s) => {
                let sub_type = <Vec<Structure<u64>>>::get_signature();
                let signature_length = sub_type.len() as u8;
                buf.push(signature_length);
                buf.extend_from_slice(sub_type.as_bytes());
                buf.push(0);
                s.serialize(buf);
            }
        }
    }
    fn deserialize(buf: &[u8], counter: &mut usize) -> Result<Self> {
        align_counter(counter, 1);

        let signature_length = buf[*counter] as usize;
        *counter += 1;

        if buf.len() < *counter + signature_length {
            return Err(DbusError::DeserializationError(
                "incomplete variant response : partial signature".into(),
            )
            .into());
        }
        let signature =
            String::from_utf8(buf[*counter..*counter + signature_length].into()).unwrap();

        *counter += signature_length + 1; // +1 for null byte

        let string_signature = String::get_signature();
        let bool_signature = bool::get_signature();
        let vec32_signature = <Vec<u32>>::get_signature();
        let vec64_signature = <Vec<u64>>::get_signature();
        let u64_signature = u64::get_signature();
        let vec_struct_u64_signature = <Vec<Structure<u64>>>::get_signature();
        if signature == string_signature {
            Ok(Self::String(String::deserialize(buf, counter)?))
        } else if signature == bool_signature {
            Ok(Self::Bool(bool::deserialize(buf, counter)?))
        } else if signature == vec32_signature {
            Ok(Self::ArrayU32(<Vec<u32>>::deserialize(buf, counter)?))
        } else if signature == vec64_signature {
            Ok(Self::ArrayU64(<Vec<u64>>::deserialize(buf, counter)?))
        } else if signature == u64_signature {
            Ok(Self::U64(u64::deserialize(buf, counter)?))
        } else if signature == vec_struct_u64_signature {
            Ok(Self::ArrayStructU64(<Vec<Structure<u64>>>::deserialize(
                buf, counter,
            )?))
        } else {
            return Err(DbusError::IncompleteImplementation(format!(
                "unsupported value signature {}",
                signature
            ))
            .into());
        }
    }
}
