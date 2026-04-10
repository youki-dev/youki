use std::num::ParseIntError;

#[derive(thiserror::Error, Debug)]
pub enum SystemdClientError {
    #[error("dbus error: {0}")]
    DBus(#[from] DbusError),
    #[error("failed to start transient unit {unit_name}, parent is {parent}: {err}")]
    FailedTransient {
        err: Box<SystemdClientError>,
        unit_name: String,
        parent: String,
    },
    #[error("failed to stop unit {unit_name}: {err}")]
    FailedStop {
        err: Box<SystemdClientError>,
        unit_name: String,
    },
    #[error("failed to set properties for unit {unit_name}: {err}")]
    FailedProperties {
        err: Box<SystemdClientError>,
        unit_name: String,
    },
    #[error("could not parse systemd version: {0}")]
    SystemdVersion(ParseIntError),
}

#[derive(thiserror::Error, Debug)]
pub enum DbusError {
    #[error("dbus authentication error: {0}")]
    AuthenticationErr(String),
    #[error("dbus implementation is incomplete: {0}")]
    IncompleteImplementation(String),
    #[error("dbus incorrect message: {0}")]
    IncorrectMessage(String),
    #[error("dbus connection error: {0}")]
    ConnectionError(String),
    #[error("dbus deserialization error: {0}")]
    DeserializationError(String),
    #[error("dbus function call error: {0}")]
    MethodCallErr(String),
    #[error("dbus resource busy error: {0}")]
    DeviceOrResourceBusy(String),
    #[error("dbus bus address error: {0}")]
    BusAddressError(String),
    #[error("dbus busctl error")]
    BusctlError(String),
    #[error("could not parse uid from busctl: {0}")]
    UidError(ParseIntError),
}

pub type Result<T> = std::result::Result<T, SystemdClientError>;

impl From<nix::Error> for SystemdClientError {
    fn from(err: nix::Error) -> SystemdClientError {
        DbusError::ConnectionError(err.to_string()).into()
    }
}

/// adjusts the padding in buffer to given alignment
/// by appending 0 to the buffer
pub fn adjust_padding(buf: &mut Vec<u8>, align: usize) {
    if align == 1 {
        return; // no padding is required for 1-alignment
    }
    let len = buf.len();
    let required_padding = (align - (len % align)) % align;
    for _ in 0..required_padding {
        buf.push(0);
    }
}

/// aligns the counter to given alignment
pub fn align_counter(ctr: &mut usize, align: usize) {
    if *ctr % align != 0 {
        // adjust counter for align
        *ctr += (align - (*ctr % align)) % align;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_adjust_padding() {
        let mut buf = vec![];
        // we need to specifically define this,
        // assert_eq gives error with vec![]
        let empty_buf: Vec<u8> = vec![];

        // empty buffer is all aligned
        adjust_padding(&mut buf, 1);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf, empty_buf);
        adjust_padding(&mut buf, 3);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf, empty_buf);
        adjust_padding(&mut buf, 8);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf, empty_buf);

        let mut buf = vec![1, 2, 3, 4];

        // align 1 should never change buffer, as everything is 1 byte aligned
        adjust_padding(&mut buf, 1);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf, vec![1, 2, 3, 4]);

        // 4 aligned buffer should not have any changes
        adjust_padding(&mut buf, 4);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf, vec![1, 2, 3, 4]);

        adjust_padding(&mut buf, 3);
        assert_eq!(buf.len(), 6);
        assert_eq!(buf, vec![1, 2, 3, 4, 0, 0]);

        let mut buf = vec![1, 2, 3, 4];
        adjust_padding(&mut buf, 8);
        assert_eq!(buf.len(), 8);
        assert_eq!(buf, vec![1, 2, 3, 4, 0, 0, 0, 0]);

        let mut buf = vec![1, 2, 3];
        adjust_padding(&mut buf, 4);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf, vec![1, 2, 3, 0]);
    }

    #[test]
    fn test_align_counter() {
        let mut ctr = 0;

        // 0 counter is always aligned
        align_counter(&mut ctr, 1);
        assert_eq!(ctr, 0);
        align_counter(&mut ctr, 2);
        assert_eq!(ctr, 0);
        align_counter(&mut ctr, 4);
        assert_eq!(ctr, 0);

        ctr = 3;
        align_counter(&mut ctr, 2);
        assert_eq!(ctr, 4);
        ctr = 3;
        align_counter(&mut ctr, 4);
        assert_eq!(ctr, 4);
        ctr = 3;
        align_counter(&mut ctr, 8);
        assert_eq!(ctr, 8);

        ctr = 4;
        align_counter(&mut ctr, 4);
        assert_eq!(ctr, 4);

        ctr = 4;
        align_counter(&mut ctr, 2);
        assert_eq!(ctr, 4);
    }
}
