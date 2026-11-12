use crate::wire::Status;

/// Everything a link operation can fail with.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// No link to the hub, and the device's hub-down setting is STOP.
    #[error("the hub is not reachable (hub-down setting: stop)")]
    HubDown,
    /// The hub answered and refused the stream.
    #[error("the hub refused: {status:?}: {message}")]
    Refused { status: Status, message: String },
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("pairing: {0}")]
    Pairing(String),
    #[error("store: {0}")]
    Store(String),
    #[error("timed out: {0}")]
    Timeout(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<rustls::Error> for LinkError {
    fn from(e: rustls::Error) -> Self {
        LinkError::Tls(e.to_string())
    }
}

impl From<crate::wire::WireError> for LinkError {
    fn from(e: crate::wire::WireError) -> Self {
        match e {
            crate::wire::WireError::Io(io) => LinkError::Io(io),
            other => LinkError::Protocol(other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, LinkError>;
