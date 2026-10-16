//! Per-process connection source (plan row 78, slice S1).
//!
//! S1 implements `snapshot()` here with the read-only IP Helper tables
//! (GetExtendedTcpTable / GetExtendedUdpTable) and process image names.
//! Until then it fails loud: an error, never an empty or invented snapshot.

use crate::protocol::Snapshot;

#[derive(Debug, thiserror::Error)]
pub enum NetstatError {
    #[error("the connection reader is not implemented yet (slice S1)")]
    NotImplemented,
}

/// Take one snapshot of the machine's sockets and their owning processes.
pub fn snapshot() -> Result<Snapshot, NetstatError> {
    Err(NetstatError::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_fails_loud_until_implemented() {
        let err = snapshot().expect_err("must not return data before S1");
        assert!(err.to_string().contains("not implemented"));
    }
}
