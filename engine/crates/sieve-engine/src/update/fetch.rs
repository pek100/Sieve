//! The fetch seam. The engine fetches by a bare file name from its one compiled
//! host; the cap comes from the signed index, or from a fixed bound before the
//! index is known, so a hostile host cannot fill the disk.

use std::path::Path;

/// Why a fetch did not produce a file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    #[error("{0}")]
    Network(String),
    #[error("{0} is over its size limit")]
    OverCap(String),
    /// The host answered and does not have it: a missing signature is a
    /// refusal, not a network failure.
    #[error("{0} is not on the update host")]
    NotFound(String),
}

pub trait Fetcher: Send {
    /// Streams the file to `dest`. Past `max_bytes` the transfer is cut and
    /// [`FetchError::OverCap`] returned, and `dest` may hold the part read.
    fn get(&self, file: &str, max_bytes: u64, dest: &Path) -> Result<(), FetchError>;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A catalogue in memory. Counts calls, so a test can prove none happened.
    #[derive(Clone, Default)]
    pub struct FakeHost {
        pub files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        pub calls: Arc<AtomicUsize>,
        pub down: Arc<Mutex<bool>>,
    }

    impl FakeHost {
        pub fn put(&self, name: &str, bytes: impl Into<Vec<u8>>) {
            self.files.lock().unwrap().insert(name.to_string(), bytes.into());
        }

        pub fn call_count(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl Fetcher for FakeHost {
        fn get(&self, file: &str, max_bytes: u64, dest: &Path) -> Result<(), FetchError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if *self.down.lock().unwrap() {
                return Err(FetchError::Network("host unreachable".into()));
            }
            let files = self.files.lock().unwrap();
            let bytes = files.get(file).ok_or_else(|| FetchError::NotFound(file.to_string()))?;
            let cap = usize::try_from(max_bytes).unwrap_or(usize::MAX);
            std::fs::write(dest, &bytes[..bytes.len().min(cap)]).map_err(|e| FetchError::Network(e.to_string()))?;
            if bytes.len() > cap { Err(FetchError::OverCap(file.to_string())) } else { Ok(()) }
        }
    }
}
