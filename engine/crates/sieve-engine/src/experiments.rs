//! Restart-only diagnostic settings. This entire module is feature gated.

use std::path::Path;
use serde::{Deserialize, Serialize};

pub const FILE: &str = "experiments.json";
// Tokio io::copy documents this default for the pinned dependency. The
// copy_default_matches_tokio test probes it so an upgrade cannot misreport it.
pub const DEFAULT_COPY_BYTES: usize = 8 * 1024;
// Bounds are the experiment contract. MTU's lower bound is IPv6's minimum
// (RFC 8200), its upper bound is Wintun's u16 packet length. The remaining
// bounds limit the resources a diagnostic file can request, not traffic.
pub const MTU_MIN: usize = 1280;
pub const MTU_MAX: usize = u16::MAX as usize;
pub const COPY_MIN: usize = 8 * 1024;
pub const COPY_MAX: usize = 1024 * 1024;
pub const BATCH_MIN: usize = 1;
pub const BATCH_MAX: usize = 256;
pub const WORKERS_MIN: usize = 1;
pub const WORKERS_MAX: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Settings {
    pub tun_mtu: u16,
    /// None retains the existing classifier allocation and tokio::io::copy.
    pub copy_buffer_bytes: Option<usize>,
    pub tun_batch: usize,
    /// None leaves the runtime builder's worker count untouched.
    pub worker_threads: Option<usize>,
}

impl Default for Settings {
    fn default() -> Self {
        Self { tun_mtu: crate::tun::MTU, copy_buffer_bytes: None, tun_batch: BATCH_MIN, worker_threads: None }
    }
}

// Deserialize integer fields with defaults instead of Option so explicit
// null is invalid too. An omitted optional override uses its default only.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileSettings {
    tun_mtu: Field,
    copy_buffer_bytes: Field,
    tun_batch: Field,
    worker_threads: Field,
}

#[derive(Default)]
struct Field(Option<usize>);

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        usize::deserialize(d).map(|n| Self(Some(n)))
    }
}

fn bounded(name: &str, field: Field, min: usize, max: usize) -> Result<Option<usize>, String> {
    if let Some(n) = field.0 && !(min..=max).contains(&n) {
        return Err(format!("{name}: {n} is outside {min}..={max}"));
    }
    Ok(field.0)
}

/// Four integer fields fit in well under 200 bytes; this leaves room for any
/// formatting while keeping the read bounded.
pub const FILE_MAX: u64 = 4 * 1024;

pub fn parse(bytes: &[u8]) -> Result<Settings, String> {
    let bytes = crate::hand_file::content(bytes).map_err(|why| format!("{FILE}: {why}"))?;
    // Serde structs can also deserialize sequences. The file contract is an
    // object, so reject arrays before applying field defaults.
    if bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err("experiments must be a JSON object".into());
    }
    let f: FileSettings = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    Ok(Settings {
        tun_mtu: bounded("tun_mtu", f.tun_mtu, MTU_MIN, MTU_MAX)?.map(|n| n as u16).unwrap_or(crate::tun::MTU),
        copy_buffer_bytes: bounded("copy_buffer_bytes", f.copy_buffer_bytes, COPY_MIN, COPY_MAX)?,
        tun_batch: bounded("tun_batch", f.tun_batch, BATCH_MIN, BATCH_MAX)?.unwrap_or(BATCH_MIN),
        worker_threads: bounded("worker_threads", f.worker_threads, WORKERS_MIN, WORKERS_MAX)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ReadResult {
    Absent,
    Ok,
    Refused { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Loaded {
    #[serde(flatten)]
    pub settings: Settings,
    pub file: ReadResult,
}

impl Loaded {
    pub fn load(dir: &Path) -> Self {
        let path = dir.join(FILE);
        match crate::hand_file::read_capped(&path, FILE_MAX) {
            Ok(Some(bytes)) => Self::from_bytes(&bytes),
            Ok(None) => Self::absent(),
            Err(why) => Self::refused(format!("{}: {why}", path.display())),
        }
    }

    pub fn absent() -> Self {
        Self { settings: Settings::default(), file: ReadResult::Absent }
    }

    fn refused(reason: String) -> Self {
        Self { settings: Settings::default(), file: ReadResult::Refused { reason } }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        match parse(bytes) {
            Ok(settings) => Self { settings, file: ReadResult::Ok },
            Err(reason) => Self::refused(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn copy_default_matches_tokio() {
        struct Observe;
        impl tokio::io::AsyncRead for Observe {
            fn poll_read(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
                assert_eq!(buf.remaining(), DEFAULT_COPY_BYTES);
                std::task::Poll::Ready(Ok(()))
            }
        }
        tokio::io::copy(&mut Observe, &mut tokio::io::sink()).await.unwrap();
    }

    #[test]
    fn missing_and_empty_use_todays_values() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Loaded::load(dir.path()), Loaded::absent());
        assert_eq!(parse(b"{}").unwrap(), Settings::default());
        std::fs::write(dir.path().join(FILE), b"{}").unwrap();
        assert_eq!(Loaded::load(dir.path()).file, ReadResult::Ok);
    }

    #[test]
    fn accepted_mtu_bounds_fit_ipstack_and_the_existing_wintun_ring() {
        for mtu in [MTU_MIN as u16, crate::tun::MTU, MTU_MAX as u16] {
            let mut config = ipstack::IpStackConfig::default();
            config.mtu(mtu).unwrap();
            assert_eq!(config.mtu, mtu);
            assert!(u32::from(mtu).next_power_of_two() < crate::tun::RING_BYTES);
            #[cfg(windows)]
            assert!(u32::from(mtu) <= wintun_bindings::MAX_IP_PACKET_SIZE);
        }
        #[cfg(windows)]
        {
            assert!((wintun_bindings::MIN_RING_CAPACITY..=wintun_bindings::MAX_RING_CAPACITY).contains(&crate::tun::RING_BYTES));
            assert!(crate::tun::RING_BYTES.is_power_of_two());
        }
    }

    #[test]
    fn every_field_accepts_both_bounds_and_refuses_both_outside_edges() {
        for (field, min, max) in [
            ("tun_mtu", MTU_MIN, MTU_MAX), ("copy_buffer_bytes", COPY_MIN, COPY_MAX),
            ("tun_batch", BATCH_MIN, BATCH_MAX), ("worker_threads", WORKERS_MIN, WORKERS_MAX),
        ] {
            for n in [min, max] {
                let json = format!("{{\"{field}\":{n}}}");
                let value = serde_json::to_value(parse(json.as_bytes()).unwrap()).unwrap();
                assert_eq!(value[field], n, "{json}");
            }
            for n in [min - 1, max + 1] {
                let json = format!("{{\"{field}\":{n}}}");
                let loaded = Loaded::from_bytes(json.as_bytes());
                assert_eq!(loaded.settings, Settings::default());
                assert!(matches!(loaded.file, ReadResult::Refused { reason } if reason.contains(field)));
            }
            for value in ["null", "-1", "1.5", "true", "\"8\""] {
                assert!(parse(format!("{{\"{field}\":{value}}}").as_bytes()).is_err());
            }
        }
    }

    #[test]
    fn unknown_malformed_and_partly_valid_files_are_wholly_refused_with_reasons() {
        for bytes in [b"{\"unknown\":1}".as_slice(), b"{", b"[]", b"{\"tun_mtu\":9000,\"tun_batch\":0}", b"{\"tun_batch\":2,\"tun_batch\":3}"] {
            let loaded = Loaded::from_bytes(bytes);
            assert_eq!(loaded.settings, Settings::default());
            assert!(matches!(loaded.file, ReadResult::Refused { reason } if !reason.is_empty()));
        }
        assert!(parse(b"{\"unknown\":1}").unwrap_err().contains("unknown field"));
        assert!(parse(b"{").unwrap_err().contains("EOF"));
    }

    #[test]
    fn a_utf8_bom_is_accepted_utf16_and_oversized_files_are_refused_by_name() {
        assert_eq!(parse(b"\xEF\xBB\xBF{\"tun_mtu\":9000}").unwrap().tun_mtu, 9000);
        let utf16: Vec<u8> = [0xFF, 0xFE].into_iter().chain("{}".encode_utf16().flat_map(u16::to_le_bytes)).collect();
        assert!(parse(&utf16).unwrap_err().contains("UTF-16"));
        let dir = tempfile::tempdir().unwrap();
        let mut big = b"{\"tun_mtu\":9000}".to_vec();
        big.resize(FILE_MAX as usize + 1, b' ');
        std::fs::write(dir.path().join(FILE), &big).unwrap();
        assert!(matches!(Loaded::load(dir.path()).file, ReadResult::Refused { reason } if reason.contains("larger")));
        big.truncate(FILE_MAX as usize);
        std::fs::write(dir.path().join(FILE), &big).unwrap();
        assert_eq!(Loaded::load(dir.path()).settings.tun_mtu, 9000, "exactly the cap is read");
    }

    #[test]
    fn an_unreadable_file_is_refused_and_a_loaded_snapshot_does_not_reload() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(FILE)).unwrap();
        assert!(matches!(Loaded::load(dir.path()).file, ReadResult::Refused { reason } if !reason.is_empty()));
        std::fs::remove_dir(dir.path().join(FILE)).unwrap();
        std::fs::write(dir.path().join(FILE), b"{\"tun_batch\":2}").unwrap();
        let loaded = Loaded::load(dir.path());
        std::fs::write(dir.path().join(FILE), b"{}").unwrap();
        assert_eq!(loaded.settings.tun_batch, BATCH_MIN + 1);
    }
}
