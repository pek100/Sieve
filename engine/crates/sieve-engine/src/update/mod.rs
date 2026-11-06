//! Signed updates (plan 7.5, slice 13; task plan docs/tasks/2026-11-02-updates.md).
//!
//! The service is the only updater. It fetches a signed index, then the
//! artefacts the index names, verifies each one's minisign signature against
//! the public key compiled into it, checks the signed kind and a signed version
//! that must rise, and only then replaces files: in the locked install folder
//! for releases, in admin-only ProgramData for data. A new engine that does not
//! come up is rolled back. The unelevated app can only send `RequestUpdate {}`.
//!
//! - [`trust`]: the compiled-in key and host, release numbers;
//! - [`verify`], [`index`]: pure checks of signed bytes;
//! - [`state`]: the version record and the in-flight record (ProgramData);
//! - [`swap`]: the only file replacement, behind an [`swap::Fs`] seam;
//! - [`fetch`], [`https`]: the fetch seam and the real client;
//! - [`cycle`]: one check or apply over those seams, and the schedule;
//! - [`finish`]: the supervisor that swaps, watches and rolls back;
//! - [`health`]: the new engine's report to its supervisor;
//! - `win`: the real service control, process spawn and worker.

pub mod cycle;
pub mod fetch;
pub mod finish;
#[cfg(windows)]
pub mod health;
pub mod https;
pub mod index;
pub mod state;
pub mod swap;
pub mod trust;
pub mod verify;
#[cfg(windows)]
pub mod win;

#[cfg(test)]
pub(crate) mod testing;

use std::fmt;
use std::path::{Path, PathBuf};

/// What a signature says it is (the trusted comment, [`verify`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    App,
    Engine,
    Resources,
    /// The signed index itself: without its own kind a signed list could be
    /// served as the index.
    Index,
    /// A Sieve-owned list, by id (`[a-z0-9-]+`).
    List(String),
}

const LIST_PREFIX: &str = "list:";

impl Kind {
    /// The kind a comment or index key names, None for anything else.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "app" => Some(Self::App),
            "engine" => Some(Self::Engine),
            "resources" => Some(Self::Resources),
            "index" => Some(Self::Index),
            other => {
                let id = other.strip_prefix(LIST_PREFIX)?;
                let valid = !id.is_empty() && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
                valid.then(|| Self::List(id.to_string()))
            }
        }
    }

    /// Replaces files in the locked install folder and restarts the service.
    pub fn is_release(&self) -> bool {
        matches!(self, Self::App | Self::Engine)
    }

    /// Where a data kind lands under `updates\`, derived from the kind. None
    /// for the kinds that are not data.
    pub fn data_file(&self) -> Option<String> {
        match self {
            Self::Resources => Some("resources".into()),
            Self::List(id) => Some(format!("list-{id}")),
            Self::App | Self::Engine | Self::Index => None,
        }
    }
}

/// The one place a data kind's signed copy lives (`updates\` in the engine's
/// admin-only folder). What is here passed signature, kind and version before it
/// was put here. The resource loader reads through this; the sensitive-list
/// consumer of slice 6 reads `Kind::List("sensitive")` the same way.
pub fn data_path(engine_dir: &Path, kind: &Kind) -> Option<PathBuf> {
    Some(engine_dir.join(swap::DATA_DIR).join(kind.data_file()?))
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::App => f.write_str("app"),
            Self::Engine => f.write_str("engine"),
            Self::Resources => f.write_str("resources"),
            Self::Index => f.write_str("index"),
            Self::List(id) => write!(f, "{LIST_PREFIX}{id}"),
        }
    }
}

/// Why signed bytes were not accepted. Each one leaves every real file as it
/// was; the reason is logged and shown in the app.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("this build has no update key")]
    NoKey,
    #[error("no signature")]
    NoSignature,
    #[error("the signature does not verify")]
    BadSignature,
    #[error("the signed comment is not an update comment: {0}")]
    BadComment(String),
    #[error("signed as {got}, asked for {want}")]
    WrongKind { want: String, got: String },
    #[error("version {version} is not newer than the installed {installed}")]
    NotNewer { version: u64, installed: u64 },
    #[error("the update index expired")]
    IndexExpired,
    #[error("index version {version} is older than the accepted {accepted}")]
    IndexOlder { version: u64, accepted: u64 },
    #[error("malformed index: {0}")]
    BadIndex(String),
    #[error("artefact file name not allowed: {0}")]
    BadFileName(String),
    #[error("signed version {signed} of {kind} differs from the index's {listed}")]
    VersionMismatch { kind: String, signed: u64, listed: u64 },
    #[error("{0} is not the size the index signed")]
    WrongSize(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_round_trip_and_nothing_else_parses() {
        for text in ["app", "engine", "resources", "index", "list:sensitive", "list:a-1"] {
            assert_eq!(Kind::parse(text).unwrap().to_string(), text);
        }
        for bad in ["", "App", "list:", "list:A", "list:a b", "list:../x", "list:a:b", "engines"] {
            assert_eq!(Kind::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn signed_data_has_one_path_per_kind_and_releases_have_none() {
        let dir = Path::new(r"C:\ProgramData\Sieve\engine");
        assert_eq!(data_path(dir, &Kind::Resources).unwrap(), dir.join("updates").join("resources"));
        assert_eq!(data_path(dir, &Kind::List("sensitive".into())).unwrap(), dir.join("updates").join("list-sensitive"));
        assert_eq!(data_path(dir, &Kind::Engine), None);
    }

    #[test]
    fn only_data_kinds_have_a_data_file_and_only_releases_are_releases() {
        assert_eq!(Kind::Resources.data_file().as_deref(), Some("resources"));
        assert_eq!(Kind::List("sensitive".into()).data_file().as_deref(), Some("list-sensitive"));
        for k in [Kind::App, Kind::Engine, Kind::Index] {
            assert_eq!(k.data_file(), None);
        }
        assert!(Kind::App.is_release() && Kind::Engine.is_release());
        assert!(!Kind::Resources.is_release() && !Kind::Index.is_release());
    }
}
