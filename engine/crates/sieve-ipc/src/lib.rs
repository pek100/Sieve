//! The pipe protocol between the Sieve app and its engine (plan 1.3). One
//! owner for the shape (S29): the engine and src-tauri both use this crate,
//! and `src/data/fixtures/engine-ipc-v1.json` is the shared fixture the TS
//! side reads too (law `tests/laws/engine-ipc.test.ts`).
//!
//! - One named pipe, [`PIPE_NAME`], carrying frames: a u32 little-endian
//!   length, then that many bytes of JSON, at most [`MAX_FRAME`].
//! - The client's first frame is [`ClientMessage::Hello`]. The engine answers
//!   [`EngineMessage::Welcome`] or [`EngineMessage::Incompatible`]
//!   ([`answer_hello`]) and closes after an Incompatible.
//! - Changing any message shape bumps [`PROTOCOL`] and the fixture in one
//!   commit.
//!
//! There is no operation that signs anything, exports a key or names a
//! certificate to mint (plan 7.2), and there never will be.

use std::io::{Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The protocol version this build speaks.
pub const PROTOCOL: u32 = 1;
/// The oldest and newest protocol versions this build accepts.
pub const SUPPORTED: [u32; 2] = [1, 1];
pub const PIPE_NAME: &str = r"\\.\pipe\sieve-engine";
/// Largest frame body in bytes (1 MiB).
pub const MAX_FRAME: usize = 1 << 20;

/// The `type` names of [`ClientMessage`], in declaration order.
pub const CLIENT_TYPES: &[&str] = &["hello", "status"];
/// The `type` names of [`EngineMessage`], in declaration order.
pub const ENGINE_TYPES: &[&str] = &["welcome", "incompatible", "status", "error"];

/// App to engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientMessage {
    /// Always the first frame.
    Hello { protocol: u32, app_version: String },
    /// Asks for [`EngineMessage::Status`].
    Status,
}

/// Engine to app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EngineMessage {
    /// The handshake succeeded. `session_id` is the Windows session of the
    /// client process: it only ever receives that session's flows and log.
    Welcome { protocol: u32, engine_version: String, session_id: u32 },
    /// The client's protocol is outside `supported` (`[min, max]`); the
    /// engine closes the pipe after this frame.
    Incompatible { supported: [u32; 2] },
    /// Facts about filtering, never assumptions (plan 1.6, 5).
    Status(EngineStatus),
    /// A request the engine refused (before Hello, malformed, unknown).
    Error { message: String },
}

/// What the engine is doing, from facts it holds (the `status` message).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineStatus {
    /// Filtering is on and every one of its parts is up.
    pub filtering: bool,
    /// Sieve's routes are installed.
    pub routes_up: bool,
    /// Flows the engine holds right now.
    pub flows: u32,
    /// HTTPS is being decrypted.
    pub decrypting: bool,
    pub last_error: Option<String>,
}

/// The engine's answer to a client's Hello.
pub fn answer_hello(client_protocol: u32, engine_version: &str, session_id: u32) -> EngineMessage {
    let [min, max] = SUPPORTED;
    if (min..=max).contains(&client_protocol) {
        EngineMessage::Welcome { protocol: PROTOCOL, engine_version: engine_version.to_string(), session_id }
    } else {
        EngineMessage::Incompatible { supported: SUPPORTED }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The peer closed the pipe cleanly between frames.
    #[error("the pipe was closed")]
    Closed,
    #[error("frame of {0} bytes is over the {MAX_FRAME} byte limit")]
    TooLarge(usize),
    #[error("malformed frame: {0}")]
    Json(#[from] serde_json::Error),
    #[error("pipe i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// One whole frame (length prefix and body). A message that serializes over
/// [`MAX_FRAME`] is refused.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(msg)?;
    let len = u32::try_from(body.len()).ok().filter(|_| body.len() <= MAX_FRAME).ok_or(FrameError::TooLarge(body.len()))?;
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// The body length a frame header announces, refused over [`MAX_FRAME`].
pub fn body_len(header: [u8; 4]) -> Result<usize, FrameError> {
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_FRAME { Err(FrameError::TooLarge(len)) } else { Ok(len) }
}

fn header_error(e: std::io::Error) -> FrameError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof { FrameError::Closed } else { e.into() }
}

/// Writes one frame; nothing is written for a refused one.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), FrameError> {
    w.write_all(&encode(msg)?)?;
    w.flush()?;
    Ok(())
}

/// Reads one frame. A length over [`MAX_FRAME`] is refused without reading
/// the body; EOF before the length is [`FrameError::Closed`].
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, FrameError> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).map_err(header_error)?;
    let mut body = vec![0u8; body_len(header)?];
    r.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}

/// The same framing over tokio streams (the engine's pipe server and the
/// app's client), built on the same [`encode`] and [`body_len`].
#[cfg(feature = "tokio")]
pub mod nonblocking {
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use super::{FrameError, body_len, encode, header_error};

    pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<(), FrameError> {
        w.write_all(&encode(msg)?).await?;
        w.flush().await?;
        Ok(())
    }

    pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T, FrameError> {
        let mut header = [0u8; 4];
        r.read_exact(&mut header).await.map_err(header_error)?;
        let mut body = vec![0u8; body_len(header)?];
        r.read_exact(&mut body).await?;
        Ok(serde_json::from_slice(&body)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const FIXTURE: &str = include_str!("../../../../src/data/fixtures/engine-ipc-v1.json");

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).unwrap()
    }

    fn types(list: &Value) -> Vec<String> {
        list.as_array().unwrap().iter().map(|m| m["type"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn fixture_constants_match_the_code() {
        let f = fixture();
        assert_eq!(f["protocol"], PROTOCOL);
        assert_eq!(f["supported"], serde_json::json!(SUPPORTED));
        assert_eq!(f["pipe"], PIPE_NAME);
        assert_eq!(f["maxFrame"], MAX_FRAME);
        assert_eq!(types(&f["client"]), CLIENT_TYPES);
        assert_eq!(types(&f["engine"]), ENGINE_TYPES);
    }

    #[test]
    fn every_fixture_message_round_trips_unchanged() {
        let f = fixture();
        for m in f["client"].as_array().unwrap() {
            let parsed: ClientMessage = serde_json::from_value(m.clone()).unwrap();
            assert_eq!(&serde_json::to_value(&parsed).unwrap(), m);
        }
        for m in f["engine"].as_array().unwrap() {
            let parsed: EngineMessage = serde_json::from_value(m.clone()).unwrap();
            assert_eq!(&serde_json::to_value(&parsed).unwrap(), m);
        }
    }

    #[test]
    fn type_lists_name_every_variant() {
        // A new variant without a CLIENT_TYPES/ENGINE_TYPES entry fails here
        // (the match is exhaustive), so the TS law sees every name.
        let client = |m: &ClientMessage| match m {
            ClientMessage::Hello { .. } => "hello",
            ClientMessage::Status => "status",
        };
        let engine = |m: &EngineMessage| match m {
            EngineMessage::Welcome { .. } => "welcome",
            EngineMessage::Incompatible { .. } => "incompatible",
            EngineMessage::Status(_) => "status",
            EngineMessage::Error { .. } => "error",
        };
        let f = fixture();
        for m in f["client"].as_array().unwrap() {
            let parsed: ClientMessage = serde_json::from_value(m.clone()).unwrap();
            assert_eq!(client(&parsed), m["type"]);
        }
        for m in f["engine"].as_array().unwrap() {
            let parsed: EngineMessage = serde_json::from_value(m.clone()).unwrap();
            assert_eq!(engine(&parsed), m["type"]);
        }
    }

    #[test]
    fn frames_round_trip_every_fixture_message() {
        let f = fixture();
        let mut wire = Vec::new();
        let msgs: Vec<EngineMessage> =
            f["engine"].as_array().unwrap().iter().map(|m| serde_json::from_value(m.clone()).unwrap()).collect();
        for m in &msgs {
            write_frame(&mut wire, m).unwrap();
        }
        let first_len = u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
        assert_eq!(first_len, serde_json::to_vec(&msgs[0]).unwrap().len(), "little-endian length prefix");
        let mut r = wire.as_slice();
        for m in &msgs {
            assert_eq!(&read_frame::<_, EngineMessage>(&mut r).unwrap(), m);
        }
        assert!(matches!(read_frame::<_, EngineMessage>(&mut r), Err(FrameError::Closed)));
    }

    #[test]
    fn oversized_and_malformed_frames_are_refused() {
        let mut wire = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
        wire.extend_from_slice(b"{}");
        assert!(matches!(read_frame::<_, ClientMessage>(&mut wire.as_slice()), Err(FrameError::TooLarge(n)) if n == MAX_FRAME + 1));

        let big = EngineMessage::Error { message: "x".repeat(MAX_FRAME) };
        let mut out = Vec::new();
        assert!(matches!(write_frame(&mut out, &big), Err(FrameError::TooLarge(_))));
        assert!(out.is_empty(), "nothing is written for a refused frame");

        let mut bad = 3u32.to_le_bytes().to_vec();
        bad.extend_from_slice(b"{x}");
        assert!(matches!(read_frame::<_, ClientMessage>(&mut bad.as_slice()), Err(FrameError::Json(_))));

        let truncated = [10u8, 0, 0, 0, b'{'];
        assert!(matches!(read_frame::<_, ClientMessage>(&mut truncated.as_slice()), Err(FrameError::Io(_))));

        let unknown = br#"{"type":"sign","data":"x"}"#;
        let mut frame = (unknown.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(unknown);
        assert!(matches!(read_frame::<_, ClientMessage>(&mut frame.as_slice()), Err(FrameError::Json(_))));
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn async_frames_match_the_blocking_ones_byte_for_byte() {
        let msg = EngineMessage::Status(EngineStatus { last_error: Some("x".into()), ..EngineStatus::default() });
        let mut blocking = Vec::new();
        write_frame(&mut blocking, &msg).unwrap();
        let mut async_wire = Vec::new();
        nonblocking::write_frame(&mut async_wire, &msg).await.unwrap();
        assert_eq!(blocking, async_wire);
        let mut r = async_wire.as_slice();
        assert_eq!(nonblocking::read_frame::<_, EngineMessage>(&mut r).await.unwrap(), msg);
        assert!(matches!(nonblocking::read_frame::<_, EngineMessage>(&mut r).await, Err(FrameError::Closed)));
    }

    #[test]
    fn status_rejects_unknown_fields() {
        let extra = r#"{"type":"status","filtering":false,"routes_up":false,"flows":0,"decrypting":false,"last_error":null,"x":1}"#;
        assert!(serde_json::from_str::<EngineMessage>(extra).is_err());
    }

    #[test]
    fn handshake_welcomes_supported_versions_and_refuses_others() {
        assert_eq!(
            answer_hello(1, "0.1.0", 3),
            EngineMessage::Welcome { protocol: PROTOCOL, engine_version: "0.1.0".into(), session_id: 3 }
        );
        for v in [0, 2, u32::MAX] {
            assert_eq!(answer_hello(v, "0.1.0", 3), EngineMessage::Incompatible { supported: SUPPORTED }, "v{v}");
        }
    }

    #[test]
    fn no_message_can_sign_export_or_mint() {
        for name in CLIENT_TYPES.iter().chain(ENGINE_TYPES) {
            for banned in ["sign", "export", "mint", "key"] {
                assert!(!name.contains(banned), "{name}");
            }
        }
    }
}
