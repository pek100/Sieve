//! The pipe protocol between the Sieve app and its engine (plan 1.3). One
//! owner for the shape (S29): the engine and src-tauri both use this crate,
//! and `src/data/fixtures/engine-ipc-v3.json` is the shared fixture the TS
//! side reads too (law `tests/laws/engine-ipc.test.ts`).
//!
//! - One named pipe, [`PIPE_NAME`], carrying frames: a u32 little-endian
//!   length, then that many bytes of JSON, at most [`MAX_FRAME`].
//! - The client's first frame is [`ClientMessage::Hello`]. The engine answers
//!   [`EngineMessage::Welcome`] or [`EngineMessage::Incompatible`]
//!   ([`answer_hello`]) and closes after an Incompatible.
//! - [`ClientMessage::SetPolicy`] is answered with the Status after the
//!   change; [`ClientMessage::Subscribe`] turns the connection into an event
//!   stream of [`EngineMessage::Flows`] batches, every [`FLOWS_BATCH_MS`].
//! - [`ClientMessage::SetDnsUpstreams`] is answered with
//!   [`EngineMessage::DnsUpstreams`], the list the engine then holds.
//! - Changing any message shape bumps [`PROTOCOL`] and the fixture in one
//!   commit (v3, the wave after slice 3: blocked flows, the grown policy, the
//!   list report, forwarded flows and guests, and the streams after them).
//!   A new message type is no shape change: a peer that never sends it is
//!   unaffected, and the app and engine ship together.
//!
//! There is no operation that signs anything, exports a key or names a
//! certificate to mint (plan 7.2), and there never will be.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The protocol version this build speaks.
pub const PROTOCOL: u32 = 3;
/// The oldest and newest protocol versions this build accepts.
pub const SUPPORTED: [u32; 2] = [3, 3];
pub const PIPE_NAME: &str = r"\\.\pipe\sieve-engine";
/// Largest frame body in bytes (1 MiB).
pub const MAX_FRAME: usize = 1 << 20;
/// A subscribed client gets the flows that changed at most this often (plan 1.3).
pub const FLOWS_BATCH_MS: u64 = 250;
/// At most this many flow events per `flows` frame; a larger batch is split,
/// so a frame stays far under [`MAX_FRAME`] (an event is a few hundred bytes).
pub const FLOWS_PER_FRAME: usize = 500;
/// At most this many rows in [`EngineStatus::guests`]: past it a new VM name
/// folds into the unidentified row, so the status stays bounded.
pub const MAX_GUESTS: usize = 32;
/// A VM name is at most this many characters on the wire.
pub const VM_NAME_MAX: usize = 64;
/// The word after `vm:` in the key of traffic whose VM has no name.
pub const VM_UNIDENTIFIED: &str = "unidentified";

/// The `apps.levels` key of a VM row, the one owner of its spelling (`:`
/// cannot occur in a Windows file name, so no exe stem collides). A VM
/// literally named "unidentified" is treated as unnamed, so two rows can never
/// share a key.
pub fn vm_key(vm: Option<&str>) -> String {
    format!("vm:{}", vm.map_or_else(|| VM_UNIDENTIFIED.to_string(), str::to_lowercase))
}

/// The `type` names of [`ClientMessage`], in declaration order.
pub const CLIENT_TYPES: &[&str] = &["hello", "status", "set_policy", "subscribe", "lists", "lists_refresh", "set_dns_upstreams"];
/// The `type` names of [`EngineMessage`], in declaration order.
pub const ENGINE_TYPES: &[&str] = &["welcome", "incompatible", "status", "error", "flows", "lists", "dns_upstreams"];
/// A flow event's rule text is cut to this many bytes: a list rule can run to
/// kilobytes, and at this cap a full `flows` frame stays under [`MAX_FRAME`].
pub const MAX_RULE_BYTES: usize = 256;
/// A skipped exception line in the list report is cut to this many bytes: 200
/// lines of each list, JSON-escaped at worst twice over, fit one frame.
pub const MAX_LISTED_LINE_BYTES: usize = 180;

/// App to engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientMessage {
    /// Always the first frame.
    Hello { protocol: u32, app_version: String },
    /// Asks for [`EngineMessage::Status`].
    Status,
    /// The user's switches. Applied only when `revision` is above the
    /// engine's (an older write is refused), persisted, answered with Status.
    SetPolicy(Policy),
    /// From now on the engine pushes [`EngineMessage::Flows`] batches of this
    /// client's session (and session 0, the services) on this connection.
    Subscribe,
    /// Asks for [`EngineMessage::Lists`].
    Lists,
    /// Downloads every selected list now, whatever its age; answered with
    /// [`EngineMessage::Lists`] as it stands (the refresh runs on).
    ListsRefresh,
    /// The encrypted DNS resolvers (`filtering.upstreams`). Applied only when
    /// `revision` is above the engine's and every address is valid, persisted,
    /// answered with [`EngineMessage::DnsUpstreams`]; a refusal is an Error.
    SetDnsUpstreams(DnsUpstreams),
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
    /// Flows that opened, moved bytes or closed since the last batch.
    Flows { flows: Vec<FlowEvent> },
    /// What the lists are doing. `compile_ms` is the last compile's time,
    /// None before the first.
    Lists { lists: Vec<ListStatus>, compile_ms: Option<u64> },
    /// The encrypted DNS resolvers the engine holds.
    DnsUpstreams(DnsUpstreams),
}

/// The encrypted DNS resolvers as the engine holds them (`dns.json`). The
/// engine validates the addresses; this crate only carries them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsUpstreams {
    /// Raised by the app on every change; 0 is the engine's default list.
    pub revision: u64,
    /// `https://`, `tls://` or `quic://` addresses, tried in order.
    pub upstreams: Vec<String>,
}

/// The user's switches as the engine holds them (`policy.json`). Every field
/// after `engine` defaults, so a file written before it loads (S39).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Raised by the app on every change; 0 is the engine's default.
    pub revision: u64,
    /// `filtering.engine`: route this computer's traffic through the engine.
    /// Off (the default) means the engine adds no adapter and no route.
    pub engine: bool,
    /// `sampling.enabled`: the global Sieve switch. Off relays every flow.
    /// Defaults off: after an upgrade nothing is blocked until the app has
    /// sent the Off list, so an Off app is never blocked by a missing field.
    #[serde(default)]
    pub sieving: bool,
    /// App keys ([`app_key`]) and guest keys ([`VM_PREFIX`]) the user turned off.
    #[serde(default)]
    pub off_apps: Vec<String>,
    /// Catalogue ids of the selected lists; None means the catalogue's defaults.
    #[serde(default)]
    pub lists: Option<Vec<String>>,
    /// The user's own domain lists (B6).
    #[serde(default)]
    pub domain_lists: Vec<DomainList>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainListKind {
    Block,
    Allow,
}

/// One user domain list (B6): entries are host names, a subdomain included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainList {
    pub kind: DomainListKind,
    pub entries: Vec<String>,
    pub enabled: bool,
}

/// One list as the engine holds it, for the per-list report (plan 5.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListStatus {
    pub id: String,
    /// In the policy's selection (the user's rules always are).
    pub enabled: bool,
    /// Milliseconds since the Unix epoch of the last good download or 304.
    pub fetched_at_ms: Option<u64>,
    /// The refresh interval read from the copy, None with no copy.
    pub refresh_s: Option<u64>,
    /// Why the last attempt failed; the last good copy stays in use.
    pub last_error: Option<String>,
    /// Network rules compiled. Those with a type or party constraint and all
    /// `$removeparam` rules do not act on a bare host before decryption.
    pub network: u64,
    /// Cosmetic rules parsed; they do nothing before slice 9.
    pub cosmetic: u64,
    pub skipped: u64,
    pub skip_reasons: BTreeMap<String, u64>,
    /// The first 200 skipped exception lines, each cut to
    /// [`MAX_LISTED_LINE_BYTES`].
    pub skipped_exceptions: Vec<String>,
    pub skipped_exceptions_total: u64,
}

/// Why the engine does not route although its switch is on (plan 1.6, 1.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Blocker {
    /// AdGuard for Windows is intercepting, whatever its service's state: its
    /// driver would capture the engine's own connections (probe run 2).
    /// `service` is its service name.
    Adguard { service: String },
    /// A full-tunnel VPN holds the default route on `adapter`.
    Vpn { adapter: String },
    /// The engine restarted `starts` times within an hour without a clean
    /// stop; it routes nothing until the user turns filtering on again.
    CrashLoop { starts: u32 },
    /// Bringing up the adapter or its routes failed; nothing is routed.
    Setup { message: String },
}

/// The engine's own counters since it started. Attribution of all flows, the
/// gate, is `attributed / flows` (plan 6); host only is
/// `(attributed - forwarded_named) / (flows - forwarded)`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counters {
    /// Flows the stack accepted (the engine's own refused ones excluded).
    pub flows: u64,
    /// Of those, flows whose process was found or whose VM an exact NAT match named.
    pub attributed: u64,
    /// Flows owned by the engine itself, refused (loop guard).
    pub own_refused: u64,
    /// DNS answers read for the IP-to-names map, from an encrypted upstream or
    /// a LAN server.
    pub dns_answers: u64,
    /// Packets read from and written to the adapter.
    pub packets_in: u64,
    pub packets_out: u64,
    /// Multicast, broadcast and link-local packets dropped before the stack.
    pub not_unicast: u64,
    /// Flows closed by a block decision.
    pub blocked: u64,
    /// Flows that matched a NAT session exactly: traffic of a VM or WSL.
    pub forwarded: u64,
    /// Of those, flows whose VM was named.
    pub forwarded_named: u64,
    /// Flows whose PID only the ETW witness gave.
    pub etw_found: u64,
    /// Flows left unknown because ETW and the owner tables disagreed.
    pub etw_disagreed: u64,
    /// ETW entries evicted from the ring plus events the session lost.
    pub etw_dropped: u64,
}

/// One row of "Virtual machines and WSL": what the engine has seen of one VM
/// since it started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guest {
    /// [`vm_key`], its key in `apps.levels`.
    pub key: String,
    /// Named by an exact NAT match; None is the unidentified row.
    pub vm: Option<String>,
    /// Flows seen since the engine started.
    pub seen: u64,
    /// Flows open now.
    pub open: u32,
}

/// What the engine is doing, from facts it holds (the `status` message).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineStatus {
    /// Filtering is on and every one of its parts is up.
    pub filtering: bool,
    /// Sieve's routes are installed.
    pub routes_up: bool,
    /// A compiled snapshot with at least one rule decides flows right now.
    pub blocking: bool,
    /// Flows the engine holds right now.
    pub flows: u32,
    /// HTTPS is being decrypted.
    pub decrypting: bool,
    pub last_error: Option<String>,
    /// The switches the engine holds.
    pub policy: Policy,
    /// Why it does not route although `policy.engine` is on.
    pub blocker: Option<Blocker>,
    /// Up VPN adapters that route only some prefixes: their traffic bypasses
    /// Sieve, which the app states (plan 1.7).
    pub split_tunnels: Vec<String>,
    pub counters: Counters,
    /// VMs whose traffic was seen since the engine started: named rows by
    /// key, then the unidentified row.
    pub guests: Vec<Guest>,
}

/// A flow that matched a NAT session exactly on its whole tuple: a guest's,
/// which has no Windows socket and so no process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forwarded {
    /// The VM that match named; None when it could not be named.
    pub vm: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowProto {
    Tcp,
    Udp,
}

/// What the first bytes said (plan 1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowKind {
    Tls,
    Http,
    Quic,
    Dns,
    /// Not decoded (another protocol, nothing sent in time, or a cap hit).
    Other,
}

/// What the engine did with the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowAction {
    Relayed,
    /// The upstream could not be reached; the app side was closed.
    Failed,
    /// A rule decided against the flow: nothing went upstream, the app was closed.
    Blocked,
}

/// Why a flow was decided the way it was (one owner: the engine's decision
/// and the log read these names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowReason {
    /// The global switch is off.
    Disabled,
    /// A DNS flow: a lookup is never a blocking decision.
    Dns,
    /// The app's or guest's row is Off.
    AppExempt,
    /// A rule blocks the name the flow carries.
    NamedBlock,
    /// An exception rule allows the name the flow carries.
    NamedAllow,
    /// No rule for the name the flow carries.
    NamedNoRule,
    /// The flow carries no name and every live name of its address blocks.
    AllResolvedNamesBlocked,
    /// The flow carries no name and some live name of its address does not block.
    MixedResolvedNames,
    /// The flow carries no name and its address has none alive.
    UnknownDomain,
}

/// One flow as the engine saw it (plan 1.3 `Flows`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowEvent {
    /// Unique for the engine's run.
    pub id: u64,
    /// None when attribution gave up (plan 6: the rate is counted).
    pub pid: Option<u32>,
    pub exe: Option<String>,
    pub session: Option<u32>,
    pub proto: FlowProto,
    /// The app's end, `ip:port` (`[v6]:port`).
    pub local: String,
    pub remote: String,
    pub kind: FlowKind,
    /// SNI, Host, QUIC SNI or the DNS question name.
    pub host: Option<String>,
    pub action: FlowAction,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// False in the last event of a flow.
    pub open: bool,
    /// Why it was decided so; None before the decision.
    pub reason: Option<FlowReason>,
    /// The rule that decided it, cut to [`MAX_RULE_BYTES`].
    pub rule: Option<String>,
    /// The id of the list holding that rule.
    pub list: Option<String>,
    /// Some for a guest's flow ("Virtual machines and WSL"). `pid` Some is a
    /// host flow, this Some is a guest's, both None is unknown.
    pub forwarded: Option<Forwarded>,
}

/// `text` cut to at most `max` bytes, on a character boundary.
pub fn cap_text(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// File name without directory and extension.
fn exe_stem(path: &str) -> &str {
    let base = path.rsplit(['\\', '/']).next().unwrap_or(path);
    match base.rsplit_once('.') {
        Some((stem, ext)) if !ext.is_empty() => stem,
        _ => base,
    }
}

/// An app's identity, the settings key of `apps.levels`: lower-case product
/// name, else exe stem, else process name. The same rule as `appIdentity` in
/// `src/core/apps.ts`; `src/data/fixtures/app-keys-v1.json` ties the two.
///
/// TENSION: a key from a ProductName can be spoofed, so an exe that names
/// itself like an Off product gets its exemption. Ad blocking is no boundary
/// against local code, and this is how the Apps page already groups apps.
pub fn app_key(product: Option<&str>, exe: Option<&str>, process_name: &str) -> String {
    let product = product.map(str::trim).filter(|p| !p.is_empty());
    product.or(exe.map(exe_stem)).unwrap_or(process_name).to_lowercase()
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

    const FIXTURE: &str = include_str!("../../../../src/data/fixtures/engine-ipc-v3.json");

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
        assert_eq!(f["flowsBatchMs"], FLOWS_BATCH_MS);
        assert_eq!(f["flowsPerFrame"], FLOWS_PER_FRAME);
        assert_eq!(types(&f["client"]), CLIENT_TYPES);
        assert_eq!(types(&f["engine"]), ENGINE_TYPES);
    }

    #[test]
    fn every_fixture_blocker_round_trips_unchanged() {
        for b in fixture()["blockers"].as_array().unwrap() {
            let parsed: Blocker = serde_json::from_value(b.clone()).unwrap();
            assert_eq!(&serde_json::to_value(&parsed).unwrap(), b);
        }
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
            ClientMessage::SetPolicy(_) => "set_policy",
            ClientMessage::Subscribe => "subscribe",
            ClientMessage::Lists => "lists",
            ClientMessage::ListsRefresh => "lists_refresh",
            ClientMessage::SetDnsUpstreams(_) => "set_dns_upstreams",
        };
        let engine = |m: &EngineMessage| match m {
            EngineMessage::Welcome { .. } => "welcome",
            EngineMessage::Incompatible { .. } => "incompatible",
            EngineMessage::Status(_) => "status",
            EngineMessage::Error { .. } => "error",
            EngineMessage::Flows { .. } => "flows",
            EngineMessage::Lists { .. } => "lists",
            EngineMessage::DnsUpstreams(_) => "dns_upstreams",
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
        let f = fixture();
        let mut status = f["engine"].as_array().unwrap().iter().find(|m| m["type"] == "status").unwrap().clone();
        assert!(serde_json::from_value::<EngineMessage>(status.clone()).is_ok());
        status["x"] = 1.into();
        assert!(serde_json::from_value::<EngineMessage>(status).is_err());
        let v1 = r#"{"type":"status","filtering":false,"routes_up":false,"flows":0,"decrypting":false,"last_error":null}"#;
        assert!(serde_json::from_str::<EngineMessage>(v1).is_err(), "a v1 status lacks the v2 fields");
    }

    /// The fixture carries every variant of the v2 enums, so the TS law sees
    /// each wire name (a new variant without a fixture example fails here).
    #[test]
    fn the_fixture_shows_every_blocker_kind_and_flow_action() {
        let f = fixture().to_string();
        for kind in ["adguard", "vpn", "crash_loop", "setup"] {
            assert!(f.contains(&format!(r#""kind":"{kind}""#)), "{kind}");
        }
        let kinds = |b: &Blocker| match b {
            Blocker::Adguard { .. } | Blocker::Vpn { .. } | Blocker::CrashLoop { .. } | Blocker::Setup { .. } => (),
        };
        kinds(&Blocker::CrashLoop { starts: 3 });
        for name in ["relayed", "failed", "blocked", "tls", "http", "quic", "dns", "other", "tcp", "udp", "named_block", "app_exempt"] {
            assert!(f.contains(&format!(r#""{name}""#)), "{name}");
        }
    }

    /// A policy file written by protocol 2 has only `revision` and `engine`.
    #[test]
    fn a_v2_policy_loads_with_sieving_off_and_no_lists_chosen() {
        let p: Policy = serde_json::from_str(r#"{"revision":4,"engine":true}"#).unwrap();
        assert_eq!(p, Policy { revision: 4, engine: true, ..Policy::default() });
        assert!(!p.sieving && p.off_apps.is_empty() && p.lists.is_none() && p.domain_lists.is_empty());
        assert!(serde_json::from_str::<Policy>(r#"{"engine":true}"#).is_err(), "still no revision, no policy");
    }

    /// Both this test and `tests/laws/app-key.test.ts` read this fixture.
    #[test]
    fn app_keys_match_the_shared_fixture() {
        let f: Value = serde_json::from_str(include_str!("../../../../src/data/fixtures/app-keys-v1.json")).unwrap();
        let cases = f["cases"].as_array().unwrap();
        assert!(cases.len() >= 8);
        for c in cases {
            let key = app_key(c["product"].as_str(), c["exe"].as_str(), c["name"].as_str().unwrap());
            assert_eq!(key, c["key"].as_str().unwrap(), "{c}");
        }
    }

    #[test]
    fn cap_text_cuts_on_a_character_boundary() {
        assert_eq!(cap_text("abc", 3), "abc");
        assert_eq!(cap_text("abcd", 3), "abc");
        assert_eq!(cap_text("aé", 2), "a", "é is two bytes");
    }

    /// The worst case: every selected list (more than the catalogue holds)
    /// with its 200 lines at their cap, all of it JSON-escaped.
    #[test]
    fn a_full_lists_frame_stays_under_the_frame_limit() {
        const LISTS_AT_WORST: usize = 14;
        const LISTED_LINES: usize = 200;
        let reasons = (0..16).map(|i| (format!("network filter error: reason {i} worded at some length"), u64::MAX)).collect();
        let list = ListStatus {
            id: "i".repeat(32),
            enabled: true,
            fetched_at_ms: Some(u64::MAX),
            refresh_s: Some(u64::MAX),
            last_error: Some("e".repeat(256)),
            network: u64::MAX,
            cosmetic: u64::MAX,
            skipped: u64::MAX,
            skip_reasons: reasons,
            skipped_exceptions: vec!["\"".repeat(MAX_LISTED_LINE_BYTES); LISTED_LINES],
            skipped_exceptions_total: u64::MAX,
        };
        let msg = EngineMessage::Lists { lists: vec![list; LISTS_AT_WORST], compile_ms: Some(u64::MAX) };
        assert!(encode(&msg).is_ok(), "{:?}", encode(&msg).err());
    }

    #[test]
    fn a_full_flows_frame_stays_under_the_frame_limit() {
        let ev = FlowEvent {
            id: u64::MAX,
            pid: Some(u32::MAX),
            exe: Some(format!(r"C:\{}\app.exe", "d".repeat(250))),
            session: Some(1),
            proto: FlowProto::Tcp,
            local: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535".into(),
            remote: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535".into(),
            kind: FlowKind::Tls,
            host: Some("h".repeat(253)),
            action: FlowAction::Relayed,
            bytes_up: u64::MAX,
            bytes_down: u64::MAX,
            open: true,
            reason: Some(FlowReason::AllResolvedNamesBlocked),
            rule: Some("\"".repeat(MAX_RULE_BYTES)),
            list: Some("l".repeat(32)),
            forwarded: Some(Forwarded { vm: Some("v".repeat(VM_NAME_MAX)) }),
        };
        let msg = EngineMessage::Flows { flows: vec![ev; FLOWS_PER_FRAME] };
        assert!(encode(&msg).is_ok());
    }

    #[test]
    fn a_status_with_max_guests_fits() {
        // A name of VM_NAME_MAX four-byte characters, the longest there is.
        let name = "\u{10FFFF}".repeat(VM_NAME_MAX);
        let guests = vec![Guest { key: vm_key(Some(&name)), vm: Some(name), seen: u64::MAX, open: u32::MAX }; MAX_GUESTS];
        let msg = EngineMessage::Status(EngineStatus { guests, ..EngineStatus::default() });
        assert!(encode(&msg).unwrap().len() < MAX_FRAME / 16, "the status stays small");
    }

    #[test]
    fn vm_keys_are_lower_case_and_the_unnamed_key_is_one() {
        assert_eq!(vm_key(Some("Ubuntu Box")), "vm:ubuntu box");
        assert_eq!(vm_key(None), "vm:unidentified");
        assert_eq!(vm_key(Some("Unidentified")), vm_key(None), "the name cannot make a second row of that key");
    }

    /// The illegal fourth state of a flow event has no example.
    #[test]
    fn no_fixture_flow_is_both_a_process_and_a_guest() {
        let f = fixture();
        let flows = f["engine"].as_array().unwrap().iter().find(|m| m["type"] == "flows").unwrap();
        let events: Vec<FlowEvent> = serde_json::from_value(flows["flows"].clone()).unwrap();
        assert!(events.iter().any(|e| e.forwarded.as_ref().is_some_and(|g| g.vm.is_some())));
        assert!(events.iter().any(|e| e.forwarded.as_ref().is_some_and(|g| g.vm.is_none())));
        for e in &events {
            assert!(e.pid.is_none() || e.forwarded.is_none(), "flow {}", e.id);
        }
    }

    #[test]
    fn the_fixtures_guests_use_the_one_key() {
        let f = fixture();
        let status = f["engine"].as_array().unwrap().iter().find(|m| m["type"] == "status").unwrap();
        let guests: Vec<Guest> = serde_json::from_value(status["guests"].clone()).unwrap();
        assert!(guests.len() >= 2);
        for g in &guests {
            assert_eq!(g.key, vm_key(g.vm.as_deref()));
        }
    }

    #[test]
    fn handshake_welcomes_supported_versions_and_refuses_others() {
        assert_eq!(
            answer_hello(PROTOCOL, "0.1.0", 3),
            EngineMessage::Welcome { protocol: PROTOCOL, engine_version: "0.1.0".into(), session_id: 3 }
        );
        for v in [0, 1, PROTOCOL - 1, PROTOCOL + 1, u32::MAX] {
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
