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
//! - [`ClientMessage::SetDnsUpstreams`] and [`ClientMessage::DnsUpstreams`] are
//!   answered with [`EngineMessage::DnsUpstreams`], the list the engine holds.
//! - Changing any message shape bumps [`PROTOCOL`] and the fixture in one
//!   commit (v3, the wave after slice 3: blocked flows, the grown policy, the
//!   list report, forwarded flows and guests, the `log` message, the status's filter
//!   facts, the certificate's status with its `removal_pending` state,
//!   `InstallRoot`, `Policy.https`, `Policy.content`, `request_update` and the
//!   `update` status).
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
/// The largest policy the engine takes, half a frame: the Status that carries
/// the policy has the other half. The app measures against it before it sends.
pub const MAX_POLICY_BYTES: usize = MAX_FRAME / 2;
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
/// At most this many log rows per `log` frame; [`log_frames`] splits a larger
/// batch, and sooner when the rows' encoded size says so.
pub const LOG_PER_FRAME: usize = 200;
/// The engine truncates a row's URL and rule to these many raw bytes. They bound
/// one row, not a frame: JSON escaping can make a byte six on the wire, so 200
/// rows at the caps can pass [`MAX_FRAME`]. [`log_frames`] is what keeps a frame
/// within it.
pub const LOG_URL_MAX: usize = 2048;
pub const LOG_RULE_MAX: usize = 1024;

/// The `type` names of [`ClientMessage`], in declaration order.
pub const CLIENT_TYPES: &[&str] = &["hello", "status", "set_policy", "subscribe", "lists", "lists_refresh", "set_dns_upstreams", "dns_upstreams", "cert_status", "install_root", "request_update", "exclusions", "try_decrypt_again", "heal_notices"];
/// The `type` names of [`EngineMessage`], in declaration order.
pub const ENGINE_TYPES: &[&str] = &["welcome", "incompatible", "status", "error", "flows", "lists", "dns_upstreams", "log", "cert_status", "exclusions", "heal_notices"];
/// A flow event's rule text is cut to this many bytes: a list rule can run to
/// kilobytes, and at this cap a full `flows` frame stays under [`MAX_FRAME`].
pub const MAX_RULE_BYTES: usize = 256;
/// A skipped exception line in the list report is cut to this many bytes: 200
/// lines of each list, JSON-escaped at worst twice over ([`listed_line`] holds
/// that worst case), fit one frame.
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
    /// Asks for [`EngineMessage::DnsUpstreams`]: the app compares it with
    /// `filtering.upstreams`, as it compares the Status's policy with its settings.
    DnsUpstreams,
    /// Asks for [`EngineMessage::CertStatus`].
    CertStatus,
    /// Reinstall: a new root and key, the old root removed at once. Refused
    /// unless `policy.https` is on. Answered with the status as it stands;
    /// the engine does the work on its own thread.
    InstallRoot,
    /// Asks for an update check, or to apply the release [`UpdateStatus::Available`]
    /// names; the engine decides which from its own state. No field, ever: the
    /// app cannot supply a URL, a path, a version or any bytes (plan 7.5). A
    /// struct variant on purpose: serde ignores extra keys on an internally
    /// tagged unit variant, even with `deny_unknown_fields`, and this one must
    /// refuse them.
    RequestUpdate {},
    /// Asks for one page of [`EngineMessage::Exclusions`], from row `after`.
    Exclusions { after: u32 },
    /// "Try decrypting again": one row, by its `line` in the list grammar, its `app`
    /// (None for an entry of every app) and its `reason` slug; or with neither `line`
    /// nor `reason`, every `auto:pinning` entry of `app`. Answered with the first page
    /// of [`EngineMessage::Exclusions`]; an unparsable line, a reason that is not
    /// `auto:*`, or any other mix of fields is an Error. No field reaches the user or
    /// list layers (plan 4.3, S24).
    TryDecryptAgain { line: Option<String>, app: Option<String>, reason: Option<String> },
    /// Asks for [`EngineMessage::HealNotices`] newer than revision `after`.
    HealNotices { after: u64 },
}

/// Engine to app. Read and written one frame at a time and never stored, so the
/// Status's size costs nothing a box would save.
#[allow(clippy::large_enum_variant)]
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
    /// What the filter did since the last batch, on the Subscribe connection,
    /// session scoped like flows (plan 8.3). Built with [`log_frames`]: a frame
    /// refused as too large would end the stream, flows included.
    Log { rows: Vec<LogRow> },
    /// The root certificate, from facts the engine holds (plan 8.1).
    CertStatus(CertStatus),
    /// One page of what the engine keeps from being decrypted (plan 8.2), built
    /// with [`exclusions_page`]. `next` is the `after` of the next page, None on
    /// the last. The `user` layer is not here: those lines are the app's own.
    Exclusions { revision: u64, rows: Vec<ExclusionRow>, total: u32, next: Option<u32>, scope: ExclusionScope, browsers: Vec<String> },
    /// What self-healing excluded since `after`, for this client's session (plan
    /// 4.3). `revision` is the next `after`; `exclusions_revision` moves when the
    /// rows do, so this is cheap to ask and the rows are read only then. `run` names
    /// this engine run: a new one starts `revision` and the notices' ids over, so an
    /// `after` from another run means nothing.
    HealNotices { run: u64, revision: u64, exclusions_revision: u64, notices: Vec<HealNotice> },
}

/// How far decryption reaches. The same two values as the engine's decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionScope {
    /// Only [`EngineMessage::Exclusions`]' `browsers`, full paths, lower case.
    #[default]
    Browsers,
    All,
}

/// One entry of the `list:*` or `auto:*` layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExclusionRow {
    /// The pattern in the list grammar, with no `$app=`.
    pub line: String,
    /// Lower-case exe file names; empty means every app.
    pub apps: Vec<String>,
    /// `list:<id>`, `auto:pinning`, `auto:client-cert` or `auto:ev`.
    pub reason: String,
    /// When the engine first wrote it; None for a list's line.
    pub created_ms: Option<u64>,
    /// How many times "Try decrypting again" was used on it.
    pub retries: u32,
}

/// One group of self-healing exclusions of one app (plan 4.3). A later exclusion
/// in the group's window raises `rev` and keeps `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealNotice {
    /// Unique for the engine's run.
    pub id: u64,
    pub session: u32,
    /// The exe's file name, lower case.
    pub exe: String,
    /// The first few hosts; `total` counts them all.
    pub hosts: Vec<String>,
    pub total: u32,
    pub rev: u64,
}

/// What [`exclusions_page`] cuts into frames.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExclusionsView {
    pub revision: u64,
    pub rows: Vec<ExclusionRow>,
    pub scope: ExclusionScope,
    pub browsers: Vec<String>,
}

/// The page of `view` from row `after`, as much as one frame holds, by encoded
/// size. A row too large for any frame cannot be sent and is passed over, so a
/// page always moves on.
pub fn exclusions_page(view: &ExclusionsView, after: u32) -> Result<EngineMessage, FrameError> {
    const SEPARATOR: usize = b",".len();
    let total = u32::try_from(view.rows.len()).unwrap_or(u32::MAX);
    let page = |rows: Vec<ExclusionRow>, next: Option<u32>| EngineMessage::Exclusions { revision: view.revision, rows, total, next, scope: view.scope, browsers: view.browsers.clone() };
    // The largest `total` and `next` there are, so the page never grows past this.
    let empty = serde_json::to_vec(&page(Vec::new(), Some(u32::MAX)))?.len();
    let mut rows = Vec::new();
    let mut size = empty;
    for (index, row) in view.rows.iter().enumerate().skip(after as usize) {
        let len = serde_json::to_vec(row)?.len();
        if empty + len > MAX_FRAME {
            continue;
        }
        if !rows.is_empty() && size + SEPARATOR + len > MAX_FRAME {
            return Ok(page(rows, u32::try_from(index).ok()));
        }
        size += len + if rows.is_empty() { 0 } else { SEPARATOR };
        rows.push(row.clone());
    }
    Ok(page(rows, None))
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
    /// App keys ([`app_key`]) and guest keys ([`vm_key`]) the user turned off.
    #[serde(default)]
    pub off_apps: Vec<String>,
    /// Catalogue ids of the selected lists; None means the catalogue's defaults.
    #[serde(default)]
    pub lists: Option<Vec<String>>,
    /// The user's own domain lists (B6).
    #[serde(default)]
    pub domain_lists: Vec<DomainList>,
    /// `filtering.https`: hold a root certificate (plan 2.4). Off removes it.
    /// Defaulted, because `policy.json` denies unknown fields and a file from
    /// before slice 5 must keep its engine switch rather than read as off.
    #[serde(default)]
    pub https: bool,
    /// `filtering.content`: decrypted pages get cosmetics and scriptlets. Needs
    /// `https`, whose interception is what carries it. Defaulted for a file from
    /// before slice 9, and left out while false, so an old reader of the file sees
    /// what it always saw.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub content: bool,
    /// `filtering.userRules`: rule lines in the lists' language, compiled
    /// untrusted beside `domain_lists`.
    #[serde(default)]
    pub user_rules: Vec<String>,
    /// `filtering.exclusions`: sites never decrypted (plan 4.5). The `user`
    /// layer of the exclusion store (`sieve_engine::exclusions`).
    #[serde(default)]
    pub exclusions: Vec<String>,
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

/// The root certificate's state; the engine derives it, the app shows it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertState {
    #[default]
    NotInstalled,
    Installed,
    /// The rotation window has come and no new root is in place yet.
    ExpiresSoon,
    /// Off or withdrawn, and removing the root has not succeeded yet: Windows
    /// may still trust it, and the engine keeps trying. Sieve mints nothing.
    RemovalPending,
}

/// Whether Firefox trusts the Windows store. `NotUsingWindows` is a policy
/// someone else set to 0: it must not read as a claim of trust.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirefoxTrust {
    #[default]
    NotInstalled,
    UsesWindows,
    NotUsingWindows,
}

/// The `cert_status` message (plan 8.1). A fact the engine does not have is
/// `null`, never a stand-in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertStatus {
    pub state: CertState,
    /// The active root's notAfter, ms since the Unix epoch.
    pub valid_until_ms: Option<u64>,
    /// SHA-1 of the root's DER, lowercase hex (`certutil -store Root <hash>`).
    pub thumbprint: Option<String>,
    pub firefox: FirefoxTrust,
    pub last_rotation_ms: Option<u64>,
    pub last_error: Option<String>,
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

/// Where signed updates stand (plan 7.5). `version` is the display form of a
/// release, for reading only; the app never sends it back.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpdateStatus {
    /// This build has no update key or host; nothing is ever fetched.
    #[default]
    NotConfigured,
    /// Nothing checked yet in this run.
    Idle,
    Checking,
    /// The last check found nothing newer.
    Current,
    /// A verified index offers this release; it installs only when asked.
    Available { version: String },
    Applying { version: String },
    /// The index expired: a stale index is reported, not trusted.
    Stale,
    /// The check could not finish (the network, a local file).
    Failed { message: String },
    /// Signed bytes were refused; nothing was replaced.
    Refused { message: String },
    /// This release did not come up; the previous one is back.
    RolledBack { version: String },
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
    /// What it filters with; None until it holds compiled lists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<FilterFacts>,
    /// Signed updates (protocol 3).
    pub update: UpdateStatus,
}

/// What the engine filters with, as the app shows it. The catalogue stays in
/// `sieve-filter`, which the app does not link; only its facts cross the pipe.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterFacts {
    pub lists: Vec<ListFact>,
    /// The resource library's pin (plan 8.4).
    pub resource_pin: Option<String>,
}

/// One filter list as the engine compiled it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListFact {
    /// The catalogue's id.
    pub id: String,
    pub title: String,
    /// The list's public project page; its issue page derives from it.
    pub homepage: String,
    /// The list's own `! Version:`.
    pub version: Option<String>,
    pub applied: u64,
    pub skipped: u64,
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

/// A list line as the report carries it: at most [`MAX_LISTED_LINE_BYTES`], with
/// no control characters. JSON writes one of those as six bytes, which would
/// break the frame bound for text that means nothing to a reader anyway.
pub fn listed_line(line: &str) -> String {
    let printable: String = line.chars().filter(|c| !c.is_control()).collect();
    cap_text(&printable, MAX_LISTED_LINE_BYTES).to_string()
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

/// The name of a process hosting these Windows services, where its exe is
/// hidden from the app: the display name when there is one, else the first by
/// name and how many more ("Windows Update and 3 more"). Sorted, so the name,
/// and the app it groups into, is stable from one read to the next. None for no
/// services. The app shows it as the row's name and the engine keys the same
/// process by it ([`app_key`]), so the row's Off means that process on both sides.
pub fn service_label(mut names: Vec<String>) -> Option<String> {
    names.retain(|n| !n.trim().is_empty());
    names.sort();
    names.dedup();
    match names.len() {
        0 => None,
        1 => names.pop(),
        n => Some(format!("{} and {} more", names[0], n - 1)),
    }
}

/// What the filter did with one request or flow (plan 8.3). A reason is a
/// slug the app turns into words; later slices add reasons with no bump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LogOutcome {
    Blocked,
    Redirected,
    ParamsRemoved,
    Hidden { elements: u32 },
    Scriptlets { count: u32 },
    Passed { reason: String },
    NotDecrypted { reason: String },
}

/// One row of the filtering log. A host-level row leaves `url` and
/// `request_type` null.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogRow {
    /// Unique for the engine's run.
    pub id: u64,
    /// When, ms since the Unix epoch.
    pub t: u64,
    pub flow_id: u64,
    pub pid: Option<u32>,
    pub exe: Option<String>,
    pub session: Option<u32>,
    pub kind: FlowKind,
    /// The name, else the remote IP.
    pub host: String,
    /// The far end, `ip:port` (`[v6]:port`).
    pub remote: String,
    /// At most [`LOG_URL_MAX`] bytes.
    pub url: Option<String>,
    pub request_type: Option<String>,
    pub outcome: LogOutcome,
    /// At most [`LOG_RULE_MAX`] bytes.
    pub rule: Option<String>,
    /// A catalogue id, or `user`.
    pub list: Option<String>,
    /// Some for a guest's flow, which has no process (see [`FlowEvent::forwarded`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded: Option<Forwarded>,
}

/// A batch of rows as the `log` messages to send.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LogFrames {
    /// In the batch's order, each encoding to at most [`MAX_FRAME`] and holding
    /// at most [`LOG_PER_FRAME`] rows.
    pub messages: Vec<EngineMessage>,
    /// Rows left out because one alone is over [`MAX_FRAME`]: only a row that
    /// skipped the caps. The caller says so; the stream goes on.
    pub oversized: usize,
}

/// Splits rows by their encoded size, which is what [`MAX_FRAME`] limits.
pub fn log_frames(rows: &[LogRow]) -> Result<LogFrames, FrameError> {
    const SEPARATOR: usize = b",".len();
    let empty = serde_json::to_vec(&EngineMessage::Log { rows: Vec::new() })?.len();
    let mut frames = LogFrames::default();
    let mut current: Vec<LogRow> = Vec::new();
    let mut size = empty;
    for row in rows {
        let len = serde_json::to_vec(row)?.len();
        if empty + len > MAX_FRAME {
            frames.oversized += 1;
            continue;
        }
        if !current.is_empty() && (current.len() == LOG_PER_FRAME || size + SEPARATOR + len > MAX_FRAME) {
            frames.messages.push(EngineMessage::Log { rows: std::mem::take(&mut current) });
            size = empty;
        }
        size += len + if current.is_empty() { 0 } else { SEPARATOR };
        current.push(row.clone());
    }
    if !current.is_empty() {
        frames.messages.push(EngineMessage::Log { rows: current });
    }
    Ok(frames)
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
        assert_eq!(f["maxPolicyBytes"], MAX_POLICY_BYTES);
        assert_eq!(f["flowsBatchMs"], FLOWS_BATCH_MS);
        assert_eq!(f["flowsPerFrame"], FLOWS_PER_FRAME);
        assert_eq!(f["logPerFrame"], LOG_PER_FRAME);
        assert_eq!(f["logUrlMax"], LOG_URL_MAX);
        assert_eq!(f["logRuleMax"], LOG_RULE_MAX);
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
            ClientMessage::DnsUpstreams => "dns_upstreams",
            ClientMessage::CertStatus => "cert_status",
            ClientMessage::InstallRoot => "install_root",
            ClientMessage::RequestUpdate {} => "request_update",
            ClientMessage::Exclusions { .. } => "exclusions",
            ClientMessage::TryDecryptAgain { .. } => "try_decrypt_again",
            ClientMessage::HealNotices { .. } => "heal_notices",
        };
        let engine = |m: &EngineMessage| match m {
            EngineMessage::Welcome { .. } => "welcome",
            EngineMessage::Incompatible { .. } => "incompatible",
            EngineMessage::Status(_) => "status",
            EngineMessage::Error { .. } => "error",
            EngineMessage::Flows { .. } => "flows",
            EngineMessage::Lists { .. } => "lists",
            EngineMessage::DnsUpstreams(_) => "dns_upstreams",
            EngineMessage::Log { .. } => "log",
            EngineMessage::CertStatus(_) => "cert_status",
            EngineMessage::Exclusions { .. } => "exclusions",
            EngineMessage::HealNotices { .. } => "heal_notices",
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
        const RAW_LINE_BYTES: usize = 4 * MAX_LISTED_LINE_BYTES;
        for escaped in ['"', '\\', '\n', '\u{1}'] {
            let line: String = std::iter::repeat_n(['a', escaped], RAW_LINE_BYTES).flatten().collect();
            let solid = escaped.to_string().repeat(RAW_LINE_BYTES);
            for raw in [line, solid] {
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
                    skipped_exceptions: vec![listed_line(&raw); LISTED_LINES],
                    skipped_exceptions_total: u64::MAX,
                };
                let msg = EngineMessage::Lists { lists: vec![list; LISTS_AT_WORST], compile_ms: Some(u64::MAX) };
                assert!(encode(&msg).is_ok(), "{escaped:?}: {:?}", encode(&msg).err());
            }
        }
    }

    /// Every outcome kind round trips, so the TS law sees each wire name, and
    /// a new variant fails here until it has a fixture example.
    #[test]
    fn every_fixture_outcome_round_trips_and_every_kind_is_shown() {
        let f = fixture();
        let outcomes = f["outcomes"].as_array().unwrap();
        let name = |o: &LogOutcome| match o {
            LogOutcome::Blocked => "blocked",
            LogOutcome::Redirected => "redirected",
            LogOutcome::ParamsRemoved => "params_removed",
            LogOutcome::Hidden { .. } => "hidden",
            LogOutcome::Scriptlets { .. } => "scriptlets",
            LogOutcome::Passed { .. } => "passed",
            LogOutcome::NotDecrypted { .. } => "not_decrypted",
        };
        let mut seen = Vec::new();
        for o in outcomes {
            let parsed: LogOutcome = serde_json::from_value(o.clone()).unwrap();
            assert_eq!(&serde_json::to_value(&parsed).unwrap(), o);
            assert_eq!(name(&parsed), o["kind"]);
            seen.push(name(&parsed));
        }
        seen.dedup();
        assert_eq!(seen, ["blocked", "redirected", "params_removed", "hidden", "scriptlets", "passed", "not_decrypted"]);
    }

    /// The status's filter facts are additive: without them the wire is as
    /// before, so a status with none round trips with no `filter` key.
    #[test]
    fn filter_facts_are_absent_until_the_engine_holds_lists() {
        let none = serde_json::to_value(EngineMessage::Status(EngineStatus::default())).unwrap();
        assert!(none.get("filter").is_none());
        let facts = FilterFacts {
            lists: vec![ListFact { id: "a".into(), title: "A".into(), homepage: "https://a.example/a".into(), version: None, applied: 1, skipped: 0 }],
            resource_pin: Some("sha256:0".into()),
        };
        let some = EngineMessage::Status(EngineStatus { filter: Some(facts), ..EngineStatus::default() });
        let wire = serde_json::to_value(&some).unwrap();
        assert_eq!(wire["filter"]["lists"][0]["homepage"], "https://a.example/a");
        assert_eq!(serde_json::from_value::<EngineMessage>(wire).unwrap(), some);
    }

    /// A row at every cap, its URL and rule made of `url` and `rule` repeated.
    fn log_row_at_caps(url: char, rule: char) -> LogRow {
        LogRow {
            id: u64::MAX,
            t: u64::MAX,
            flow_id: u64::MAX,
            pid: Some(u32::MAX),
            exe: Some(format!(r"C:\{}\app.exe", "d".repeat(250))),
            session: Some(u32::MAX),
            kind: FlowKind::Tls,
            host: "h".repeat(253),
            remote: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535".into(),
            url: Some(url.to_string().repeat(LOG_URL_MAX)),
            request_type: Some("xmlhttprequest".into()),
            outcome: LogOutcome::NotDecrypted { reason: "r".repeat(64) },
            rule: Some(rule.to_string().repeat(LOG_RULE_MAX)),
            list: Some("adguard-url-tracking".into()),
            forwarded: None,
        }
    }

    fn rows_of(frames: &LogFrames) -> Vec<LogRow> {
        frames.messages.iter().flat_map(|m| match m {
            EngineMessage::Log { rows } => rows.clone(),
            other => panic!("not a log message: {other:?}"),
        }).collect()
    }

    /// Every frame encodes and holds what the limits allow, and no frame could
    /// have taken the next one's first row: nothing lost, nothing split early.
    fn assert_split_exactly(rows: &[LogRow], frames: &LogFrames) {
        assert_eq!(rows_of(frames), rows);
        let batches: Vec<&Vec<LogRow>> = frames.messages.iter().map(|m| match m {
            EngineMessage::Log { rows } => rows,
            other => panic!("not a log message: {other:?}"),
        }).collect();
        for (i, batch) in batches.iter().enumerate() {
            assert!(!batch.is_empty());
            assert!(batch.len() <= LOG_PER_FRAME);
            let body = encode(&frames.messages[i]).unwrap().len() - 4;
            assert!(body <= MAX_FRAME, "{body}");
            if let Some(next) = batches.get(i + 1) {
                let next_row = serde_json::to_vec(&next[0]).unwrap().len();
                assert!(batch.len() == LOG_PER_FRAME || body + 1 + next_row > MAX_FRAME, "frame {i} of {body} bytes split early");
            }
        }
    }

    #[test]
    fn plain_rows_at_the_caps_fill_one_frame_by_count() {
        let rows = vec![log_row_at_caps('u', 'r'); LOG_PER_FRAME];
        let frames = log_frames(&rows).unwrap();
        assert_eq!(frames.messages.len(), 1);
        assert_split_exactly(&rows, &frames);

        let rows = vec![log_row_at_caps('u', 'r'); LOG_PER_FRAME + 1];
        let frames = log_frames(&rows).unwrap();
        assert_eq!(frames.messages.len(), 2);
        assert_split_exactly(&rows, &frames);
    }

    /// The raw caps do not bound a frame: escaping does the rest, up to six
    /// bytes for one. Sent whole these are refused, and that would end the stream.
    #[test]
    fn rows_that_escape_at_the_caps_split_by_encoded_size() {
        for (url, rule, parts) in [('\\', 'r', 2), ('\\', '\\', 2), ('\u{1}', 'r', 3), ('\u{1}', '\u{1}', 4)] {
            let rows = vec![log_row_at_caps(url, rule); LOG_PER_FRAME];
            assert!(matches!(encode(&EngineMessage::Log { rows: rows.clone() }), Err(FrameError::TooLarge(_))));
            let frames = log_frames(&rows).unwrap();
            assert_eq!(frames.messages.len(), parts, "{url:?} {rule:?}");
            assert_eq!(frames.oversized, 0);
            assert_split_exactly(&rows, &frames);
        }
    }

    #[test]
    fn a_row_too_large_alone_is_counted_and_the_rest_still_go() {
        let plain = log_row_at_caps('u', 'r');
        let huge = LogRow { url: Some("u".repeat(MAX_FRAME)), ..plain.clone() };
        let frames = log_frames(&[plain.clone(), huge, plain.clone()]).unwrap();
        assert_eq!(frames.oversized, 1);
        assert_split_exactly(&[plain.clone(), plain], &frames);
    }

    #[test]
    fn no_rows_are_no_frames() {
        assert_eq!(log_frames(&[]).unwrap(), LogFrames::default());
    }

    /// A row that just fits alone is sent: the limit is on the body, inclusive.
    #[test]
    fn a_frame_of_exactly_the_limit_goes() {
        let mut row = log_row_at_caps('u', 'r');
        let overhead = encode(&EngineMessage::Log { rows: vec![row.clone()] }).unwrap().len() - 4 - LOG_URL_MAX;
        row.url = Some("u".repeat(MAX_FRAME - overhead));
        let frames = log_frames(std::slice::from_ref(&row)).unwrap();
        assert_eq!(frames.oversized, 0);
        assert_eq!(encode(&frames.messages[0]).unwrap().len() - 4, MAX_FRAME);
    }

    /// The fixture's `certStatuses` are what the app's mock serves, so TS,
    /// Rust and the mock share one shape; each state has an example.
    #[test]
    fn every_fixture_cert_status_round_trips_and_every_state_is_shown() {
        let f = fixture();
        let examples = f["certStatuses"].as_object().unwrap();
        for (name, example) in examples {
            let parsed: CertStatus = serde_json::from_value(example.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(&serde_json::to_value(&parsed).unwrap(), example, "{name}");
        }
        let text = f.to_string();
        for wire in ["not_installed", "installed", "expires_soon", "removal_pending", "uses_windows", "not_using_windows"] {
            assert!(text.contains(&format!(r#""{wire}""#)), "{wire}");
        }
        let _exhaustive = |s: CertState, ff: FirefoxTrust| match (s, ff) {
            (CertState::NotInstalled | CertState::Installed | CertState::ExpiresSoon | CertState::RemovalPending, _) => match ff {
                FirefoxTrust::NotInstalled | FirefoxTrust::UsesWindows | FirefoxTrust::NotUsingWindows => (),
            },
        };
    }

    #[test]
    fn the_fixtures_policy_with_content_round_trips_unchanged() {
        let wire = fixture()["policyWithContent"].clone();
        let parsed: ClientMessage = serde_json::from_value(wire.clone()).unwrap();
        assert!(matches!(&parsed, ClientMessage::SetPolicy(p) if p.content));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
    }

    #[test]
    fn the_policy_without_content_loads_and_serializes_without_it() {
        let old: Policy = serde_json::from_str(r#"{"revision":4,"engine":true,"https":true}"#).unwrap();
        assert!(!old.content);
        assert!(serde_json::to_value(&old).unwrap().get("content").is_none(), "false is left out");
        let on = Policy { content: true, ..old };
        let wire = serde_json::to_value(&on).unwrap();
        assert_eq!(wire["content"], true);
        assert_eq!(serde_json::from_value::<Policy>(wire).unwrap(), on, "the round trip");
    }

    #[test]
    fn an_old_policy_file_keeps_its_engine_switch_and_reads_https_off() {
        let old: Policy = serde_json::from_str(r#"{"revision":4,"engine":true}"#).unwrap();
        assert_eq!(old, Policy { revision: 4, engine: true, https: false, ..Policy::default() });
        assert!(serde_json::from_str::<Policy>(r#"{"revision":4,"engine":true,"x":1}"#).is_err(), "unknown fields stay refused");
    }

    #[test]
    fn every_fixture_update_round_trips_and_a_v2_status_is_refused() {
        let updates = fixture()["updates"].as_array().unwrap().clone();
        assert!(!updates.is_empty());
        for u in updates {
            let parsed: UpdateStatus = serde_json::from_value(u.clone()).unwrap();
            assert_eq!(serde_json::to_value(&parsed).unwrap(), u);
        }
        let f = fixture();
        let mut status = f["engine"].as_array().unwrap().iter().find(|m| m["type"] == "status").unwrap().clone();
        status.as_object_mut().unwrap().remove("update");
        assert!(serde_json::from_value::<EngineMessage>(status).is_err(), "a v2 status lacks update");
    }

    /// The fixture carries every update state, so the TS law sees each name (a
    /// new state without an example fails here: the match is exhaustive).
    #[test]
    fn the_fixture_shows_every_update_kind() {
        let name = |u: &UpdateStatus| match u {
            UpdateStatus::NotConfigured => "not_configured",
            UpdateStatus::Idle => "idle",
            UpdateStatus::Checking => "checking",
            UpdateStatus::Current => "current",
            UpdateStatus::Available { .. } => "available",
            UpdateStatus::Applying { .. } => "applying",
            UpdateStatus::Stale => "stale",
            UpdateStatus::Failed { .. } => "failed",
            UpdateStatus::Refused { .. } => "refused",
            UpdateStatus::RolledBack { .. } => "rolled_back",
        };
        let f = fixture();
        let shown: Vec<&str> = f["updates"].as_array().unwrap().iter().map(|u| name(&serde_json::from_value(u.clone()).unwrap())).collect();
        assert_eq!(
            shown,
            ["not_configured", "idle", "checking", "current", "available", "applying", "stale", "failed", "refused", "rolled_back"]
        );
    }

    /// Plan 7.5: the one update message carries no field, and a client message
    /// names no file, path or data of any kind.
    #[test]
    fn request_update_has_no_fields_and_refuses_any() {
        assert_eq!(serde_json::to_value(ClientMessage::RequestUpdate {}).unwrap(), serde_json::json!({"type": "request_update"}));
        assert_eq!(serde_json::from_str::<ClientMessage>(r#"{"type":"request_update"}"#).unwrap(), ClientMessage::RequestUpdate {});
        for extra in [r#"{"type":"request_update","url":"x"}"#, r#"{"type":"request_update","version":"9"}"#, r#"{"type":"request_update","path":"C:\\x"}"#] {
            assert!(serde_json::from_str::<ClientMessage>(extra).is_err(), "{extra}");
        }
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

    /// The auto layer at its caps (3 x 1024, from `exclusions::auto`), every host at
    /// its 253 bytes and a long exe name, plus a list: past one frame.
    fn rows_at_the_caps() -> Vec<ExclusionRow> {
        const AUTO_AT_WORST: usize = 3 * 1024;
        const LIST_LINES: usize = 2000;
        let row = |i: usize| ExclusionRow { line: format!("\"h{i}{}\"", "h".repeat(240)), apps: vec![format!("{}.exe", "e".repeat(200))], reason: "auto:client-cert".into(), created_ms: Some(u64::MAX), retries: u32::MAX };
        (0..AUTO_AT_WORST + LIST_LINES).map(row).collect()
    }

    fn view_of(rows: Vec<ExclusionRow>) -> ExclusionsView {
        ExclusionsView { revision: 7, rows, scope: ExclusionScope::Browsers, browsers: vec![format!(r"c:\{}\browser.exe", "d".repeat(250)); 8] }
    }

    fn walk(view: &ExclusionsView) -> Vec<Vec<ExclusionRow>> {
        let (mut pages, mut after) = (Vec::new(), 0);
        loop {
            let EngineMessage::Exclusions { rows, next, total, .. } = exclusions_page(view, after).unwrap() else { panic!("not a page") };
            assert_eq!(total as usize, view.rows.len());
            pages.push(rows);
            let Some(next) = next else { return pages };
            assert!(next > after, "a page moves on");
            after = next;
        }
    }

    #[test]
    fn exclusion_pages_fit_a_frame_at_the_caps() {
        let view = view_of(rows_at_the_caps());
        let whole = EngineMessage::Exclusions { revision: 7, rows: view.rows.clone(), total: 0, next: None, scope: view.scope, browsers: view.browsers.clone() };
        assert!(matches!(encode(&whole), Err(FrameError::TooLarge(_))), "the control: sent whole it is refused");
        let mut after = 0;
        loop {
            let page = exclusions_page(&view, after).unwrap();
            assert!(encode(&page).unwrap().len() - 4 <= MAX_FRAME);
            let EngineMessage::Exclusions { next, .. } = page else { panic!() };
            let Some(next) = next else { break };
            after = next;
        }
        assert!(after > 0, "more than one page");
    }

    #[test]
    fn every_row_arrives_once_across_pages() {
        let view = view_of(rows_at_the_caps());
        let pages = walk(&view);
        assert!(pages.len() > 1);
        assert_eq!(pages.concat(), view.rows);
    }

    #[test]
    fn no_rows_is_one_empty_page_and_a_cursor_past_the_end_is_empty() {
        let view = view_of(Vec::new());
        assert_eq!(walk(&view), [Vec::<ExclusionRow>::new()]);
        let view = view_of(rows_at_the_caps());
        let EngineMessage::Exclusions { rows, next, .. } = exclusions_page(&view, u32::MAX).unwrap() else { panic!() };
        assert!(rows.is_empty() && next.is_none());
    }

    #[test]
    fn a_row_too_large_for_any_frame_is_passed_over() {
        let plain = rows_at_the_caps().swap_remove(0);
        let huge = ExclusionRow { line: "h".repeat(MAX_FRAME), ..plain.clone() };
        let view = view_of(vec![plain.clone(), huge, plain.clone()]);
        assert_eq!(walk(&view).concat(), [plain.clone(), plain]);
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
