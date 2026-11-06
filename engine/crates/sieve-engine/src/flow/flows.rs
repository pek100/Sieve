//! Who owns a flow seen on the TUN, and what to do with it.
//!
//! Attribution (read only, no admin needed, the same IP Helper tables
//! Sieve's netstat module reads): when a new outbound flow appears on the
//! TUN (local addr:port -> remote addr:port), look the local end up in the
//! owner-pid rows of `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` or
//! `GetExtendedUdpTable(UDP_TABLE_OWNER_PID)` for its address family.
//!
//! - TCP: a row whose local and remote ends both match wins; a row whose
//!   local end matches and remote is unspecified:0 is accepted next.
//! - UDP rows have no remote end: match local addr:port, then the wildcard
//!   address (0.0.0.0 or ::) with the same port (unconnected sockets).
//!   Both protocols require a unique nonzero PID at the chosen specificity.
//! - The table can lag the first packet (a SYN is on the wire before the
//!   row is visible to a reader). [`Attributor`] keeps one snapshot per
//!   table, refreshes it on a miss at most every [`REFRESH_MIN_MS`], and
//!   answers `Pending` until [`GIVE_UP_MS`] after the first miss, then
//!   `Unknown`. The caller holds the flow's packets meanwhile (classify).
//! - A [`PidWitness`] (ETW) is a second exact source, asked with every lookup:
//!   [`combine`] takes a PID only one of them gave, and two different answers
//!   make the flow unknown, never one or the other. Agreement is checked with
//!   what the witness holds at decision time: waiting for ETW on a table hit
//!   would add latency to every flow, and a later contradiction is not re-judged.
//!
//! The decision itself is `crate::domain`. Here: [`Action`], the probe's
//! [`AppPolicy`], and each executable's app key ([`AppKeys`]).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;

use crate::flow::etw::{ETW_FLUSH_MIN_MS, PidWitness, Unwitnessed, Witnessed};
use crate::flow::packet::{Packet, Proto};
use sieve_ipc::{app_key, service_label};

/// A refresh of a table is never more frequent than this on misses.
pub const REFRESH_MIN_MS: u64 = 15;
/// A flow still unmatched this long after its first lookup is Unknown.
pub const GIVE_UP_MS: u64 = 250;
/// A table snapshot older than this is refreshed before any lookup.
pub const SNAPSHOT_MAX_AGE_MS: u64 = 2_000;
/// PID 0 names no process, in an owner row or an ETW event: no owner is proven.
pub const NO_OWNER_PID: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

impl FiveTuple {
    /// The key of a packet the host sent into the TUN: its source is local.
    pub fn outbound(p: &Packet<'_>) -> Self {
        Self { proto: p.proto, local: SocketAddr::new(p.src, p.src_port), remote: SocketAddr::new(p.dst, p.dst_port) }
    }

    pub fn is_v6(&self) -> bool {
        self.local.is_ipv6()
    }
}

/// One owner-pid row. `remote` is None for UDP rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerRow {
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub pid: u32,
}

/// Which of the four tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Table {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
}

impl Table {
    pub fn of(t: &FiveTuple) -> Self {
        match (t.proto, t.is_v6()) {
            (Proto::Tcp, false) => Table::Tcp4,
            (Proto::Tcp, true) => Table::Tcp6,
            (Proto::Udp, false) => Table::Udp4,
            (Proto::Udp, true) => Table::Udp6,
        }
    }

    /// Bytes per row in the buffer Windows fills (after the u32 count).
    fn row_len(self) -> usize {
        match self {
            Table::Tcp4 => 24, // state, laddr, lport, raddr, rport, pid
            Table::Tcp6 => 56, // laddr16, lscope, lport, raddr16, rscope, rport, state, pid
            Table::Udp4 => 12, // laddr, lport, pid
            Table::Udp6 => 28, // laddr16, lscope, lport, pid
        }
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// A port stored in a DWORD: network byte order in the first two bytes.
fn port_at(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn v4_at(b: &[u8], at: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3]))
}

fn v6_at(b: &[u8], at: usize) -> IpAddr {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[at..at + 16]);
    IpAddr::V6(Ipv6Addr::from(a))
}

/// Decodes a MIB_*TABLE_OWNER_PID buffer. A count larger than the buffer
/// holds is clamped to the whole rows present (never read past the end).
pub fn decode_table(table: Table, buf: &[u8]) -> Vec<OwnerRow> {
    if buf.len() < 4 {
        return Vec::new();
    }
    let claimed = u32_at(buf, 0) as usize;
    let len = table.row_len();
    let fit = (buf.len() - 4) / len;
    (0..claimed.min(fit))
        .map(|i| {
            let r = &buf[4 + i * len..4 + (i + 1) * len];
            match table {
                Table::Tcp4 => OwnerRow {
                    local: SocketAddr::new(v4_at(r, 4), port_at(r, 8)),
                    remote: Some(SocketAddr::new(v4_at(r, 12), port_at(r, 16))),
                    pid: u32_at(r, 20),
                },
                Table::Tcp6 => OwnerRow {
                    local: SocketAddr::new(v6_at(r, 0), port_at(r, 20)),
                    remote: Some(SocketAddr::new(v6_at(r, 24), port_at(r, 44))),
                    pid: u32_at(r, 52),
                },
                Table::Udp4 => OwnerRow { local: SocketAddr::new(v4_at(r, 0), port_at(r, 4)), remote: None, pid: u32_at(r, 8) },
                Table::Udp6 => OwnerRow { local: SocketAddr::new(v6_at(r, 0), port_at(r, 20)), remote: None, pid: u32_at(r, 24) },
            }
        })
        .collect()
}

/// The owner of `flow` among `rows`, best match first (see module docs).
pub fn match_owner(flow: &FiveTuple, rows: &[OwnerRow]) -> Option<u32> {
    // Reused ports and shared UDP bindings must not borrow another app's
    // exemption. At the first matching specificity, require one known PID.
    fn unique<'a>(mut rows: impl Iterator<Item = &'a OwnerRow>) -> Option<Option<u32>> {
        let first = rows.next()?.pid;
        Some((first != NO_OWNER_PID && rows.all(|r| r.pid == first)).then_some(first))
    }
    if flow.proto == Proto::Tcp {
        if let Some(owner) = unique(rows.iter().filter(|r| r.local == flow.local && r.remote == Some(flow.remote))) {
            return owner;
        }
        // A different known remote is never a "not connected yet" row.
        return unique(rows.iter().filter(|r| r.local == flow.local && r.remote.is_some_and(|remote| remote.ip().is_unspecified() && remote.port() == 0))).flatten();
    }
    if let Some(owner) = unique(rows.iter().filter(|r| r.local == flow.local && r.remote.is_none())) {
        return owner;
    }
    unique(rows.iter().filter(|r| r.local.port() == flow.local.port() && r.local.ip().is_unspecified()
        && r.local.is_ipv4() == flow.local.is_ipv4() && r.remote.is_none())).flatten()
}

/// Where table bytes come from: the OS in the probe, a fake in tests.
pub trait OwnerSource {
    fn read(&mut self, table: Table) -> Option<Vec<OwnerRow>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    Pid(u32),
    /// A PID only the witness gave: no table row, an exact tuple in ETW.
    WitnessOnly(u32),
    /// The sources contradict each other: the flow is unknown. `table` is what
    /// the owner tables said, kept for the loop guard and nothing else. The
    /// witness side needs no such field: the ring never holds the engine's PID.
    Disagreed { table: Option<u32> },
    /// Not in the table yet; ask again (hold the packet meanwhile).
    Pending,
    /// Still not found after [`GIVE_UP_MS`]: unattributed.
    Unknown,
}

/// What the owner tables and the witness say together. A contradiction never
/// picks a side: a witness conflict or two different PIDs is [`Owner::Disagreed`].
/// A witness saying [`NO_OWNER_PID`] has said nothing, whichever witness it is.
pub fn combine(table: Option<u32>, witnessed: Witnessed, gave_up: bool) -> Owner {
    let witnessed = if witnessed == Witnessed::Pid(NO_OWNER_PID) { Witnessed::Nothing } else { witnessed };
    match (table, witnessed) {
        (_, Witnessed::Conflict) => Owner::Disagreed { table },
        (Some(t), Witnessed::Pid(w)) if t != w => Owner::Disagreed { table },
        (Some(t), _) => Owner::Pid(t),
        (None, Witnessed::Pid(w)) => Owner::WitnessOnly(w),
        (None, Witnessed::Nothing) if gave_up => Owner::Unknown,
        (None, Witnessed::Nothing) => Owner::Pending,
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AttributionStats {
    pub table_reads: u64,
    pub table_read_errors: u64,
    pub found_first_try: u64,
    pub found_after_retry: u64,
    pub unknown: u64,
    pub witness_only: u64,
    pub disagreed: u64,
}

struct Snapshot {
    rows: Vec<OwnerRow>,
    read_ms: u64,
}

/// Flow -> pid with a snapshot cache, refresh on miss and a give-up time.
pub struct Attributor<S: OwnerSource, W: PidWitness = Unwitnessed> {
    source: S,
    witness: W,
    snapshots: HashMap<Table, Snapshot>,
    first_miss: HashMap<FiveTuple, u64>,
    last_nudge_ms: Option<u64>,
    pub stats: AttributionStats,
}

impl<S: OwnerSource, W: PidWitness> Attributor<S, W> {
    pub fn new(source: S, witness: W) -> Self {
        Self { source, witness, snapshots: HashMap::new(), first_miss: HashMap::new(), last_nudge_ms: None, stats: AttributionStats::default() }
    }

    fn refresh(&mut self, table: Table, now_ms: u64) {
        self.stats.table_reads += 1;
        match self.source.read(table) {
            Some(rows) => {
                self.snapshots.insert(table, Snapshot { rows, read_ms: now_ms });
            }
            None => {
                self.stats.table_read_errors += 1;
                // Keep the old snapshot but mark the attempt, so a failing
                // read is not retried on every packet.
                let rows = self.snapshots.remove(&table).map(|s| s.rows).unwrap_or_default();
                self.snapshots.insert(table, Snapshot { rows, read_ms: now_ms });
            }
        }
    }

    /// The owner of `flow` at time `now_ms` (any monotonic millisecond clock).
    pub fn owner(&mut self, flow: &FiveTuple, now_ms: u64) -> Owner {
        let table = Table::of(flow);
        let stale = self.snapshots.get(&table).is_none_or(|s| now_ms.saturating_sub(s.read_ms) > SNAPSHOT_MAX_AGE_MS);
        if stale {
            self.refresh(table, now_ms);
        }
        let held = |a: &Self| a.snapshots.get(&table).and_then(|s| match_owner(flow, &s.rows));
        let mut from_table = held(self);
        let can_refresh = self.snapshots.get(&table).is_none_or(|s| now_ms.saturating_sub(s.read_ms) >= REFRESH_MIN_MS);
        if from_table.is_none() && can_refresh {
            self.refresh(table, now_ms);
            from_table = held(self);
        }
        let witnessed = self.witness.answer(flow, now_ms);
        let first = *self.first_miss.entry(*flow).or_insert(now_ms);
        let gave_up = now_ms.saturating_sub(first) >= GIVE_UP_MS;
        let owner = combine(from_table, witnessed, gave_up);
        if owner == Owner::Pending {
            self.nudge(now_ms);
            return owner;
        }
        let retried = first != now_ms;
        self.first_miss.remove(flow);
        match owner {
            Owner::Pid(_) | Owner::WitnessOnly(_) if retried => self.stats.found_after_retry += 1,
            Owner::Pid(_) | Owner::WitnessOnly(_) => self.stats.found_first_try += 1,
            Owner::Disagreed { .. } => self.stats.disagreed += 1,
            Owner::Unknown => self.stats.unknown += 1,
            Owner::Pending => {}
        }
        if matches!(owner, Owner::WitnessOnly(_)) {
            self.stats.witness_only += 1;
        }
        owner
    }

    /// A pending flow asks the witness to deliver, at most every
    /// [`ETW_FLUSH_MIN_MS`] across all flows.
    fn nudge(&mut self, now_ms: u64) {
        if self.last_nudge_ms.is_none_or(|at| now_ms.saturating_sub(at) >= ETW_FLUSH_MIN_MS) {
            self.last_nudge_ms = Some(now_ms);
            self.witness.nudge();
        }
    }
}

/// pid -> exe path, cached for a short time (pids are reused, so the
/// entry expires; a process that exits keeps its answer until then).
pub struct ExeCache<F: FnMut(u32) -> Option<String>> {
    lookup: F,
    entries: HashMap<u32, (Option<String>, u64)>,
}

pub const EXE_CACHE_MS: u64 = 10_000;

impl<F: FnMut(u32) -> Option<String>> ExeCache<F> {
    pub fn new(lookup: F) -> Self {
        Self { lookup, entries: HashMap::new() }
    }

    pub fn exe(&mut self, pid: u32, now_ms: u64) -> Option<String> {
        if let Some((exe, at)) = self.entries.get(&pid)
            && now_ms.saturating_sub(*at) < EXE_CACHE_MS
        {
            return exe.clone();
        }
        let exe = if pid == 0 || pid == 4 { None } else { (self.lookup)(pid) };
        self.entries.insert(pid, (exe.clone(), now_ms));
        exe
    }
}

/// At most this many exe paths keep their key; past it the cache starts over
/// (a machine has far fewer executables with sockets; this only bounds it).
const MAX_APP_KEYS: usize = 4_096;

/// exe path -> app key, read once per path: version info does not change
/// while a file is in use. The lookup runs outside the lock.
pub struct AppKeys<F, H> {
    product_of: F,
    hidden_name: H,
    keys: Mutex<HashMap<String, String>>,
}

impl<F: Fn(&str) -> Option<String>, H: Fn(u32) -> Option<String>> AppKeys<F, H> {
    /// `hidden_name`: the name the app shows for a pid whose exe it cannot read
    /// ([`HiddenNames`]), None for a pid it can.
    pub fn new(product_of: F, hidden_name: H) -> Self {
        Self { product_of, hidden_name, keys: Mutex::default() }
    }

    fn keys(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        self.keys.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn key(&self, exe: &str) -> String {
        if let Some(hit) = self.keys().get(exe) {
            return hit.clone();
        }
        let key = app_key((self.product_of)(exe).as_deref(), Some(exe), "");
        let mut keys = self.keys();
        if keys.len() >= MAX_APP_KEYS {
            keys.clear();
        }
        keys.insert(exe.to_string(), key.clone());
        key
    }

    /// The app key of `pid`, the key of the row the app shows it under: the name
    /// it shows for an exe hidden from it, else from the exe, or the fixed label
    /// of a kernel pid (the app's `label`). None when nothing names it: an
    /// unattributed flow is sieved rather than given a guessed exemption.
    ///
    /// The engine runs as SYSTEM and reads exes the unelevated app cannot. Keying
    /// those by what the engine reads would put svchost.exe under "microsoft
    /// windows operating system", the row of the readable explorer.exe, while the
    /// app lists that host as "DHCP Client and 3 more" and reads it as sieved: that
    /// product row's Off would exempt every service host, and the service row's
    /// Off none. So both sides key such a process by the name the app shows.
    ///
    /// TENSION: the name moves as a host's services stop and start, and a row's Off
    /// goes with its old name, on both sides alike. And "hidden" is judged here,
    /// not asked of the app ([`hidden_from_the_app`]); where the two differ the
    /// process is keyed under a row that is not the one it shows in, which fails
    /// on the safe side for a row that reads sieved: it stays sieved.
    pub fn of_pid(&self, pid: u32, exe: Option<&str>) -> Option<String> {
        match (exe, pid) {
            (None, 0) => return Some(app_key(None, None, "System idle")),
            (None, 4) => return Some(app_key(None, None, "System")),
            _ => {}
        }
        match (self.hidden_name)(pid) {
            Some(name) => Some(app_key(None, None, &name)),
            None => exe.map(|exe| self.key(exe)),
        }
    }
}

/// Whether the unelevated app is refused this process, from the account the
/// process runs as (its SID as text; None when it could not be read): only a
/// person's own accounts, local, domain (S-1-5-21) or Entra (S-1-12-1), leave
/// their processes open to that person. SYSTEM, the service accounts and virtual
/// service accounts do not.
pub fn hidden_from_the_app(account: Option<&str>) -> bool {
    account.is_none_or(|sid| !(sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-")))
}

/// The name the app shows for a pid whose exe is hidden from it: what its
/// services are called, else "pid n" (`src-tauri`'s `netstat::process::label`).
/// The service table is read at most once per [`EXE_CACHE_MS`], outside the lock.
pub struct HiddenNames<A, S> {
    account_of: A,
    read_services: S,
    /// The table and when it was read.
    services: Mutex<Option<(ServiceTable, u64)>>,
}

/// The display names of the running services each pid hosts.
pub type ServiceTable = HashMap<u32, Vec<String>>;

impl<A: Fn(u32) -> Option<String>, S: Fn() -> ServiceTable> HiddenNames<A, S> {
    pub fn new(account_of: A, read_services: S) -> Self {
        Self { account_of, read_services, services: Mutex::default() }
    }

    /// None when the app can read the exe itself.
    pub fn name(&self, pid: u32, now_ms: u64) -> Option<String> {
        if !hidden_from_the_app((self.account_of)(pid).as_deref()) {
            return None;
        }
        let held = {
            let services = self.services.lock().unwrap_or_else(|p| p.into_inner());
            services.as_ref().filter(|(_, at)| now_ms.saturating_sub(*at) < EXE_CACHE_MS).map(|(table, _)| table.get(&pid).cloned())
        };
        let names = held.unwrap_or_else(|| {
            let table = (self.read_services)();
            let names = table.get(&pid).cloned();
            *self.services.lock().unwrap_or_else(|p| p.into_inner()) = Some((table, now_ms));
            names
        });
        Some(names.and_then(service_label).unwrap_or_else(|| format!("pid {pid}")))
    }
}

/// A version-resource string as a name: it ends at the first NUL (Windows'
/// reported length can run past it), control and invisible characters go, and
/// whitespace runs collapse. Empty after that means no name.
///
/// TENSION: the OS read and this cleaning also live in
/// `src-tauri/src/netstat/process.rs`. `sieve-ipc` and `sieve-filter` make no
/// Windows calls and the engine never links Tauri, so the pure key rule is
/// shared (`sieve_ipc::app_key`) and this read is duplicated.
pub fn clean_resource_string(words: &[u16]) -> Option<String> {
    let end = words.iter().position(|&w| w == 0).unwrap_or(words.len());
    let text: String = char::decode_utf16(words[..end].iter().copied())
        .filter_map(Result::ok)
        .filter(|c| !c.is_control() && !matches!(*c, '\u{FFFD}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}' | '\u{E000}'..='\u{F8FF}'))
        .collect();
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    (!text.is_empty()).then_some(text)
}

/// Per-app level, mirroring Sieve's `off < watch < sieve`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Off,
    Watch,
    Sieve,
}

/// Which apps are filtered. An app is named by full path (contains a
/// backslash or slash) or by file name; both compare case-insensitively.
#[derive(Debug, Clone)]
pub struct AppPolicy {
    pub default: Level,
    apps: Vec<(String, Level)>,
}

impl AppPolicy {
    pub fn new(default: Level) -> Self {
        Self { default, apps: Vec::new() }
    }

    pub fn set(mut self, app: &str, level: Level) -> Self {
        self.apps.push((app.to_lowercase().replace('/', "\\"), level));
        self
    }

    /// The level for an exe path (None when the pid or path is unknown:
    /// the default applies).
    pub fn level_of(&self, exe: Option<&str>) -> Level {
        let Some(exe) = exe else { return self.default };
        let path = exe.to_lowercase().replace('/', "\\");
        let name = path.rsplit('\\').next().unwrap_or(&path);
        // A full-path entry beats a file-name entry; later entries win ties.
        let by_path = self.apps.iter().rev().find(|(k, _)| k.contains('\\') && *k == path);
        let by_name = || self.apps.iter().rev().find(|(k, _)| !k.contains('\\') && k == name);
        by_path.or_else(by_name).map_or(self.default, |(_, l)| *l)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Pass,
    Drop,
}

/// The OS lookups the probe uses. Read only.
#[cfg(windows)]
pub mod os {
    use super::{OwnerRow, OwnerSource, Table, decode_table};

    /// Reads one owner-pid table (size probe, then fill; bounded retries
    /// when the table grows in between).
    pub fn read_table(table: Table) -> Option<Vec<u8>> {
        use std::ffi::c_void;
        use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
        };
        use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

        let af = match table {
            Table::Tcp4 | Table::Udp4 => u32::from(AF_INET.0),
            Table::Tcp6 | Table::Udp6 => u32::from(AF_INET6.0),
        };
        let call = |buf: Option<*mut c_void>, size: &mut u32| -> u32 {
            // SAFETY: `buf` is None (size probe) or a live buffer of at least
            // `*size` bytes that Windows fills and does not keep.
            unsafe {
                match table {
                    Table::Tcp4 | Table::Tcp6 => GetExtendedTcpTable(buf, size, false, af, TCP_TABLE_OWNER_PID_ALL, 0),
                    Table::Udp4 | Table::Udp6 => GetExtendedUdpTable(buf, size, false, af, UDP_TABLE_OWNER_PID, 0),
                }
            }
        };
        let mut size: u32 = 0;
        let first = call(None, &mut size);
        if first != NO_ERROR.0 && first != ERROR_INSUFFICIENT_BUFFER.0 {
            return None;
        }
        for _ in 0..5 {
            let words = size.div_ceil(4).max(1);
            let mut buf = vec![0u32; words as usize];
            let mut len = words * 4;
            let code = call(Some(buf.as_mut_ptr().cast::<c_void>()), &mut len);
            if code == NO_ERROR.0 {
                return Some(buf.iter().flat_map(|w| w.to_ne_bytes()).collect());
            }
            if code != ERROR_INSUFFICIENT_BUFFER.0 {
                return None;
            }
            size = len;
        }
        None
    }

    /// The live tables.
    pub struct IpHelper;

    impl OwnerSource for IpHelper {
        fn read(&mut self, table: Table) -> Option<Vec<OwnerRow>> {
            read_table(table).map(|b| decode_table(table, &b))
        }
    }

    /// Full image path of a process, or None when Windows refuses.
    pub fn exe_path(pid: u32) -> Option<String> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        };
        use windows::core::PWSTR;

        // SAFETY: plain call; the handle is closed below.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let mut buf = vec![0u16; 32_768];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` u16s; Windows writes at most that many.
        let ok = unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len) };
        // SAFETY: `handle` came from OpenProcess and is closed once.
        let _ = unsafe { CloseHandle(handle) };
        ok.ok()?;
        buf.get(..len as usize).map(String::from_utf16_lossy).filter(|p| !p.is_empty())
    }

    /// The name the app shows for `pid` when its exe is hidden from the app.
    pub fn hidden_name(pid: u32) -> Option<String> {
        type Names = super::HiddenNames<fn(u32) -> Option<String>, fn() -> std::collections::HashMap<u32, Vec<String>>>;
        static NAMES: std::sync::OnceLock<Names> = std::sync::OnceLock::new();
        NAMES.get_or_init(|| super::HiddenNames::new(account_of, service_names)).name(pid, crate::watchdog::monotonic_ms())
    }

    /// The account a process runs as, its SID as text; None when Windows refuses.
    pub fn account_of(pid: u32) -> Option<String> {
        use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
        use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};
        use windows::core::PWSTR;

        // SAFETY: plain call; the handle is closed below.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let mut token = HANDLE::default();
        // SAFETY: `process` is open and `token` is a valid out pointer.
        let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
        // SAFETY: `process` came from OpenProcess and is closed once.
        let _ = unsafe { CloseHandle(process) };
        opened.ok()?;
        // u64 storage keeps the buffer aligned for the TOKEN_USER written into it;
        // a TOKEN_USER and its SID fit in far less than this.
        let mut buf = [0u64; 32];
        let mut len = 0u32;
        // SAFETY: the buffer is writable for the size given and `len` is a valid out pointer.
        let read = unsafe { GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), size_of_val(&buf) as u32, &mut len) };
        // SAFETY: `token` came from OpenProcessToken and is closed once.
        let _ = unsafe { CloseHandle(token) };
        read.ok()?;
        // SAFETY: the call above succeeded, so the buffer starts with a TOKEN_USER.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut text = PWSTR::null();
        // SAFETY: `sid` points into `buf`; `text` is a valid out pointer, freed below.
        unsafe { ConvertSidToStringSidW(sid, &mut text) }.ok()?;
        // SAFETY: Windows wrote a NUL-terminated string to `text`.
        let out = unsafe { text.to_string() }.ok();
        // SAFETY: `text` was allocated by ConvertSidToStringSidW for LocalFree, once.
        let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
        out
    }

    /// First buffer for the service list (64 KiB, about 400 services); it grows
    /// to what Windows asks for.
    const SERVICE_BUF_WORDS: usize = 8 * 1024;
    /// Calls before giving up on a list that keeps changing under us.
    const SERVICE_ROUNDS: usize = 16;

    /// Running Windows services by the pid that hosts them, display names. Empty
    /// when Windows refuses; the names are then "pid n".
    ///
    /// TENSION: this OS read also lives in `src-tauri/src/netstat/process.rs`, for
    /// the same reason as `clean_resource_string` below. The pure rule is shared
    /// (`sieve_ipc::service_label`). The app reads the list as the user and this as
    /// SYSTEM: a service the user may not query would make the labels differ, and
    /// that row's Off then exempts nothing, the safe side
    /// (docs/live/engine-slice-3.md, "A row's Off").
    pub fn service_names() -> std::collections::HashMap<u32, Vec<String>> {
        use windows::Win32::Foundation::ERROR_MORE_DATA;
        use windows::Win32::System::Services::{
            CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW, SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
        };
        use windows::core::PCWSTR;

        let mut out: std::collections::HashMap<u32, Vec<String>> = std::collections::HashMap::new();
        // SAFETY: plain call; the handle is closed below on every path.
        let Ok(scm) = (unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) }) else {
            return out;
        };
        // u64 storage keeps the buffer aligned for the structs Windows writes into it.
        let mut buf: Vec<u64> = vec![0; SERVICE_BUF_WORDS];
        let mut resume: u32 = 0;
        for _ in 0..SERVICE_ROUNDS {
            let (mut needed, mut count) = (0u32, 0u32);
            let result = {
                // SAFETY: a byte view of `buf`, which outlives this call.
                let bytes = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len() * 8) };
                // SAFETY: `bytes` is writable for its whole length; the out pointers are valid locals.
                unsafe { EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, Some(bytes), &mut needed, &mut count, Some(&mut resume), PCWSTR::null()) }
            };
            // SAFETY: Windows wrote `count` entries at the start of `buf`; their
            // strings point into `buf`, which is not touched until they are read.
            let entries = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(), count as usize) };
            for e in entries {
                let pid = e.ServiceStatusProcess.dwProcessId;
                // SAFETY: a NUL-terminated string inside `buf` (or null, which reads as an error).
                let name = if e.lpDisplayName.is_null() { None } else { unsafe { e.lpDisplayName.to_string() }.ok() };
                if let (true, Some(name)) = (pid != 0, name) {
                    out.entry(pid).or_default().push(name);
                }
            }
            match result {
                Ok(()) => break,
                Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => {
                    // Nothing fitted: grow to what Windows asked for, then ask again from `resume`.
                    if count == 0 {
                        buf = vec![0; (needed as usize).div_ceil(8).max(buf.len() * 2)];
                    }
                }
                Err(_) => break,
            }
        }
        // SAFETY: `scm` came from OpenSCManagerW and is closed once.
        let _ = unsafe { CloseServiceHandle(scm) };
        out
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// ProductName from an exe's version resource (uncached: see `AppKeys`).
    pub fn product_name(exe: &str) -> Option<String> {
        use std::ffi::c_void;
        use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW};
        use windows::core::PCWSTR;

        let path = wide(exe);
        // SAFETY: `path` is a NUL-terminated UTF-16 string that outlives the calls.
        let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(path.as_ptr()), None) };
        if size == 0 {
            return None;
        }
        // u32 storage keeps the block aligned for the u16 strings inside it.
        let mut block = vec![0u32; (size as usize).div_ceil(4)];
        // SAFETY: `block` has at least `size` bytes.
        unsafe { GetFileVersionInfoW(PCWSTR(path.as_ptr()), None, size, block.as_mut_ptr().cast::<c_void>()) }.ok()?;

        let mut keys: Vec<(u16, u16)> = Vec::new();
        if let Some(words) = version_value(&block, "\\VarFileInfo\\Translation") {
            keys.extend(words.chunks_exact(2).map(|p| (p[0], p[1])));
        }
        // Common fallbacks when the translation table is missing or wrong:
        // US English with Unicode, US English with Windows-1252, neutral Unicode.
        keys.extend([(0x0409, 0x04B0), (0x0409, 0x04E4), (0x0000, 0x04B0)]);
        keys.into_iter().find_map(|(lang, cp)| {
            let words = version_value(&block, &format!("\\StringFileInfo\\{lang:04x}{cp:04x}\\ProductName"))?;
            super::clean_resource_string(words)
        })
    }

    /// VerQueryValueW for `sub`, as the u16 words it points at (the
    /// translation table's length is in bytes, a string's in characters).
    fn version_value<'a>(block: &'a [u32], sub: &str) -> Option<&'a [u16]> {
        use std::ffi::c_void;
        use windows::Win32::Storage::FileSystem::VerQueryValueW;
        use windows::core::PCWSTR;

        let key = wide(sub);
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        // SAFETY: `block` is the buffer GetFileVersionInfoW filled; `ptr` is
        // set to a location inside it and `len` to its length.
        let ok = unsafe { VerQueryValueW(block.as_ptr().cast::<c_void>(), PCWSTR(key.as_ptr()), &mut ptr, &mut len) };
        if !ok.as_bool() || ptr.is_null() || len == 0 || !ptr.cast::<u16>().is_aligned() {
            return None;
        }
        let words = if sub.starts_with("\\VarFileInfo") { len as usize / 2 } else { len as usize };
        let start = block.as_ptr() as usize;
        let end = start + block.len() * 4;
        let at = ptr as usize;
        if at < start || at + words * 2 > end {
            return None;
        }
        // SAFETY: checked above that [ptr, ptr + words * 2) lies inside `block`
        // and is 2-byte aligned; the slice borrows `block`.
        Some(unsafe { std::slice::from_raw_parts(ptr.cast::<u16>(), words) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::packet::build;
    use proptest::prelude::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn tcp(local: &str, remote: &str) -> FiveTuple {
        FiveTuple { proto: Proto::Tcp, local: sa(local), remote: sa(remote) }
    }

    fn udp(local: &str, remote: &str) -> FiveTuple {
        FiveTuple { proto: Proto::Udp, local: sa(local), remote: sa(remote) }
    }

    fn port_dword(p: u16) -> [u8; 4] {
        let b = p.to_be_bytes();
        [b[0], b[1], 0, 0]
    }

    fn tcp4_buf(rows: &[(&str, &str, u32)]) -> Vec<u8> {
        let mut b = (rows.len() as u32).to_ne_bytes().to_vec();
        for (l, r, pid) in rows {
            let (l, r) = (sa(l), sa(r));
            let (IpAddr::V4(la), IpAddr::V4(ra)) = (l.ip(), r.ip()) else { panic!() };
            b.extend_from_slice(&5u32.to_ne_bytes()); // ESTABLISHED
            b.extend_from_slice(&la.octets());
            b.extend_from_slice(&port_dword(l.port()));
            b.extend_from_slice(&ra.octets());
            b.extend_from_slice(&port_dword(r.port()));
            b.extend_from_slice(&pid.to_ne_bytes());
        }
        b
    }

    #[test]
    fn decodes_tcp4_rows_with_network_order_ports() {
        let buf = tcp4_buf(&[("10.0.0.2:50000", "93.184.216.34:443", 4242)]);
        let rows = decode_table(Table::Tcp4, &buf);
        assert_eq!(rows, vec![OwnerRow { local: sa("10.0.0.2:50000"), remote: Some(sa("93.184.216.34:443")), pid: 4242 }]);
    }

    #[test]
    fn decodes_tcp6_udp4_udp6_rows() {
        let mut b = 1u32.to_ne_bytes().to_vec();
        let l: Ipv6Addr = "fd00::2".parse().unwrap();
        let r: Ipv6Addr = "2606:4700::1".parse().unwrap();
        b.extend_from_slice(&l.octets());
        b.extend_from_slice(&0u32.to_ne_bytes());
        b.extend_from_slice(&port_dword(51000));
        b.extend_from_slice(&r.octets());
        b.extend_from_slice(&0u32.to_ne_bytes());
        b.extend_from_slice(&port_dword(443));
        b.extend_from_slice(&5u32.to_ne_bytes());
        b.extend_from_slice(&77u32.to_ne_bytes());
        let rows = decode_table(Table::Tcp6, &b);
        assert_eq!(rows[0].local, sa("[fd00::2]:51000"));
        assert_eq!(rows[0].remote, Some(sa("[2606:4700::1]:443")));
        assert_eq!(rows[0].pid, 77);

        let mut b = 1u32.to_ne_bytes().to_vec();
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(&port_dword(5353));
        b.extend_from_slice(&9u32.to_ne_bytes());
        assert_eq!(decode_table(Table::Udp4, &b), vec![OwnerRow { local: sa("0.0.0.0:5353"), remote: None, pid: 9 }]);

        let mut b = 1u32.to_ne_bytes().to_vec();
        b.extend_from_slice(&l.octets());
        b.extend_from_slice(&0u32.to_ne_bytes());
        b.extend_from_slice(&port_dword(60000));
        b.extend_from_slice(&11u32.to_ne_bytes());
        assert_eq!(decode_table(Table::Udp6, &b)[0], OwnerRow { local: sa("[fd00::2]:60000"), remote: None, pid: 11 });
    }

    #[test]
    fn a_count_larger_than_the_buffer_is_clamped() {
        let mut buf = tcp4_buf(&[("10.0.0.2:1", "1.1.1.1:443", 1)]);
        buf[0..4].copy_from_slice(&1000u32.to_ne_bytes());
        assert_eq!(decode_table(Table::Tcp4, &buf).len(), 1);
        assert!(decode_table(Table::Udp6, &[1, 0]).is_empty());
    }

    #[test]
    fn matching_prefers_exact_then_local_then_wildcard() {
        let rows = vec![
            OwnerRow { local: sa("0.0.0.0:5000"), remote: None, pid: 1 },
            OwnerRow { local: sa("10.0.0.2:5000"), remote: Some(sa("2.2.2.2:443")), pid: 2 },
            OwnerRow { local: sa("10.0.0.2:5000"), remote: Some(sa("1.1.1.1:443")), pid: 3 },
        ];
        assert_eq!(match_owner(&tcp("10.0.0.2:5000", "1.1.1.1:443"), &rows), Some(3));
        assert_eq!(match_owner(&tcp("10.0.0.2:5000", "9.9.9.9:443"), &rows), None);
        assert_eq!(match_owner(&udp("10.0.0.7:5000", "9.9.9.9:443"), &rows), Some(1));
        assert_eq!(match_owner(&udp("10.0.0.7:6000", "9.9.9.9:443"), &rows), None);
    }

    #[test]
    fn attribution_never_guesses_between_apps_or_counts_pid_zero() {
        let flow = tcp("10.0.0.2:5000", "1.1.1.1:443");
        let row = OwnerRow { local: flow.local, remote: Some(flow.remote), pid: 0 };
        assert_eq!(match_owner(&flow, &[row]), None);
        assert_eq!(match_owner(&flow, &[OwnerRow {pid: 1, ..row}, OwnerRow {pid: 2, ..row}]), None);
        let flow = udp("10.0.0.2:5000", "1.1.1.1:443");
        let rows = [OwnerRow {local: sa("0.0.0.0:5000"), remote: None, pid: 1}, OwnerRow {local: sa("0.0.0.0:5000"), remote: None, pid: 2}];
        assert_eq!(match_owner(&flow, &rows), None);
        assert_eq!(match_owner(&flow, &[rows[0], rows[0]]), Some(1));
    }

    #[test]
    fn only_a_truly_unconnected_tcp_row_can_supply_a_local_fallback() {
        let flow = tcp("10.0.0.2:5000", "1.1.1.1:443");
        let row = OwnerRow {local: flow.local, remote: Some(sa("0.0.0.0:0")), pid: 42};
        assert_eq!(match_owner(&flow, &[row]), Some(42));
        let wrong_remote = OwnerRow {remote: Some(sa("2.2.2.2:443")), ..row};
        assert_eq!(match_owner(&flow, &[wrong_remote]), None);
    }

    /// A fake table source: rows appear after `visible_after` reads.
    struct Lagging {
        rows: Vec<OwnerRow>,
        visible_after: u32,
        reads: u32,
        fail: bool,
    }

    impl OwnerSource for Lagging {
        fn read(&mut self, _t: Table) -> Option<Vec<OwnerRow>> {
            self.reads += 1;
            if self.fail {
                return None;
            }
            Some(if self.reads > self.visible_after { self.rows.clone() } else { Vec::new() })
        }
    }

    fn lagging(visible_after: u32) -> Lagging {
        Lagging {
            rows: vec![OwnerRow { local: sa("10.0.0.2:5000"), remote: Some(sa("1.1.1.1:443")), pid: 42 }],
            visible_after,
            reads: 0,
            fail: false,
        }
    }

    use std::cell::Cell;

    /// A fake witness: one fixed answer, and how often it was nudged.
    #[derive(Default)]
    struct Fixed {
        answer: Option<Witnessed>,
        nudges: Cell<u32>,
    }

    impl PidWitness for Fixed {
        fn answer(&self, _flow: &FiveTuple, _now_ms: u64) -> Witnessed {
            self.answer.unwrap_or(Witnessed::Nothing)
        }

        fn nudge(&self) {
            self.nudges.set(self.nudges.get() + 1);
        }
    }

    #[test]
    fn combine_matches_the_table() {
        use Witnessed::{Conflict, Nothing, Pid};
        assert_eq!(combine(Some(7), Pid(7), false), Owner::Pid(7), "agree");
        assert_eq!(combine(None, Pid(7), false), Owner::WitnessOnly(7), "ETW only");
        assert_eq!(combine(Some(7), Nothing, false), Owner::Pid(7), "table only");
        assert_eq!(combine(Some(7), Pid(8), false), Owner::Disagreed { table: Some(7) }, "disagree");
        assert_eq!(combine(Some(7), Conflict, false), Owner::Disagreed { table: Some(7) }, "ETW conflict, with a table row");
        assert_eq!(combine(None, Conflict, false), Owner::Disagreed { table: None }, "ETW conflict alone");
        assert_eq!(combine(None, Nothing, false), Owner::Pending, "neither, still waiting");
        assert_eq!(combine(None, Nothing, true), Owner::Unknown, "neither, past the give-up");
        assert_eq!(combine(None, Pid(7), true), Owner::WitnessOnly(7), "a late ETW answer still counts");
    }

    #[test]
    fn a_witness_pid_zero_is_no_answer() {
        assert_eq!(combine(None, Witnessed::Pid(0), false), Owner::Pending);
        assert_eq!(combine(None, Witnessed::Pid(0), true), Owner::Unknown);
        assert_eq!(combine(Some(7), Witnessed::Pid(0), false), Owner::Pid(7));
    }

    #[test]
    fn a_witness_names_a_socket_the_table_cannot_see() {
        let w = Fixed { answer: Some(Witnessed::Pid(9)), ..Fixed::default() };
        let mut a = Attributor::new(lagging(u32::MAX), w);
        assert_eq!(a.owner(&tcp("10.0.0.2:5000", "1.1.1.1:443"), 0), Owner::WitnessOnly(9));
        assert_eq!((a.stats.witness_only, a.stats.found_first_try, a.stats.unknown), (1, 1, 0));
    }

    #[test]
    fn a_disagreement_clears_first_miss() {
        let f = tcp("10.0.0.2:5000", "1.1.1.1:443");
        // Pending first (a real first_miss entry), then a table row that the witness contradicts.
        let mut a = Attributor::new(lagging(1), Fixed::default());
        assert_eq!(a.owner(&f, 0), Owner::Pending);
        assert_eq!(a.first_miss.len(), 1);
        a.witness.answer = Some(Witnessed::Pid(43));
        assert_eq!(a.owner(&f, REFRESH_MIN_MS), Owner::Disagreed { table: Some(42) });
        assert!(a.first_miss.is_empty());
        assert_eq!(a.stats.disagreed, 1);
    }

    #[test]
    fn a_pending_flow_nudges_the_witness_at_most_every_flush_interval() {
        let mut a = Attributor::new(lagging(u32::MAX), Fixed::default());
        let f = tcp("10.0.0.2:5000", "1.1.1.1:443");
        for t in 0..ETW_FLUSH_MIN_MS {
            assert_eq!(a.owner(&f, t), Owner::Pending);
        }
        assert_eq!(a.witness.nudges.get(), 1);
        assert_eq!(a.owner(&f, ETW_FLUSH_MIN_MS), Owner::Pending);
        assert_eq!(a.witness.nudges.get(), 2);
        // Another flow shares the bound: nudges are per witness, not per flow.
        assert_eq!(a.owner(&tcp("10.0.0.2:5001", "1.1.1.1:443"), ETW_FLUSH_MIN_MS + 1), Owner::Pending);
        assert_eq!(a.witness.nudges.get(), 2);
    }

    #[test]
    fn a_found_flow_never_nudges() {
        let mut a = Attributor::new(lagging(0), Fixed::default());
        assert_eq!(a.owner(&tcp("10.0.0.2:5000", "1.1.1.1:443"), 0), Owner::Pid(42));
        assert_eq!(a.witness.nudges.get(), 0);
    }

    #[test]
    fn found_on_the_first_lookup_when_the_table_has_it() {
        let mut a = Attributor::new(lagging(0), Unwitnessed);
        assert_eq!(a.owner(&tcp("10.0.0.2:5000", "1.1.1.1:443"), 0), Owner::Pid(42));
        assert_eq!(a.stats.found_first_try, 1);
    }

    #[test]
    fn a_lagging_table_gives_pending_then_the_pid() {
        let mut a = Attributor::new(lagging(3), Unwitnessed);
        let f = tcp("10.0.0.2:5000", "1.1.1.1:443");
        assert_eq!(a.owner(&f, 0), Owner::Pending);
        // Within REFRESH_MIN_MS no new read happens.
        assert_eq!(a.owner(&f, 5), Owner::Pending);
        assert_eq!(a.source.reads, 1);
        assert_eq!(a.owner(&f, 20), Owner::Pending);
        assert_eq!(a.owner(&f, 40), Owner::Pending);
        assert_eq!(a.owner(&f, 60), Owner::Pid(42));
        assert_eq!(a.stats.found_after_retry, 1);
        // Cached now: no extra reads for the next lookup.
        let reads = a.source.reads;
        assert_eq!(a.owner(&f, 61), Owner::Pid(42));
        assert_eq!(a.source.reads, reads);
    }

    #[test]
    fn a_flow_never_in_the_table_becomes_unknown_after_the_give_up_time() {
        let mut a = Attributor::new(lagging(u32::MAX), Unwitnessed);
        let f = tcp("10.0.0.2:5000", "1.1.1.1:443");
        let mut t = 0;
        while t < GIVE_UP_MS {
            assert_eq!(a.owner(&f, t), Owner::Pending, "t={t}");
            t += 10;
        }
        assert_eq!(a.owner(&f, GIVE_UP_MS), Owner::Unknown);
        assert_eq!(a.stats.unknown, 1);
        // Reads were rate limited: at most one per REFRESH_MIN_MS plus the first.
        assert!(u64::from(a.source.reads) <= GIVE_UP_MS / REFRESH_MIN_MS + 2, "reads {}", a.source.reads);
    }

    #[test]
    fn failing_table_reads_are_counted_and_rate_limited() {
        let mut src = lagging(0);
        src.fail = true;
        let mut a = Attributor::new(src, Unwitnessed);
        let f = tcp("10.0.0.2:5000", "1.1.1.1:443");
        for t in 0..10 {
            assert_eq!(a.owner(&f, t), Owner::Pending);
        }
        assert_eq!(a.stats.table_read_errors, 1);
    }

    #[test]
    fn outbound_tuple_from_a_packet() {
        let p = build::ip(Proto::Udp, "10.0.0.2".parse().unwrap(), "1.1.1.1".parse().unwrap(), 5000, 443, 0, b"x");
        let pkt = crate::flow::packet::parse(&p).unwrap();
        assert_eq!(FiveTuple::outbound(&pkt), udp("10.0.0.2:5000", "1.1.1.1:443"));
    }

    #[test]
    fn exe_cache_expires_and_never_asks_for_kernel_pids() {
        let mut calls = 0;
        let mut c = ExeCache::new(|pid| {
            calls += 1;
            Some(format!("C:\\p{pid}.exe"))
        });
        assert_eq!(c.exe(10, 0).as_deref(), Some("C:\\p10.exe"));
        assert_eq!(c.exe(10, 5_000).as_deref(), Some("C:\\p10.exe"));
        assert_eq!(c.exe(4, 0), None);
        assert_eq!(c.exe(10, EXE_CACHE_MS + 1).as_deref(), Some("C:\\p10.exe"));
        drop(c);
        assert_eq!(calls, 2);
    }

    #[test]
    fn an_exes_key_is_read_once_per_path() {
        let asked = Mutex::new(Vec::new());
        let keys = AppKeys::new(
            |exe: &str| {
                asked.lock().unwrap().push(exe.to_string());
                exe.contains("chrome").then(|| "Google Chrome".to_string())
            },
            |_: u32| None,
        );
        assert_eq!(keys.key(r"C:\x\chrome.exe"), "google chrome");
        assert_eq!(keys.key(r"C:\x\chrome.exe"), "google chrome");
        assert_eq!(keys.key(r"C:\x\Tool.exe"), "tool");
        assert_eq!(asked.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_pid_has_a_key_from_its_exe_or_its_fixed_label_never_a_guess() {
        let keys = AppKeys::new(|_: &str| None, |_: u32| None);
        assert_eq!(keys.of_pid(99, Some(r"C:\x\Tool.exe")).as_deref(), Some("tool"));
        assert_eq!(keys.of_pid(4, None).as_deref(), Some("system"));
        assert_eq!(keys.of_pid(0, None).as_deref(), Some("system idle"));
        assert_eq!(keys.of_pid(99, None), None);
    }

    const WINDOWS_PRODUCT: &str = "Microsoft Windows Operating System";
    const SVCHOST: &str = r"C:\Windows\System32\svchost.exe";
    const EXPLORER: &str = r"C:\Windows\explorer.exe";
    const HOST: u32 = 1200;
    const SHELL: u32 = 3000;
    const WORKER: u32 = 3300;

    /// A machine: a service host and a service's worker as SYSTEM, and the
    /// user's own shell. All three exes carry Windows' product name.
    fn machine_keys() -> AppKeys<impl Fn(&str) -> Option<String>, impl Fn(u32) -> Option<String>> {
        let names = HiddenNames::new(
            |pid| Some(if pid == SHELL { "S-1-5-21-1-2-3-1001" } else { "S-1-5-18" }.to_string()),
            || HashMap::from([(HOST, vec!["DNS Client".to_string(), "DHCP Client".to_string()])]),
        );
        AppKeys::new(|_: &str| Some(WINDOWS_PRODUCT.to_string()), move |pid| names.name(pid, 0))
    }

    /// The key is the row's: the app shows the host under its services and the
    /// worker under its pid, and only the readable exe under the product name.
    #[test]
    fn a_process_hidden_from_the_app_has_the_key_of_the_row_the_app_shows_it_in() {
        let keys = machine_keys();
        assert_eq!(keys.of_pid(HOST, Some(SVCHOST)).as_deref(), Some("dhcp client and 1 more"));
        assert_eq!(keys.of_pid(WORKER, Some(SVCHOST)).as_deref(), Some("pid 3300"));
        assert_eq!(keys.of_pid(SHELL, Some(EXPLORER)).as_deref(), Some("microsoft windows operating system"));
    }

    /// The Off leak: one row's Off exempts that row's traffic and no other row's.
    #[test]
    fn a_rows_off_exempts_only_that_row() {
        use crate::domain::{DomainFilter, Flow, Owner as FlowOwner, Reason};
        use sieve_filter::rules::{ListText, RuleEngine, RuleSet};
        use std::sync::Arc;

        let keys = machine_keys();
        let lists = RuleEngine::compile(&[ListText { id: "test", text: "||ads.example^\n", trusted: false }]);
        let rules = RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(lists) };
        let off = |key: &str| DomainFilter::new(&sieve_ipc::Policy { sieving: true, off_apps: vec![key.to_string()], ..Default::default() }, rules.clone());
        let exempt = |filter: &DomainFilter, pid: u32, exe: &str| {
            let key = keys.of_pid(pid, Some(exe)).unwrap();
            let flow = Flow { dns: false, name: Some("ads.example"), remote: "192.0.2.1".parse().unwrap(), owner: FlowOwner::App { key: &key } };
            filter.decide(flow, &Mutex::default(), 0).reason == Reason::AppExempt
        };

        let product_row = off("microsoft windows operating system");
        assert!(exempt(&product_row, SHELL, EXPLORER));
        assert!(!exempt(&product_row, HOST, SVCHOST), "the service host's own row still reads sieved");
        assert!(!exempt(&product_row, WORKER, SVCHOST), "and so does the worker's");

        let service_row = off("dhcp client and 1 more");
        assert!(exempt(&service_row, HOST, SVCHOST), "their traffic is relayed untouched, as the setting says");
        assert!(!exempt(&service_row, SHELL, EXPLORER));
    }

    #[test]
    fn only_a_persons_own_account_leaves_a_process_readable() {
        for person in ["S-1-5-21-1-2-3-1001", "S-1-12-1-1-2-3-4"] {
            assert!(!hidden_from_the_app(Some(person)), "{person}");
        }
        for other in ["S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-80-1-2-3-4-5", "S-1-5-90-0-1", "S-1-5-96-0-1"] {
            assert!(hidden_from_the_app(Some(other)), "{other}");
        }
        assert!(hidden_from_the_app(None), "unread: no shared key is given on a guess");
    }

    #[test]
    fn the_service_table_is_read_once_per_period_and_only_for_a_hidden_process() {
        let reads = std::cell::Cell::new(0);
        let names = HiddenNames::new(
            |pid| Some(if pid == SHELL { "S-1-5-21-1" } else { "S-1-5-18" }.to_string()),
            || {
                reads.set(reads.get() + 1);
                HashMap::from([(HOST, vec!["DNS Client".to_string()])])
            },
        );
        assert_eq!(names.name(SHELL, 0), None);
        assert_eq!(reads.get(), 0);
        assert_eq!(names.name(HOST, 0).as_deref(), Some("DNS Client"));
        assert_eq!(names.name(WORKER, 1).as_deref(), Some("pid 3300"));
        assert_eq!(reads.get(), 1);
        assert_eq!(names.name(HOST, EXE_CACHE_MS).as_deref(), Some("DNS Client"));
        assert_eq!(reads.get(), 2);
    }

    /// Windows' own answer for this process: a test runs as a person.
    #[cfg(windows)]
    #[test]
    fn this_process_reads_as_its_users_account() {
        let sid = os::account_of(std::process::id()).expect("a process can read its own token");
        assert!(sid.starts_with("S-1-"), "{sid}");
    }

    #[test]
    fn a_resource_string_ends_at_its_nul_and_loses_invisible_characters() {
        let words = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        assert_eq!(clean_resource_string(&words("NVIDIA App\0junk")).as_deref(), Some("NVIDIA App"));
        assert_eq!(clean_resource_string(&words("  a \t b\u{200B} ")).as_deref(), Some("a b"));
        assert_eq!(clean_resource_string(&words("\u{FEFF}  ")), None);
    }

    proptest! {
        #[test]
        fn table_decoding_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            for t in [Table::Tcp4, Table::Tcp6, Table::Udp4, Table::Udp6] {
                let _ = decode_table(t, &bytes);
            }
        }

    }
}
