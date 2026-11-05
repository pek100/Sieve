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
//! Decision: [`verdict`] is pure: (domain, exe, rules, policy) -> pass or
//! drop with a reason. Per-app levels mirror Sieve's (`sieve` filters,
//! `off` and `watch` never drop). A flow whose domain is unknown (no SNI,
//! no Host, undecodable) passes, and the reason says so.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::flow::etw::{ETW_FLUSH_MIN_MS, PidWitness, Unwitnessed, Witnessed};
use crate::flow::packet::{Packet, Proto};
use sieve_filter::rules::{HostVerdict, RuleEngine};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No domain could be read from the flow (no SNI, no Host, not decoded).
    UnknownDomain,
    /// The app's level is below `sieve`.
    AppNotFiltered(Level),
    /// An allow rule matched.
    Allowed,
    /// No rule matched.
    NoRule,
    /// A block rule matched for a filtered app.
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub reason: Reason,
}

impl Decision {
    fn pass(reason: Reason) -> Self {
        Self { action: Action::Pass, reason }
    }
}

/// The verdict for one flow.
pub fn verdict(domain: Option<&str>, exe: Option<&str>, rules: &RuleEngine, policy: &AppPolicy) -> Decision {
    let Some(domain) = domain else {
        return Decision::pass(Reason::UnknownDomain);
    };
    let level = policy.level_of(exe);
    if level != Level::Sieve {
        return Decision::pass(Reason::AppNotFiltered(level));
    }
    match rules.check_host(domain) {
        HostVerdict::Block => Decision { action: Action::Drop, reason: Reason::Blocked },
        HostVerdict::Allow => Decision::pass(Reason::Allowed),
        HostVerdict::None => Decision::pass(Reason::NoRule),
    }
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

    /// The spike matched with a copy of the DNS rule set; the engine asks
    /// the one rule engine (plan 5.1). The rules below are the same text.
    fn rules(text: &str) -> RuleEngine {
        RuleEngine::compile(&[sieve_filter::rules::ListText { id: "test", text, trusted: false }])
    }

    const CURL: &str = r"C:\Windows\System32\curl.exe";
    const OTHER: &str = r"C:\Users\me\AppData\Local\Temp\curl-other.exe";

    #[test]
    fn blocked_domain_drops_only_for_filtered_apps() {
        let r = rules("||ads.example^\n@@||ok.ads.example^");
        let policy = AppPolicy::new(Level::Sieve).set("curl-other.exe", Level::Off);
        assert_eq!(verdict(Some("x.ads.example"), Some(CURL), &r, &policy), Decision { action: Action::Drop, reason: Reason::Blocked });
        assert_eq!(
            verdict(Some("x.ads.example"), Some(OTHER), &r, &policy),
            Decision { action: Action::Pass, reason: Reason::AppNotFiltered(Level::Off) }
        );
        assert_eq!(verdict(Some("ok.ads.example"), Some(CURL), &r, &policy).reason, Reason::Allowed);
        assert_eq!(verdict(Some("news.example"), Some(CURL), &r, &policy).reason, Reason::NoRule);
    }

    #[test]
    fn unknown_domain_always_passes_and_says_so() {
        let r = rules("||ads.example^");
        let policy = AppPolicy::new(Level::Sieve);
        for exe in [Some(CURL), None] {
            assert_eq!(verdict(None, exe, &r, &policy), Decision { action: Action::Pass, reason: Reason::UnknownDomain });
        }
    }

    #[test]
    fn unknown_app_gets_the_default_level() {
        let r = rules("||ads.example^");
        assert_eq!(verdict(Some("ads.example"), None, &r, &AppPolicy::new(Level::Sieve)).action, Action::Drop);
        assert_eq!(verdict(Some("ads.example"), None, &r, &AppPolicy::new(Level::Off)).action, Action::Pass);
    }

    #[test]
    fn enforce_test_policy_blocks_one_exe_only() {
        // The probe's --enforce-test shape: default off, one exe sieved.
        let r = rules("||sieve-spike-test.example^");
        let policy = AppPolicy::new(Level::Off).set(CURL, Level::Sieve);
        assert_eq!(verdict(Some("sieve-spike-test.example"), Some(CURL), &r, &policy).action, Action::Drop);
        assert_eq!(verdict(Some("sieve-spike-test.example"), Some(&CURL.to_uppercase()), &r, &policy).action, Action::Drop);
        assert_eq!(verdict(Some("sieve-spike-test.example"), Some(OTHER), &r, &policy).action, Action::Pass);
        assert_eq!(verdict(Some("other.example"), Some(CURL), &r, &policy).action, Action::Pass);
    }

    #[test]
    fn watch_level_never_drops_and_full_path_beats_file_name() {
        let r = rules("||ads.example^");
        let policy = AppPolicy::new(Level::Off).set("curl.exe", Level::Sieve).set(CURL, Level::Watch);
        assert_eq!(verdict(Some("ads.example"), Some(CURL), &r, &policy).reason, Reason::AppNotFiltered(Level::Watch));
        assert_eq!(verdict(Some("ads.example"), Some(r"D:\x\curl.exe"), &r, &policy).action, Action::Drop);
    }

    proptest! {
        #[test]
        fn table_decoding_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            for t in [Table::Tcp4, Table::Tcp6, Table::Udp4, Table::Udp6] {
                let _ = decode_table(t, &bytes);
            }
        }

        #[test]
        fn verdict_never_drops_for_off_or_watch(domain in "[a-z]{1,8}\\.example", exe in "[a-z]{1,8}\\.exe") {
            let r = rules("||example^\nexample.com");
            let r2 = rules(&format!("||{domain}^"));
            for level in [Level::Off, Level::Watch] {
                let p = AppPolicy::new(level);
                prop_assert_eq!(verdict(Some(&domain), Some(&exe), &r, &p).action, Action::Pass);
                prop_assert_eq!(verdict(Some(&domain), Some(&exe), &r2, &p).action, Action::Pass);
            }
            prop_assert_eq!(verdict(Some(&domain), Some(&exe), &r2, &AppPolicy::new(Level::Sieve)).action, Action::Drop);
        }
    }
}
