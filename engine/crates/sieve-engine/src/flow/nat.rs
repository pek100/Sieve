//! Guest traffic has no Windows socket, so no owner row can ever name it. What
//! proves it is NAT state: a session equal to the flow on protocol, external
//! source and external destination (the flow's `local` on the TUN is the
//! NAT's EXTERNAL source). No TTL, no guess: a flow without that exact match
//! is not forwarded (docs/tasks/2026-11-02-attribution.md, D1, D4, D14, D15).
//!
//! - [`NatSource`]: where sessions come from; every source is asked.
//! - [`VmDirectory`]: internal IP to the system's own name for the VM. If any
//!   link fails the name is None, and the flow takes the unidentified row.
//! - [`NatTable`]: the index of the last read. All reads run on one thread
//!   ([`NatTable::spawn`]), which owns whatever its sources need (a COM
//!   apartment), so a flow task waits on a reply and never blocks a runtime
//!   worker. A read is rate limited and bounded; a timeout is no match.
//!
//! A failed read costs attribution only, never routing. No timer: a machine
//! with no VMs reads NAT state only for its rare unknown flows.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use sieve_ipc::{Forwarded, VM_NAME_MAX, VM_UNIDENTIFIED};
use tokio::sync::oneshot;

use crate::flow::flows::FiveTuple;
use crate::flow::packet::Proto;

#[cfg(windows)]
pub mod os;

/// A fresh read is asked for at most this often.
pub const NAT_REFRESH_MIN_MS: u64 = 250;
/// A flow waits this long for a read; past it the flow has no match, and the
/// timeout is counted.
pub const NAT_READ_TIMEOUT_MS: u64 = 1_000;

/// `Microsoft-Windows-WinNat`, from the local manifest.
pub const WINNAT: u128 = 0x66C0_7ECD_6667_43FC_93F8_05CF_07F4_46EC;
pub const WINNAT_SESSION_CREATED: u16 = 1001;
pub const WINNAT_SESSION_DELETED: u16 = 1005;
pub const WINNAT_EVENTS: [u16; 2] = [WINNAT_SESSION_CREATED, WINNAT_SESSION_DELETED];
/// Sessions the event-built table holds at most, FIFO.
pub const WINNAT_TABLE_CAP: usize = 4096;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;
const SOCKADDR_IN_LEN: usize = 16;
const SOCKADDR_IN6_LEN: usize = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatSession {
    pub proto: Proto,
    pub internal_source: SocketAddr,
    pub external_source: SocketAddr,
    pub external_destination: SocketAddr,
}

/// What a session is matched on: never its internal side.
type NatKey = (Proto, SocketAddr, SocketAddr);

impl NatSession {
    fn key(&self) -> NatKey {
        (self.proto, self.external_source, self.external_destination)
    }
}

fn parse_address(ip: &str, port: u16) -> Option<SocketAddr> {
    // WMI may spell a scope ("fe80::1%3"); a match compares ip and port only.
    let ip: IpAddr = ip.split('%').next()?.trim().parse().ok()?;
    Some(SocketAddr::new(ip.to_canonical(), port))
}

/// One `MSFT_NetNatSession` row, from its own field values. A protocol that is
/// neither TCP nor UDP, or an unreadable address, is no session.
pub fn session_from_fields(protocol: u32, internal: (&str, u16), external_source: (&str, u16), external_destination: (&str, u16)) -> Option<NatSession> {
    Some(NatSession {
        proto: Proto::from_number(u8::try_from(protocol).ok()?)?,
        internal_source: parse_address(internal.0, internal.1)?,
        external_source: parse_address(external_source.0, external_source.1)?,
        external_destination: parse_address(external_destination.0, external_destination.1)?,
    })
}

/// Sessions from one place. One thread owns every source; it never moves.
pub trait NatSource {
    fn read(&mut self) -> Result<Vec<NatSession>, String>;
}

/// Internal IP to the VM's raw name, as the system spells it.
pub trait VmDirectory {
    fn vm_of(&mut self, internal: IpAddr) -> Option<String>;
}

/// No names: every forwarded flow is unidentified.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDirectory;

impl VmDirectory for NoDirectory {
    fn vm_of(&mut self, _internal: IpAddr) -> Option<String> {
        None
    }
}

/// The name as the wire and the UI carry it: control-free, trimmed, capped. A
/// name with no letter or digit, or the reserved word of the unidentified row,
/// is unnamed, so two rows can never share a key.
pub fn vm_name(raw: &str) -> Option<String> {
    let clean: String = raw.chars().filter(|c| !c.is_control()).collect();
    let capped: String = clean.trim().chars().take(VM_NAME_MAX).collect();
    let name = capped.trim_end();
    (name.chars().any(char::is_alphanumeric) && !name.eq_ignore_ascii_case(VM_UNIDENTIFIED)).then(|| name.to_string())
}

/// Every session by its key, each with what it proves about its VM.
pub type NatIndex = HashMap<NatKey, Forwarded>;

/// Two sessions on one external tuple with different internal ends are still
/// forwarded (both are guests), but which VM it is, is not proven.
pub fn index_sessions(sessions: &[NatSession], directory: &mut dyn VmDirectory) -> NatIndex {
    let mut internal: HashMap<NatKey, Option<IpAddr>> = HashMap::new();
    for s in sessions {
        let ip = s.internal_source.ip();
        match internal.entry(s.key()) {
            Entry::Vacant(v) => {
                v.insert(Some(ip));
            }
            Entry::Occupied(mut o) if *o.get() != Some(ip) => {
                o.insert(None);
            }
            Entry::Occupied(_) => {}
        }
    }
    let mut names: HashMap<IpAddr, Option<String>> = HashMap::new();
    internal
        .into_iter()
        .map(|(key, ip)| {
            let vm = ip.and_then(|ip| names.entry(ip).or_insert_with(|| directory.vm_of(ip).and_then(|raw| vm_name(&raw))).clone());
            (key, Forwarded { vm })
        })
        .collect()
}

/// The exact match of a flow: protocol, external source, external destination.
pub fn exact_match(flow: &FiveTuple, index: &NatIndex) -> Option<Forwarded> {
    let key = (flow.proto, SocketAddr::new(flow.local.ip().to_canonical(), flow.local.port()), SocketAddr::new(flow.remote.ip().to_canonical(), flow.remote.port()));
    index.get(&key).cloned()
}

/// What the table counted: a failed or slow read is no match, and shows here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct NatStats {
    pub reads: u64,
    pub read_errors: u64,
    pub timeouts: u64,
}

#[derive(Debug, Default)]
struct Shared {
    index: Mutex<NatIndex>,
    reads: AtomicU64,
    read_errors: AtomicU64,
    timeouts: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn read_all(sources: &mut [Box<dyn NatSource>], directory: &mut dyn VmDirectory, shared: &Shared) {
    shared.reads.fetch_add(1, Ordering::Relaxed);
    let mut sessions = Vec::new();
    let mut answered = false;
    for source in sources {
        match source.read() {
            Ok(mut s) => {
                answered = true;
                sessions.append(&mut s);
            }
            Err(_) => {
                shared.read_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    // When nothing answered, the sessions of the last read still stand.
    if answered {
        let index = index_sessions(&sessions, directory);
        *lock(&shared.index) = index;
    }
}

/// The NAT state the engine holds, and the one thread that reads it.
pub struct NatTable {
    shared: Arc<Shared>,
    requests: SyncSender<oneshot::Sender<()>>,
    /// One read at a time; holds when the last one started (monotonic ms).
    last_read: tokio::sync::Mutex<Option<u64>>,
}

impl NatTable {
    /// Starts the reader thread, which builds its sources with `make`, so
    /// they live and die on it. It ends once the table is dropped and any read
    /// in progress returned, so a hung read can never hold up a take-down. A
    /// thread that cannot start leaves a table that always answers no match.
    pub fn spawn<F>(make: F) -> Self
    where
        F: FnOnce() -> (Vec<Box<dyn NatSource>>, Box<dyn VmDirectory>) + Send + 'static,
    {
        let shared = Arc::new(Shared::default());
        // One waiting behind a read in progress: a hung source cannot pile up work.
        let (requests, queue) = sync_channel::<oneshot::Sender<()>>(1);
        let thread_shared = shared.clone();
        let _ = std::thread::Builder::new().name("sieve-nat".into()).spawn(move || {
            let (mut sources, mut directory) = make();
            while let Ok(done) = queue.recv() {
                read_all(&mut sources, directory.as_mut(), &thread_shared);
                let _ = done.send(());
            }
        });
        Self { shared, requests, last_read: tokio::sync::Mutex::new(None) }
    }

    /// The match in what is held, with no read: for a flow that already has
    /// an owner.
    pub fn held_match(&self, flow: &FiveTuple) -> Option<Forwarded> {
        exact_match(flow, &lock(&self.shared.index))
    }

    /// The match after a read that started no earlier than `now_ms` minus
    /// [`NAT_REFRESH_MIN_MS`]. A flow gives up on its owner that long after its
    /// first lookup, so such a read already saw any session behind this flow.
    pub async fn fresh_match(&self, flow: &FiveTuple, now_ms: u64) -> Option<Forwarded> {
        self.refresh(now_ms).await;
        self.held_match(flow)
    }

    async fn refresh(&self, now_ms: u64) {
        let mut last = self.last_read.lock().await;
        if last.is_some_and(|at| now_ms.saturating_sub(at) < NAT_REFRESH_MIN_MS) {
            return;
        }
        *last = Some(now_ms);
        let (done, finished) = oneshot::channel();
        match self.requests.try_send(done) {
            Ok(()) => {
                let outcome = tokio::time::timeout(Duration::from_millis(NAT_READ_TIMEOUT_MS), finished).await;
                if outcome.is_err() {
                    self.shared.timeouts.fetch_add(1, Ordering::Relaxed);
                }
            }
            // An overrunning read still holds the thread: already counted.
            Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Disconnected(_)) => {
                self.shared.read_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn stats(&self) -> NatStats {
        let l = |c: &AtomicU64| c.load(Ordering::Relaxed);
        NatStats { reads: l(&self.shared.reads), read_errors: l(&self.shared.read_errors), timeouts: l(&self.shared.timeouts) }
    }
}

/// One session event of the WinNat provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinNatEvent {
    Created(NatSession),
    Deleted(NatSession),
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// A `win:SocketAddress`: a SOCKADDR_IN or SOCKADDR_IN6 of `len` bytes.
fn socket_address(b: &[u8], at: usize, len: usize) -> Option<SocketAddr> {
    let s = b.get(at..at.checked_add(len)?)?;
    let family = u16::from_ne_bytes([*s.first()?, *s.get(1)?]);
    let port = u16::from_be_bytes([*s.get(2)?, *s.get(3)?]);
    let ip: IpAddr = match (family, len) {
        (AF_INET, SOCKADDR_IN_LEN) => Ipv4Addr::from(<[u8; 4]>::try_from(&s[4..8]).ok()?).into(),
        (AF_INET6, SOCKADDR_IN6_LEN) => Ipv6Addr::from(<[u8; 16]>::try_from(&s[8..24]).ok()?).into(),
        _ => return None,
    };
    Some(SocketAddr::new(ip.to_canonical(), port))
}

/// Events 1001 and 1005. Their two template versions differ only by a trailing
/// compartment id, which this does not read.
pub fn decode_winnat(id: u16, payload: &[u8]) -> Option<WinNatEvent> {
    if !WINNAT_EVENTS.contains(&id) {
        return None;
    }
    let internal_len = u32_at(payload, 0)? as usize;
    let internal_source = socket_address(payload, 4, internal_len)?;
    let external_at = (4usize).checked_add(internal_len.checked_mul(2)?)?;
    let external_len = u32_at(payload, external_at)? as usize;
    let external_source = socket_address(payload, external_at + 4, external_len)?;
    let external_destination = socket_address(payload, (external_at + 4).checked_add(external_len)?, external_len)?;
    let proto_at = (external_at + 4).checked_add(external_len.checked_mul(2)?)?;
    let proto = Proto::from_number(u8::try_from(u32_at(payload, proto_at)?).ok()?)?;
    let session = NatSession { proto, internal_source, external_source, external_destination };
    Some(if id == WINNAT_SESSION_CREATED { WinNatEvent::Created(session) } else { WinNatEvent::Deleted(session) })
}

/// The sessions WinNat's events say exist now, bounded.
#[derive(Debug, Default)]
pub struct WinNatTable {
    sessions: HashMap<NatKey, NatSession>,
    order: VecDeque<NatKey>,
}

impl WinNatTable {
    pub fn apply(&mut self, event: WinNatEvent) {
        match event {
            WinNatEvent::Created(s) => {
                if self.sessions.insert(s.key(), s).is_some() {
                    return;
                }
                self.order.push_back(s.key());
                if self.sessions.len() > WINNAT_TABLE_CAP
                    && let Some(oldest) = self.order.pop_front()
                {
                    self.sessions.remove(&oldest);
                }
            }
            WinNatEvent::Deleted(s) => {
                if self.sessions.remove(&s.key()).is_some() {
                    self.order.retain(|k| *k != s.key());
                }
            }
        }
    }

    pub fn sessions(&self) -> Vec<NatSession> {
        self.sessions.values().copied().collect()
    }
}

/// A source over the table the ETW session fills.
pub struct WinNatEvents(pub Arc<Mutex<WinNatTable>>);

impl NatSource for WinNatEvents {
    fn read(&mut self) -> Result<Vec<NatSession>, String> {
        Ok(lock(&self.0).sessions())
    }
}

/// What one host compute endpoint says: its addresses and the VM it serves.
/// UNVERIFIED shape: HNS answers Access denied without elevation (live proof
/// L1), so this reads the two documented spellings of each field and anything
/// else is no answer, never a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointFacts {
    pub ips: Vec<IpAddr>,
    pub vm_id: String,
}

pub fn parse_endpoint(json: &str) -> Option<EndpointFacts> {
    let v: Value = serde_json::from_str(json).ok()?;
    let vm_id = v.get("VirtualMachine").or_else(|| v.get("VirtualMachineId"))?.as_str().filter(|s| !s.is_empty())?.to_string();
    let listed = v.get("IpConfigurations").and_then(Value::as_array).into_iter().flatten().filter_map(|c| c.get("IpAddress"));
    let ips = listed.chain(v.get("IPAddress")).filter_map(Value::as_str).filter_map(|s| s.parse::<IpAddr>().ok()).map(|ip| ip.to_canonical()).collect();
    Some(EndpointFacts { ips, vm_id })
}

/// The ids in a JSON array of strings (`HcnEnumerateEndpoints`).
pub fn parse_id_list(json: &str) -> Vec<String> {
    let v: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    v.as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect()
}

/// Compute system id, lower case, to its `Owner` (`HcsEnumerateComputeSystems`).
pub fn parse_compute_systems(json: &str) -> HashMap<String, String> {
    let v: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| Some((s.get("Id")?.as_str()?.to_lowercase(), s.get("Owner")?.as_str()?.to_string())))
        .collect()
}

/// A GUID and nothing else: the only id ever placed into a WMI query.
pub fn is_guid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12]) && groups.iter().all(|g| g.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::mpsc;

    const NAT_FIXTURE: &str = include_str!("../../fixtures/nat-sessions.json");
    const EVENTS_FIXTURE: &str = include_str!("../../testdata/winnat-session-events.json");

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn session(proto: Proto, internal: &str, source: &str, destination: &str) -> NatSession {
        NatSession { proto, internal_source: sa(internal), external_source: sa(source), external_destination: sa(destination) }
    }

    const INTERNAL: &str = "172.17.83.30:36099";
    const SRC: &str = "198.18.0.1:62049";
    const DST: &str = "185.125.190.57:123";

    fn the_session() -> NatSession {
        session(Proto::Udp, INTERNAL, SRC, DST)
    }

    fn udp_flow(local: &str, remote: &str) -> FiveTuple {
        FiveTuple { proto: Proto::Udp, local: sa(local), remote: sa(remote) }
    }

    struct Names(Vec<(IpAddr, &'static str)>);

    impl VmDirectory for Names {
        fn vm_of(&mut self, internal: IpAddr) -> Option<String> {
            self.0.iter().find(|(ip, _)| *ip == internal).map(|(_, n)| n.to_string())
        }
    }

    fn index(sessions: &[NatSession]) -> NatIndex {
        index_sessions(sessions, &mut NoDirectory)
    }

    #[test]
    fn the_recorded_session_shape_matches_its_flow() {
        let f: Value = serde_json::from_str(NAT_FIXTURE).unwrap();
        let s = &f["sessions"][0];
        let field = |name: &str| s[name].as_str().unwrap().to_string();
        let port = |name: &str| s[name].as_u64().unwrap() as u16;
        let parsed = session_from_fields(
            s["Protocol"].as_u64().unwrap() as u32,
            (&field("InternalSourceAddress"), port("InternalSourcePort")),
            (&field("ExternalSourceAddress"), port("ExternalSourcePort")),
            (&field("ExternalDestinationAddress"), port("ExternalDestinationPort")),
        )
        .unwrap();
        assert_eq!(parsed, the_session());
        let flow = udp_flow(f["flow"]["local"].as_str().unwrap(), f["flow"]["remote"].as_str().unwrap());
        assert_eq!(exact_match(&flow, &index(&[parsed])), Some(Forwarded { vm: None }));
    }

    #[test]
    fn exact_match_requires_protocol_and_both_external_ends() {
        let idx = index(&[the_session()]);
        assert!(exact_match(&udp_flow(SRC, DST), &idx).is_some());
        let tcp = FiveTuple { proto: Proto::Tcp, local: sa(SRC), remote: sa(DST) };
        for other in [
            tcp,
            udp_flow("198.18.0.2:62049", DST),
            udp_flow("198.18.0.1:62050", DST),
            udp_flow(SRC, "185.125.190.58:123"),
            udp_flow(SRC, "185.125.190.57:124"),
            // The session's internal side is not what a flow is matched on.
            udp_flow(INTERNAL, DST),
        ] {
            assert_eq!(exact_match(&other, &idx), None, "{other:?}");
        }
    }

    #[test]
    fn a_session_names_its_vm_through_the_directory_only() {
        let mut names = Names(vec![(sa(INTERNAL).ip(), " DevBox\n")]);
        let idx = index_sessions(&[the_session()], &mut names);
        assert_eq!(exact_match(&udp_flow(SRC, DST), &idx), Some(Forwarded { vm: Some("DevBox".into()) }));
    }

    #[test]
    fn two_sessions_on_one_external_tuple_are_forwarded_but_unnamed() {
        let mut names = Names(vec![(sa(INTERNAL).ip(), "DevBox"), (sa("172.17.83.31:1").ip(), "Other")]);
        let both = [the_session(), session(Proto::Udp, "172.17.83.31:36099", SRC, DST)];
        let idx = index_sessions(&both, &mut names);
        assert_eq!(exact_match(&udp_flow(SRC, DST), &idx), Some(Forwarded { vm: None }));
        // The same session reported by two sources is one guest, still named.
        let idx = index_sessions(&[the_session(), the_session()], &mut names);
        assert_eq!(exact_match(&udp_flow(SRC, DST), &idx), Some(Forwarded { vm: Some("DevBox".into()) }));
    }

    #[test]
    fn vm_names_are_trimmed_capped_and_control_free() {
        assert_eq!(vm_name("  Dev\u{7}Box \r\n").as_deref(), Some("DevBox"));
        let long = "n".repeat(VM_NAME_MAX * 2);
        assert_eq!(vm_name(&long).unwrap().chars().count(), VM_NAME_MAX);
        let multi = "\u{4e2d}".repeat(VM_NAME_MAX + 1);
        assert_eq!(vm_name(&multi).unwrap().chars().count(), VM_NAME_MAX, "characters, not bytes");
    }

    #[test]
    fn no_alphanumeric_name_is_unnamed() {
        for raw in ["", "   ", "---", "\n\t", "\u{7}"] {
            assert_eq!(vm_name(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn the_name_unidentified_is_unnamed() {
        for raw in ["unidentified", "Unidentified", " UNIDENTIFIED "] {
            assert_eq!(vm_name(raw), None, "{raw:?}");
        }
    }

    struct Fake {
        answer: Result<Vec<NatSession>, String>,
        reads: Arc<AtomicU64>,
    }

    impl NatSource for Fake {
        fn read(&mut self) -> Result<Vec<NatSession>, String> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.answer.clone()
        }
    }

    fn table(sources: Vec<Fake>) -> NatTable {
        NatTable::spawn(move || (sources.into_iter().map(|s| Box::new(s) as Box<dyn NatSource>).collect(), Box::new(NoDirectory)))
    }

    #[tokio::test]
    async fn a_read_error_is_no_match_and_counted() {
        let t = table(vec![Fake { answer: Err("denied".into()), reads: Arc::default() }]);
        assert_eq!(t.fresh_match(&udp_flow(SRC, DST), 1_000).await, None);
        assert_eq!(t.stats(), NatStats { reads: 1, read_errors: 1, timeouts: 0 });
    }

    #[tokio::test]
    async fn reads_are_rate_limited() {
        let reads = Arc::new(AtomicU64::new(0));
        let t = table(vec![Fake { answer: Ok(vec![the_session()]), reads: reads.clone() }]);
        assert!(t.fresh_match(&udp_flow(SRC, DST), 1_000).await.is_some());
        assert!(t.fresh_match(&udp_flow(SRC, DST), 1_000 + NAT_REFRESH_MIN_MS - 1).await.is_some());
        assert_eq!(reads.load(Ordering::Relaxed), 1, "the read just done answered");
        assert!(t.fresh_match(&udp_flow(SRC, DST), 1_000 + NAT_REFRESH_MIN_MS).await.is_some());
        assert_eq!(reads.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn a_held_match_issues_no_read() {
        let reads = Arc::new(AtomicU64::new(0));
        let t = table(vec![Fake { answer: Ok(vec![the_session()]), reads: reads.clone() }]);
        assert_eq!(t.held_match(&udp_flow(SRC, DST)), None, "nothing is held before the first read");
        assert_eq!(reads.load(Ordering::Relaxed), 0);
    }

    /// Blocks each read until the test lets it finish.
    struct Slow(mpsc::Receiver<()>);

    impl NatSource for Slow {
        fn read(&mut self) -> Result<Vec<NatSession>, String> {
            let _ = self.0.recv();
            Ok(vec![the_session()])
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_read_times_out_to_no_match() {
        let (release, wait) = mpsc::channel();
        let t = NatTable::spawn(move || (vec![Box::new(Slow(wait)) as Box<dyn NatSource>], Box::new(NoDirectory)));
        assert_eq!(t.fresh_match(&udp_flow(SRC, DST), 1_000).await, None);
        assert_eq!(t.stats().timeouts, 1);
        // A read overrunning holds the thread: one more waits behind it, no pile-up.
        assert_eq!(t.fresh_match(&udp_flow(SRC, DST), 2_000).await, None);
        assert_eq!(t.fresh_match(&udp_flow(SRC, DST), 3_000).await, None);
        drop(release);
        // The late read still lands, for the flows after it.
        for _ in 0..200 {
            if t.held_match(&udp_flow(SRC, DST)).is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the late read never landed");
    }

    #[tokio::test]
    async fn every_source_is_asked() {
        let (first, second) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let t = table(vec![
            Fake { answer: Err("first source denied".into()), reads: first.clone() },
            Fake { answer: Ok(vec![the_session()]), reads: second.clone() },
        ]);
        assert!(t.fresh_match(&udp_flow(SRC, DST), 1_000).await.is_some(), "a match in the second source counts");
        assert_eq!((first.load(Ordering::Relaxed), second.load(Ordering::Relaxed)), (1, 1));
        assert_eq!(t.stats().read_errors, 1);
    }

    fn winnat_events() -> Vec<(u16, u64, Vec<u8>)> {
        let f: Value = serde_json::from_str(EVENTS_FIXTURE).unwrap();
        assert!(f["source"].as_str().unwrap().contains("Hand-built"), "the fixture says what it is");
        f["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["id"].as_u64().unwrap() as u16, e["version"].as_u64().unwrap(), unhex(e["payload_hex"].as_str().unwrap())))
            .collect()
    }

    #[test]
    fn decode_winnat_reads_both_template_versions() {
        let events = winnat_events();
        let seen: Vec<(u16, u64)> = events.iter().map(|(id, v, _)| (*id, *v)).collect();
        assert_eq!(seen, [(1001, 0), (1001, 1), (1005, 0), (1005, 1)]);
        for (id, version, bytes) in &events {
            let want = if *id == WINNAT_SESSION_CREATED { WinNatEvent::Created(the_session()) } else { WinNatEvent::Deleted(the_session()) };
            assert_eq!(decode_winnat(*id, bytes), Some(want), "{id} v{version}");
        }
    }

    #[test]
    fn a_broken_winnat_event_decodes_to_none() {
        let (_, _, bytes) = winnat_events().remove(0);
        assert_eq!(decode_winnat(1002, &bytes), None, "another event");
        // Protocol, the last field read, ends at byte 76.
        for cut in [0, 3, 10, 40, 60, 75] {
            assert_eq!(decode_winnat(WINNAT_SESSION_CREATED, &bytes[..cut]), None, "{cut} bytes");
        }
        let mut wrong_len = bytes.clone();
        wrong_len[0] = 12;
        assert_eq!(decode_winnat(WINNAT_SESSION_CREATED, &wrong_len), None);
    }

    #[test]
    fn a_deleted_session_leaves_the_table() {
        let mut t = WinNatTable::default();
        t.apply(WinNatEvent::Created(the_session()));
        assert_eq!(t.sessions(), [the_session()]);
        t.apply(WinNatEvent::Deleted(the_session()));
        assert!(t.sessions().is_empty());
        assert!(t.order.is_empty());
    }

    #[test]
    fn the_session_table_is_bounded() {
        let mut t = WinNatTable::default();
        let at = |i: usize| session(Proto::Tcp, INTERNAL, &format!("198.18.{}.{}:{}", i / 65_536, (i / 256) % 256, i % 60_000 + 1), DST);
        for i in 0..WINNAT_TABLE_CAP + 5 {
            t.apply(WinNatEvent::Created(at(i)));
        }
        assert_eq!(t.sessions().len(), WINNAT_TABLE_CAP);
        assert!(!t.sessions().contains(&at(0)), "FIFO");
        assert!(t.sessions().contains(&at(WINNAT_TABLE_CAP + 4)));
    }

    #[test]
    fn host_compute_answers_are_read_or_refused() {
        let v2 = r#"{"ID":"e","VirtualMachine":"11111111-2222-3333-4444-555555555555","IpConfigurations":[{"IpAddress":"172.17.83.30","PrefixLength":20}]}"#;
        let got = parse_endpoint(v2).unwrap();
        assert_eq!(got.vm_id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(got.ips, [sa(INTERNAL).ip()]);
        let v1 = r#"{"IPAddress":"172.17.83.30","VirtualMachine":"a"}"#;
        assert_eq!(parse_endpoint(v1).unwrap().ips, [sa(INTERNAL).ip()]);
        for no_vm in ["{}", "not json", r#"{"VirtualMachine":""}"#, r#"{"VirtualMachine":7}"#, "[]"] {
            assert_eq!(parse_endpoint(no_vm), None, "{no_vm}");
        }
        assert_eq!(parse_id_list(r#"["a","b",7]"#), ["a", "b"]);
        assert!(parse_id_list("oops").is_empty());
        let systems = parse_compute_systems(r#"[{"Id":"ABC","Owner":"Someone"},{"Id":"no-owner"},7]"#);
        assert_eq!(systems.len(), 1);
        assert_eq!(systems["abc"], "Someone");
    }

    #[test]
    fn only_a_guid_can_reach_a_query() {
        assert!(is_guid("11111111-2222-3333-4444-55555555abcd"));
        for bad in ["", "x", "11111111-2222-3333-4444-55555555abc'", "' OR 1=1 --", "11111111-2222-3333-4444-55555555abcde"] {
            assert!(!is_guid(bad), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn decode_winnat_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..120), id in prop_oneof![Just(1001u16), Just(1005u16), any::<u16>()]) {
            let _ = decode_winnat(id, &bytes);
        }
    }
}
