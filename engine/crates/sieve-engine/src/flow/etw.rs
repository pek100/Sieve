//! A second exact PID source (A2): `Microsoft-Windows-Kernel-Network` reports
//! the PID with the exact local and remote ends on a TCP connect and a UDP
//! send, so it names host sockets the owner tables can no longer see (a
//! one-shot UDP socket that sent and closed before the lookup).
//!
//! Rules (docs/tasks/2026-11-02-attribution.md, D6 to D8):
//! - [`decode`] is pure over the one prefix all four events share.
//! - [`EtwRing`] holds unique tuples, not raw events, FIFO-evicted at
//!   [`ETW_RING_CAP`]. A repeat from one PID takes no slot; a different PID on
//!   a tuple within [`ETW_MATCH_WINDOW_MS`] is a conflict, which answers unknown.
//! - [`PidWitness`] is what the attributor asks. Delivery lags (a real-time
//!   session delivers on a full buffer or a 1 s flush), so a pending flow
//!   nudges its witness to flush, at most every [`ETW_FLUSH_MIN_MS`].
//! - `os` (Windows): one named real-time session, no log file, that lives
//!   exactly as long as the routes. Nothing here persists, and a session that
//!   cannot start costs attribution only, never routing.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::flow::flows::{FiveTuple, NO_OWNER_PID};
use crate::flow::nat::WinNatTable;
use crate::flow::packet::Proto;
use crate::stack::Meters;

/// `Microsoft-Windows-Kernel-Network`, from the local manifest.
pub const KERNEL_NETWORK: u128 = 0x7DD4_2A49_5329_4832_8DFD_43D9_7915_3A88;
/// Its IPV4 and IPV6 keywords.
pub const KERNEL_NETWORK_KEYWORDS: u64 = 0x10 | 0x20;
/// "TCP connection attempted", v4 and v6.
pub const TCP_CONNECT_V4: u16 = 12;
pub const TCP_CONNECT_V6: u16 = 28;
/// "UDP send", v4 and v6.
pub const UDP_SEND_V4: u16 = 42;
pub const UDP_SEND_V6: u16 = 58;
/// The only events the session asks for: without this filter, every TCP send
/// is an event, on a path already over its CPU budget.
pub const KERNEL_NETWORK_EVENTS: [u16; 4] = [TCP_CONNECT_V4, TCP_CONNECT_V6, UDP_SEND_V4, UDP_SEND_V6];

/// Unique tuples the ring holds at most.
pub const ETW_RING_CAP: usize = 4096;
/// An entry answers for this long: the 1 s minimum `FlushTimer` plus margin.
pub const ETW_MATCH_WINDOW_MS: u64 = 2_000;
/// A pending flow flushes the session at most this often.
pub const ETW_FLUSH_MIN_MS: u64 = 50;

const PREFIX_V4: usize = 8 + 4 + 4 + 2 + 2;
const PREFIX_V6: usize = 8 + 16 + 16 + 2 + 2;

/// One decoded event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtwEvent {
    pub pid: u32,
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// A v4-mapped address is the IPv4 address: the owner tables show dual-mode
/// sockets as IPv4, and without this the same socket could never match.
fn canonical(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(ip.to_canonical(), port)
}

/// One of the four events' `PID, size, daddr, saddr, dport, sport` prefix.
/// Ports are `win:Port`: network order. An unknown or truncated event is None.
pub fn decode(id: u16, payload: &[u8]) -> Option<EtwEvent> {
    let (proto, v6) = match id {
        TCP_CONNECT_V4 => (Proto::Tcp, false),
        TCP_CONNECT_V6 => (Proto::Tcp, true),
        UDP_SEND_V4 => (Proto::Udp, false),
        UDP_SEND_V6 => (Proto::Udp, true),
        _ => return None,
    };
    if payload.len() < if v6 { PREFIX_V6 } else { PREFIX_V4 } {
        return None;
    }
    let pid = u32::from_ne_bytes(payload[..4].try_into().ok()?);
    let (daddr, saddr, ports): (IpAddr, IpAddr, &[u8]) = if v6 {
        let d: [u8; 16] = payload[8..24].try_into().ok()?;
        let s: [u8; 16] = payload[24..40].try_into().ok()?;
        (Ipv6Addr::from(d).into(), Ipv6Addr::from(s).into(), &payload[40..44])
    } else {
        let d: [u8; 4] = payload[8..12].try_into().ok()?;
        let s: [u8; 4] = payload[12..16].try_into().ok()?;
        (Ipv4Addr::from(d).into(), Ipv4Addr::from(s).into(), &payload[16..20])
    };
    let dport = u16::from_be_bytes([ports[0], ports[1]]);
    let sport = u16::from_be_bytes([ports[2], ports[3]]);
    Some(EtwEvent { pid, proto, local: canonical(saddr, sport), remote: canonical(daddr, dport) })
}

/// What the witness says about a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Witnessed {
    /// Nothing within the window.
    Nothing,
    Pid(u32),
    /// Two PIDs on this exact tuple within the window: it answers unknown.
    Conflict,
}

/// A second source of the flow's PID, asked with every owner lookup.
pub trait PidWitness {
    fn answer(&self, flow: &FiveTuple, now_ms: u64) -> Witnessed;
    /// A flow is pending: deliver what the source holds, soon.
    fn nudge(&self) {}
}

/// No second source: the owner tables alone answer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unwitnessed;

impl PidWitness for Unwitnessed {
    fn answer(&self, _flow: &FiveTuple, _now_ms: u64) -> Witnessed {
        Witnessed::Nothing
    }
}

impl<W: PidWitness + ?Sized> PidWitness for Box<W> {
    fn answer(&self, flow: &FiveTuple, now_ms: u64) -> Witnessed {
        (**self).answer(flow, now_ms)
    }

    fn nudge(&self) {
        (**self).nudge();
    }
}

type Key = (Proto, SocketAddr, SocketAddr);

#[derive(Debug)]
struct Entry {
    pid: u32,
    at_ms: u64,
    conflict: bool,
}

/// Recent host sockets by exact tuple (D7).
#[derive(Debug)]
pub struct EtwRing {
    own_pid: u32,
    entries: HashMap<Key, Entry>,
    order: VecDeque<Key>,
    evictions: u64,
}

impl EtwRing {
    pub fn new(own_pid: u32) -> Self {
        Self { own_pid, entries: HashMap::new(), order: VecDeque::new(), evictions: 0 }
    }

    /// Stores one event that happened at `at_ms`, which delivery may have made
    /// old; true when it evicted an older tuple. The engine's own events are
    /// dropped here: every upstream UDP send would be one. So is PID 0, which names
    /// no owner: stored, it could conflict with a real PID on the tuple or replace it.
    pub fn insert(&mut self, e: &EtwEvent, at_ms: u64) -> bool {
        if e.pid == self.own_pid || e.pid == NO_OWNER_PID {
            return false;
        }
        let key = (e.proto, e.local, e.remote);
        if let Some(entry) = self.entries.get_mut(&key) {
            let recent = at_ms.abs_diff(entry.at_ms) <= ETW_MATCH_WINDOW_MS;
            let late = at_ms < entry.at_ms;
            if late && !recent {
                return false;
            }
            // An older entry on this tuple is port reuse: replaced, not a conflict.
            entry.conflict = recent && (entry.conflict || entry.pid != e.pid);
            if !late {
                entry.pid = e.pid;
                entry.at_ms = at_ms;
            }
            return false;
        }
        let evicted = self.entries.len() >= ETW_RING_CAP;
        if evicted && let Some(oldest) = self.order.pop_front() {
            self.entries.remove(&oldest);
            self.evictions += 1;
        }
        self.order.push_back(key);
        self.entries.insert(key, Entry { pid: e.pid, at_ms, conflict: false });
        evicted
    }

    /// The exact tuple's answer: proto, both addresses and both ports.
    pub fn answer(&self, flow: &FiveTuple, now_ms: u64) -> Witnessed {
        let key = (flow.proto, canonical(flow.local.ip(), flow.local.port()), canonical(flow.remote.ip(), flow.remote.port()));
        match self.entries.get(&key) {
            Some(e) if now_ms.saturating_sub(e.at_ms) > ETW_MATCH_WINDOW_MS => Witnessed::Nothing,
            Some(e) if e.conflict => Witnessed::Conflict,
            Some(e) => Witnessed::Pid(e.pid),
            None => Witnessed::Nothing,
        }
    }

    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// FILETIME's tick is 100 ns.
const FILETIME_TICKS_PER_MS: i64 = 10_000;

/// When an event happened on the monotonic clock: its age, from two FILETIMEs,
/// taken off now. An event dated ahead of now has no age.
pub fn occurred_at_ms(now_ms: u64, now_filetime: i64, event_filetime: i64) -> u64 {
    let age_ms = now_filetime.saturating_sub(event_filetime).max(0) / FILETIME_TICKS_PER_MS;
    now_ms.saturating_sub(age_ms.unsigned_abs())
}

/// Where the session's events go. Never panics: it runs in an ETW callback.
#[derive(Debug, Clone)]
pub struct Sinks {
    pub ring: Arc<Mutex<EtwRing>>,
    pub winnat: Arc<Mutex<WinNatTable>>,
    pub meters: Arc<Meters>,
}

impl Sinks {
    pub fn new(own_pid: u32, meters: Arc<Meters>) -> Self {
        Self { ring: Arc::new(Mutex::new(EtwRing::new(own_pid))), winnat: Arc::default(), meters }
    }

    /// `at_ms`: when the event happened, not when it was delivered.
    pub fn ingest(&self, provider: u128, id: u16, payload: &[u8], at_ms: u64) {
        #[cfg(feature = "attribution-diagnostics")]
        lock(&self.meters.attribution).record_raw_event(provider, id, payload, at_ms);
        if provider == crate::flow::nat::WINNAT {
            if let Some(event) = crate::flow::nat::decode_winnat(id, payload) {
                lock(&self.winnat).apply(event);
            }
        } else if provider == KERNEL_NETWORK
            && let Some(event) = decode(id, payload)
            && lock(&self.ring).insert(&event, at_ms)
        {
            Meters::bump(&self.meters.etw_dropped);
        }
    }
}

/// The ring as the attributor's witness; `flush` delivers what the session holds.
pub struct RingWitness<F: Fn() + Send> {
    pub ring: Arc<Mutex<EtwRing>>,
    pub flush: F,
}

impl<F: Fn() + Send> PidWitness for RingWitness<F> {
    fn answer(&self, flow: &FiveTuple, now_ms: u64) -> Witnessed {
        lock(&self.ring).answer(flow, now_ms)
    }

    fn nudge(&self) {
        (self.flush)();
    }
}

/// `EVENT_FILTER_EVENT_ID` with its trailing array: `FilterIn`, a reserved
/// byte, the count, then the ids.
pub fn event_id_filter(ids: &[u16]) -> Vec<u8> {
    let mut b = vec![1u8, 0];
    b.extend_from_slice(&(ids.len() as u16).to_ne_bytes());
    for id in ids {
        b.extend_from_slice(&id.to_ne_bytes());
    }
    b
}

/// How long a start waits to learn its consumer has the session open.
pub const CONSUMER_OPEN_BOUND: Duration = Duration::from_secs(5);

/// Runs a consumer on its own thread and answers once it has the session
/// open, so a consumer that cannot open fails the start, which is what puts
/// it in `last_error`. Past that, `on_end` gets what ended it.
pub fn spawn_consumer<T>(
    open: impl FnOnce() -> Result<T, String> + Send + 'static,
    process: impl FnOnce(T) -> Result<(), String> + Send + 'static,
    on_end: impl FnOnce(Result<(), String>) + Send + 'static,
    bound: Duration,
) -> Result<JoinHandle<()>, String> {
    let (opened, wait) = std::sync::mpsc::sync_channel(1);
    let consumer = std::thread::Builder::new()
        .name("sieve-etw".into())
        .spawn(move || match open() {
            Ok(session) => {
                let _ = opened.send(Ok(()));
                on_end(process(session));
            }
            Err(why) => {
                let _ = opened.send(Err(why));
            }
        })
        .map_err(|e| format!("no consumer thread: {e}"))?;
    match wait.recv_timeout(bound) {
        Ok(Ok(())) => Ok(consumer),
        Ok(Err(why)) => Err(why),
        Err(RecvTimeoutError::Timeout) => Err(format!("the consumer did not open the session within {} s", bound.as_secs())),
        Err(RecvTimeoutError::Disconnected) => Err("the consumer ended before it opened the session".into()),
    }
}

/// What a consumer's end means for `last_error`. Only a stop the engine asked
/// for is expected; any other end, even a clean one (someone stopped the
/// session by name), leaves the witness answering nothing for the whole run.
pub fn consumer_failure(stopping: bool, end: &Result<(), String>) -> Option<String> {
    match end {
        _ if stopping => None,
        Ok(()) => Some("attribution without ETW: the session ended while the routes were up".into()),
        Err(why) => Some(format!("attribution without ETW: {why}")),
    }
}

/// The named real-time session. The one place that starts, flushes or stops it.
#[cfg(windows)]
pub mod os {
    use std::ffi::c_void;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND, WIN32_ERROR};
    use windows::Win32::System::Diagnostics::Etw::{
        CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_TYPE_EVENT_ID, EVENT_RECORD, EVENT_TRACE_CONTROL,
        EVENT_TRACE_CONTROL_FLUSH, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
        EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace,
        StartTraceW, TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
    };
    use windows::core::{GUID, PCWSTR, PWSTR};

    use super::{CONSUMER_OPEN_BOUND, KERNEL_NETWORK, KERNEL_NETWORK_EVENTS, KERNEL_NETWORK_KEYWORDS, Sinks, consumer_failure, event_id_filter, occurred_at_ms, spawn_consumer};
    use crate::flow::nat::{WINNAT, WINNAT_EVENTS};
    use crate::stack::Meters;
    use crate::watchdog::monotonic_ms;

    /// The session's name; a leftover of this name is stopped at every start.
    pub const SESSION_NAME: &str = "SieveEngineAttribution";
    /// `FlushTimer`, seconds: the minimum, and why the nudge exists.
    const FLUSH_TIMER_S: u32 = 1;
    /// Small fixed buffers: 64 KiB each, 4 to 8 of them.
    const BUFFER_KB: u32 = 64;
    const MIN_BUFFERS: u32 = 4;
    const MAX_BUFFERS: u32 = 8;
    /// `WNODE_HEADER.ClientContext`: query performance counter timestamps.
    const CLOCK_QPC: u32 = 1;
    const ALL_KEYWORDS: u64 = u64::MAX;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// `EVENT_TRACE_PROPERTIES` and the room Windows wants for the name after it.
    #[repr(C)]
    struct Properties {
        base: EVENT_TRACE_PROPERTIES,
        name: [u16; 64],
    }

    fn properties() -> Box<Properties> {
        // SAFETY: both fields are plain data for which all zeros is valid.
        let mut p: Box<Properties> = Box::new(unsafe { std::mem::zeroed() });
        p.base.Wnode.BufferSize = size_of::<Properties>() as u32;
        p.base.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        p.base.Wnode.ClientContext = CLOCK_QPC;
        p.base.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        p
    }

    fn control(code: EVENT_TRACE_CONTROL) -> (WIN32_ERROR, Box<Properties>) {
        let name = wide(SESSION_NAME);
        let mut p = properties();
        // SAFETY: `name` is NUL-terminated and `p` is a live block of Wnode.BufferSize bytes.
        let r = unsafe { ControlTraceW(CONTROLTRACE_HANDLE::default(), PCWSTR(name.as_ptr()), &mut p.base, code) };
        (r, p)
    }

    /// Stops a session of this name, whoever left it (a real-time session
    /// outlives a killed controller). None there is fine.
    pub fn stop_stale() -> Result<String, String> {
        match control(EVENT_TRACE_CONTROL_STOP).0 {
            ERROR_SUCCESS => Ok("a leftover session was stopped".into()),
            ERROR_WMI_INSTANCE_NOT_FOUND => Ok("no session".into()),
            e => Err(format!("stopping {SESSION_NAME}: Win32 error {}", e.0)),
        }
    }

    /// Asks the session to deliver what it holds now, and counts what it lost.
    fn flush(lost_seen: &AtomicU64, meters: &Meters) {
        let (r, p) = control(EVENT_TRACE_CONTROL_FLUSH);
        if r != ERROR_SUCCESS {
            return;
        }
        let lost = u64::from(p.base.EventsLost) + u64::from(p.base.RealTimeBuffersLost);
        let before = lost_seen.swap(lost, Ordering::Relaxed);
        meters.etw_dropped.fetch_add(lost.saturating_sub(before), Ordering::Relaxed);
    }

    /// FILETIME's epoch, 1601, before the Unix one, in FILETIME ticks.
    const UNIX_EPOCH_FILETIME: i64 = 116_444_736_000_000_000;
    const FILETIME_TICKS_PER_S: i64 = 10_000_000;

    /// The wall clock as a FILETIME, the form `ProcessTrace` converts every
    /// `EventHeader.TimeStamp` to (the consumer does not ask for
    /// `PROCESS_TRACE_MODE_RAW_TIMESTAMP`). Live proof L2 reads the result.
    fn now_filetime() -> i64 {
        let since_unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let seconds = i64::try_from(since_unix.as_secs()).unwrap_or(i64::MAX / FILETIME_TICKS_PER_S);
        UNIX_EPOCH_FILETIME + seconds * FILETIME_TICKS_PER_S + i64::from(since_unix.subsec_nanos() / 100)
    }

    /// Runs on the consumer thread for every event of the session.
    unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
        // SAFETY: Windows hands a record valid for this call; UserContext is
        // the `Sinks` the consumer thread keeps alive until ProcessTrace returns.
        let (r, sinks) = unsafe { (&*record, &*(*record).UserContext.cast::<Sinks>()) };
        let payload = if r.UserData.is_null() {
            &[][..]
        } else {
            // SAFETY: UserData holds UserDataLength bytes for this call.
            unsafe { std::slice::from_raw_parts(r.UserData.cast::<u8>(), usize::from(r.UserDataLength)) }
        };
        let at_ms = occurred_at_ms(monotonic_ms(), now_filetime(), r.EventHeader.TimeStamp);
        sinks.ingest(r.EventHeader.ProviderId.to_u128(), r.EventHeader.EventDescriptor.Id, payload, at_ms);
    }

    fn enable(handle: CONTROLTRACE_HANDLE, provider: u128, keywords: u64, ids: &[u16]) -> WIN32_ERROR {
        let filter = event_id_filter(ids);
        let mut descriptor = EVENT_FILTER_DESCRIPTOR { Ptr: filter.as_ptr() as u64, Size: filter.len() as u32, Type: EVENT_FILTER_TYPE_EVENT_ID };
        let params = ENABLE_TRACE_PARAMETERS {
            Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
            EnableFilterDesc: &mut descriptor,
            FilterDescCount: 1,
            ..ENABLE_TRACE_PARAMETERS::default()
        };
        let guid = GUID::from_u128(provider);
        // SAFETY: `guid`, `params`, `descriptor` and `filter` outlive the call,
        // which copies the filter.
        unsafe { EnableTraceEx2(handle, &guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER.0, TRACE_LEVEL_VERBOSE as u8, keywords, 0, 0, Some(&params)) }
    }

    /// One open read of a session. Lives on the consumer thread: Windows reads
    /// through these boxes until the trace closes, and their addresses are stable.
    struct Consumer {
        trace: PROCESSTRACE_HANDLE,
        _log: Box<EVENT_TRACE_LOGFILEW>,
        _name: Vec<u16>,
        _sinks: Box<Sinks>,
    }

    impl Consumer {
        fn open(session: &str, sinks: Sinks) -> Result<Self, String> {
            let mut name = wide(session);
            let sinks = Box::new(sinks);
            // SAFETY: all zeros is a valid EVENT_TRACE_LOGFILEW before the fields below.
            let mut log: Box<EVENT_TRACE_LOGFILEW> = Box::new(unsafe { std::mem::zeroed() });
            log.LoggerName = PWSTR(name.as_mut_ptr());
            log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            log.Anonymous2.EventRecordCallback = Some(on_event);
            log.Context = (&raw const *sinks).cast_mut().cast::<c_void>();
            // SAFETY: `log` and what it points at live as long as `Consumer`.
            let trace = unsafe { OpenTraceW(&mut *log) };
            if trace.Value == u64::MAX {
                let code = std::io::Error::last_os_error().raw_os_error().unwrap_or_default();
                return Err(format!("opening {session}: Win32 error {code}"));
            }
            Ok(Self { trace, _log: log, _name: name, _sinks: sinks })
        }

        /// Delivers events until the session stops, then closes the trace.
        fn process(self) -> Result<(), String> {
            // SAFETY: `trace` came from OpenTraceW.
            let processed = unsafe { ProcessTrace(&[self.trace], None, None) };
            // SAFETY: `trace` is closed once, after its callbacks ended.
            let _ = unsafe { CloseTrace(self.trace) };
            if processed == ERROR_SUCCESS { Ok(()) } else { Err(format!("reading the session: Win32 error {}", processed.0)) }
        }
    }

    /// The running session and its consumer thread.
    pub struct EtwSession {
        consumer: std::thread::JoinHandle<()>,
        /// Set before the engine stops it, so the consumer's end is expected.
        stopping: Arc<AtomicBool>,
        /// Why the WinNat provider could not be enabled; the tables and
        /// Kernel-Network still work.
        pub winnat_error: Option<String>,
    }

    /// Starts the session (real-time, no log file, fixed small buffers) and
    /// its consumer, and returns once the consumer has it open. Any failure
    /// leaves no session behind. If the consumer ends later, unasked, the
    /// session is stopped (no provider stays enabled for nobody) and `report`
    /// gets why.
    pub fn start(sinks: Sinks, report: impl FnOnce(String) + Send + 'static) -> Result<EtwSession, String> {
        let name = wide(SESSION_NAME);
        let mut handle = CONTROLTRACE_HANDLE::default();
        let begin = |handle: &mut CONTROLTRACE_HANDLE| {
            let mut p = properties();
            p.base.BufferSize = BUFFER_KB;
            p.base.MinimumBuffers = MIN_BUFFERS;
            p.base.MaximumBuffers = MAX_BUFFERS;
            p.base.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            p.base.FlushTimer = FLUSH_TIMER_S;
            // SAFETY: `name` is NUL-terminated; `p` is a live block of Wnode.BufferSize bytes.
            unsafe { StartTraceW(handle, PCWSTR(name.as_ptr()), &mut p.base) }
        };
        let mut started = begin(&mut handle);
        if started == ERROR_ALREADY_EXISTS {
            stop_stale()?;
            started = begin(&mut handle);
        }
        if started != ERROR_SUCCESS {
            return Err(format!("starting {SESSION_NAME}: Win32 error {}", started.0));
        }
        let fail = |why: String| {
            let _ = stop_stale();
            why
        };
        let enabled = enable(handle, KERNEL_NETWORK, KERNEL_NETWORK_KEYWORDS, &KERNEL_NETWORK_EVENTS);
        if enabled != ERROR_SUCCESS {
            return Err(fail(format!("enabling Kernel-Network: Win32 error {}", enabled.0)));
        }
        let winnat = enable(handle, WINNAT, ALL_KEYWORDS, &WINNAT_EVENTS);
        let winnat_error = (winnat != ERROR_SUCCESS).then(|| format!("enabling WinNat events: Win32 error {}", winnat.0));

        let stopping = Arc::new(AtomicBool::new(false));
        let asked = stopping.clone();
        let consumer = spawn_consumer(
            move || Consumer::open(SESSION_NAME, sinks),
            Consumer::process,
            move |end| {
                if let Some(why) = consumer_failure(asked.load(Ordering::Acquire), &end) {
                    let _ = stop_stale();
                    report(why);
                }
            },
            CONSUMER_OPEN_BOUND,
        )
        .map_err(|why| {
            // A consumer that opens late must not stop a later run's session.
            stopping.store(true, Ordering::Release);
            fail(format!("ETW consumer: {why}"))
        })?;
        Ok(EtwSession { consumer, stopping, winnat_error })
    }

    impl EtwSession {
        /// Stops the session and waits at most `bound` for its consumer, then
        /// detaches it. Call after the routes are deleted, so a hang here
        /// cannot hold a route.
        pub fn stop(self, bound: Duration) -> Result<String, String> {
            self.stopping.store(true, Ordering::Release);
            let stopped = stop_stale();
            let (done, wait) = std::sync::mpsc::channel();
            let consumer = self.consumer;
            let joiner = std::thread::Builder::new().name("sieve-etw-stop".into()).spawn(move || {
                let _ = consumer.join();
                let _ = done.send(());
            });
            if joiner.is_ok() && wait.recv_timeout(bound).is_err() {
                return Err(format!("the ETW consumer did not end within {} s; detached", bound.as_secs()));
            }
            stopped
        }
    }

    /// The flush the witness nudges with. By name, so it can never reach
    /// anything but this session, and it needs no handle to outlive.
    pub fn flusher(meters: Arc<Meters>) -> impl Fn() + Send {
        let lost_seen = AtomicU64::new(0);
        move || flush(&lost_seen, &meters)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Asks Windows for a session nobody started: reads only, starts nothing.
        #[test]
        fn reading_a_session_that_does_not_exist_is_an_error_not_silence() {
            let sinks = Sinks::new(std::process::id(), Arc::default());
            let read = Consumer::open("SieveEngineAttributionNoSuchSession", sinks).and_then(Consumer::process);
            let why = read.expect_err("no session to read");
            assert!(why.contains("Win32 error"), "{why}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::Value;

    const FIXTURE: &str = include_str!("../../testdata/kernel-network-events.json");
    const OWN: u32 = 999;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn event(pid: u32, proto: Proto, local: &str, remote: &str) -> EtwEvent {
        EtwEvent { pid, proto, local: sa(local), remote: sa(remote) }
    }

    fn flow(proto: Proto, local: &str, remote: &str) -> FiveTuple {
        FiveTuple { proto, local: sa(local), remote: sa(remote) }
    }

    const L: &str = "198.18.0.1:50000";
    const R: &str = "93.184.215.14:443";

    #[test]
    fn decodes_all_four_events_from_the_manifest_templates() {
        let f: Value = serde_json::from_str(FIXTURE).unwrap();
        assert!(f["source"].as_str().unwrap().contains("Hand-built"), "the fixture says what it is");
        let events = f["events"].as_array().unwrap();
        let mut ids: Vec<u16> = events.iter().map(|e| e["id"].as_u64().unwrap() as u16).collect();
        ids.sort_unstable();
        assert_eq!(ids, KERNEL_NETWORK_EVENTS);
        for e in events {
            let id = e["id"].as_u64().unwrap() as u16;
            let got = decode(id, &unhex(e["payload_hex"].as_str().unwrap())).unwrap_or_else(|| panic!("event {id}"));
            let proto = if e["proto"] == "tcp" { Proto::Tcp } else { Proto::Udp };
            assert_eq!(got, event(e["pid"].as_u64().unwrap() as u32, proto, e["local"].as_str().unwrap(), e["remote"].as_str().unwrap()), "event {id}");
        }
    }

    #[test]
    fn a_truncated_or_unknown_event_decodes_to_none() {
        let f: Value = serde_json::from_str(FIXTURE).unwrap();
        for e in f["events"].as_array().unwrap() {
            let id = e["id"].as_u64().unwrap() as u16;
            let bytes = unhex(e["payload_hex"].as_str().unwrap());
            let prefix = if id == TCP_CONNECT_V6 || id == UDP_SEND_V6 { PREFIX_V6 } else { PREFIX_V4 };
            assert!(decode(id, &bytes[..prefix]).is_some(), "the prefix alone is enough");
            assert_eq!(decode(id, &bytes[..prefix - 1]), None);
            assert_eq!(decode(13, &bytes), None, "another event of the provider");
        }
        assert_eq!(decode(TCP_CONNECT_V4, &[]), None);
    }

    #[test]
    fn v4_mapped_addresses_normalise_to_ipv4() {
        let mut b = vec![0u8; PREFIX_V6];
        b[..4].copy_from_slice(&7u32.to_ne_bytes());
        b[8..24].copy_from_slice(&"::ffff:93.184.215.14".parse::<Ipv6Addr>().unwrap().octets());
        b[24..40].copy_from_slice(&"::ffff:198.18.0.1".parse::<Ipv6Addr>().unwrap().octets());
        b[40..42].copy_from_slice(&443u16.to_be_bytes());
        b[42..44].copy_from_slice(&50000u16.to_be_bytes());
        assert_eq!(decode(TCP_CONNECT_V6, &b), Some(event(7, Proto::Tcp, L, R)));
    }

    #[test]
    fn exact_means_all_four_fields() {
        let mut ring = EtwRing::new(OWN);
        ring.insert(&event(7, Proto::Tcp, L, R), 0);
        assert_eq!(ring.answer(&flow(Proto::Tcp, L, R), 1), Witnessed::Pid(7));
        for other in [
            flow(Proto::Udp, L, R),
            flow(Proto::Tcp, "198.18.0.2:50000", R),
            flow(Proto::Tcp, "198.18.0.1:50001", R),
            flow(Proto::Tcp, L, "93.184.215.15:443"),
            flow(Proto::Tcp, L, "93.184.215.14:444"),
        ] {
            assert_eq!(ring.answer(&other, 1), Witnessed::Nothing, "{other:?}");
        }
    }

    #[test]
    fn an_event_outside_the_window_does_not_answer() {
        let mut ring = EtwRing::new(OWN);
        ring.insert(&event(7, Proto::Tcp, L, R), 100);
        assert_eq!(ring.answer(&flow(Proto::Tcp, L, R), 100 + ETW_MATCH_WINDOW_MS), Witnessed::Pid(7));
        assert_eq!(ring.answer(&flow(Proto::Tcp, L, R), 100 + ETW_MATCH_WINDOW_MS + 1), Witnessed::Nothing);
    }

    #[test]
    fn two_pids_on_one_tuple_within_the_window_answer_conflict() {
        let mut ring = EtwRing::new(OWN);
        ring.insert(&event(7, Proto::Udp, L, R), 0);
        ring.insert(&event(8, Proto::Udp, L, R), ETW_MATCH_WINDOW_MS);
        assert_eq!(ring.answer(&flow(Proto::Udp, L, R), ETW_MATCH_WINDOW_MS), Witnessed::Conflict);
        ring.insert(&event(8, Proto::Udp, L, R), ETW_MATCH_WINDOW_MS + 1);
        assert_eq!(ring.answer(&flow(Proto::Udp, L, R), ETW_MATCH_WINDOW_MS + 1), Witnessed::Conflict, "a repeat does not clear it");
    }

    #[test]
    fn an_old_entry_is_replaced_not_conflicted() {
        let mut ring = EtwRing::new(OWN);
        ring.insert(&event(7, Proto::Udp, L, R), 0);
        ring.insert(&event(8, Proto::Udp, L, R), ETW_MATCH_WINDOW_MS + 1);
        assert_eq!(ring.answer(&flow(Proto::Udp, L, R), ETW_MATCH_WINDOW_MS + 1), Witnessed::Pid(8));
        assert_eq!(ring.len(), 1);
    }

    /// Delivered now, but it happened long ago: it says nothing about a flow now.
    #[test]
    fn a_late_event_is_as_old_as_when_it_happened() {
        const NOW: u64 = 100_000;
        const NOW_FILETIME: i64 = 133_000_000_000_000_000;
        const TICKS_PER_MS: i64 = 10_000;
        let happened = |ago_ms: i64| occurred_at_ms(NOW, NOW_FILETIME, NOW_FILETIME - ago_ms * TICKS_PER_MS);
        assert_eq!(happened(0), NOW);
        assert_eq!(happened(30_000), NOW - 30_000);
        assert_eq!(happened(-500), NOW, "dated ahead of now: no age");
        assert_eq!(happened(i64::MAX / TICKS_PER_MS / 2), 0, "older than this clock");

        let mut ring = EtwRing::new(OWN);
        ring.insert(&event(7, Proto::Udp, L, R), happened(30_000));
        assert_eq!(ring.answer(&flow(Proto::Udp, L, R), NOW), Witnessed::Nothing);
    }

    /// Delivery can run behind: an older event neither replaces a newer one nor,
    /// from outside the window, marks it.
    #[test]
    fn an_event_delivered_out_of_order_does_not_rewrite_a_newer_one() {
        const AT: u64 = 10 * ETW_MATCH_WINDOW_MS;
        let mut ring = EtwRing::new(OWN);
        ring.insert(&event(8, Proto::Udp, L, R), AT);
        ring.insert(&event(7, Proto::Udp, L, R), AT - ETW_MATCH_WINDOW_MS - 1);
        assert_eq!(ring.answer(&flow(Proto::Udp, L, R), AT), Witnessed::Pid(8), "the tuple's earlier owner");
        ring.insert(&event(7, Proto::Udp, L, R), AT - 1);
        assert_eq!(ring.answer(&flow(Proto::Udp, L, R), AT), Witnessed::Conflict, "inside the window: two owners");
    }

    #[test]
    fn a_busy_socket_takes_one_slot() {
        let mut ring = EtwRing::new(OWN);
        for t in 0..(ETW_RING_CAP as u64 * 2) {
            assert!(!ring.insert(&event(7, Proto::Udp, L, R), t));
        }
        assert_eq!((ring.len(), ring.evictions()), (1, 0));
    }

    #[test]
    fn the_ring_is_bounded_and_counts_every_eviction() {
        let mut ring = EtwRing::new(OWN);
        let tuple = |i: usize| event(7, Proto::Tcp, &format!("10.0.{}.{}:{}", i / 65_536, (i / 256) % 256, i % 60_000 + 1), R);
        for i in 0..ETW_RING_CAP {
            assert!(!ring.insert(&tuple(i), 0));
        }
        for extra in 1..=5 {
            assert!(ring.insert(&tuple(ETW_RING_CAP + extra), 0));
            assert_eq!(ring.len(), ETW_RING_CAP);
            assert_eq!(ring.evictions(), extra as u64);
        }
        let oldest = tuple(0);
        assert_eq!(ring.answer(&FiveTuple { proto: Proto::Tcp, local: oldest.local, remote: oldest.remote }, 0), Witnessed::Nothing, "FIFO");
    }

    #[test]
    fn the_engines_own_events_are_not_stored() {
        let mut ring = EtwRing::new(OWN);
        ring.insert(&event(OWN, Proto::Udp, L, R), 0);
        assert!(ring.is_empty());
    }

    #[test]
    fn a_pid_zero_event_is_no_answer_and_leaves_a_real_pid_alone() {
        let mut ring = EtwRing::new(OWN);
        ring.insert(&event(0, Proto::Udp, L, R), 0);
        assert!(ring.is_empty(), "PID 0 names no owner");
        ring.insert(&event(7, Proto::Udp, L, R), 1);
        ring.insert(&event(0, Proto::Udp, L, R), 2);
        assert_eq!(ring.answer(&flow(Proto::Udp, L, R), 2), Witnessed::Pid(7), "neither a conflict nor a replacement");
    }

    #[test]
    fn sinks_send_each_provider_to_its_own_table_and_count_evictions() {
        let meters = Arc::new(Meters::default());
        let sinks = Sinks::new(OWN, meters.clone());
        let f: Value = serde_json::from_str(FIXTURE).unwrap();
        let e = &f["events"][0];
        let (id, bytes) = (e["id"].as_u64().unwrap() as u16, unhex(e["payload_hex"].as_str().unwrap()));
        sinks.ingest(0x1234, id, &bytes, 0);
        assert!(lock(&sinks.ring).is_empty(), "another provider's event is not this one");
        sinks.ingest(KERNEL_NETWORK, id, &bytes, 0);
        assert_eq!(lock(&sinks.ring).len(), 1);
        assert_eq!(meters.counters().etw_dropped, 0);
    }

    const BOUND: Duration = Duration::from_secs(30);

    type End = Result<(), String>;

    fn ended() -> (impl FnOnce(End) + Send + 'static, std::sync::mpsc::Receiver<End>) {
        let (tx, rx) = std::sync::mpsc::channel();
        (move |end| tx.send(end).unwrap(), rx)
    }

    #[test]
    fn a_consumer_that_cannot_open_fails_the_start() {
        let (on_end, end) = ended();
        let started = spawn_consumer(|| Err::<(), _>("opening: Win32 error 5".to_string()), |()| Ok(()), on_end, BOUND);
        assert_eq!(started.err().as_deref(), Some("opening: Win32 error 5"));
        assert!(end.recv_timeout(BOUND).is_err(), "nothing ran, so nothing ended");
    }

    #[test]
    fn a_start_does_not_return_before_the_consumer_opens() {
        let (entered, opening) = std::sync::mpsc::channel();
        let (on_end, end) = ended();
        let consumer = spawn_consumer(
            move || {
                std::thread::sleep(Duration::from_millis(50));
                entered.send("opened").unwrap();
                Ok(())
            },
            |()| Ok(()),
            on_end,
            BOUND,
        )
        .unwrap();
        assert_eq!(opening.try_recv(), Ok("opened"), "the start waited for the open");
        assert_eq!(end.recv_timeout(BOUND).unwrap(), Ok(()));
        consumer.join().unwrap();
    }

    #[test]
    fn a_consumer_that_never_opens_fails_the_start_within_its_bound() {
        let (release, hung) = std::sync::mpsc::channel::<()>();
        let (on_end, _end) = ended();
        let started = spawn_consumer(
            move || {
                let _ = hung.recv();
                Err::<(), _>("too late".to_string())
            },
            |()| Ok(()),
            on_end,
            Duration::from_millis(20),
        );
        assert!(started.err().unwrap().contains("did not open"));
        drop(release);
    }

    #[test]
    fn a_consumer_that_dies_opening_fails_the_start() {
        let (on_end, _end) = ended();
        let started = spawn_consumer(|| -> Result<(), String> { panic!("a test's expected panic") }, |()| Ok(()), on_end, BOUND);
        assert!(started.err().unwrap().contains("before it opened"));
    }

    #[test]
    fn a_read_that_fails_after_the_start_reaches_its_end_report() {
        let (on_end, end) = ended();
        let consumer = spawn_consumer(|| Ok(()), |()| Err("reading the session: Win32 error 6".to_string()), on_end, BOUND).unwrap();
        assert_eq!(end.recv_timeout(BOUND).unwrap(), Err("reading the session: Win32 error 6".to_string()));
        consumer.join().unwrap();
    }

    #[test]
    fn only_a_stop_the_engine_asked_for_is_a_quiet_end() {
        let failed: Result<(), String> = Err("reading the session: Win32 error 6".into());
        assert_eq!(consumer_failure(true, &Ok(())), None);
        assert_eq!(consumer_failure(true, &failed), None);
        assert_eq!(consumer_failure(false, &failed).as_deref(), Some("attribution without ETW: reading the session: Win32 error 6"));
        assert!(consumer_failure(false, &Ok(())).unwrap().starts_with("attribution without ETW:"), "stopped by someone else");
    }

    #[test]
    fn the_event_filter_has_the_layout_windows_reads() {
        assert_eq!(event_id_filter(&[12, 300]), [1, 0, 2, 0, 12, 0, 44, 1]);
    }

    proptest! {
        #[test]
        fn decode_never_panics(id in any::<u16>(), bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = decode(id, &bytes);
            for id in KERNEL_NETWORK_EVENTS {
                let _ = decode(id, &bytes);
            }
        }
    }
}
