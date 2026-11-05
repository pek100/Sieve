//! Coexistence with AdGuard and VPNs (plan 1.7, the user's decision of
//! 2026-10-17). Read only, apart from one test connection that carries no data.
//!
//! - AdGuard for Windows intercepting: the engine routes nothing (probe run 2:
//!   its driver redirected every flow to its service process and captured the
//!   engine's own connections, which looped). The app offers to pause AdGuard;
//!   the engine never touches it.
//! - A full-tunnel VPN (a tunnel adapter, not Sieve's, that holds a default
//!   or /1 route): the engine routes nothing and says "Paused while <adapter>
//!   is connected"; it resumes when the VPN's routes go (`NotifyRouteChange2`).
//! - A split-tunnel VPN (a tunnel adapter with narrower routes only) is
//!   allowed and named, because its traffic bypasses Sieve (`route::plan`
//!   keeps its prefixes out).
//!
//! "Intercepting" is judged by behaviour, not by the service's state: `sc stop`
//! ends AdGuard's filtering but leaves its service in StopPending for good
//! (observed live 2026-10-18), and protection can be off while it is Running.
//! So while its service is alive the engine opens one TCP socket, pinned like
//! every engine socket, to a documentation address nothing answers, and writes
//! nothing on it. Either witness means someone local took the connection: the
//! connect finished, or a row of AdGuard's process touches the probe (its
//! remote end is the probe's local end, the proxy's accepted socket, or the
//! probe's destination, the proxy's upstream socket). The row shape is a model
//! until live proof L1 (docs/live/engine-slice-3.md); the connect witness keeps
//! the verdict safe if the model is wrong.
//!
//! A service that is absent or stopped means no probe at all, so a computer
//! without AdGuard never sends this packet. Adapters and drivers are not
//! signals: AdGuard's drivers stay loaded while it is paused, and AdGuard VPN
//! is a different product that `classify` treats as any other tunnel.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use sieve_ipc::Blocker;

use crate::flow::flows::OwnerRow;
use crate::route::pin::{self, Egress};
use crate::route::plan::is_tunnel;
use crate::route::table::NetTables;

/// AdGuard for Windows' service name (read 2026-10-18 from this machine's
/// service manager). The app's pause offer stops and starts the same name
/// (src/core/engine.ts, law).
pub const ADGUARD_SERVICE: &str = "Adguard Service";

/// A route this wide or wider means the adapter carries everything.
const FULL_TUNNEL_MAX_LEN: u8 = 1;

/// Port 443 at a public-range address: outside AdGuard's default exclusions
/// (research E4). RFC 5737, so nothing real is contacted.
pub const PROBE_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);
/// RFC 3849, used when IPv4 has no egress.
pub const PROBE_V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 443);
/// How long the probe's connect may run. A local proxy accepts at once; a
/// wrong clear verdict lasts one recheck, so no repeated-verdict ladder.
pub const PROBE_WINDOW: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coexistence {
    pub blocker: Option<Blocker>,
    pub split_tunnels: Vec<String>,
}

/// AdGuard's service as far as the probe cares: absent and stopped have one
/// consequence. `pid` is its process, None when the service manager gives none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdguardService {
    NotRunning,
    Alive { pid: Option<u32> },
}

/// What one probe saw. `rows` is the owner table of the probe's family, read
/// while the probe's socket was open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeObservation {
    pub local: SocketAddr,
    pub dest: SocketAddr,
    pub connected: bool,
    pub rows: Vec<OwnerRow>,
}

impl ProbeObservation {
    /// A row whose remote end is the probe's local end or its destination.
    pub fn touches(&self, row: &OwnerRow) -> bool {
        row.remote == Some(self.local) || row.remote == Some(self.dest)
    }
}

/// The two witnesses (module docs). A finished connect counts even with no
/// AdGuard row: nothing can answer that address, and the failure it prevents
/// is two interceptors looping.
pub fn intercepted(obs: &ProbeObservation, adguard_pid: Option<u32>) -> bool {
    obs.connected || adguard_pid.filter(|pid| *pid != 0).is_some_and(|pid| obs.rows.iter().any(|r| r.pid == pid && obs.touches(r)))
}

/// The verdict: no probe unless the service is alive. `probe` answers None
/// when neither family has an egress (bring-up refuses that itself); its error
/// is the caller's error, never a verdict.
pub async fn adguard_intercepts<F, Fut>(service: AdguardService, probe: F) -> Result<bool, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<ProbeObservation>, String>>,
{
    let AdguardService::Alive { pid } = service else { return Ok(false) };
    Ok(probe().await?.is_some_and(|obs| intercepted(&obs, pid)))
}

/// Where the probe goes and leaves by, IPv4 first, with Sieve's routes ignored.
pub fn probe_dest(tables: &NetTables) -> Option<(SocketAddr, Egress)> {
    [PROBE_V4, PROBE_V6].into_iter().find_map(|dest| pin::egress(tables, None, dest.ip()).ok().map(|egress| (dest, egress)))
}

/// What may run beside the engine, from facts only. AdGuard wins over a VPN
/// (it would capture the engine's connections whatever the routes are).
pub fn classify(tables: &NetTables, adguard_intercepting: bool) -> Coexistence {
    let mut full = None;
    let mut split = Vec::new();
    for a in tables.others().filter(|a| is_tunnel(a.if_type, &a.description)) {
        let routes: Vec<u8> = tables.routes_on(a).map(|r| r.dest.length()).collect();
        if routes.iter().any(|len| *len <= FULL_TUNNEL_MAX_LEN) {
            full.get_or_insert_with(|| a.alias.clone());
        } else if !routes.is_empty() {
            split.push(a.alias.clone());
        }
    }
    let blocker = if adguard_intercepting {
        Some(Blocker::Adguard { service: ADGUARD_SERVICE.to_string() })
    } else {
        full.map(|adapter| Blocker::Vpn { adapter })
    };
    Coexistence { blocker, split_tunnels: split }
}

#[cfg(windows)]
fn service_of(state: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE, pid: u32) -> AdguardService {
    if state == windows::Win32::System::Services::SERVICE_STOPPED {
        AdguardService::NotRunning
    } else {
        AdguardService::Alive { pid: (pid != 0).then_some(pid) }
    }
}

/// AdGuard's service state and process, in one call, with connect and query
/// access only. A service that does not exist is not running.
#[cfg(windows)]
pub fn adguard_service() -> Result<AdguardService, String> {
    use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS,
        SERVICE_STATUS_PROCESS,
    };
    use windows::core::{HSTRING, PCWSTR};

    // SAFETY: plain SCM calls; every handle is closed below, and `bytes` is
    // exactly the plain-data struct the call fills.
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).map_err(|e| format!("service manager: {e}"))?;
        let result = match OpenServiceW(scm, &HSTRING::from(ADGUARD_SERVICE), SERVICE_QUERY_STATUS) {
            Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => Ok(AdguardService::NotRunning),
            Err(e) => Err(format!("{ADGUARD_SERVICE}: {e}")),
            Ok(service) => {
                let mut status = SERVICE_STATUS_PROCESS::default();
                let bytes = std::slice::from_raw_parts_mut((&raw mut status).cast::<u8>(), size_of::<SERVICE_STATUS_PROCESS>());
                let mut needed = 0u32;
                let read = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, Some(bytes), &mut needed);
                let _ = CloseServiceHandle(service);
                read.map(|()| service_of(status.dwCurrentState, status.dwProcessId)).map_err(|e| format!("{ADGUARD_SERVICE} status: {e}"))
            }
        };
        let _ = CloseServiceHandle(scm);
        result
    }
}

/// One connect within `window`, then one read of the probe's family's owner
/// table. The pending connect, or the stream it finished with, keeps the socket
/// open through the read; it closes on return. A refused or failed connect is
/// an answer (not connected); a table that cannot be read is an error.
#[cfg(windows)]
async fn observe<S: crate::flow::flows::OwnerSource>(
    socket: socket2::Socket,
    dest: SocketAddr,
    window: Duration,
    source: &mut S,
) -> Result<ProbeObservation, String> {
    use crate::flow::flows::{FiveTuple, Table};
    use crate::flow::packet::Proto;

    let local = socket.local_addr().map_err(|e| format!("probe socket address: {e}"))?.as_socket().ok_or("the probe socket has no address")?;
    let connect = tokio::net::TcpSocket::from_std_stream(socket.into()).connect(dest);
    tokio::pin!(connect);
    let outcome = tokio::time::timeout(window, &mut connect).await;
    let connected = matches!(outcome, Ok(Ok(_)));
    let table = Table::of(&FiveTuple { proto: Proto::Tcp, local, remote: dest });
    let rows = source.read(table).ok_or_else(|| format!("the owner table {table:?} could not be read"))?;
    Ok(ProbeObservation { local, dest, connected, rows })
}

/// The production probe: pinned, within [`PROBE_WINDOW`]. Pinning matters with
/// Sieve's routes up, where an unpinned SYN would enter Sieve's own stack and
/// complete; AdGuard redirects before routing, so the pin does not hide it.
#[cfg(windows)]
pub async fn probe_adguard(tables: &NetTables) -> Result<Option<ProbeObservation>, String> {
    let Some((dest, egress)) = probe_dest(tables) else { return Ok(None) };
    let socket = pin::egress_socket(egress, dest, false)?;
    observe(socket, dest, PROBE_WINDOW, &mut crate::flow::flows::os::IpHelper).await.map(Some)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::HashMap;

    use serde::Deserialize;

    use super::*;
    use crate::route::prefix::Prefix;
    use crate::route::table::fixtures::*;

    const PROBE_CASES: &str = include_str!("../fixtures/adguard-probe.json");

    #[derive(Deserialize)]
    struct Row {
        local: SocketAddr,
        remote: Option<SocketAddr>,
        pid: u32,
    }

    #[derive(Deserialize)]
    struct Observation {
        local: SocketAddr,
        dest: SocketAddr,
        connected: bool,
        rows: Vec<Row>,
    }

    impl Observation {
        fn parsed(&self) -> ProbeObservation {
            let rows = self.rows.iter().map(|r| OwnerRow { local: r.local, remote: r.remote, pid: r.pid }).collect();
            ProbeObservation { local: self.local, dest: self.dest, connected: self.connected, rows }
        }
    }

    #[derive(Deserialize)]
    struct Case {
        name: String,
        service: String,
        pid: Option<u32>,
        observation: String,
        tables: String,
        intercepting: bool,
        blocker: Option<Blocker>,
        probes: u32,
    }

    #[derive(Deserialize)]
    struct Fixture {
        about: String,
        observations: HashMap<String, Observation>,
        cases: Vec<Case>,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(PROBE_CASES).expect("adguard-probe.json parses")
    }

    fn tables_of(name: &str) -> NetTables {
        load(match name {
            "home" => HOME,
            "vpn_full" => VPN_FULL,
            "vpn_split" => VPN_SPLIT,
            other => panic!("no tables fixture named {other}"),
        })
    }

    async fn run(fixture: &Fixture, case: &Case) {
        let service = match case.service.as_str() {
            "stopped" | "absent" => AdguardService::NotRunning,
            "running" | "stop_pending" => AdguardService::Alive { pid: case.pid },
            other => panic!("{}: no service state named {other}", case.name),
        };
        let calls = Cell::new(0);
        let observed = fixture.observations[&case.observation].parsed();
        let verdict = adguard_intercepts(service, || {
            calls.set(calls.get() + 1);
            std::future::ready(Ok(Some(observed)))
        })
        .await
        .expect("the fake probe does not fail");
        assert_eq!(verdict, case.intercepting, "{}: verdict", case.name);
        assert_eq!(calls.get(), case.probes, "{}: probes sent", case.name);
        assert_eq!(classify(&tables_of(&case.tables), verdict).blocker, case.blocker, "{}: blocker", case.name);
    }

    async fn check(names: &[&str]) {
        let f = fixture();
        for name in names {
            let case = f.cases.iter().find(|c| c.name == *name).unwrap_or_else(|| panic!("no case named {name}"));
            run(&f, case).await;
        }
    }

    #[tokio::test]
    async fn every_fixture_case_holds_and_says_it_is_constructed() {
        let f = fixture();
        assert!(f.about.contains("constructed from the redirect model"), "{}", f.about);
        assert!(!f.cases.is_empty());
        for case in &f.cases {
            run(&f, case).await;
        }
    }

    #[tokio::test]
    async fn running_and_intercepting_refuses_whatever_the_tables_say() {
        check(&["running_intercepted_home", "running_intercepted_vpn_full", "running_intercepted_vpn_split", "running_intercepted_over_ipv6"]).await;
    }

    #[tokio::test]
    async fn stop_pending_and_not_intercepting_lets_the_engine_route() {
        check(&["stop_pending_clear_home"]).await;
    }

    #[tokio::test]
    async fn running_and_not_intercepting_lets_the_engine_route() {
        check(&["running_protection_off_home"]).await;
    }

    #[tokio::test]
    async fn stopped_and_absent_send_no_probe() {
        check(&["stopped_sends_no_probe", "absent_sends_no_probe"]).await;
    }

    #[tokio::test]
    async fn a_proxy_row_is_a_witness_without_a_finished_connect() {
        check(&["accepted_row_is_a_witness", "upstream_row_is_a_witness"]).await;
    }

    #[tokio::test]
    async fn a_finished_connect_with_no_adguard_row_counts_as_intercepting() {
        check(&["finished_connect_without_a_row"]).await;
    }

    #[tokio::test]
    async fn another_process_row_is_no_witness() {
        check(&["another_process_row"]).await;
    }

    #[tokio::test]
    async fn no_known_pid_still_has_the_connect_witness() {
        check(&["no_pid_finished_connect", "no_pid_rows_alone"]).await;
        // A row with no known owner reads as pid 0 and is never AdGuard's.
        let mut obs = fixture().observations["accepted_row"].parsed();
        for r in &mut obs.rows {
            r.pid = 0;
        }
        assert!(!intercepted(&obs, Some(0)));
        assert!(!intercepted(&obs, Some(4242)));
    }

    #[tokio::test]
    async fn the_adguard_vpn_adapter_is_a_vpn_not_adguard() {
        check(&["paused_with_adguard_vpn", "stopped_with_adguard_vpn", "intercepting_with_adguard_vpn"]).await;
    }

    #[tokio::test]
    async fn a_failed_probe_is_an_error_not_a_verdict() {
        let failed = adguard_intercepts(AdguardService::Alive { pid: Some(4242) }, || std::future::ready(Err("socket: denied".to_string()))).await;
        assert_eq!(failed, Err("socket: denied".to_string()));
    }

    #[tokio::test]
    async fn no_egress_is_no_verdict_to_refuse_on() {
        let none = adguard_intercepts(AdguardService::Alive { pid: Some(4242) }, || std::future::ready(Ok(None))).await;
        assert_eq!(none, Ok(false));
    }

    #[test]
    fn the_probe_addresses_are_documentation_ranges() {
        let v4: Prefix = "192.0.2.0/24".parse().unwrap();
        let v6: Prefix = "2001:db8::/32".parse().unwrap();
        assert!(v4.contains(PROBE_V4.ip()) && PROBE_V4.port() == 443);
        assert!(v6.contains(PROBE_V6.ip()) && PROBE_V6.port() == 443);
    }

    #[test]
    fn probe_dest_prefers_ipv4_and_falls_back_and_ignores_sieves_adapter() {
        let wifi_v4 = Egress { if_index: 6, source: "192.168.7.20".parse().unwrap() };
        assert_eq!(probe_dest(&load(HOME)), Some((PROBE_V4, wifi_v4)));
        assert_eq!(probe_dest(&load(SIEVE_UP)), Some((PROBE_V4, wifi_v4)), "Sieve's routes are ignored");

        let mut v6_only = load(HOME);
        v6_only.routes.retain(|r| !(r.dest.is_ipv4() && r.dest.length() == 0));
        assert_eq!(probe_dest(&v6_only), Some((PROBE_V6, Egress { if_index: 6, source: "2001:db8:7:1::20".parse().unwrap() })));

        let mut none = load(HOME);
        none.routes.retain(|r| r.dest.length() != 0);
        assert_eq!(probe_dest(&none), None);
    }

    #[test]
    fn home_alone_is_clear() {
        assert_eq!(classify(&load(HOME), false), Coexistence::default());
    }

    #[test]
    fn a_full_tunnel_vpn_pauses_the_engine_and_is_named() {
        let c = classify(&load(VPN_FULL), false);
        assert_eq!(c.blocker, Some(Blocker::Vpn { adapter: "AdGuard VPN".into() }));
        assert!(c.split_tunnels.is_empty());
    }

    #[test]
    fn a_vpn_with_a_default_route_is_full_too() {
        let mut t = load(VPN_SPLIT);
        let corp = t.routes.iter_mut().find(|r| r.if_index == 41).unwrap();
        corp.dest = "0.0.0.0/0".parse().unwrap();
        assert_eq!(classify(&t, false).blocker, Some(Blocker::Vpn { adapter: "Corp VPN".into() }));
    }

    #[test]
    fn a_split_tunnel_is_allowed_and_stated_and_a_down_tap_is_ignored() {
        let c = classify(&load(VPN_SPLIT), false);
        assert_eq!(c, Coexistence { blocker: None, split_tunnels: vec!["Corp VPN".into()] });
    }

    #[test]
    fn sieves_own_adapter_is_never_a_vpn() {
        assert_eq!(classify(&load(SIEVE_UP), false), Coexistence::default());
    }

    #[test]
    fn hyper_v_holding_the_default_route_is_not_a_vpn() {
        let mut t = load(HOME);
        for r in t.routes.iter_mut().filter(|r| r.dest.length() == 0) {
            r.if_index = 24;
        }
        assert_eq!(classify(&t, false), Coexistence::default());
    }

    #[cfg(windows)]
    mod os {
        use std::time::Instant;

        use socket2::{Domain, Protocol, Socket, Type};
        use windows::Win32::System::Services::{
            SERVICE_CONTINUE_PENDING, SERVICE_PAUSE_PENDING, SERVICE_PAUSED, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STOP_PENDING,
            SERVICE_STOPPED,
        };

        use super::*;
        use crate::flow::flows::os::IpHelper;

        /// Long enough for a loopback connect on a machine that may suspend tests.
        const LOOPBACK_WINDOW: Duration = Duration::from_secs(10);
        /// A watchdog may suspend this process mid-test.
        const SLACK: Duration = Duration::from_secs(60);

        fn loopback_socket() -> Socket {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
            socket.set_nonblocking(true).unwrap();
            socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into()).unwrap();
            socket
        }

        /// AdGuard filters localhost (research E4), so what loopback shows is
        /// asserted only while it does not.
        fn adguard_stays_out() -> bool {
            adguard_service() == Ok(AdguardService::NotRunning)
        }

        #[tokio::test]
        async fn the_observation_of_a_local_listener_is_connected_with_its_row() {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let dest = listener.local_addr().unwrap();
            let obs = observe(loopback_socket(), dest, LOOPBACK_WINDOW, &mut IpHelper).await.unwrap();
            let me = std::process::id();
            assert!(obs.connected, "{obs:?}");
            assert!(intercepted(&obs, Some(me)));
            if adguard_stays_out() {
                assert!(obs.rows.iter().any(|r| r.pid == me && r.local == obs.local && r.remote == Some(dest)), "the probe's own row");
                let row_alone = ProbeObservation { connected: false, ..obs };
                assert!(intercepted(&row_alone, Some(me)), "the row is a witness by itself");
            }
        }

        #[tokio::test]
        async fn the_observation_of_a_closed_local_port_is_not_connected() {
            let dest = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap();
            let started = Instant::now();
            let obs = observe(loopback_socket(), dest, PROBE_WINDOW, &mut IpHelper).await.unwrap();
            assert!(started.elapsed() < PROBE_WINDOW + SLACK, "{:?}", started.elapsed());
            if adguard_stays_out() {
                assert!(!obs.connected, "{obs:?}");
                assert!(!intercepted(&obs, None));
            }
        }

        #[test]
        fn a_table_that_cannot_be_read_fails_the_observation() {
            struct Unreadable;
            impl crate::flow::flows::OwnerSource for Unreadable {
                fn read(&mut self, _table: crate::flow::flows::Table) -> Option<Vec<OwnerRow>> {
                    None
                }
            }
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let dest = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap();
            let failed = runtime.block_on(observe(loopback_socket(), dest, Duration::ZERO, &mut Unreadable));
            assert!(failed.unwrap_err().contains("could not be read"));
        }

        /// Read only, no admin: the service manager answers for AdGuard's service.
        #[test]
        fn adguards_service_is_readable_without_admin() {
            assert!(adguard_service().is_ok());
        }

        #[test]
        fn service_state_mapping() {
            assert_eq!(service_of(SERVICE_STOPPED, 0), AdguardService::NotRunning);
            assert_eq!(service_of(SERVICE_STOPPED, 4242), AdguardService::NotRunning);
            for state in [SERVICE_START_PENDING, SERVICE_RUNNING, SERVICE_STOP_PENDING, SERVICE_PAUSED, SERVICE_PAUSE_PENDING, SERVICE_CONTINUE_PENDING] {
                assert_eq!(service_of(state, 4242), AdguardService::Alive { pid: Some(4242) });
                assert_eq!(service_of(state, 0), AdguardService::Alive { pid: None });
            }
        }
    }
}
