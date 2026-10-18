//! Coexistence with AdGuard and VPNs (plan 1.7, the user's decision of
//! 2026-10-17). Read only: the service manager's state of AdGuard's service,
//! and the adapter and forwarding tables.
//!
//! - AdGuard for Windows' service running: the engine routes nothing (probe
//!   run 2: its driver redirected every flow to AdguardSvc.exe and captured
//!   the engine's own connections, which looped). The app offers to pause
//!   AdGuard; the engine never touches it.
//! - A full-tunnel VPN (a tunnel adapter, not Sieve's, that holds a default
//!   or /1 route): the engine routes nothing and says "Paused while <adapter>
//!   is connected"; it resumes when the VPN's routes go (`NotifyRouteChange2`).
//! - A split-tunnel VPN (a tunnel adapter with narrower routes only) is
//!   allowed and named, because its traffic bypasses Sieve (`route::plan`
//!   keeps its prefixes out).

use sieve_ipc::Blocker;

use crate::route::plan::is_tunnel;
use crate::route::table::NetTables;

/// AdGuard for Windows' service name (read 2026-10-18 from this machine's
/// service manager: "Adguard Service", image `AdguardSvc.exe`). The app's
/// pause offer stops and starts the same name (src/core/engine.ts, law).
pub const ADGUARD_SERVICE: &str = "Adguard Service";

/// A route this wide or wider means the adapter carries everything.
const FULL_TUNNEL_MAX_LEN: u8 = 1;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coexistence {
    pub blocker: Option<Blocker>,
    pub split_tunnels: Vec<String>,
}

/// What may run beside the engine, from facts only. AdGuard wins over a VPN
/// (it would capture the engine's connections whatever the routes are).
pub fn classify(tables: &NetTables, adguard_running: bool) -> Coexistence {
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
    let blocker = if adguard_running {
        Some(Blocker::Adguard { service: ADGUARD_SERVICE.to_string() })
    } else {
        full.map(|adapter| Blocker::Vpn { adapter })
    };
    Coexistence { blocker, split_tunnels: split }
}

/// Is AdGuard's service running (any state but stopped: a starting or
/// stopping service may already capture traffic)? The service manager with
/// connect and query access only; a service that does not exist is not running.
#[cfg(windows)]
pub fn adguard_running() -> Result<bool, String> {
    use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
        SERVICE_STATUS, SERVICE_STOPPED,
    };
    use windows::core::{HSTRING, PCWSTR};

    // SAFETY: plain SCM calls; every handle is closed below.
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).map_err(|e| format!("service manager: {e}"))?;
        let result = match OpenServiceW(scm, &HSTRING::from(ADGUARD_SERVICE), SERVICE_QUERY_STATUS) {
            Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => Ok(false),
            Err(e) => Err(format!("{ADGUARD_SERVICE}: {e}")),
            Ok(service) => {
                let mut status = SERVICE_STATUS::default();
                let read = QueryServiceStatus(service, &mut status).map(|()| status.dwCurrentState != SERVICE_STOPPED);
                let _ = CloseServiceHandle(service);
                read.map_err(|e| format!("{ADGUARD_SERVICE} status: {e}"))
            }
        };
        let _ = CloseServiceHandle(scm);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::table::fixtures::*;

    #[test]
    fn home_alone_is_clear() {
        assert_eq!(classify(&load(HOME), false), Coexistence::default());
    }

    #[test]
    fn adguard_running_refuses_whatever_the_tables_say() {
        for t in [load(HOME), load(VPN_FULL), load(VPN_SPLIT)] {
            assert_eq!(classify(&t, true).blocker, Some(Blocker::Adguard { service: "Adguard Service".into() }));
        }
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

    /// Read only, no admin: the service manager answers for AdGuard's service.
    #[cfg(windows)]
    #[test]
    fn adguards_service_state_is_readable_without_admin() {
        assert!(adguard_running().is_ok());
    }
}
