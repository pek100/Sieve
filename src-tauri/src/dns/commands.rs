//! Tauri commands for the DNS engine. Thin: parse the config at the
//! boundary, hand the engine the real clock and fetcher, turn errors into
//! strings. Starting the proxy changes nothing on the system; Windows keeps
//! its own DNS servers until the user points it here (`crate::sysdns`).
//!
//! - `dns_start(config?)` -> `DnsStatus` (fails when already running)
//! - `dns_stop()` -> `DnsStatus` (stopped; a no-op when not running)
//! - `dns_status()` -> `DnsStatus` (see `status.rs` for the v1 shape)
//! - `dns_self_check()` -> `SelfCheck` (fails when not running)

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use tauri::{AppHandle, Manager, State};

use super::engine::{Engine, EngineConfig, system_clock};
use super::lists::{DEFAULT_LIST_URL, http_fetcher};
use super::probe::SelfCheck;
use super::proxy::{DEFAULT_BINDS, DEFAULT_UPSTREAMS};
use super::status::DnsStatus;

/// The running engine, if any. Managed by Tauri (`.manage` in lib.rs).
#[derive(Default)]
pub struct DnsState(tokio::sync::Mutex<Option<Engine>>);

impl DnsState {
    /// The engine slot, for other commands that need the running filter (sysdns).
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, Option<Engine>> {
        self.0.lock().await
    }
}

/// `dns_start` argument. Every key is optional on the wire; a missing key
/// takes the default below (the only place the defaults are spelled out).
/// `{"binds": ["127.0.0.1:53", "[::1]:53"], "upstreams": ["1.1.1.1:53", "9.9.9.9"],
///   "list_url": "https://..."}`; an upstream without a port means :53.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub binds: Vec<String>,
    pub upstreams: Vec<String>,
    pub list_url: String,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            binds: DEFAULT_BINDS.iter().map(|s| (*s).to_owned()).collect(),
            upstreams: DEFAULT_UPSTREAMS.iter().map(|s| (*s).to_owned()).collect(),
            list_url: DEFAULT_LIST_URL.to_owned(),
        }
    }
}

const DNS_PORT: u16 = 53;

impl DnsConfig {
    /// The one normalizer for this boundary.
    pub fn resolve(self, data_dir: PathBuf) -> Result<EngineConfig, String> {
        let binds = self
            .binds
            .iter()
            .map(|b| b.parse::<SocketAddr>().map_err(|_| format!("bind is not an ip:port: {b}")))
            .collect::<Result<Vec<_>, _>>()?;
        if binds.is_empty() {
            return Err("at least one listen address is needed".to_owned());
        }
        let upstreams = self
            .upstreams
            .iter()
            .map(|u| parse_upstream(u))
            .collect::<Result<Vec<_>, _>>()?;
        if upstreams.is_empty() {
            return Err("at least one upstream is needed".to_owned());
        }
        if !self.list_url.starts_with("https://") {
            return Err(format!("list_url must be https: {}", self.list_url));
        }
        Ok(EngineConfig { binds, upstreams, list_url: self.list_url, data_dir })
    }
}

fn parse_upstream(raw: &str) -> Result<SocketAddr, String> {
    let s = raw.trim();
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    s.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .map(|ip| SocketAddr::new(ip, DNS_PORT))
        .map_err(|_| format!("upstream is not an ip or ip:port: {raw}"))
}

#[tauri::command]
pub async fn dns_start(
    app: AppHandle,
    state: State<'_, DnsState>,
    config: Option<DnsConfig>,
) -> Result<DnsStatus, String> {
    let mut slot = state.0.lock().await;
    if slot.is_some() {
        return Err("DNS filter is already running; stop it first".to_owned());
    }
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("no app data dir: {e}"))?
        .join("dns");
    let engine_config = config.unwrap_or_default().resolve(data_dir)?;
    let engine = Engine::start(engine_config, http_fetcher(), system_clock())
        .await
        .map_err(|e| e.to_string())?;
    let status = engine.status();
    *slot = Some(engine);
    Ok(status)
}

#[tauri::command]
pub async fn dns_stop(state: State<'_, DnsState>) -> Result<DnsStatus, String> {
    if let Some(engine) = state.0.lock().await.take() {
        engine.stop().await;
    }
    Ok(DnsStatus::stopped())
}

#[tauri::command]
pub async fn dns_status(state: State<'_, DnsState>) -> Result<DnsStatus, String> {
    Ok(state.0.lock().await.as_ref().map_or_else(DnsStatus::stopped, Engine::status))
}

#[tauri::command]
pub async fn dns_self_check(state: State<'_, DnsState>) -> Result<SelfCheck, String> {
    let slot = state.0.lock().await;
    let engine = slot.as_ref().ok_or("DNS filter is not running")?;
    Ok(engine.self_check().await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_keys_take_the_defaults() {
        let c: DnsConfig = serde_json::from_str("{}").expect("parses");
        assert_eq!(c, DnsConfig::default());
        let e = c.resolve(PathBuf::from("x")).expect("resolves");
        let want: Vec<SocketAddr> = ["127.0.0.1:53", "[::1]:53"].iter().map(|s| s.parse().expect("a")).collect();
        assert_eq!(e.binds, want, "both loopback families, so Windows can point IPv4 and IPv6 here");
        assert_eq!(e.upstreams.len(), 2);
        assert_eq!(e.list_url, DEFAULT_LIST_URL);
    }

    #[test]
    fn upstream_without_port_means_53() {
        let c: DnsConfig =
            serde_json::from_str(r#"{"upstreams": ["9.9.9.9", "2620:fe::fe", "[2606:4700::1111]:5353"]}"#)
                .expect("parses");
        let e = c.resolve(PathBuf::from("x")).expect("resolves");
        let want: Vec<SocketAddr> = ["9.9.9.9:53", "[2620:fe::fe]:53", "[2606:4700::1111]:5353"]
            .iter()
            .map(|s| s.parse().expect("a"))
            .collect();
        assert_eq!(e.upstreams, want);
    }

    #[test]
    fn bad_config_is_refused_at_the_boundary() {
        for json in [
            r#"{"binds": ["localhost:53"]}"#,
            r#"{"binds": []}"#,
            r#"{"upstreams": []}"#,
            r#"{"upstreams": ["dns.google"]}"#,
            r#"{"list_url": "http://plain.example/list.txt"}"#,
        ] {
            let c: DnsConfig = serde_json::from_str(json).expect("parses");
            assert!(c.resolve(PathBuf::from("x")).is_err(), "{json}");
        }
        assert!(serde_json::from_str::<DnsConfig>(r#"{"bnid": "x"}"#).is_err(), "typo keys are refused");
        assert!(serde_json::from_str::<DnsConfig>(r#"{"bind": "127.0.0.1:53"}"#).is_err(), "the v1 key is refused, not ignored");
    }
}
