//! Validated encrypted resolver addresses and the narrow LAN-only exception.
//! No resolver connection or Windows setting is changed by this module.

use std::net::IpAddr;
use std::str::FromStr;
use std::future::Future;
use std::time::Duration;

use crate::route::prefix::Prefix;

pub const DEFAULTS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query",
];

pub const REQUEST_BUDGET: Duration = Duration::from_secs(2);
pub const MAX_UPSTREAMS: usize = 8;

/// Implementations verify TLS identity, bound reply size and validate the
/// DNS transaction before returning. Cancellation must discard any partly
/// read stream response before that connection can be reused.
pub trait Exchange {
    fn exchange(&self, upstream: &Upstream, query: &[u8]) -> impl Future<Output = Result<Vec<u8>, String>> + Send;
}

/// One absolute deadline covers all encrypted attempts. Each remaining
/// endpoint gets an equal share of the remaining time, so an unresponsive
/// first endpoint cannot consume the fallback's entire budget. There is
/// deliberately no plaintext fallback here.
pub async fn resolve<E: Exchange>(endpoints: &[Upstream], query: &[u8], exchange: &E) -> Result<Vec<u8>, String> {
    if endpoints.is_empty() || endpoints.len() > MAX_UPSTREAMS {
        return Err("configure between one and eight encrypted DNS upstreams".into());
    }
    let deadline = tokio::time::Instant::now() + REQUEST_BUDGET;
    let mut failures = Vec::new();
    for (index, endpoint) in endpoints.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() { break; }
        let share = remaining / (endpoints.len() - index) as u32;
        match tokio::time::timeout(share, exchange.exchange(endpoint, query)).await {
            Ok(Ok(reply)) => return Ok(reply),
            Ok(Err(error)) => failures.push(error),
            Err(_) => failures.push("encrypted DNS upstream timed out".into()),
        }
    }
    Err(format!("all encrypted DNS upstreams failed: {}", failures.join("; ")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind { Https, Tls, Quic }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub kind: Kind,
    /// DNS name for TLS verification, or an IP literal without brackets.
    pub host: String,
    pub port: u16,
    /// HTTP request target, including a configured query string; DoT/DoQ use none.
    pub request_target: Option<String>,
}

impl FromStr for Upstream {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        // URL parsers repair some whitespace and backslashes. Configuration
        // must reject those rather than silently select a different endpoint.
        if input.chars().any(|c| c.is_whitespace() || c.is_control() || c == '\\') {
            return Err("resolver address contains whitespace or a backslash".into());
        }
        let url = url::Url::parse(input).map_err(|_| "invalid resolver URL")?;
        let kind = match url.scheme() {
            "https" => Kind::Https,
            "tls" => Kind::Tls,
            "quic" => Kind::Quic,
            _ => return Err("resolver must use https://, tls:// or quic://".into()),
        };
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err("resolver credentials and fragments are not supported".into());
        }
        let host = match url.host().ok_or("resolver host is missing")? {
            url::Host::Domain(name) => crate::flow::sni::host_name(name.as_bytes())
                .ok_or("invalid resolver hostname")?,
            url::Host::Ipv4(ip) => ip.to_string(),
            url::Host::Ipv6(ip) => ip.to_string(),
        };
        let port = url.port().unwrap_or(if kind == Kind::Https {443} else {853});
        if port == 0 { return Err("resolver port must not be zero".into()); }
        let request_target = if kind == Kind::Https {
            let mut target = url.path().to_owned();
            if let Some(q) = url.query() { target.push('?'); target.push_str(q); }
            Some(target)
        } else {
            if !matches!(url.path(), "" | "/") || url.query().is_some() {
                return Err("TLS and QUIC resolvers take a host and optional port only".into());
            }
            None
        };
        Ok(Self {kind, host, port, request_target})
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitHorizon {
    suffix: String,
    server: IpAddr,
}

impl SplitHorizon {
    /// `lan_prefixes` must come from the adapter's live network tables.
    /// A public DNS address can never become a plaintext fallback, even
    /// when a caller accidentally supplies a default route as its LAN.
    pub fn new(suffix: &str, server: IpAddr, lan_prefixes: &[Prefix]) -> Option<Self> {
        let suffix = crate::flow::sni::host_name(suffix.as_bytes())?;
        let private = match server {
            IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
            IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00 == 0xfc00) || (ip.segments()[0] & 0xffc0 == 0xfe80),
        };
        (private && lan_prefixes.iter().any(|p| p.contains(server))).then_some(Self {suffix, server})
    }
}

/// Match only exact suffixes or complete child labels, longest suffix first.
/// No matching configured LAN suffix means encrypted DNS, including when
/// every encrypted upstream is unavailable.
pub fn split_server(name: &str, rules: &[SplitHorizon]) -> Option<IpAddr> {
    let name = crate::flow::sni::host_name(name.as_bytes())?;
    rules.iter().filter(|r| name == r.suffix || name.strip_suffix(&r.suffix).is_some_and(|p| p.ends_with('.')))
        .max_by_key(|r| r.suffix.len()).map(|r| r.server)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FirstNeverAnswers;
    impl Exchange for FirstNeverAnswers {
        async fn exchange(&self, upstream: &Upstream, _: &[u8]) -> Result<Vec<u8>, String> {
            if upstream.host == "cloudflare-dns.com" { std::future::pending().await }
            else { Ok(vec![1, 2, 3]) }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_unresponsive_primary_leaves_time_for_the_second_upstream() {
        let endpoints: Vec<Upstream> = DEFAULTS.iter().map(|s| s.parse().unwrap()).collect();
        let start = tokio::time::Instant::now();
        assert_eq!(resolve(&endpoints, &[0], &FirstNeverAnswers).await.unwrap(), vec![1, 2, 3]);
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        assert!(start.elapsed() < REQUEST_BUDGET);
    }

    #[tokio::test(start_paused = true)]
    async fn all_timeouts_share_one_deadline_and_do_not_fall_back_to_plaintext() {
        let endpoint: Upstream = DEFAULTS[0].parse().unwrap();
        let start = tokio::time::Instant::now();
        assert!(resolve(&[endpoint.clone(), endpoint], &[0], &FirstNeverAnswers).await.is_err());
        assert_eq!(start.elapsed(), REQUEST_BUDGET);
        assert!(resolve(&[], &[0], &FirstNeverAnswers).await.is_err());
    }

    #[test]
    fn accepts_only_encrypted_kinds_and_preserves_tls_identity() {
        for value in DEFAULTS { assert_eq!(value.parse::<Upstream>().unwrap().kind, Kind::Https); }
        let dot: Upstream = "tls://dns.example:8853".parse().unwrap();
        assert_eq!((dot.kind, dot.host.as_str(), dot.port), (Kind::Tls, "dns.example", 8853));
        let doq: Upstream = "quic://[2001:db8::1]".parse().unwrap();
        assert_eq!((doq.kind, doq.host.as_str(), doq.port), (Kind::Quic, "2001:db8::1", 853));
        let doh: Upstream = "https://dns.example/dns-query?profile=1".parse().unwrap();
        assert_eq!(doh.request_target.as_deref(), Some("/dns-query?profile=1"));
    }

    #[test]
    fn refuses_plaintext_ambiguous_or_unsupported_addresses() {
        for bad in ["1.1.1.1", "udp://1.1.1.1", "http://dns.example/dns-query", "https://u:p@dns.example/", "https://dns.example/#fragment", "https://dns.example:0/", "tls://dns.example/path", "quic://dns.example?x=1", "https://dns.example\\other", " https://dns.example/", "https://dns.\nexample/"] {
            assert!(bad.parse::<Upstream>().is_err(), "{bad}");
        }
    }

    #[test]
    fn split_horizon_cannot_leak_names_to_a_public_or_unrelated_server() {
        let lan = ["192.168.7.0/24".parse().unwrap()];
        let rule = SplitHorizon::new("corp.example", "192.168.7.1".parse().unwrap(), &lan).unwrap();
        assert!(SplitHorizon::new("corp.example", "192.168.8.1".parse().unwrap(), &lan).is_none());
        assert!(SplitHorizon::new("corp.example", "8.8.8.8".parse().unwrap(), &["0.0.0.0/0".parse().unwrap()]).is_none());
        assert!(SplitHorizon::new("corp.example", "127.0.0.1".parse().unwrap(), &["127.0.0.0/8".parse().unwrap()]).is_none());
        assert_eq!(split_server("host.CORP.example", std::slice::from_ref(&rule)), Some(rule.server));
        assert_eq!(split_server("notcorp.example", std::slice::from_ref(&rule)), None);
        assert_eq!(split_server("corp.example.attacker.test", &[rule]), None);
    }

    #[test]
    fn the_most_specific_configured_suffix_wins() {
        let lan = ["10.0.0.0/8".parse().unwrap()];
        let broad = SplitHorizon::new("corp.example", "10.0.0.1".parse().unwrap(), &lan).unwrap();
        let narrow = SplitHorizon::new("dev.corp.example", "10.0.0.2".parse().unwrap(), &lan).unwrap();
        assert_eq!(split_server("api.dev.corp.example", &[narrow.clone(), broad]), Some(narrow.server));
    }
}
