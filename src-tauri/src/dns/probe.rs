//! Probe: asks a DNS server over UDP the way any client would. Used by the
//! self check (`dns_self_check`) and by the live check test, so the app and
//! the test judge the proxy with the same code.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use serde::Serialize;

use super::proxy::udp_exchange;

/// A name that exists and is not on any ad list.
pub const KNOWN_GOOD_NAME: &str = "example.com";
/// How long one probe query may take (a forwarded one includes upstream).
pub const PROBE_TIMEOUT_MS: u64 = 5_000;

/// One A query to `server`. A wildcard bind address is asked on loopback.
pub async fn query_a(server: SocketAddr, name: &str) -> Result<Message, String> {
    let target = loopback_for(server);
    let mut msg = Message::query();
    msg.metadata.recursion_desired = true;
    let fqdn = Name::from_ascii(format!("{}.", name.trim_end_matches('.')))
        .map_err(|e| format!("bad name {name}: {e}"))?;
    msg.add_query(Query::query(fqdn, RecordType::A));
    let id = msg.metadata.id;
    let bytes = msg.to_vec().map_err(|e| e.to_string())?;
    let reply =
        udp_exchange(target, &bytes, id, Duration::from_millis(PROBE_TIMEOUT_MS)).await?;
    Message::from_vec(&reply).map_err(|e| format!("bad reply: {e}"))
}

fn loopback_for(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => (Ipv4Addr::LOCALHOST, addr.port()).into(),
        IpAddr::V6(ip) if ip.is_unspecified() => (Ipv6Addr::LOCALHOST, addr.port()).into(),
        _ => addr,
    }
}

/// The IPv4 answers of a reply.
pub fn a_records(m: &Message) -> Vec<Ipv4Addr> {
    m.answers
        .iter()
        .filter_map(|r| match r.data.ip_addr() {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        })
        .collect()
}

/// True when `m` is the proxy's block answer for an A query.
pub fn is_block_answer(m: &Message) -> bool {
    m.metadata.response_code == ResponseCode::NoError && a_records(m) == [Ipv4Addr::UNSPECIFIED]
}

/// True when `m` resolved to at least one real address.
pub fn is_resolved(m: &Message) -> bool {
    m.metadata.response_code == ResponseCode::NoError
        && a_records(m).iter().any(|ip| !ip.is_unspecified())
}

/// What a reply said, for people: `NOERROR 0.0.0.0` or `SERVFAIL (no records)`.
pub fn describe(m: &Message) -> String {
    let ips: Vec<String> = a_records(m).iter().map(Ipv4Addr::to_string).collect();
    // Debug of the variant (NoError, ServFail, NXDomain) upper-cased is the
    // conventional mnemonic (NOERROR, SERVFAIL, NXDOMAIN).
    let code = format!("{:?}", m.metadata.response_code).to_uppercase();
    if ips.is_empty() { format!("{code} (no records)") } else { format!("{code} {}", ips.join(", ")) }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: String,
    pub expect: String,
    pub got: String,
    pub pass: bool,
}

/// Self check result: `pass` is true only when every check passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SelfCheck {
    pub pass: bool,
    pub checks: Vec<Check>,
}

/// Asks the proxy at `server` for `blocked` (a name its rules block) and
/// for `good` (expected to resolve through the upstreams).
pub async fn self_check(server: SocketAddr, blocked: Option<String>, good: &str) -> SelfCheck {
    let blocked_check = match blocked {
        Some(name) => run(server, &name, "NOERROR 0.0.0.0 (blocked)", is_block_answer).await,
        None => Check {
            name: String::new(),
            expect: "NOERROR 0.0.0.0 (blocked)".to_owned(),
            got: "no block rule is loaded".to_owned(),
            pass: false,
        },
    };
    let good_check = run(server, good, "NOERROR with a real address", is_resolved).await;
    let checks = vec![blocked_check, good_check];
    SelfCheck { pass: checks.iter().all(|c| c.pass), checks }
}

async fn run(server: SocketAddr, name: &str, expect: &str, ok: fn(&Message) -> bool) -> Check {
    let (got, pass) = match query_a(server, name).await {
        Ok(m) => (describe(&m), ok(&m)),
        Err(e) => (format!("no answer: {e}"), false),
    };
    Check { name: name.to_owned(), expect: expect.to_owned(), got, pass }
}

#[cfg(test)]
mod tests {
    use super::super::proxy::tests::{FAKE_ANSWER, FakeUpstream};
    use super::super::proxy::{Proxy, ProxyConfig};
    use super::super::rules::RuleSet;
    use super::*;

    async fn proxy_with(rules: &str, upstream: SocketAddr) -> Proxy {
        let mut r = RuleSet::new();
        r.add_text(rules);
        let config = ProxyConfig {
            bind: "127.0.0.1:0".parse().expect("addr"),
            upstreams: vec![upstream],
            upstream_timeout: Duration::from_millis(500),
        };
        Proxy::start(config, r).await.expect("start")
    }

    #[tokio::test]
    async fn self_check_passes_against_a_working_proxy() {
        let up = FakeUpstream::start(false).await;
        let proxy = proxy_with("||doubleclick.net^", up.addr).await;
        let rules = proxy.rules().read().expect("lock").clone();
        let got = self_check(proxy.local_addr(), rules.sample_blocked(), "example.com").await;
        assert!(got.pass, "{got:?}");
        assert_eq!(got.checks[0].name, "doubleclick.net");
        assert_eq!(got.checks[0].got, "NOERROR 0.0.0.0");
        assert_eq!(got.checks[1].got, format!("NOERROR {FAKE_ANSWER}"));
        proxy.stop().await;
    }

    #[tokio::test]
    async fn self_check_fails_when_the_name_is_not_blocked() {
        let up = FakeUpstream::start(false).await;
        let proxy = proxy_with("||doubleclick.net^", up.addr).await;
        let got = self_check(proxy.local_addr(), Some("not-blocked.example".into()), "example.com").await;
        assert!(!got.pass);
        assert!(!got.checks[0].pass);
        assert!(got.checks[1].pass);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn self_check_fails_without_rules_or_without_a_server() {
        let up = FakeUpstream::start(false).await;
        let proxy = proxy_with("", up.addr).await;
        let got = self_check(proxy.local_addr(), None, "example.com").await;
        assert!(!got.pass);
        let addr = proxy.local_addr();
        proxy.stop().await;
        let gone = self_check(addr, Some("doubleclick.net".into()), "example.com").await;
        assert!(!gone.pass);
        assert!(gone.checks.iter().all(|c| c.got.starts_with("no answer")), "{gone:?}");
    }

    #[test]
    fn wildcard_bind_is_probed_on_loopback() {
        assert_eq!(loopback_for("0.0.0.0:53".parse().expect("a")), "127.0.0.1:53".parse().expect("a"));
        assert_eq!(loopback_for("[::]:53".parse().expect("a")), "[::1]:53".parse().expect("a"));
        assert_eq!(loopback_for("127.0.0.2:5353".parse().expect("a")), "127.0.0.2:5353".parse().expect("a"));
    }
}
