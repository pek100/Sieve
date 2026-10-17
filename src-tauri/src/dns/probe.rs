//! Probe: asks a DNS server over UDP the way any client would. Used by the
//! self check (`dns_self_check`) and by the live check test, so the app and
//! the test judge the proxy with the same code.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use serde::Serialize;

use super::proxy::udp_exchange;
use super::rules::CANARY_NAME;

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

/// What a check tests. The TypeScript mirror is `CHECK_KINDS` in
/// src/data/protocol.ts (protocol law).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckKind {
    /// At least one block rule is loaded (asks no listener; `server` empty).
    Rules,
    /// The built-in canary gets the block answer on this listener.
    Canary,
    /// A normal name resolves through the upstreams via this listener.
    Resolve,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub kind: CheckKind,
    /// The address that was asked; empty for `Rules`.
    pub server: String,
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

const EXPECT_BLOCKED: &str = "NOERROR 0.0.0.0 (blocked)";
const EXPECT_RESOLVED: &str = "NOERROR with a real address";

/// The self check of a proxy listening on `servers` with `block_rules`
/// block rules loaded. On every listen address it asks for `CANARY_NAME`
/// (answered by the proxy itself, whatever the list holds, so the check is
/// the same on every machine and every list) and for `good` (a normal name,
/// forwarded to the upstreams). With no block rule loaded the filter would
/// block nothing, so that fails too. The canary never leaves the machine.
pub async fn self_check(servers: &[SocketAddr], block_rules: usize, good: &str) -> SelfCheck {
    let mut checks = Vec::with_capacity(2 * servers.len() + 1);
    if block_rules == 0 {
        checks.push(Check {
            kind: CheckKind::Rules,
            server: String::new(),
            name: String::new(),
            expect: "at least one block rule".to_owned(),
            got: "no block rule is loaded".to_owned(),
            pass: false,
        });
    }
    for &server in servers {
        checks.push(run(CheckKind::Canary, server, CANARY_NAME, EXPECT_BLOCKED, is_block_answer).await);
        checks.push(run(CheckKind::Resolve, server, good, EXPECT_RESOLVED, is_resolved).await);
    }
    // No server, no check: an empty list never passes.
    let pass = !servers.is_empty() && checks.iter().all(|c| c.pass);
    SelfCheck { pass, checks }
}

async fn run(kind: CheckKind, server: SocketAddr, name: &str, expect: &str, ok: fn(&Message) -> bool) -> Check {
    let (got, pass) = match query_a(server, name).await {
        Ok(m) => (describe(&m), ok(&m)),
        Err(e) => (format!("no answer: {e}"), false),
    };
    Check { kind, server: server.to_string(), name: name.to_owned(), expect: expect.to_owned(), got, pass }
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
            binds: vec!["127.0.0.1:0".parse().expect("addr")],
            upstreams: vec![upstream],
            upstream_timeout: Duration::from_millis(500),
        };
        Proxy::start(config, r).await.expect("start")
    }

    #[tokio::test]
    async fn self_check_passes_against_a_working_proxy() {
        let up = FakeUpstream::start(false).await;
        let proxy = proxy_with("||doubleclick.net^", up.addr).await;
        let got = self_check(proxy.local_addrs(), 1, "example.com").await;
        assert!(got.pass, "{got:?}");
        let kinds: Vec<CheckKind> = got.checks.iter().map(|c| c.kind).collect();
        assert_eq!(kinds, vec![CheckKind::Canary, CheckKind::Resolve]);
        assert_eq!(got.checks[0].name, CANARY_NAME);
        assert_eq!(got.checks[0].server, proxy.local_addr().to_string());
        assert_eq!(got.checks[0].got, "NOERROR 0.0.0.0");
        assert_eq!(got.checks[1].got, format!("NOERROR {FAKE_ANSWER}"));
        assert_eq!(proxy.stats().top_blocked, vec![], "the canary is not a blocked domain");
        proxy.stop().await;
    }

    #[tokio::test]
    async fn self_check_asks_every_listen_address_for_both_names() {
        let up = FakeUpstream::start(false).await;
        let mut r = RuleSet::new();
        r.add_text("||doubleclick.net^");
        let config = ProxyConfig {
            binds: vec!["127.0.0.1:0".parse().expect("addr"), "[::1]:0".parse().expect("addr")],
            upstreams: vec![up.addr],
            upstream_timeout: Duration::from_millis(500),
        };
        let proxy = Proxy::start(config, r).await.expect("start");
        let got = self_check(proxy.local_addrs(), 1, "example.com").await;
        assert!(got.pass, "{got:?}");
        let asked: Vec<(&str, CheckKind)> = got.checks.iter().map(|c| (c.server.as_str(), c.kind)).collect();
        let a = proxy.local_addrs()[0].to_string();
        let b = proxy.local_addrs()[1].to_string();
        assert_eq!(
            asked,
            vec![
                (a.as_str(), CheckKind::Canary),
                (a.as_str(), CheckKind::Resolve),
                (b.as_str(), CheckKind::Canary),
                (b.as_str(), CheckKind::Resolve),
            ],
        );
        let s = proxy.stats();
        assert_eq!((s.blocked, s.forwarded), (0, 2), "the canary is never counted; the normal name once per listener");
        proxy.stop().await;
    }

    #[tokio::test]
    async fn the_canary_passes_whatever_the_list_holds() {
        let up = FakeUpstream::start(false).await;
        // The real list's line that broke the old check: now never a rule.
        let proxy = proxy_with("-tototix.gif\n||doubleclick.net^\n@@||sieve.invalid^", up.addr).await;
        let got = self_check(proxy.local_addrs(), 1, "example.com").await;
        assert!(got.pass, "{got:?}");
        proxy.stop().await;
    }

    #[tokio::test]
    async fn self_check_fails_when_the_normal_name_does_not_resolve() {
        let up = FakeUpstream::start(false).await;
        let proxy = proxy_with("||doubleclick.net^", up.addr).await;
        let got = self_check(proxy.local_addrs(), 1, "doubleclick.net").await;
        assert!(!got.pass);
        assert!(got.checks[0].pass, "canary");
        assert!(!got.checks[1].pass, "a blocked name does not resolve");
        proxy.stop().await;
    }

    #[tokio::test]
    async fn self_check_fails_without_rules_or_without_a_server() {
        let up = FakeUpstream::start(false).await;
        let proxy = proxy_with("", up.addr).await;
        let got = self_check(proxy.local_addrs(), 0, "example.com").await;
        assert!(!got.pass);
        assert_eq!(got.checks[0].kind, CheckKind::Rules);
        assert_eq!((got.checks[0].server.as_str(), got.checks[0].pass), ("", false));
        assert!(got.checks[1..].iter().all(|c| c.pass), "the proxy itself works: {got:?}");
        let addr = proxy.local_addr();
        proxy.stop().await;
        let gone = self_check(&[addr], 1, "example.com").await;
        assert!(!gone.pass);
        assert!(gone.checks.iter().all(|c| c.got.starts_with("no answer")), "{gone:?}");
        assert!(!self_check(&[], 1, "example.com").await.pass, "no server never passes");
    }

    #[test]
    fn check_kinds_serialise_lower_case() {
        let v = serde_json::to_value([CheckKind::Rules, CheckKind::Canary, CheckKind::Resolve]).expect("json");
        assert_eq!(v, serde_json::json!(["rules", "canary", "resolve"]));
    }

    #[test]
    fn wildcard_bind_is_probed_on_loopback() {
        assert_eq!(loopback_for("0.0.0.0:53".parse().expect("a")), "127.0.0.1:53".parse().expect("a"));
        assert_eq!(loopback_for("[::]:53".parse().expect("a")), "[::1]:53".parse().expect("a"));
        assert_eq!(loopback_for("127.0.0.2:5353".parse().expect("a")), "127.0.0.2:5353".parse().expect("a"));
    }
}
