//! The encrypted resolver list, its failover, and the narrow LAN-only
//! exception. No Windows setting is read for writing or written here.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use super::{question_names, reverse};
use crate::route::plan;
use crate::route::prefix::Prefix;
use crate::route::table::{Adapter, NetTables};

/// One default resolver: where it is, and its addresses, so reaching it never
/// asks plain DNS (or the DNS it is about to serve).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultResolver {
    pub url: &'static str,
    pub ips: &'static [&'static str],
}

/// The plan's resolvers, in the order they are tried (plan 1.4).
pub const DEFAULTS: &[DefaultResolver] = &[
    DefaultResolver {
        url: "https://cloudflare-dns.com/dns-query",
        ips: &["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
    },
    DefaultResolver {
        url: "https://dns.quad9.net/dns-query",
        ips: &["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
    },
];

/// A resolver whose addresses are known without a lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolver {
    pub upstream: Upstream,
    pub ips: Vec<IpAddr>,
}

/// [`DEFAULTS`] as data. Their parsing is pinned by a test.
pub fn known_resolvers() -> Result<Vec<Resolver>, String> {
    DEFAULTS
        .iter()
        .map(|d| {
            let ips = d.ips.iter().map(|ip| ip.parse().map_err(|e| format!("{ip}: {e}"))).collect::<Result<_, String>>()?;
            Ok(Resolver { upstream: d.url.parse()?, ips })
        })
        .collect()
}

const HTTPS_PORT: u16 = 443;
/// DoT (RFC 7858) and DoQ (RFC 9250) share it, on TCP and UDP.
const DNS_TLS_PORT: u16 = 853;

pub const REQUEST_BUDGET: Duration = Duration::from_secs(2);
pub const MAX_UPSTREAMS: usize = 8;
/// An upstream that just failed is tried after the healthy ones this long,
/// so a dead first upstream does not add its share to every lookup. It is
/// still tried when they fail, so recovery needs no probe.
pub const FAILED_COOLDOWN: Duration = Duration::from_secs(30);

/// Implementations verify TLS identity, bound reply size and validate the
/// DNS transaction before returning. Cancellation must discard any partly
/// read stream response before that connection can be reused.
pub trait Exchange {
    fn exchange(&self, upstream: &Upstream, query: &[u8]) -> impl Future<Output = Result<Vec<u8>, String>> + Send;
}

/// Which endpoints (by position in the list) failed recently.
#[derive(Debug, Default)]
pub struct Health {
    cooling_until: Mutex<HashMap<usize, Instant>>,
}

impl Health {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<usize, Instant>> {
        self.cooling_until.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The order to try `count` endpoints: configured order, the ones in their
    /// cooldown after the others.
    fn order(&self, count: usize) -> Vec<usize> {
        let now = Instant::now();
        let mut cooling = self.lock();
        cooling.retain(|_, until| *until > now);
        let (healthy, failed): (Vec<usize>, Vec<usize>) = (0..count).partition(|i| !cooling.contains_key(i));
        [healthy, failed].concat()
    }

    fn failed(&self, index: usize) {
        self.lock().insert(index, Instant::now() + FAILED_COOLDOWN);
    }

    fn answered(&self, index: usize) {
        self.lock().remove(&index);
    }
}

/// One absolute deadline covers all encrypted attempts. Each remaining
/// endpoint gets an equal share of the remaining time, so an unresponsive
/// first endpoint cannot consume the fallback's entire budget. There is
/// deliberately no plaintext fallback here.
pub async fn resolve<E: Exchange>(endpoints: &[Upstream], query: &[u8], exchange: &E, health: &Health) -> Result<Vec<u8>, String> {
    if endpoints.is_empty() || endpoints.len() > MAX_UPSTREAMS {
        return Err(format!("configure between one and {MAX_UPSTREAMS} encrypted DNS upstreams"));
    }
    let deadline = Instant::now() + REQUEST_BUDGET;
    let mut failures = Vec::new();
    for (tried, index) in health.order(endpoints.len()).into_iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { break; }
        let share = remaining / (endpoints.len() - tried) as u32;
        match tokio::time::timeout(share, exchange.exchange(&endpoints[index], query)).await {
            Ok(Ok(reply)) => {
                health.answered(index);
                return Ok(reply);
            }
            Ok(Err(error)) => failures.push(error),
            Err(_) => failures.push("encrypted DNS upstream timed out".into()),
        }
        health.failed(index);
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

impl Kind {
    fn default_port(self) -> u16 {
        if self == Kind::Https { HTTPS_PORT } else { DNS_TLS_PORT }
    }
}

/// The address as a URL: the DoH request URI (a default port is left out, so
/// `:authority` is the name a server's virtual host expects), and the one form
/// reports use.
impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self.kind { Kind::Https => "https", Kind::Tls => "tls", Kind::Quic => "quic" };
        if self.host.contains(':') {
            write!(f, "{scheme}://[{}]", self.host)?;
        } else {
            write!(f, "{scheme}://{}", self.host)?;
        }
        if self.port != self.kind.default_port() {
            write!(f, ":{}", self.port)?;
        }
        f.write_str(self.request_target.as_deref().unwrap_or(""))
    }
}

impl FromStr for Upstream {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        // URL parsers repair some whitespace and backslashes. Configuration
        // must reject those rather than silently select a different endpoint.
        if input.chars().any(|c| c.is_whitespace() || c.is_control() || c == '\\') {
            return Err("resolver address contains whitespace or a backslash".into());
        }
        // The same repair: `https:x` and `https:///x` both parse to the host `x`.
        let authority = input.split_once(':').and_then(|(_, rest)| rest.strip_prefix("//"));
        if authority.is_none_or(|rest| rest.starts_with('/')) {
            return Err("resolver address must name its host right after ://".into());
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
        let port = url.port().unwrap_or(kind.default_port());
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
    /// None: the adapter's only servers cannot be reached from here, so the
    /// suffix's names have nowhere to go but must not go public.
    server: Option<IpAddr>,
}

/// Where one query goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// To this LAN server and nowhere else.
    Lan(IpAddr),
    /// Nowhere: SERVFAIL, because it may be a LAN name and has no LAN server.
    Refused,
    /// A private reverse name with no LAN server to ask: answered here.
    NoServer,
    /// To the encrypted upstreams: nothing in it is a LAN name.
    Encrypted,
}

impl SplitHorizon {
    /// `lan_prefixes` must come from the adapter's live network tables.
    /// A public DNS address can never become a plaintext fallback, even
    /// when a caller accidentally supplies a default route as its LAN.
    pub fn new(suffix: &str, server: IpAddr, lan_prefixes: &[Prefix]) -> Option<Self> {
        let suffix = crate::flow::sni::host_name(suffix.as_bytes())?;
        private_inside(server, lan_prefixes).then_some(Self { suffix, server: Some(server) })
    }

    /// A suffix whose adapter has no server this engine can reach.
    fn unreachable(suffix: &str) -> Option<Self> {
        Some(Self { suffix: crate::flow::sni::host_name(suffix.as_bytes())?, server: None })
    }

    /// True for the suffix itself and for complete child labels, ASCII
    /// case-insensitive, whatever octets the other labels hold.
    fn covers(&self, labels: &[Vec<u8>]) -> bool {
        let suffix = self.suffix.split('.').rev();
        suffix.clone().count() <= labels.len() && suffix.zip(labels.iter().rev()).all(|(want, label)| label.eq_ignore_ascii_case(want.as_bytes()))
    }
}

/// True for a private address inside these prefixes.
fn private_inside(server: IpAddr, prefixes: &[Prefix]) -> bool {
    let private = match server {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00 == 0xfc00) || (ip.segments()[0] & 0xffc0 == 0xfe80),
    };
    private && prefixes.iter().any(|p| p.contains(server))
}

/// An adapter's first DNS server that plain DNS may reach: private, inside a
/// hole, not a link-local IPv6 one (its address has no scope, and pinning refuses
/// a link-local source).
fn lan_server(adapter: &Adapter, holes: &[Prefix]) -> Option<IpAddr> {
    adapter.dns.iter().copied().find(|ip| !is_v6_link_local(*ip) && private_inside(*ip, holes))
}

/// The most specific rule over a name, longest suffix first. Between two equal
/// suffixes one with a server wins, whatever the adapter order: a second adapter
/// with only a link-local server must not refuse a name another one can answer.
fn rule_for<'a>(labels: &[Vec<u8>], rules: &'a [SplitHorizon]) -> Option<&'a SplitHorizon> {
    rules.iter().filter(|r| r.covers(labels)).max_by_key(|r| (r.suffix.len(), r.server.is_some()))
}

/// Where a query goes, read from the wire and not from what the evidence parser
/// accepts. A query with no name under a suffix goes encrypted, including when
/// every encrypted upstream is unavailable. One whose names all have the same
/// LAN server goes there. Anything that might carry a LAN name and has no one
/// server for it is refused: the public upstream would publish that name. With
/// no rules at all there is no LAN name to protect, and an unreadable query goes
/// encrypted, opaque.
pub fn split_route(query: &[u8], rules: &[SplitHorizon]) -> Path {
    if rules.is_empty() {
        return Path::Encrypted;
    }
    let Some(names) = question_names(query) else { return Path::Refused };
    let mut matched = names.iter().map(|labels| rule_for(labels, rules));
    let Some(first) = matched.next() else { return Path::Encrypted };
    if matched.any(|other| other.map(|r| r.server) != first.map(|r| r.server)) {
        return Path::Refused;
    }
    match first {
        None => Path::Encrypted,
        Some(SplitHorizon { server: Some(server), .. }) => Path::Lan(*server),
        Some(_) => Path::Refused,
    }
}

/// The rules these tables imply, computed per query (few adapters, no cache):
/// each suffix of each other up adapter, with [`lan_server`].
/// When such servers are all the adapter has, its suffix still holds, with no
/// server. A public server is another matter: an ISP's or a router's suffix under
/// a public domain resolves publicly, so that suffix makes no rule.
pub fn split_rules(tables: &NetTables) -> Vec<SplitHorizon> {
    let holes = plan::holes(tables);
    let mut rules = Vec::new();
    for adapter in tables.others() {
        let only_link_local = !adapter.dns.is_empty() && adapter.dns.iter().all(|ip| is_v6_link_local(*ip));
        let server = lan_server(adapter, &holes);
        for suffix in &adapter.dns_suffixes {
            let qualifying = server.and_then(|server| SplitHorizon::new(suffix, server, &holes));
            rules.extend(qualifying.or_else(|| only_link_local.then(|| SplitHorizon::unreachable(suffix)).flatten()));
        }
    }
    rules
}

fn is_v6_link_local(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80)
}

/// The route of a query, `name` being its one question as [`parse`](super::parse)
/// reads it. A configured suffix wins. A private reverse name goes
/// to the server of the adapter whose on-link prefix holds the address, else to
/// the first server of any other adapter, and never to the public upstream.
pub fn path_of(query: &[u8], name: Option<&str>, tables: &NetTables) -> Path {
    let configured = split_route(query, &split_rules(tables));
    if configured != Path::Encrypted {
        return configured;
    }
    let Some(address) = name.and_then(reverse::private_address) else { return Path::Encrypted };
    let holes = plan::holes(tables);
    let holds_address = |a: &&Adapter| a.addresses.iter().filter_map(|addr| addr.on_link()).any(|p| p.contains(address));
    let covering = tables.others().filter(holds_address).find_map(|a| lan_server(a, &holes));
    covering.or_else(|| tables.others().find_map(|a| lan_server(a, &holes))).map_or(Path::NoServer, Path::Lan)
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

    fn defaults() -> Vec<Upstream> {
        DEFAULTS.iter().map(|d| d.url.parse().unwrap()).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn an_unresponsive_primary_leaves_time_for_the_second_upstream() {
        let endpoints = defaults();
        let start = Instant::now();
        assert_eq!(resolve(&endpoints, &[0], &FirstNeverAnswers, &Health::default()).await.unwrap(), vec![1, 2, 3]);
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        assert!(start.elapsed() < REQUEST_BUDGET);
    }

    #[tokio::test(start_paused = true)]
    async fn all_timeouts_share_one_deadline_and_do_not_fall_back_to_plaintext() {
        let endpoint = defaults().remove(0);
        let start = Instant::now();
        let health = Health::default();
        assert!(resolve(&[endpoint.clone(), endpoint], &[0], &FirstNeverAnswers, &health).await.is_err());
        assert_eq!(start.elapsed(), REQUEST_BUDGET);
        assert!(resolve(&[], &[0], &FirstNeverAnswers, &health).await.is_err());
    }

    /// Answers from the hosts it holds, fails the rest, and records the order.
    struct Scripted {
        up: Mutex<Vec<String>>,
        tried: Mutex<Vec<String>>,
    }

    impl Scripted {
        fn with(up: &[&str]) -> Self {
            Self { up: Mutex::new(up.iter().map(|s| s.to_string()).collect()), tried: Mutex::default() }
        }

        fn take_tried(&self) -> Vec<String> {
            std::mem::take(&mut *self.tried.lock().unwrap())
        }
    }

    impl Exchange for Scripted {
        async fn exchange(&self, upstream: &Upstream, _: &[u8]) -> Result<Vec<u8>, String> {
            self.tried.lock().unwrap().push(upstream.host.clone());
            if self.up.lock().unwrap().contains(&upstream.host) { Ok(vec![1]) } else { Err("down".into()) }
        }
    }

    fn named(hosts: &[&str]) -> Vec<Upstream> {
        hosts.iter().map(|h| format!("tls://{h}").parse().unwrap()).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_upstream_is_tried_after_healthy_ones_during_its_cooldown_then_first_again() {
        let list = named(&["one.test", "two.test"]);
        let fake = Scripted::with(&["two.test"]);
        let health = Health::default();
        resolve(&list, &[0], &fake, &health).await.unwrap();
        assert_eq!(fake.take_tried(), ["one.test", "two.test"]);
        resolve(&list, &[0], &fake, &health).await.unwrap();
        assert_eq!(fake.take_tried(), ["two.test"], "the failed one waits its cooldown");
        tokio::time::advance(FAILED_COOLDOWN + Duration::from_millis(1)).await;
        *fake.up.lock().unwrap() = vec!["one.test".into(), "two.test".into()];
        resolve(&list, &[0], &fake, &health).await.unwrap();
        assert_eq!(fake.take_tried(), ["one.test"], "first again after the cooldown");
    }

    #[tokio::test(start_paused = true)]
    async fn a_cooling_upstream_is_still_tried_when_the_healthy_ones_fail() {
        let list = named(&["one.test", "two.test"]);
        let fake = Scripted::with(&["two.test"]);
        let health = Health::default();
        resolve(&list, &[0], &fake, &health).await.unwrap();
        fake.take_tried();
        *fake.up.lock().unwrap() = vec!["one.test".into()];
        resolve(&list, &[0], &fake, &health).await.unwrap();
        assert_eq!(fake.take_tried(), ["two.test", "one.test"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_cooldown_changes_order_and_never_the_two_second_guarantee() {
        // The only answering upstream is cooling, and the silent one goes first.
        let list = defaults();
        let health = Health::default();
        health.failed(1);
        let start = Instant::now();
        assert!(resolve(&list, &[0], &FirstNeverAnswers, &health).await.is_ok());
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    #[test]
    fn every_default_parses_and_all_its_addresses_parse() {
        let known = known_resolvers().unwrap();
        assert_eq!(known.len(), DEFAULTS.len());
        for resolver in &known {
            assert_eq!(resolver.upstream.kind, Kind::Https, "DoH by default");
            assert!(!resolver.ips.is_empty());
            assert!(resolver.ips.iter().all(|ip| !ip.is_loopback()));
        }
    }

    #[test]
    fn the_display_form_parses_back_to_the_same_upstream() {
        for address in ["https://dns.example/dns-query?profile=1", "tls://dns.example:8853", "quic://[2001:db8::1]", "https://[2001:db8::1]:8443/q", "tls://192.0.2.1"] {
            let upstream: Upstream = address.parse().unwrap();
            assert_eq!(upstream.to_string().parse::<Upstream>().unwrap(), upstream, "{address}");
        }
        let doh: Upstream = "https://dns.example:443/dns-query".parse().unwrap();
        assert_eq!(doh.to_string(), "https://dns.example/dns-query", "the authority a virtual host expects");
        let dot: Upstream = "tls://dns.example:853".parse().unwrap();
        assert_eq!(dot.to_string(), "tls://dns.example");
    }

    #[test]
    fn accepts_only_encrypted_kinds_and_preserves_tls_identity() {
        for value in DEFAULTS { assert_eq!(value.url.parse::<Upstream>().unwrap().kind, Kind::Https); }
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
        let server: IpAddr = "192.168.7.1".parse().unwrap();
        let rule = SplitHorizon::new("corp.example", server, &lan).unwrap();
        assert!(SplitHorizon::new("corp.example", "192.168.8.1".parse().unwrap(), &lan).is_none());
        assert!(SplitHorizon::new("corp.example", "8.8.8.8".parse().unwrap(), &["0.0.0.0/0".parse().unwrap()]).is_none());
        assert!(SplitHorizon::new("corp.example", "127.0.0.1".parse().unwrap(), &["127.0.0.0/8".parse().unwrap()]).is_none());
        assert_eq!(route_of("host.CORP.example", std::slice::from_ref(&rule)), Path::Lan(server));
        assert_eq!(route_of("notcorp.example", std::slice::from_ref(&rule)), Path::Encrypted);
        assert_eq!(route_of("corp.example.attacker.test", &[rule]), Path::Encrypted);
    }

    #[test]
    fn the_most_specific_configured_suffix_wins() {
        let lan = ["10.0.0.0/8".parse().unwrap()];
        let broad = SplitHorizon::new("corp.example", "10.0.0.1".parse().unwrap(), &lan).unwrap();
        let narrow = SplitHorizon::new("dev.corp.example", "10.0.0.2".parse().unwrap(), &lan).unwrap();
        assert_eq!(route_of("api.dev.corp.example", &[narrow, broad]), Path::Lan("10.0.0.2".parse().unwrap()));
    }

    /// A query with these names, as raw labels.
    fn wire_query(names: &[&[&[u8]]]) -> Vec<u8> {
        let mut q = vec![0, 1, 1, 0, 0, names.len() as u8, 0, 0, 0, 0, 0, 0];
        for labels in names {
            for label in *labels {
                q.push(label.len() as u8);
                q.extend_from_slice(label);
            }
            q.extend_from_slice(&[0, 0, 1, 0, 1]);
        }
        q
    }

    #[test]
    fn the_route_is_read_from_the_wire_not_from_what_the_parser_accepts() {
        let server: IpAddr = "192.168.7.1".parse().unwrap();
        let lan_prefix = ["192.168.7.0/24".parse().unwrap()];
        let rules = [SplitHorizon::new("lan", server, &lan_prefix).unwrap()];
        const NON_ASCII: &[u8] = b"\xc3\xa9";
        let under: &[&[u8]] = &[NON_ASCII, b"LAN"];
        let also_under: &[&[u8]] = &[b"b", b"lan"];
        let elsewhere: &[&[u8]] = &[NON_ASCII, b"example"];

        let one = wire_query(&[under]);
        assert!(crate::dns::parse(&one).is_none(), "the parser refuses it");
        assert_eq!(split_route(&one, &rules), Path::Lan(server), "and it stays on the LAN");
        assert_eq!(split_route(&wire_query(&[under, also_under]), &rules), Path::Lan(server), "several questions, one server");
        assert_eq!(split_route(&wire_query(&[elsewhere]), &rules), Path::Encrypted);
        assert_eq!(split_route(&wire_query(&[under, elsewhere]), &rules), Path::Refused, "the questions disagree");
        assert_eq!(split_route(&wire_query(&[]), &rules), Path::Encrypted, "no name to protect");

        let mut cut = wire_query(&[under]);
        cut.truncate(cut.len() - 6);
        assert_eq!(split_route(&cut, &rules), Path::Refused, "it cannot be walked");
        assert_eq!(split_route(&cut, &[]), Path::Encrypted, "with no rule there is no LAN name");
    }

    fn with_suffix(tables: &mut NetTables, alias: &str, suffix: &str) {
        let adapter = tables.adapters.iter_mut().find(|a| a.alias == alias).unwrap();
        adapter.dns_suffixes.push(suffix.into());
    }

    fn route_of(name: &str, rules: &[SplitHorizon]) -> Path {
        split_route(&crate::dns::query_for(name, crate::dns::TYPE_A).unwrap(), rules)
    }

    fn path_for(name: &str, tables: &NetTables) -> Path {
        path_of(&crate::dns::query_for(name, crate::dns::TYPE_A).unwrap(), Some(name), tables)
    }

    const ROUTER_REVERSE: &str = "7.168.192.in-addr.arpa";

    fn wifi(tables: &mut NetTables) -> &mut Adapter {
        tables.adapters.iter_mut().find(|a| a.alias == "Wi-Fi").unwrap()
    }

    #[test]
    fn a_private_reverse_name_goes_to_the_adapter_that_covers_it() {
        use crate::route::table::fixtures::*;
        let router = "192.168.7.1".parse().unwrap();
        assert_eq!(path_for(ROUTER_REVERSE, &load(HOME)), Path::Lan(router));
        // Another adapter holds the address and has its own private server.
        let mut two = load(HOME);
        let default_switch = two.adapters.iter_mut().find(|a| a.alias.starts_with("vEthernet")).unwrap();
        let on_link = default_switch.addresses[0].on_link().unwrap();
        let other_dns = on_link.addr();
        default_switch.dns = vec![other_dns];
        let octets = match on_link.addr() {
            IpAddr::V4(ip) => ip.octets(),
            IpAddr::V6(_) => panic!("the fixture's first address is IPv4"),
        };
        let name = format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);
        assert_eq!(path_for(&name, &two), Path::Lan(other_dns));
        assert_eq!(path_for(ROUTER_REVERSE, &two), Path::Lan(router), "each to its own");
    }

    #[test]
    fn with_no_covering_adapter_any_adapters_private_server_answers() {
        use crate::route::table::fixtures::*;
        assert_eq!(path_for("5.0.0.10.in-addr.arpa", &load(HOME)), Path::Lan("192.168.7.1".parse().unwrap()));
    }

    #[test]
    fn with_no_private_server_a_private_reverse_name_has_no_path() {
        use crate::route::table::fixtures::*;
        let others_empty = |dns: Vec<IpAddr>| {
            let mut t = load(HOME);
            wifi(&mut t).dns = dns;
            t
        };
        for dns in [vec!["8.8.8.8".parse().unwrap()], vec!["fe80::1".parse().unwrap()], vec![]] {
            assert_eq!(path_for(ROUTER_REVERSE, &others_empty(dns.clone())), Path::NoServer, "{dns:?}");
        }
    }

    #[test]
    fn public_names_go_encrypted() {
        use crate::route::table::fixtures::*;
        for name in ["www.example", "8.8.8.8.in-addr.arpa", "192.in-addr.arpa", "in-addr.arpa", "example.arpa"] {
            assert_eq!(path_for(name, &load(HOME)), Path::Encrypted, "{name}");
        }
    }

    #[test]
    fn a_configured_suffix_wins_over_the_reverse_rule() {
        use crate::route::table::fixtures::*;
        let mut tables = load(HOME);
        let default_switch = tables.adapters.iter_mut().find(|a| a.alias.starts_with("vEthernet")).unwrap();
        let server = default_switch.addresses[0].on_link().unwrap().addr();
        default_switch.dns = vec![server];
        default_switch.dns_suffixes = vec!["168.192.in-addr.arpa".into()];
        assert_eq!(path_for(ROUTER_REVERSE, &tables), Path::Lan(server), "not the Wi-Fi router, which covers the address");
    }

    #[test]
    fn rules_derive_from_adapter_suffixes_and_only_excluded_private_servers_qualify() {
        use crate::route::table::fixtures::*;
        let lan: IpAddr = "192.168.7.1".parse().unwrap();
        // The home network: the router's server qualifies.
        let mut home = load(HOME);
        assert!(split_rules(&home).is_empty(), "no suffix, no rule");
        with_suffix(&mut home, "Wi-Fi", "lan");
        let rules = split_rules(&home);
        assert_eq!(route_of("router.lan", &rules), Path::Lan(lan));
        assert_eq!(route_of("router.example", &rules), Path::Encrypted);

        // A public server, even in a public hole, qualifies nothing.
        let mut public = load(VPN_SPLIT);
        let vpn = public.adapters.iter_mut().find(|a| a.alias == "Corp VPN").unwrap();
        vpn.dns = vec!["203.0.113.53".parse().unwrap()];
        vpn.dns_suffixes = vec!["corp.example".into()];
        assert!(plan::holes(&public).iter().any(|p| p.contains("203.0.113.53".parse().unwrap())), "it is a hole");
        assert_eq!(route_of("a.corp.example", &split_rules(&public)), Path::Encrypted);

        // A link-local IPv6 server is skipped, a later private one is taken.
        // With nothing else, the suffix's names are refused: they never go public.
        let mut scoped = load(HOME);
        let wifi = scoped.adapters.iter_mut().find(|a| a.alias == "Wi-Fi").unwrap();
        wifi.dns = vec!["fe80::1".parse().unwrap()];
        wifi.dns_suffixes = vec!["lan".into()];
        assert_eq!(route_of("router.lan", &split_rules(&scoped)), Path::Refused);
        assert_eq!(route_of("router.example", &split_rules(&scoped)), Path::Encrypted);
        scoped.adapters.iter_mut().find(|a| a.alias == "Wi-Fi").unwrap().dns.push(lan);
        assert_eq!(route_of("router.lan", &split_rules(&scoped)), Path::Lan(lan));

        // Two adapters with one suffix: the one with a reachable server answers,
        // in either order.
        let lan_rule = SplitHorizon { suffix: "lan".to_string(), server: Some(lan) };
        let no_server = SplitHorizon::unreachable("lan").unwrap();
        assert_eq!(route_of("router.lan", &[lan_rule.clone(), no_server.clone()]), Path::Lan(lan));
        assert_eq!(route_of("router.lan", &[no_server, lan_rule]), Path::Lan(lan));

        // A link-local server beside a public one: the suffix resolves publicly.
        let mut mixed = load(HOME);
        let wifi = mixed.adapters.iter_mut().find(|a| a.alias == "Wi-Fi").unwrap();
        wifi.dns = vec!["fe80::1".parse().unwrap(), "8.8.8.8".parse().unwrap()];
        wifi.dns_suffixes = vec!["lan".into()];
        assert!(split_rules(&mixed).is_empty());

        // A public server the plan routes does not qualify.
        let mut routed = load(HOME);
        routed.adapters.iter_mut().find(|a| a.alias == "Wi-Fi").unwrap().dns = vec!["8.8.8.8".parse().unwrap()];
        with_suffix(&mut routed, "Wi-Fi", "lan");
        assert!(split_rules(&routed).is_empty());

        // Sieve's own adapter contributes none.
        let mut own = load(SIEVE_UP);
        let sieve = own.adapters.iter_mut().find(|a| a.alias == "Sieve").unwrap();
        sieve.dns = vec![lan];
        sieve.dns_suffixes = vec!["sieve.example".into()];
        assert!(split_rules(&own).is_empty());
    }
}
