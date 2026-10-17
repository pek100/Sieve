//! The probe's pure parts: arguments, the enforce-test safety guard, the
//! per-flow log record and the summary counters with their text and JSON
//! renderings. The Windows side (adapter, routes, forwarder) is in
//! `src/bin/probe/`; nothing here touches the OS.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::Serialize;

use crate::classify::{Decoded, Kind};
use crate::flows::{Action, AppPolicy, Decision, Level, Reason};
use crate::rules::RuleSet;

pub const DEFAULT_SECONDS: u64 = 60;
pub const MAX_SECONDS: u64 = 600;
pub const DEFAULT_WINTUN_DLL: &str = r"E:\ml-tools\wintun\wintun\bin\amd64\wintun.dll";

/// Top-level domains reserved for tests (RFC 2606, RFC 6761). The
/// enforce test only ever drops names under one of these, so a typo can
/// never block a real site.
pub const RESERVED_TLDS: [&str; 4] = ["example", "test", "invalid", "localhost"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforceTest {
    /// The one domain that may be dropped (exact name or a subdomain).
    pub domain: String,
    /// The one exe it is dropped for (file name or full path).
    pub exe: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// The host whose address(es) get a /32 (/128) route into the TUN.
    pub route_host: String,
    /// Or explicit addresses instead of resolving `route_host`.
    pub route_ips: Vec<IpAddr>,
    pub seconds: u64,
    pub wintun_dll: PathBuf,
    pub out_dir: PathBuf,
    /// Optional adblock-syntax list for the observe-mode "would be" verdicts.
    pub rules_file: Option<PathBuf>,
    /// Apps exempted (level off) in observe mode.
    pub exempt: Vec<String>,
    pub enforce: Option<EnforceTest>,
    /// Where DNS (port 53) flows that enter the TUN are sent; None keeps
    /// their original destination (through the physical interface).
    pub dns_via: Option<std::net::SocketAddr>,
}

pub const USAGE: &str = "\
probe: Sieve Wintun spike. Routes ONE test host through a Wintun TUN, attributes
each flow to its app, decodes TLS SNI / HTTP Host / QUIC Initial SNI, logs the
verdict it would give and forwards everything (observe), or drops one test
domain for one exe (enforce test). Needs an elevated (admin) terminal.

  probe --route-host <name>          host to route through the TUN (resolved once)
        [--route-ip <ip>]...         or explicit IPv4/IPv6 addresses (repeatable)
        [--seconds <n>]              run time, default 60, max 600
        [--wintun-dll <path>]        default E:\\ml-tools\\wintun\\wintun\\bin\\amd64\\wintun.dll
        [--out <dir>]                report folder, default the current folder
        [--rules <file>]             adblock-syntax list for would-be verdicts
        [--exempt <exe>]...          apps set to off in observe mode
        [--dns-via <ip:port>]        send TUN DNS flows here (e.g. 127.0.0.1:53)
        [--enforce-test --block-domain <name> --block-exe <exe>]
                                     drop <name> (must end in .example, .test,
                                     .invalid or .localhost) for <exe> only
";

pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Args, String> {
    let mut it = args.into_iter();
    let mut a = Args {
        route_host: String::new(),
        route_ips: Vec::new(),
        seconds: DEFAULT_SECONDS,
        wintun_dll: PathBuf::from(DEFAULT_WINTUN_DLL),
        out_dir: PathBuf::from("."),
        rules_file: None,
        exempt: Vec::new(),
        enforce: None,
        dns_via: None,
    };
    let mut enforce = false;
    let mut block_domain = None;
    let mut block_exe = None;
    while let Some(flag) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match flag.as_str() {
            "--route-host" => a.route_host = value("--route-host")?,
            "--route-ip" => {
                let v = value("--route-ip")?;
                a.route_ips.push(v.parse().map_err(|_| format!("--route-ip: not an IP address: {v}"))?);
            }
            "--seconds" => {
                let v = value("--seconds")?;
                a.seconds = v.parse().map_err(|_| format!("--seconds: not a number: {v}"))?;
                if a.seconds == 0 || a.seconds > MAX_SECONDS {
                    return Err(format!("--seconds must be 1..={MAX_SECONDS}"));
                }
            }
            "--wintun-dll" => a.wintun_dll = value("--wintun-dll")?.into(),
            "--out" => a.out_dir = value("--out")?.into(),
            "--rules" => a.rules_file = Some(value("--rules")?.into()),
            "--exempt" => a.exempt.push(value("--exempt")?),
            "--dns-via" => {
                let v = value("--dns-via")?;
                a.dns_via = Some(v.parse().map_err(|_| format!("--dns-via: not ip:port: {v}"))?);
            }
            "--enforce-test" => enforce = true,
            "--block-domain" => block_domain = Some(value("--block-domain")?),
            "--block-exe" => block_exe = Some(value("--block-exe")?),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if a.route_host.is_empty() && a.route_ips.is_empty() {
        return Err("--route-host or --route-ip is required (the probe never routes everything)".into());
    }
    match (enforce, block_domain, block_exe) {
        (false, None, None) => {}
        (true, Some(d), Some(e)) => a.enforce = Some(EnforceTest { domain: checked_test_domain(&d)?, exe: e }),
        (true, _, _) => return Err("--enforce-test needs both --block-domain and --block-exe".into()),
        (false, _, _) => return Err("--block-domain/--block-exe only work with --enforce-test".into()),
    }
    Ok(a)
}

/// The enforce test's domain, lower case, if it is under a reserved TLD.
pub fn checked_test_domain(raw: &str) -> Result<String, String> {
    let d = crate::sni::host_name(raw.as_bytes()).ok_or_else(|| format!("not a host name: {raw}"))?;
    let tld = d.rsplit('.').next().unwrap_or_default();
    if d.contains('.') && RESERVED_TLDS.contains(&tld) {
        Ok(d)
    } else {
        Err(format!(
            "--block-domain must end in .{} (reserved test names), got {d}",
            RESERVED_TLDS.join(", .")
        ))
    }
}

/// Most host routes one run may add.
pub const MAX_ROUTES: usize = 8;

/// Refuses addresses that must never be routed into the test TUN: loopback,
/// unspecified, multicast, broadcast, link-local, private/ULA (the LAN
/// gateway, DNS server or a NAS live there), CGNAT (Tailscale and VPNs),
/// documentation, and the TUN's own benchmark range.
pub fn check_route_target(ip: IpAddr) -> Result<(), String> {
    let bad = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
                || v4.is_private()
                || v4.is_documentation()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] == 0
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xfe00) == 0xfc00
                || v6.to_ipv4_mapped().is_some()
                || (s[0] == 0x2001 && s[1] == 0x0db8)
        }
    };
    if bad { Err(format!("{ip} is not a public unicast address; refusing to route it into the TUN")) } else { Ok(()) }
}

/// The rules and per-app policy the run decides with.
pub fn policy_for(args: &Args, list_text: Option<&str>) -> (RuleSet, AppPolicy) {
    let mut rules = RuleSet::new();
    match &args.enforce {
        Some(e) => {
            rules.add_line(&format!("||{}^", e.domain));
            (rules, AppPolicy::new(Level::Off).set(&e.exe, Level::Sieve))
        }
        None => {
            if let Some(text) = list_text {
                rules.add_text(text);
            }
            let policy = args.exempt.iter().fold(AppPolicy::new(Level::Sieve), |p, e| p.set(e, Level::Off));
            (rules, policy)
        }
    }
}

/// One decided flow, as logged and reported.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FlowRecord {
    pub t_ms: u64,
    pub proto: &'static str,
    pub local: String,
    pub remote: String,
    pub pid: Option<u32>,
    pub exe: Option<String>,
    pub kind: Option<&'static str>,
    pub domain: Option<String>,
    pub alpn: Vec<String>,
    pub ech: bool,
    pub failure: Option<&'static str>,
    pub verdict: &'static str,
    pub reason: String,
    /// True when the verdict was applied (enforce test), false when only
    /// logged (observe).
    pub enforced: bool,
}

pub fn reason_label(r: Reason) -> String {
    match r {
        Reason::UnknownDomain => "unknown domain (passes)".into(),
        Reason::AppNotFiltered(l) => format!("app level {l:?} (not filtered)").to_lowercase(),
        Reason::Allowed => "allow rule".into(),
        Reason::NoRule => "no rule".into(),
        Reason::Blocked => "block rule".into(),
    }
}

impl FlowRecord {
    pub fn line(&self) -> String {
        let exe = self.exe.as_deref().map_or("?", |p| p.rsplit(['\\', '/']).next().unwrap_or(p));
        format!(
            "[{:>7.3}s] {:<4} pid={:<6} exe={:<22} kind={:<4} domain={:<32} ech={} verdict={}{} ({}){}",
            self.t_ms as f64 / 1000.0,
            self.proto,
            self.pid.map_or("?".into(), |p| p.to_string()),
            exe,
            self.kind.unwrap_or("-"),
            self.domain.as_deref().unwrap_or("-"),
            self.ech,
            self.verdict,
            if self.enforced { "" } else { " (would)" },
            self.reason,
            self.failure.map_or(String::new(), |f| format!(" failure={f}")),
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub fn record(
    t_ms: u64,
    proto: &'static str,
    local: std::net::SocketAddr,
    remote: std::net::SocketAddr,
    pid: Option<u32>,
    exe: Option<String>,
    d: &Decoded,
    decision: Decision,
    enforced: bool,
) -> FlowRecord {
    FlowRecord {
        t_ms,
        proto,
        local: local.to_string(),
        remote: remote.to_string(),
        pid,
        exe,
        kind: d.kind.map(Kind::label),
        domain: d.domain.clone(),
        alpn: d.alpn.clone(),
        ech: d.ech,
        failure: d.failure,
        verdict: match decision.action {
            Action::Pass => "pass",
            Action::Drop => "drop",
        },
        reason: reason_label(decision.reason),
        enforced,
    }
}

/// Summary counters.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Summary {
    pub flows: u64,
    pub tcp_flows: u64,
    pub udp_flows: u64,
    pub dns_flows: u64,
    pub attributed: u64,
    pub attributed_after_retry: u64,
    pub unattributed: u64,
    pub exe_unknown: u64,
    pub decoded: BTreeMap<String, u64>,
    pub ech: u64,
    pub no_domain: BTreeMap<String, u64>,
    pub would_drop: u64,
    pub dropped: u64,
    pub forwarder_errors: BTreeMap<String, u64>,
    pub tun_packets_in: u64,
    pub tun_packets_out: u64,
    pub table_reads: u64,
    pub table_read_errors: u64,
}

impl Summary {
    pub fn add(&mut self, r: &FlowRecord) {
        self.flows += 1;
        match r.proto {
            "tcp" => self.tcp_flows += 1,
            _ => self.udp_flows += 1,
        }
        if r.pid.is_some() {
            self.attributed += 1;
            if r.exe.is_none() {
                self.exe_unknown += 1;
            }
        } else {
            self.unattributed += 1;
        }
        match (&r.domain, r.kind) {
            (Some(_), Some(k)) => *self.decoded.entry(k.to_string()).or_default() += 1,
            _ => *self.no_domain.entry(r.failure.unwrap_or("unknown").to_string()).or_default() += 1,
        }
        if r.ech {
            self.ech += 1;
        }
        if r.verdict == "drop" {
            if r.enforced {
                self.dropped += 1;
            } else {
                self.would_drop += 1;
            }
        }
    }

    pub fn forwarder_error(&mut self, what: &str) {
        *self.forwarder_errors.entry(what.to_string()).or_default() += 1;
    }

    pub fn text(&self) -> String {
        let map = |m: &BTreeMap<String, u64>| {
            if m.is_empty() {
                "none".to_string()
            } else {
                m.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ")
            }
        };
        format!(
            "flows: {} (tcp {}, udp {}, dns {})\n\
             attributed to a pid: {} (after a table retry: {}), unattributed: {}, exe unreadable: {}\n\
             decoded domains by kind: {}\n\
             ECH offered (outer name only): {}\n\
             no domain, by reason: {}\n\
             would drop (observe): {}, dropped (enforce test): {}\n\
             forwarder errors: {}\n\
             TUN packets in/out: {}/{}, owner-table reads: {} (errors {})\n",
            self.flows,
            self.tcp_flows,
            self.udp_flows,
            self.dns_flows,
            self.attributed,
            self.attributed_after_retry,
            self.unattributed,
            self.exe_unknown,
            map(&self.decoded),
            self.ech,
            map(&self.no_domain),
            self.would_drop,
            self.dropped,
            map(&self.forwarder_errors),
            self.tun_packets_in,
            self.tun_packets_out,
            self.table_reads,
            self.table_read_errors,
        )
    }
}

/// The text shown when the probe is not elevated: the exact command to run
/// in an admin terminal. Arguments with spaces are quoted.
pub fn admin_command(exe: &str, args: &[String]) -> String {
    let q = |s: &str| if s.contains(' ') || s.is_empty() { format!("\"{s}\"") } else { s.to_string() };
    let mut out = format!("& {}", q(exe));
    for a in args {
        out.push(' ');
        out.push_str(&q(a));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flows::verdict;

    fn args(s: &str) -> Result<Args, String> {
        parse_args(s.split_whitespace().map(String::from))
    }

    #[test]
    fn route_host_is_required_and_defaults_apply() {
        assert!(args("").is_err());
        let a = args("--route-host example.com").unwrap();
        assert_eq!(a.seconds, 60);
        assert_eq!(a.enforce, None);
        assert_eq!(a.wintun_dll, PathBuf::from(DEFAULT_WINTUN_DLL));
        let a = args("--route-ip 93.184.215.14 --route-ip 2606:2800:21f:cb07:6820:80da:af6b:8b2c").unwrap();
        assert_eq!(a.route_ips.len(), 2);
    }

    #[test]
    fn enforce_test_needs_both_parts_and_a_reserved_domain() {
        let a = args("--route-host example.com --enforce-test --block-domain Sieve-Spike-Test.example --block-exe curl.exe")
            .unwrap();
        assert_eq!(a.enforce, Some(EnforceTest { domain: "sieve-spike-test.example".into(), exe: "curl.exe".into() }));
        assert!(args("--route-host example.com --enforce-test --block-domain a.example").is_err());
        assert!(args("--route-host example.com --block-domain a.example --block-exe curl.exe").is_err());
        for real in ["google.com", "example", "ads.doubleclick.net", "example.com"] {
            let e = args(&format!("--route-host x.com --enforce-test --block-domain {real} --block-exe curl.exe"));
            assert!(e.is_err(), "{real} must be refused");
        }
        for ok in ["a.test", "x.y.invalid", "spike.localhost"] {
            assert!(checked_test_domain(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn bad_values_are_refused() {
        assert!(args("--route-host x.com --seconds 0").is_err());
        assert!(args("--route-host x.com --seconds 601").is_err());
        assert!(args("--route-host x.com --route-ip nope").is_err());
        assert!(args("--route-host x.com --dns-via 127.0.0.1").is_err());
        assert!(args("--route-host x.com --bogus").is_err());
        assert!(args("--route-host").is_err());
        assert_eq!(args("--help"), Err(String::new()));
    }

    #[test]
    fn enforce_policy_drops_the_test_domain_for_the_one_exe_only() {
        let a = args("--route-host example.com --enforce-test --block-domain sieve-spike-test.example --block-exe curl.exe")
            .unwrap();
        let (rules, policy) = policy_for(&a, Some("||example.com^"));
        let curl = Some(r"C:\Windows\System32\curl.exe");
        let other = Some(r"C:\Temp\curl-other.exe");
        assert_eq!(verdict(Some("sieve-spike-test.example"), curl, &rules, &policy).action, Action::Drop);
        assert_eq!(verdict(Some("sieve-spike-test.example"), other, &rules, &policy).action, Action::Pass);
        assert_eq!(verdict(Some("sieve-spike-test.example"), None, &rules, &policy).action, Action::Pass);
        // The list file is ignored in enforce mode.
        assert_eq!(verdict(Some("example.com"), curl, &rules, &policy).action, Action::Pass);
    }

    #[test]
    fn observe_policy_uses_the_list_and_exemptions() {
        let a = args("--route-host x.com --exempt firefox.exe").unwrap();
        let (rules, policy) = policy_for(&a, Some("||ads.example^"));
        assert_eq!(verdict(Some("ads.example"), Some("chrome.exe"), &rules, &policy).action, Action::Drop);
        assert_eq!(verdict(Some("ads.example"), Some(r"C:\ff\firefox.exe"), &rules, &policy).action, Action::Pass);
    }

    #[test]
    fn summary_counts_and_text() {
        let d = Decoded { kind: Some(Kind::Tls), domain: Some("a.example".into()), alpn: vec![], ech: true, failure: None };
        let drop = Decision { action: Action::Drop, reason: Reason::Blocked };
        let pass = Decision { action: Action::Pass, reason: Reason::UnknownDomain };
        let l = "10.0.0.2:5000".parse().unwrap();
        let r = "1.1.1.1:443".parse().unwrap();
        let mut s = Summary::default();
        s.add(&record(1, "tcp", l, r, Some(7), Some("C:\\c.exe".into()), &d, drop, true));
        s.add(&record(2, "udp", l, r, None, None, &Decoded { failure: Some("not tls/quic/http"), ..Default::default() }, pass, false));
        assert_eq!((s.flows, s.tcp_flows, s.udp_flows, s.attributed, s.unattributed), (2, 1, 1, 1, 1));
        assert_eq!((s.ech, s.dropped, s.would_drop), (1, 1, 0));
        assert_eq!(s.decoded.get("tls"), Some(&1));
        assert_eq!(s.no_domain.get("not tls/quic/http"), Some(&1));
        let t = s.text();
        assert!(t.contains("decoded domains by kind: tls=1"), "{t}");
        let line = record(1, "tcp", l, r, Some(7), Some("C:\\x\\c.exe".into()), &d, drop, false).line();
        assert!(line.contains("exe=c.exe") && line.contains("verdict=drop (would)"), "{line}");
        assert!(serde_json::to_string(&s).unwrap().contains("\"dropped\":1"));
    }

    #[test]
    fn only_public_unicast_addresses_may_be_routed() {
        for ok in ["93.184.215.14", "1.1.1.1", "2606:4700::1111", "142.250.1.1"] {
            assert!(check_route_target(ok.parse().unwrap()).is_ok(), "{ok}");
        }
        for bad in [
            "127.0.0.1", "0.0.0.0", "10.0.0.1", "192.168.1.1", "172.16.5.5", "169.254.1.1", "100.64.0.1",
            "100.127.255.1", "198.18.211.1", "224.0.0.251", "255.255.255.255", "192.0.2.1", "240.0.0.1",
            "::1", "::", "fe80::1", "fd00::1", "ff02::1", "::ffff:8.8.8.8", "2001:db8::1",
        ] {
            assert!(check_route_target(bad.parse().unwrap()).is_err(), "{bad}");
        }
    }

    #[test]
    fn admin_command_quotes_spaces() {
        let c = admin_command(r"F:\a b\probe.exe", &["--route-host".into(), "example.com".into()]);
        assert_eq!(c, r#"& "F:\a b\probe.exe" --route-host example.com"#);
    }
}
