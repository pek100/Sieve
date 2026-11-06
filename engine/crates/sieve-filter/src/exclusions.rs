//! The HTTPS exclusion syntax (plan E10 and 4.1): what is never decrypted.
//!
//! One entry per line:
//! - `bank.example`            the host and every subdomain;
//! - `"login.bank.example"`    that host only (quoted means exact);
//! - `*.cdn.example`, `pay*.example`  `*` matches any run of host characters,
//!   the whole host must match;
//! - `192.0.2.7`, `2001:db8::7`  one IP address;
//! - any of the above with `$app=a.exe|b.exe`: only for those executables
//!   (file names, case-insensitive);
//! - `// comment` lines and blank lines are ignored.
//!
//! A line that does not parse is skipped and counted with its reason, never
//! guessed. Safety asymmetry (S24, plan 4.1): an exclusion can only cause a
//! pass-through, so where a fact is missing the matcher errs toward
//! excluding (an app-limited entry matches a flow whose exe is unknown).

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;

const COMMENT: &str = "//";
const APP_MODIFIER: &str = "app=";
const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Pattern {
    /// The host and its subdomains.
    Subdomains(String),
    /// Exactly this host.
    Exact(String),
    /// A host glob with `*`.
    Wildcard(String),
    Ip(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exclusion {
    pub pattern: Pattern,
    /// Lower-case exe file names; empty means every app.
    pub apps: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SkipReason {
    BadHost,
    UnterminatedQuote,
    WildcardInExact,
    UnknownModifier,
    EmptyAppList,
    BadAppName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// 1-based line number.
    pub line: usize,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    pub entries: Vec<Exclusion>,
    pub skipped: Vec<Skipped>,
}

/// Parses a whole exclusion file.
pub fn parse(text: &str) -> Parsed {
    let mut out = Parsed::default();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(COMMENT) {
            continue;
        }
        match parse_line(line) {
            Ok(e) => out.entries.push(e),
            Err(reason) => out.skipped.push(Skipped { line: i + 1, reason }),
        }
    }
    out
}

/// Parses one non-comment line.
pub fn parse_line(line: &str) -> Result<Exclusion, SkipReason> {
    let (body, modifier) = match line.split_once('$') {
        Some((b, m)) => (b.trim(), Some(m.trim())),
        None => (line, None),
    };
    let apps = match modifier {
        None => Vec::new(),
        Some(m) => parse_apps(m)?,
    };
    Ok(Exclusion { pattern: parse_pattern(body)?, apps })
}

fn parse_apps(modifier: &str) -> Result<Vec<String>, SkipReason> {
    let list = modifier.strip_prefix(APP_MODIFIER).ok_or(SkipReason::UnknownModifier)?;
    if list.trim().is_empty() {
        return Err(SkipReason::EmptyAppList);
    }
    list.split('|')
        .map(|a| {
            let a = a.trim().to_ascii_lowercase();
            let valid = !a.is_empty() && !a.contains(['\\', '/', ' ', '*', '$', '"']);
            if valid { Ok(a) } else { Err(SkipReason::BadAppName) }
        })
        .collect()
}

fn parse_pattern(body: &str) -> Result<Pattern, SkipReason> {
    if let Some(rest) = body.strip_prefix('"') {
        let host = rest.strip_suffix('"').ok_or(SkipReason::UnterminatedQuote)?;
        if host.contains('*') {
            return Err(SkipReason::WildcardInExact);
        }
        return host_name(host, false).map(Pattern::Exact);
    }
    if body.ends_with('"') {
        return Err(SkipReason::UnterminatedQuote);
    }
    if let Ok(ip) = body.parse::<IpAddr>() {
        return Ok(Pattern::Ip(ip));
    }
    if body.contains('*') {
        return host_name(body, true).map(Pattern::Wildcard);
    }
    host_name(body, false).map(Pattern::Subdomains)
}

/// A lower-case host name (or host glob when `glob`): labels of a-z, 0-9,
/// `-` and `_`, no empty label, no leading or trailing `-`, one trailing dot
/// dropped. Anything else (spaces, non-ASCII, ports, paths) is refused.
fn host_name(raw: &str, glob: bool) -> Result<String, SkipReason> {
    let host = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= MAX_LABEL_LEN
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || (glob && b == b'*'))
    };
    if host.is_empty() || host.len() > MAX_HOST_LEN || !host.split('.').all(label_ok) {
        return Err(SkipReason::BadHost);
    }
    Ok(host)
}

/// `*` matches any run (also empty) of characters in `text`.
fn glob_match(glob: &str, text: &str) -> bool {
    let parts: Vec<&str> = glob.split('*').collect();
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if parts.len() == 1 {
        return glob == text;
    }
    if !text.starts_with(first) || !text[first.len()..].ends_with(last) || text.len() < first.len() + last.len() {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

impl Exclusion {
    /// True when this entry excludes a flow to `host` (lower case, as
    /// decoded) or to `ip`, made by `exe` (full path or file name; None when
    /// unknown).
    pub fn matches(&self, host: Option<&str>, ip: Option<IpAddr>, exe: Option<&str>) -> bool {
        let target = match (&self.pattern, host) {
            (Pattern::Ip(want), _) => ip == Some(*want),
            (Pattern::Exact(h), Some(host)) => host == h,
            (Pattern::Subdomains(h), Some(host)) => {
                host == h || host.strip_suffix(h.as_str()).is_some_and(|p| p.ends_with('.'))
            }
            (Pattern::Wildcard(g), Some(host)) => glob_match(g, host),
            (_, None) => false,
        };
        target && self.app_matches(exe)
    }

    fn app_matches(&self, exe: Option<&str>) -> bool {
        let Some(exe) = exe else { return true };
        if self.apps.is_empty() {
            return true;
        }
        let name = exe.rsplit(['\\', '/']).next().unwrap_or(exe).to_ascii_lowercase();
        self.apps.contains(&name)
    }
}

// ---- The one decision (plan 4.1, task D11): pure, no I/O, no clock, no Windows.

/// TLDs reserved for vetted institutions (plan 4.1).
pub const RESTRICTED_TLDS: [&str; 4] = ["gov", "mil", "bank", "insurance"];
/// The label before the TLD of a government public suffix: `gov.uk`, `gouv.fr`,
/// `gob.mx`, `govt.nz`, `go.jp`, `gv.at` (plan 4.1, `exclusions.governmentLabels`).
pub const GOVERNMENT_LABELS: [&str; 6] = ["gov", "gouv", "gob", "govt", "go", "gv"];
/// The ALPN values interception speaks over TCP (plan 2.8).
pub const HTTP_ALPN: [&str; 2] = ["h2", "http/1.1"];
/// The ALPN value a QUIC flow would have to carry to be HTTP/3 (plan section 3).
pub const QUIC_ALPN: [&str; 1] = ["h3"];
/// With no ALPN at all a TCP flow is only taken on these ports (plan 2.8).
pub const NO_ALPN_PORTS: [u16; 2] = [443, 8443];

/// How a flow travels: the ALPN floor asks for what that transport carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Quic,
}

/// How far decryption reaches today (the user's decision: browsers first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Browsers,
    All,
}

/// What upstream validation said (plan 2.6). `Eligible` is the only one that
/// lets a flow go on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamVerdict {
    Eligible,
    NonPublicRoot,
    Invalid,
    Revoked,
    /// The trust call did not answer in time. Never cached.
    Unavailable,
    /// The upstream handshake failed: it needs less than rustls offers.
    Protocol,
}

/// An entry the engine wrote itself (plan 4.1's table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutoReason {
    Pinning,
    ClientCert,
    Ev,
}

impl AutoReason {
    pub const ALL: [Self; 3] = [Self::Pinning, Self::ClientCert, Self::Ev];

    fn slug(self) -> &'static str {
        match self {
            Self::Pinning => "auto:pinning",
            Self::ClientCert => "auto:client-cert",
            Self::Ev => "auto:ev",
        }
    }
}

/// Facts that forbid decryption whatever any list says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Floor {
    /// A VM's or WSL's flow.
    Forwarded,
    /// No exe or no session known: never a guess (S24).
    UnknownApp,
    /// Session 0: Windows services.
    Service,
    /// Browsers first: Windows does not declare this exe a browser.
    AppScope,
    /// No installed, in-date root to mint from.
    NoRoot,
    NoExclusionList,
    NoSni,
    /// A real ECH cannot be ruled out (task D9).
    Ech,
    Alpn,
    /// The client or the server needs what rustls does not speak.
    Protocol,
    RestrictedSuffix,
    NonPublicRoot,
    UpstreamInvalid,
    UpstreamRevoked,
    UpstreamUnavailable,
}

impl Floor {
    /// Every floor fact, for the coverage law and the property tests.
    pub const ALL: [Self; 15] = [
        Self::Forwarded,
        Self::UnknownApp,
        Self::Service,
        Self::AppScope,
        Self::NoRoot,
        Self::NoExclusionList,
        Self::NoSni,
        Self::Ech,
        Self::Alpn,
        Self::Protocol,
        Self::RestrictedSuffix,
        Self::NonPublicRoot,
        Self::UpstreamInvalid,
        Self::UpstreamRevoked,
        Self::UpstreamUnavailable,
    ];

    fn slug(self) -> &'static str {
        match self {
            Self::Forwarded => "floor:forwarded",
            Self::UnknownApp => "floor:unknown-app",
            Self::Service => "floor:service",
            Self::AppScope => "floor:app-scope",
            Self::NoRoot => "floor:no-root",
            Self::NoExclusionList => "floor:no-exclusion-list",
            Self::NoSni => "floor:no-sni",
            Self::Ech => "floor:ech",
            Self::Alpn => "floor:alpn",
            Self::Protocol => "floor:protocol",
            Self::RestrictedSuffix => "floor:restricted-suffix",
            Self::NonPublicRoot => "floor:non-public-root",
            Self::UpstreamInvalid => "floor:upstream-invalid",
            Self::UpstreamRevoked => "floor:upstream-revoked",
            Self::UpstreamUnavailable => "floor:upstream-unavailable",
        }
    }
}

/// Where a stored entry came from. Reported in this order of precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    User,
    List(String),
    Auto(AutoReason),
}

impl Source {
    fn rank(&self) -> u8 {
        match self {
            Self::User => 0,
            Self::List(_) => 1,
            Self::Auto(_) => 2,
        }
    }
}

/// Why a flow is not decrypted. Every pass-through carries one to the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassReason {
    /// `filtering.https` is off.
    SwitchOff,
    Floor(Floor),
    Stored(Source),
    /// The app's row is Off (plan 4.4).
    AppOff,
}

impl PassReason {
    /// The word the log and the UI read: `floor:service`, `list:banks`, `auto:pinning`.
    pub fn slug(&self) -> Cow<'_, str> {
        match self {
            Self::SwitchOff => Cow::Borrowed("off"),
            Self::Floor(f) => Cow::Borrowed(f.slug()),
            Self::Stored(Source::User) => Cow::Borrowed("user"),
            Self::Stored(Source::List(id)) => Cow::Owned(format!("list:{id}")),
            Self::Stored(Source::Auto(a)) => Cow::Borrowed(a.slug()),
            Self::AppOff => Cow::Borrowed("app_off"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decrypt {
    Intercept,
    PassThrough(PassReason),
}

/// What is known about one flow. `upstream: None` means "not known yet":
/// `Intercept` then means "eligible, go and ask".
#[derive(Debug, Clone, Copy)]
pub struct FlowFacts<'a> {
    pub transport: Transport,
    /// `Owner::may_decrypt`.
    pub may_decrypt: bool,
    pub exe: Option<&'a str>,
    pub session: Option<u32>,
    pub host: Option<&'a str>,
    pub ip: IpAddr,
    pub port: u16,
    pub alpn: &'a [String],
    pub ech: bool,
    /// The client shares a version, a suite and a group with rustls.
    pub client_compatible: bool,
    /// Windows declares this exe a browser.
    pub app_in_scope: bool,
    pub app_off: bool,
    pub upstream: Option<UpstreamVerdict>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Switches {
    pub https: bool,
    pub root_ready: bool,
    /// Every enabled exclusion source has loaded once.
    pub lists_ready: bool,
    /// `https.skipEv` (plan 2.6): constant true until a UI shows it (S35).
    pub skip_ev: bool,
    pub scope: Scope,
}

/// True for a host under a suffix reserved for vetted institutions: a
/// restricted TLD, or a known public suffix of two or more labels whose label
/// before the TLD is a government one. So `go.jp` is caught, and `go.com` and
/// `gov.example` are not.
pub fn restricted_suffix(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.rsplit('.').next().is_some_and(|tld| RESTRICTED_TLDS.contains(&tld)) {
        return true;
    }
    let Some(suffix) = psl::suffix(host.as_bytes()).filter(|s| s.is_known()) else { return false };
    let Ok(text) = std::str::from_utf8(suffix.as_bytes()) else { return false };
    text.rsplit('.').nth(1).is_some_and(|label| GOVERNMENT_LABELS.contains(&label))
}

fn alpn_floor(facts: &FlowFacts<'_>) -> bool {
    let offered = |wanted: &[&str]| facts.alpn.iter().any(|a| wanted.contains(&a.as_str()));
    match facts.transport {
        Transport::Quic => !offered(&QUIC_ALPN),
        Transport::Tcp if facts.alpn.is_empty() => !NO_ALPN_PORTS.contains(&facts.port),
        Transport::Tcp => !offered(&HTTP_ALPN),
    }
}

fn floor(facts: &FlowFacts<'_>, switches: &Switches) -> Option<Floor> {
    if !facts.may_decrypt {
        return Some(Floor::Forwarded);
    }
    if facts.exe.is_none() || facts.session.is_none() {
        return Some(Floor::UnknownApp);
    }
    if facts.session == Some(0) {
        return Some(Floor::Service);
    }
    if switches.scope == Scope::Browsers && !facts.app_in_scope {
        return Some(Floor::AppScope);
    }
    if !switches.root_ready {
        return Some(Floor::NoRoot);
    }
    if !switches.lists_ready {
        return Some(Floor::NoExclusionList);
    }
    let Some(host) = facts.host else { return Some(Floor::NoSni) };
    if facts.ech {
        return Some(Floor::Ech);
    }
    if alpn_floor(facts) {
        return Some(Floor::Alpn);
    }
    if !facts.client_compatible {
        return Some(Floor::Protocol);
    }
    if restricted_suffix(host) {
        return Some(Floor::RestrictedSuffix);
    }
    match facts.upstream? {
        UpstreamVerdict::Eligible => None,
        UpstreamVerdict::NonPublicRoot => Some(Floor::NonPublicRoot),
        UpstreamVerdict::Invalid => Some(Floor::UpstreamInvalid),
        UpstreamVerdict::Revoked => Some(Floor::UpstreamRevoked),
        UpstreamVerdict::Unavailable => Some(Floor::UpstreamUnavailable),
        UpstreamVerdict::Protocol => Some(Floor::Protocol),
    }
}

/// The one function (plan 4.1): switch, floor, store, app Off, intercept. No
/// list can reach past the floor (S24): an entry can only add a pass-through.
pub fn decrypt(facts: &FlowFacts<'_>, store: &ExclusionSet, switches: &Switches) -> Decrypt {
    if !switches.https {
        return Decrypt::PassThrough(PassReason::SwitchOff);
    }
    if let Some(fact) = floor(facts, switches) {
        return Decrypt::PassThrough(PassReason::Floor(fact));
    }
    if let Some(source) = store.find(facts.host, facts.ip, facts.exe, switches.skip_ev) {
        return Decrypt::PassThrough(PassReason::Stored(source.clone()));
    }
    if facts.app_off {
        return Decrypt::PassThrough(PassReason::AppOff);
    }
    Decrypt::Intercept
}

/// One entry and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stored {
    entry: Exclusion,
    source: Source,
}

/// One snapshot of the store (plan 4.1), read once per flow: hosts are indexed
/// by the name they carry, so a lookup walks the flow's own suffixes however
/// long the lists are; globs and IPs are scanned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExclusionSet {
    hosts: HashMap<String, Vec<Stored>>,
    scanned: Vec<Stored>,
    len: usize,
}

impl ExclusionSet {
    /// Adds entries from one source.
    pub fn add(&mut self, entries: impl IntoIterator<Item = Exclusion>, source: &Source) {
        for entry in entries {
            self.len += 1;
            let stored = Stored { entry, source: source.clone() };
            match &stored.entry.pattern {
                Pattern::Subdomains(h) | Pattern::Exact(h) => self.hosts.entry(h.clone()).or_default().push(stored),
                Pattern::Wildcard(_) | Pattern::Ip(_) => self.scanned.push(stored),
            }
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The source of the highest-ranked entry matching this flow. `auto:ev`
    /// only counts while `skip_ev` holds.
    pub fn find(&self, host: Option<&str>, ip: IpAddr, exe: Option<&str>, skip_ev: bool) -> Option<&Source> {
        let lower = host.map(str::to_ascii_lowercase);
        let host = lower.as_deref();
        let suffixes = std::iter::successors(host, |h| h.split_once('.').map(|(_, rest)| rest));
        suffixes
            .filter_map(|s| self.hosts.get(s))
            .flatten()
            .chain(&self.scanned)
            .filter(|s| (skip_ev || s.source != Source::Auto(AutoReason::Ev)) && s.entry.matches(host, Some(ip), exe))
            .map(|s| &s.source)
            .min_by_key(|s| s.rank())
    }
}

#[cfg(test)]
mod decrypt_tests {
    use super::*;
    use proptest::prelude::*;

    const CHROME: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    const HOST: &str = "news.example";

    fn alpn() -> Vec<String> {
        vec!["h2".to_string(), "http/1.1".to_string()]
    }

    fn switches() -> Switches {
        Switches { https: true, root_ready: true, lists_ready: true, skip_ev: true, scope: Scope::Browsers }
    }

    fn ip() -> IpAddr {
        "192.0.2.1".parse().unwrap()
    }

    /// A flow with no floor fact, no entry and Eligible upstream.
    fn base(alpn: &[String]) -> FlowFacts<'_> {
        FlowFacts {
            transport: Transport::Tcp,
            may_decrypt: true,
            exe: Some(CHROME),
            session: Some(1),
            host: Some(HOST),
            ip: ip(),
            port: 443,
            alpn,
            ech: false,
            client_compatible: true,
            app_in_scope: true,
            app_off: false,
            upstream: Some(UpstreamVerdict::Eligible),
        }
    }

    const NO_ALPN_FOR_HTTP: [&str; 1] = ["acme-tls/1"];

    /// The facts and switches with exactly this floor fact set.
    fn with_floor<'a>(fact: Floor, alpn: &'a [String], bad_alpn: &'a [String]) -> (FlowFacts<'a>, Switches) {
        let (mut f, mut s) = (base(alpn), switches());
        match fact {
            Floor::Forwarded => f.may_decrypt = false,
            Floor::UnknownApp => f.session = None,
            Floor::Service => f.session = Some(0),
            Floor::AppScope => f.app_in_scope = false,
            Floor::NoRoot => s.root_ready = false,
            Floor::NoExclusionList => s.lists_ready = false,
            Floor::NoSni => f.host = None,
            Floor::Ech => f.ech = true,
            Floor::Alpn => f.alpn = bad_alpn,
            Floor::Protocol => f.client_compatible = false,
            Floor::RestrictedSuffix => f.host = Some("service.gov.uk"),
            Floor::NonPublicRoot => f.upstream = Some(UpstreamVerdict::NonPublicRoot),
            Floor::UpstreamInvalid => f.upstream = Some(UpstreamVerdict::Invalid),
            Floor::UpstreamRevoked => f.upstream = Some(UpstreamVerdict::Revoked),
            Floor::UpstreamUnavailable => f.upstream = Some(UpstreamVerdict::Unavailable),
        }
        (f, s)
    }

    fn store_of(text: &str, auto: &[(Exclusion, AutoReason)]) -> ExclusionSet {
        let mut set = ExclusionSet::default();
        set.add(parse(text).entries, &Source::List("fuzz".into()));
        for (entry, reason) in auto {
            set.add([entry.clone()], &Source::Auto(*reason));
        }
        set
    }

    fn line(host: &str) -> Exclusion {
        parse_line(host).unwrap()
    }

    #[test]
    fn a_flow_with_no_floor_fact_and_an_empty_store_intercepts() {
        let alpn = alpn();
        assert_eq!(decrypt(&base(&alpn), &ExclusionSet::default(), &switches()), Decrypt::Intercept);
        assert_eq!(decrypt(&FlowFacts { upstream: None, ..base(&alpn) }, &ExclusionSet::default(), &switches()), Decrypt::Intercept, "not known yet: go and ask");
    }

    #[test]
    fn every_pass_reason_is_reachable_and_has_a_slug() {
        let (alpn, bad) = (alpn(), vec![NO_ALPN_FOR_HTTP[0].to_string()]);
        let empty = ExclusionSet::default();
        let mut slugs = Vec::new();
        for fact in Floor::ALL {
            let (f, s) = with_floor(fact, &alpn, &bad);
            let Decrypt::PassThrough(reason) = decrypt(&f, &empty, &s) else { panic!("{fact:?} intercepted") };
            assert_eq!(reason, PassReason::Floor(fact));
            slugs.push(reason.slug().into_owned());
        }
        let stored = [Source::User, Source::List("banks".into()), Source::Auto(AutoReason::Pinning), Source::Auto(AutoReason::ClientCert), Source::Auto(AutoReason::Ev)];
        for source in &stored {
            let mut set = ExclusionSet::default();
            set.add([line(HOST)], source);
            let Decrypt::PassThrough(reason) = decrypt(&base(&alpn), &set, &switches()) else { panic!("{source:?} intercepted") };
            assert_eq!(reason, PassReason::Stored(source.clone()));
            slugs.push(reason.slug().into_owned());
        }
        assert_eq!(decrypt(&base(&alpn), &empty, &Switches { https: false, ..switches() }), Decrypt::PassThrough(PassReason::SwitchOff));
        slugs.push(PassReason::SwitchOff.slug().into_owned());
        assert_eq!(decrypt(&FlowFacts { app_off: true, ..base(&alpn) }, &empty, &switches()), Decrypt::PassThrough(PassReason::AppOff));
        slugs.push(PassReason::AppOff.slug().into_owned());
        let mut unique = slugs.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), slugs.len(), "no two reasons share a slug: {slugs:?}");
        assert!(slugs.contains(&"list:banks".to_string()) && slugs.contains(&"auto:pinning".to_string()) && slugs.contains(&"floor:service".to_string()));
        assert_eq!(AutoReason::ALL.len(), 3);
    }

    #[test]
    fn evaluation_order_is_floor_store_app_off() {
        let alpn = alpn();
        let mut set = ExclusionSet::default();
        set.add([line(HOST)], &Source::User);
        let both = FlowFacts { session: Some(0), app_off: true, ..base(&alpn) };
        assert_eq!(decrypt(&both, &set, &switches()), Decrypt::PassThrough(PassReason::Floor(Floor::Service)), "floor first");
        let stored_and_off = FlowFacts { app_off: true, ..base(&alpn) };
        assert_eq!(decrypt(&stored_and_off, &set, &switches()), Decrypt::PassThrough(PassReason::Stored(Source::User)), "store before Off");
        assert_eq!(decrypt(&stored_and_off, &ExclusionSet::default(), &switches()), Decrypt::PassThrough(PassReason::AppOff));
        assert_eq!(decrypt(&both, &set, &Switches { https: false, ..switches() }), Decrypt::PassThrough(PassReason::SwitchOff), "the switch before all");
    }

    #[test]
    fn forwarded_is_never_intercepted() {
        let alpn = alpn();
        for scope in [Scope::Browsers, Scope::All] {
            let f = FlowFacts { may_decrypt: false, ..base(&alpn) };
            assert_eq!(decrypt(&f, &ExclusionSet::default(), &Switches { scope, ..switches() }), Decrypt::PassThrough(PassReason::Floor(Floor::Forwarded)));
        }
    }

    #[test]
    fn session_zero_and_unknown_session_never_intercept() {
        let alpn = alpn();
        let at = |session| decrypt(&FlowFacts { session, ..base(&alpn) }, &ExclusionSet::default(), &Switches { scope: Scope::All, ..switches() });
        assert_eq!(at(Some(0)), Decrypt::PassThrough(PassReason::Floor(Floor::Service)));
        assert_eq!(at(None), Decrypt::PassThrough(PassReason::Floor(Floor::UnknownApp)));
    }

    #[test]
    fn unknown_exe_never_intercepts() {
        let alpn = alpn();
        let f = FlowFacts { exe: None, ..base(&alpn) };
        assert_eq!(decrypt(&f, &ExclusionSet::default(), &Switches { scope: Scope::All, ..switches() }), Decrypt::PassThrough(PassReason::Floor(Floor::UnknownApp)));
    }

    #[test]
    fn non_browser_is_out_of_scope() {
        let alpn = alpn();
        let f = FlowFacts { app_in_scope: false, ..base(&alpn) };
        assert_eq!(decrypt(&f, &ExclusionSet::default(), &switches()), Decrypt::PassThrough(PassReason::Floor(Floor::AppScope)));
        assert_eq!(decrypt(&f, &ExclusionSet::default(), &Switches { scope: Scope::All, ..switches() }), Decrypt::Intercept, "the one-line widening");
    }

    #[test]
    fn restricted_suffix_table() {
        for host in ["www.example.gov", "army.mil", "my.bank", "x.insurance", "service.gov.uk", "impots.gouv.fr", "city.go.jp", "GOV.UK.", "a.gob.mx"] {
            assert!(restricted_suffix(host), "{host}");
        }
        for host in ["go.com", "www.go.com", "gov.example", "example.com", "bank.example", "goverment.uk"] {
            assert!(!restricted_suffix(host), "{host}");
        }
    }

    #[test]
    fn quic_asks_for_h3_and_tcp_for_h2_or_http1() {
        let at = |transport, names: &[&str], port| {
            let alpn: Vec<String> = names.iter().map(|s| s.to_string()).collect();
            let f = FlowFacts { transport, port, alpn: &alpn, ..base(&alpn) };
            decrypt(&f, &ExclusionSet::default(), &switches()) == Decrypt::Intercept
        };
        assert!(at(Transport::Quic, &["h3"], 443));
        assert!(!at(Transport::Quic, &["h2"], 443) && !at(Transport::Quic, &[], 443));
        assert!(at(Transport::Tcp, &["h2"], 9000) && at(Transport::Tcp, &["http/1.1"], 9000));
        assert!(!at(Transport::Tcp, &["h3"], 443) && !at(Transport::Tcp, &["acme-tls/1"], 443));
        assert!(at(Transport::Tcp, &[], 443) && at(Transport::Tcp, &[], 8443) && !at(Transport::Tcp, &[], 8444));
    }

    #[test]
    fn the_set_finds_every_pattern_kind_through_its_index() {
        let alpn = alpn();
        let mut set = ExclusionSet::default();
        set.add(parse("bank.example\n\"exact.example\"\n*.cdn.example\n192.0.2.7\napp.example$app=client.exe\n").entries, &Source::List("x".into()));
        assert_eq!(set.len(), 5);
        let hits = |host: &str, ip: &str, exe: &'static str| {
            let f = FlowFacts { host: Some(host), ip: ip.parse().unwrap(), exe: Some(exe), ..base(&alpn) };
            decrypt(&f, &set, &switches()) != Decrypt::Intercept
        };
        assert!(hits("a.b.bank.example", "192.0.2.1", CHROME));
        assert!(hits("EXACT.example", "192.0.2.1", CHROME), "a host is lower-cased once");
        assert!(!hits("www.exact.example", "192.0.2.1", CHROME));
        assert!(hits("img.cdn.example", "192.0.2.1", CHROME));
        assert!(hits("any.example", "192.0.2.7", CHROME));
        assert!(hits("app.example", "192.0.2.1", r"C:\x\Client.exe"));
        assert!(!hits("app.example", "192.0.2.1", CHROME));
    }

    #[test]
    fn auto_ev_only_counts_with_skip_on() {
        let alpn = alpn();
        let mut set = ExclusionSet::default();
        set.add([line(HOST)], &Source::Auto(AutoReason::Ev));
        assert_eq!(decrypt(&base(&alpn), &set, &switches()), Decrypt::PassThrough(PassReason::Stored(Source::Auto(AutoReason::Ev))));
        assert_eq!(decrypt(&base(&alpn), &set, &Switches { skip_ev: false, ..switches() }), Decrypt::Intercept);
    }

    /// Host names from the facts themselves, so the arbitrary lists do match.
    fn list_lines() -> impl Strategy<Value = String> {
        let host = prop_oneof!["[a-z]{1,4}\\.example", Just(HOST.to_string()), Just("service.gov.uk".to_string()), Just("*".to_string()), Just("192.0.2.1".to_string()), "[ -~]{0,20}"];
        prop::collection::vec((host, prop_oneof![Just(""), Just("$app=chrome.exe")]).prop_map(|(h, m)| format!("{h}{m}")), 0..12).prop_map(|lines| lines.join("\n"))
    }

    fn arbitrary_auto() -> impl Strategy<Value = Vec<(Exclusion, AutoReason)>> {
        let entry = prop_oneof![Just(HOST), Just("service.gov.uk"), Just("other.example")].prop_map(line);
        prop::collection::vec((entry, prop::sample::select(AutoReason::ALL.to_vec())), 0..4)
    }

    proptest! {
        #[test]
        fn no_list_input_yields_intercept_for_a_floor_fact(text in list_lines(), auto in arbitrary_auto(), root in any::<bool>(), lists in any::<bool>(), skip_ev in any::<bool>()) {
            let store = store_of(&text, &auto);
            let (alpn, bad) = (alpn(), vec![NO_ALPN_FOR_HTTP[0].to_string()]);
            // Exactly the floor under test holds, so its reason must be the answer.
            for fact in Floor::ALL {
                let (f, s) = with_floor(fact, &alpn, &bad);
                prop_assert_eq!(decrypt(&f, &store, &Switches { skip_ev, ..s }), Decrypt::PassThrough(PassReason::Floor(fact)));
            }
            // Whatever the other switches say, no input decrypts past a floor fact.
            for fact in Floor::ALL {
                let (f, s) = with_floor(fact, &alpn, &bad);
                let s = Switches { root_ready: s.root_ready && root, lists_ready: s.lists_ready && lists, skip_ev, scope: Scope::Browsers, https: true };
                prop_assert_ne!(decrypt(&f, &store, &s), Decrypt::Intercept);
            }
        }

        #[test]
        fn adding_entries_never_turns_a_pass_through_into_intercept(text in list_lines(), more in list_lines(), auto in arbitrary_auto(), host in "[a-z]{1,4}\\.example", exe in prop_oneof![Just(CHROME), Just(r"C:\x\other.exe")]) {
            let alpn = alpn();
            let f = FlowFacts { host: Some(&host), exe: Some(exe), ..base(&alpn) };
            let small = store_of(&text, &[]);
            let mut large = store_of(&text, &auto);
            large.add(parse(&more).entries, &Source::User);
            if decrypt(&f, &small, &switches()) != Decrypt::Intercept {
                prop_assert_ne!(decrypt(&f, &large, &switches()), Decrypt::Intercept);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Every E10 form, plus the lines that must be skipped.
    const FILE: &str = r#"
// Banks (comment line)
bank.example
"login.exact.example"
*.cdn.example
pay*.example
192.0.2.7
2001:db8::7
updates.example$app=updater.exe|Helper.EXE
"pinned.example"$app=client.exe
Trailing.Dot.Example.

bad host.example
"unterminated.example
"star*.example"
also.bad.example$domain=x.example
empty.example$app=
path.example$app=C:\x\y.exe
-dash.example
naïve.example
"#;

    fn parsed() -> Parsed {
        parse(FILE)
    }

    #[test]
    fn every_e10_form_parses() {
        let p = parsed();
        let want = vec![
            Exclusion { pattern: Pattern::Subdomains("bank.example".into()), apps: vec![] },
            Exclusion { pattern: Pattern::Exact("login.exact.example".into()), apps: vec![] },
            Exclusion { pattern: Pattern::Wildcard("*.cdn.example".into()), apps: vec![] },
            Exclusion { pattern: Pattern::Wildcard("pay*.example".into()), apps: vec![] },
            Exclusion { pattern: Pattern::Ip("192.0.2.7".parse().unwrap()), apps: vec![] },
            Exclusion { pattern: Pattern::Ip("2001:db8::7".parse().unwrap()), apps: vec![] },
            Exclusion {
                pattern: Pattern::Subdomains("updates.example".into()),
                apps: vec!["updater.exe".into(), "helper.exe".into()],
            },
            Exclusion { pattern: Pattern::Exact("pinned.example".into()), apps: vec!["client.exe".into()] },
            Exclusion { pattern: Pattern::Subdomains("trailing.dot.example".into()), apps: vec![] },
        ];
        assert_eq!(p.entries, want);
    }

    #[test]
    fn bad_lines_are_skipped_and_counted_with_line_and_reason() {
        let got: Vec<_> = parsed().skipped.iter().map(|s| (s.line, s.reason)).collect();
        assert_eq!(
            got,
            [
                (13, SkipReason::BadHost),
                (14, SkipReason::UnterminatedQuote),
                (15, SkipReason::WildcardInExact),
                (16, SkipReason::UnknownModifier),
                (17, SkipReason::EmptyAppList),
                (18, SkipReason::BadAppName),
                (19, SkipReason::BadHost),
                (20, SkipReason::BadHost),
            ]
        );
    }

    #[test]
    fn subdomain_exact_wildcard_and_ip_semantics() {
        let p = parsed();
        let any = |host: &str| p.entries.iter().any(|e| e.matches(Some(host), None, Some("chrome.exe")));
        assert!(any("bank.example") && any("www.bank.example") && any("a.b.bank.example"));
        assert!(!any("notbank.example"), "a suffix that is not a label boundary");
        assert!(any("login.exact.example") && !any("www.login.exact.example") && !any("exact.example"));
        assert!(any("img.cdn.example") && !any("cdn.example"));
        assert!(any("pay.example") && any("payments.example") && !any("x.pay.example.org"));
        let ip = |s: &str| p.entries.iter().any(|e| e.matches(None, Some(s.parse().unwrap()), None));
        assert!(ip("192.0.2.7") && ip("2001:db8::7") && !ip("192.0.2.8"));
        assert!(!p.entries[0].matches(None, None, None), "no host and no ip matches nothing");
    }

    #[test]
    fn app_limited_entries_apply_to_those_exes_only_and_to_unknown_exes() {
        let p = parsed();
        let updates = &p.entries[6];
        assert!(updates.matches(Some("updates.example"), None, Some(r"C:\Program Files\X\UPDATER.exe")));
        assert!(updates.matches(Some("cdn.updates.example"), None, Some("helper.exe")));
        assert!(!updates.matches(Some("updates.example"), None, Some(r"C:\x\chrome.exe")));
        assert!(updates.matches(Some("updates.example"), None, None), "unknown exe errs toward pass-through");
    }

    #[test]
    fn glob_edge_cases() {
        assert!(glob_match("*", "anything.example"));
        assert!(glob_match("a*b*c", "abc") && glob_match("a*b*c", "aXbYc"));
        assert!(!glob_match("a*b*c", "acb"));
        assert!(!glob_match("ab*ba", "aba"), "the prefix and suffix may not overlap");
    }

    proptest! {
        #[test]
        fn parsing_any_text_never_panics_and_accounts_for_every_rule_line(text in "[ -~\n\"$*|.]{0,400}") {
            let p = parse(&text);
            let lines = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with(COMMENT)).count();
            prop_assert_eq!(p.entries.len() + p.skipped.len(), lines);
        }
    }
}
