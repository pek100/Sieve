//! The one rule engine (plan 5.1): uBlock Origin's dialect matched by
//! brave/adblock-rust. Every decision, full URL or host only, asks it.
//!
//! - [`RuleEngine::compile`] builds one immutable engine from list texts and
//!   reports, per list, what the rules became and what was skipped and why
//!   (S17: a skipped rule is a count, never silently partial).
//! - [`RuleEngine::check_host`] is the host-level decision for flows that
//!   carry only a name (TLS SNI, HTTP Host, QUIC SNI, DNS): a synthetic
//!   request `https://<host>/` of type `other` with no initiator. A block
//!   needs rules that cover every party and every network request type, so
//!   `$third-party`, `$image` and `$~image` never close a host (the DNS
//!   filter's semantics, S14 by construction).
//! - [`RuleSet`] is what a flow asks: the user's rules first, then the lists.
//!   Two engines make "the user wins" hold by construction: in one engine a
//!   list's `$important` would beat a user allow and a list's `@@` a user block.
//!
//! Engines are built without adblock-rust's pattern fusion. Fusion merges
//! plain patterns into one rule whose text is ` <+> `-joined and whose source
//! location is lost, and a decision must name its one rule and its one list
//! (plan 5.3). The library's source location then gives the list directly.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use adblock::Engine;
use adblock::blocker::BlockerResult;
use adblock::lists::{FilterSet, ParseOptions, ParsedLine, parse_filter};
use adblock::request::Request;
use adblock::resources::PermissionMask;

use crate::cosmetic::{CosmeticBuilder, CosmeticIndex, ScriptletUse, network_half, page_exception};

/// The synthetic host-level request (module doc).
const SYNTHETIC_TYPE: &str = "other";
const SYNTHETIC_METHOD: &str = "GET";
/// A block verdict is re-asked as this type: `@@||host^$document` says the
/// whole site is allowed, and a synthetic `other` request does not match it.
const DOCUMENT_TYPE: &str = "document";
/// The request types a rule with no type constraint matches, beside
/// [`SYNTHETIC_TYPE`] (the library's `FROM_NETWORK_TYPES`; a test keeps them equal).
const OTHER_NETWORK_TYPES: [&str; 10] = ["font", "image", "media", "object", "ping", "script", "stylesheet", "sub_frame", "websocket", "xhr"];
/// A rule without this character has no options, hence no constraints.
const OPTIONS_START: char = '$';

/// The id of the user's own rules in reports and decisions.
pub const USER_LIST: &str = "user";
/// Skip reason for a user entry that is not a host name.
pub const NOT_A_HOST: &str = "not a host name";
/// Skip reason for a user rule line holding a line break.
pub const RULE_WITH_A_BREAK: &str = "holds a line break";
/// At most this many skipped exception lines are kept per list, so the report
/// stays under the pipe's frame limit; the total stays exact.
pub const MAX_LISTED_EXCEPTIONS: usize = 200;

/// The cosmetic exception separators of the dialect.
const COSMETIC_EXCEPTIONS: [&str; 4] = ["#@#", "#@?#", "#@$#", "#@%#"];

/// One list's text handed to the compiler.
#[derive(Debug, Clone, Copy)]
pub struct ListText<'a> {
    pub id: &'a str,
    pub text: &'a str,
    /// Catalogue trust: may use `trusted-*` scriptlets. User rules never are.
    pub trusted: bool,
}

/// What compiling one list did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListReport {
    pub id: String,
    /// Network rules parsed. Those with a type or party constraint and all
    /// `$removeparam` rules cannot decide a bare host; they decide decrypted
    /// requests (`check_request`), while `filtering.https` is on.
    pub network: usize,
    /// Cosmetic rules parsed. They have an effect only on a decrypted page, while
    /// `filtering.content` is on.
    pub cosmetic: usize,
    pub skipped: usize,
    /// Skip reason (the parser's own words) to count.
    pub skip_reasons: BTreeMap<String, usize>,
    /// The first [`MAX_LISTED_EXCEPTIONS`] skipped exception lines: a skipped
    /// exception over-blocks, so each is named (plan 5.2).
    pub skipped_exceptions: Vec<String>,
    pub skipped_exceptions_total: usize,
    /// Rules naming a scriptlet the loaded bundle lacks ("N rules need a newer
    /// resource library", plan 5.5). `None` until a bundle is loaded.
    pub missing_scriptlets: Option<usize>,
}

/// The engine's answer for a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostVerdict {
    Block,
    /// An exception rule matched (`@@`).
    Allow,
    /// No rule matched.
    None,
}

/// A verdict with where it came from (plan 5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDecision {
    pub verdict: HostVerdict,
    /// The rule's text as its list wrote it.
    pub rule: Option<String>,
    /// The id of the list that holds the rule.
    pub list: Option<String>,
}

impl HostDecision {
    const NO_RULE: Self = Self { verdict: HostVerdict::None, rule: None, list: None };
}

/// One decrypted request as the rule engine asks about it.
#[derive(Debug, Clone, Copy)]
pub struct RequestQuery<'a> {
    pub url: &'a str,
    /// The page that made the request; empty for a navigation.
    pub initiator: &'a str,
    /// adblock's request type: `document`, `script`, `xhr`, `websocket` and so on.
    pub request_type: &'a str,
    pub method: &'a str,
}

/// The answer for one request (task D13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestDecision {
    pub verdict: HostVerdict,
    pub rule: Option<String>,
    pub list: Option<String>,
    /// A block's resource as a `data:` URL; None means a plain block.
    pub redirect: Option<String>,
    /// The URL with `$removeparam` applied, when that changed it.
    pub rewritten: Option<String>,
}

impl Default for RequestDecision {
    fn default() -> Self {
        Self { verdict: HostVerdict::None, rule: None, list: None, redirect: None, rewritten: None }
    }
}

/// A kind of user domain entry (B6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainKind {
    Block,
    Allow,
}

pub struct RuleEngine {
    pub(crate) engine: Engine,
    pub(crate) reports: Vec<ListReport>,
    pub(crate) cosmetic: CosmeticIndex,
    /// Per list, parallel to `reports`.
    pub(crate) scriptlets: Vec<ScriptletUse>,
    /// A derived network half, by list index, to the line its list wrote.
    written: HashMap<(u32, String), String>,
}

impl std::fmt::Debug for RuleEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleEngine").field("reports", &self.reports).finish_non_exhaustive()
    }
}

/// Lines the parser treats as comments or headers, not rules.
fn is_comment(line: &str) -> bool {
    line.starts_with('!') || line.starts_with("[Adblock") || (line.starts_with('#') && line[1..].starts_with(char::is_whitespace))
}

fn is_exception(line: &str) -> bool {
    line.starts_with("@@") || COSMETIC_EXCEPTIONS.iter().any(|marker| line.contains(marker))
}

fn options(trusted: bool) -> ParseOptions {
    let permissions = if trusted { PermissionMask::from_bits(u8::MAX) } else { PermissionMask::default() };
    ParseOptions { permissions, ..ParseOptions::default() }
}

fn rule_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !is_comment(l))
}

/// A compiled list's derived network lines: half to the line that says it.
type NetworkHalves = Vec<(String, String)>;

fn report(list: &ListText<'_>, cosmetic: &mut CosmeticBuilder) -> (ListReport, ScriptletUse, NetworkHalves) {
    let opts = options(list.trusted);
    let mut r = ListReport { id: list.id.to_string(), ..ListReport::default() };
    let mut scriptlets = ScriptletUse::new();
    let mut halves = NetworkHalves::new();
    for line in rule_lines(list.text) {
        // A skipped exception is a defect (plan 5.2): the parser refuses these
        // options, so a line it can answer through `page_exception` is applied.
        let exception = page_exception(line).filter(|e| parse_filter(e.rule(), false, opts).is_ok());
        let answered = exception.is_some();
        if let Some(exception) = exception {
            cosmetic.add_exception(exception);
        }
        if let Some(half) = network_half(line, opts) {
            halves.push((half, line.to_string()));
        }
        match parse_filter(line, false, opts) {
            Ok(parsed) => {
                match &parsed {
                    ParsedLine::Network(_) => r.network += 1,
                    ParsedLine::Cosmetic(_) => r.cosmetic += 1,
                }
                if let Some(name) = cosmetic.observe(line, &parsed) {
                    *scriptlets.entry(name).or_default() += 1;
                }
            }
            Err(_) if answered => r.network += 1,
            Err(e) => {
                r.skipped += 1;
                *r.skip_reasons.entry(e.to_string()).or_default() += 1;
                if is_exception(line) {
                    r.skipped_exceptions_total += 1;
                    if r.skipped_exceptions.len() < MAX_LISTED_EXCEPTIONS {
                        r.skipped_exceptions.push(line.to_string());
                    }
                }
            }
        }
    }
    (r, scriptlets, halves)
}

/// True when `text` holds at least one rule the parser accepts: a response
/// without one must not replace a good copy (plan 5.4).
pub fn has_a_rule(text: &str) -> bool {
    rule_lines(text).any(|line| parse_filter(line, false, options(false)).is_ok())
}

/// One form of a host name for every check: lower case, no trailing dot, an
/// IPv6 literal in brackets (`http::host_of` reports it without them).
fn normalise_host(host: &str) -> Cow<'_, str> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.contains(':') && !host.starts_with('[') {
        return Cow::Owned(format!("[{}]", host.to_ascii_lowercase()));
    }
    if host.bytes().any(|b| b.is_ascii_uppercase()) { Cow::Owned(host.to_ascii_lowercase()) } else { Cow::Borrowed(host) }
}

/// The rule of one user entry, or None when it is not a host name. Only host
/// characters pass, so an entry can never carry rule syntax into the engine.
pub fn domain_rule(entry: &str, kind: DomainKind) -> Option<String> {
    let host = normalise_host(entry.trim());
    let valid_label = |l: &str| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_');
    if host.is_empty() || !host.split('.').all(valid_label) {
        return None;
    }
    Some(match kind {
        DomainKind::Block => format!("||{host}^"),
        DomainKind::Allow => format!("@@||{host}^"),
    })
}

impl RuleEngine {
    /// Compiles every list into one engine. Rules the parser refuses are
    /// skipped and counted in [`RuleEngine::reports`]. A line's network half goes
    /// in with its own list's text, after it, so its list stays right and no
    /// later list's index moves.
    pub fn compile(lists: &[ListText<'_>]) -> Self {
        let mut set = FilterSet::new(true);
        let mut cosmetic = CosmeticBuilder::default();
        let mut reports = Vec::with_capacity(lists.len());
        let mut scriptlets = Vec::with_capacity(lists.len());
        let mut written = HashMap::new();
        for (index, list) in lists.iter().enumerate() {
            let (report, uses, halves) = report(list, &mut cosmetic);
            let mut text = list.text.to_string();
            for (half, line) in halves {
                text.push('\n');
                text.push_str(&half);
                written.entry((index as u32, half)).or_insert(line);
            }
            set.add_filter_list(text, options(list.trusted));
            reports.push(report);
            scriptlets.push(uses);
        }
        Self { engine: Engine::new_with_filter_set_no_optimize(set), reports, cosmetic: cosmetic.build(), scriptlets, written }
    }

    /// The rule's text as its list wrote it, and the list.
    fn rule_text(&self, result: Option<adblock::sourcemap::FilterRuleDebugInfo>) -> (Option<String>, Option<String>) {
        let Some(info) = result else { return (None, None) };
        let Some(location) = info.source_location else { return (info.raw_line, None) };
        let list = self.reports.get(location.source_index as usize).map(|r| r.id.clone());
        let written = info.raw_line.as_ref().and_then(|raw| self.written.get(&(location.source_index, raw.clone()))).cloned();
        (written.or(info.raw_line), list)
    }

    /// An engine with no rules: it answers None for everything.
    pub fn empty() -> Self {
        Self::compile(&[])
    }

    /// The user's domain entries as one engine (B6). A bad entry is skipped
    /// and counted under [`NOT_A_HOST`].
    pub fn compile_user<'a>(entries: impl IntoIterator<Item = (DomainKind, &'a str)>) -> Self {
        Self::compile_user_rules(entries, std::iter::empty())
    }

    /// The user's domain entries and own rule lines as one engine, never
    /// trusted. A rule holding a line break would be two rules to the parser,
    /// so it is skipped and counted under [`RULE_WITH_A_BREAK`].
    pub fn compile_user_rules<'a>(entries: impl IntoIterator<Item = (DomainKind, &'a str)>, rules: impl IntoIterator<Item = &'a str>) -> Self {
        let (mut text, mut bad) = (String::new(), 0);
        for (kind, entry) in entries {
            match domain_rule(entry, kind) {
                Some(rule) => {
                    text.push_str(&rule);
                    text.push('\n');
                }
                None => bad += 1,
            }
        }
        let mut broken = 0;
        for rule in rules {
            if rule.contains(['\r', '\n']) {
                broken += 1;
            } else {
                text.push_str(rule);
                text.push('\n');
            }
        }
        let mut engine = Self::compile(&[ListText { id: USER_LIST, text: &text, trusted: false }]);
        for (count, reason) in [(bad, NOT_A_HOST), (broken, RULE_WITH_A_BREAK)] {
            if count > 0 {
                engine.reports[0].skipped += count;
                engine.reports[0].skip_reasons.insert(reason.to_string(), count);
            }
        }
        engine
    }

    pub fn reports(&self) -> &[ListReport] {
        &self.reports
    }

    fn decision(&self, verdict: HostVerdict, result: Option<adblock::sourcemap::FilterRuleDebugInfo>) -> HostDecision {
        let (rule, list) = self.rule_text(result);
        HostDecision { verdict, rule, list }
    }

    /// The host-level decision (module doc). A name that is not a valid URL
    /// host matches nothing.
    ///
    /// adblock-rust reads a request with no initiator as third-party, so a
    /// `$third-party` rule would decide a bare host (and block a site the
    /// user opened directly). The request is asked twice, as third-party and
    /// as first-party, and blocks only when both block: then the rule that
    /// decided carries no party constraint. Type constraints get the same
    /// treatment (`closes_every_type`).
    ///
    /// Exceptions are always looked for, not only after a block rule matched:
    /// a user's allow entry lives in an engine with no block rule to match.
    pub fn check_host(&self, host: &str) -> HostDecision {
        let host = normalise_host(host);
        let url = format!("https://{host}/");
        let Ok(third) = Request::new(&url, "", SYNTHETIC_TYPE, SYNTHETIC_METHOD) else {
            return HostDecision::NO_RULE;
        };
        let first = Request::preparsed(&third.url, &third.hostname, "", SYNTHETIC_TYPE, false, SYNTHETIC_METHOD);
        let as_third: BlockerResult = self.engine.check_network_request_subset(&third, false, true);
        let as_first: BlockerResult = self.engine.check_network_request_subset(&first, false, true);
        if as_third.should_block() && as_first.should_block() && self.closes_every_type(&third, &as_third) {
            return self.after_block(&url, as_third, as_first);
        }
        let exception = as_third.exception.or(as_first.exception);
        if exception.is_some() {
            return self.decision(HostVerdict::Allow, exception);
        }
        HostDecision::NO_RULE
    }

    /// Closing a host stops all its traffic, so block rules must cover every
    /// request type from either party: `||host^$~image` and `||host^$other` say
    /// less than that and wait for full URLs. Only block rules are asked about:
    /// exceptions are `after_block`'s question. A decided rule with no options
    /// covers them all by itself, so only a rule with options pays the questions
    /// (20 of them would put the host p99 over the matcher's limit).
    fn closes_every_type(&self, request: &Request, decided: &BlockerResult) -> bool {
        let no_options = decided.filter.as_ref().and_then(|f| f.raw_line.as_deref()).is_some_and(|line| !line.contains(OPTIONS_START));
        no_options
            || OTHER_NETWORK_TYPES.iter().all(|kind| {
                [true, false].into_iter().all(|third_party| {
                    let asked = Request::preparsed(&request.url, &request.hostname, "", kind, third_party, SYNTHETIC_METHOD);
                    self.engine.check_network_request_subset(&asked, false, false).filter.is_some()
                })
            })
    }

    /// The block path's last question: an `$important` rule stands, anything
    /// else yields to a `$document` exception on the host.
    fn after_block(&self, url: &str, as_third: BlockerResult, as_first: BlockerResult) -> HostDecision {
        let important = as_third.important && as_first.important;
        if !important
            && let Ok(document) = Request::new(url, "", DOCUMENT_TYPE, SYNTHETIC_METHOD)
            && let Some(exception) = self.engine.check_network_request_subset(&document, true, true).exception
        {
            return self.decision(HostVerdict::Allow, Some(exception));
        }
        self.decision(HostVerdict::Block, as_third.filter)
    }

    /// The full-URL decision of one decrypted request (plan 5.3, task D13). The
    /// library's answer plus the question host checks already ask: a block
    /// yields to a `$document` exception on the page that made the request
    /// (the request itself for a navigation), unless `$important`.
    pub fn check_request(&self, query: &RequestQuery<'_>) -> RequestDecision {
        let Ok(request) = Request::new(query.url, query.initiator, query.request_type, query.method) else { return RequestDecision::default() };
        // Exceptions are always looked for: a user's allow entry lives in an
        // engine with no block rule to match (the same as `check_host`).
        let result = self.engine.check_network_request_subset(&request, false, true);
        let rewritten = result.rewritten_url.clone();
        if result.should_block() {
            let page = if query.initiator.is_empty() { query.url } else { query.initiator };
            if !result.important
                && let Ok(document) = Request::new(page, "", DOCUMENT_TYPE, SYNTHETIC_METHOD)
                && let Some(exception) = self.engine.check_network_request_subset(&document, true, true).exception
            {
                let (rule, list) = self.rule_text(Some(exception));
                return RequestDecision { verdict: HostVerdict::Allow, rule, list, redirect: None, rewritten };
            }
            let redirect = result.redirect;
            let (rule, list) = self.rule_text(result.filter);
            return RequestDecision { verdict: HostVerdict::Block, rule, list, redirect, rewritten: None };
        }
        if result.exception.is_some() {
            let (rule, list) = self.rule_text(result.exception);
            return RequestDecision { verdict: HostVerdict::Allow, rule, list, redirect: None, rewritten };
        }
        RequestDecision { rewritten, ..RequestDecision::default() }
    }

    /// A full-URL verdict alone (the benchmark measures this).
    pub fn check_url(&self, url: &str, initiator: &str, request_type: &str) -> HostVerdict {
        let Ok(request) = Request::new(url, initiator, request_type, SYNTHETIC_METHOD) else { return HostVerdict::None };
        let result = self.engine.check_network_request(&request);
        if result.should_block() {
            HostVerdict::Block
        } else if result.exception.is_some() {
            HostVerdict::Allow
        } else {
            HostVerdict::None
        }
    }
}

/// What a flow asks: the user's rules, then the lists (module doc).
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub user: Arc<RuleEngine>,
    pub lists: Arc<RuleEngine>,
}

impl RuleSet {
    /// No rules at all: every flow passes.
    pub fn empty() -> Self {
        Self { user: Arc::new(RuleEngine::empty()), lists: Arc::new(RuleEngine::empty()) }
    }

    pub fn check_host(&self, host: &str) -> HostDecision {
        let user = self.user.check_host(host);
        if user.verdict == HostVerdict::None { self.lists.check_host(host) } else { user }
    }

    /// The user's engine first: its verdict decides. Otherwise the lists are
    /// asked about the URL as the user's engine left it, and a parameter
    /// either removed stays removed.
    pub fn check_request(&self, query: &RequestQuery<'_>) -> RequestDecision {
        let user = self.user.check_request(query);
        if user.verdict != HostVerdict::None {
            return user;
        }
        let asked = user.rewritten.as_deref().unwrap_or(query.url);
        let lists = self.lists.check_request(&RequestQuery { url: asked, ..*query });
        RequestDecision { rewritten: lists.rewritten.clone().or(user.rewritten), ..lists }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adblock::filters::network::NetworkFilterMask;
    use proptest::prelude::*;

    /// The slice 1 acceptance fixture (plan section 9).
    const FIXTURE: &str = "\
[Adblock Plus 2.0]
! Title: Sieve fixture
! Expires: 1 day
||ads.sieve-test.invalid^
||tracker.sieve-test.invalid^$third-party
@@||ok.ads.sieve-test.invalid^
example.invalid##.banner
example.invalid##+js(set-constant, adsAllowed, true)
||bad$unknown-option-xyz
";

    fn engine(text: &str) -> RuleEngine {
        RuleEngine::compile(&[ListText { id: "fixture", text, trusted: true }])
    }

    fn verdict(e: &RuleEngine, host: &str) -> HostVerdict {
        e.check_host(host).verdict
    }

    fn user(entries: &[(DomainKind, &str)]) -> RuleEngine {
        RuleEngine::compile_user(entries.iter().copied())
    }

    fn set(user_rules: RuleEngine, list: &str) -> RuleSet {
        RuleSet { user: Arc::new(user_rules), lists: Arc::new(engine(list)) }
    }

    /// The form the log's row actions write (src/core/log-actions.ts): an IPv6
    /// literal in a rule takes its URL form, in brackets; bare, it matches nothing.
    #[test]
    fn an_ipv6_rule_matches_only_in_its_bracketed_form() {
        const V6: &str = "[2001:db8::1]";
        assert_eq!(verdict(&engine("||[2001:db8::1]^\n"), V6), HostVerdict::Block);
        assert_eq!(verdict(&engine("||2001:db8::1^\n"), V6), HostVerdict::None);
        assert_eq!(verdict(&engine("||[2001:db8::1]^\n@@||[2001:db8::1]^\n"), V6), HostVerdict::Allow);
        assert_eq!(verdict(&engine("||198.51.100.25^\n"), "198.51.100.25"), HostVerdict::Block);
    }

    #[test]
    fn the_fixture_list_blocks_the_test_host_and_its_subdomains() {
        let e = engine(FIXTURE);
        assert_eq!(verdict(&e, "ads.sieve-test.invalid"), HostVerdict::Block);
        assert_eq!(verdict(&e, "x.ads.sieve-test.invalid"), HostVerdict::Block);
        assert_eq!(verdict(&e, "ok.ads.sieve-test.invalid"), HostVerdict::Allow);
        assert_eq!(verdict(&e, "news.sieve-test.invalid"), HostVerdict::None);
        assert_eq!(verdict(&e, "sieve-test.invalid"), HostVerdict::None);
    }

    #[test]
    fn host_checks_ignore_rules_with_party_or_type_constraints() {
        // The synthetic request has no initiator, so a $third-party rule does
        // not decide a bare host (the DNS filter's semantics).
        assert_eq!(verdict(&engine(FIXTURE), "tracker.sieve-test.invalid"), HostVerdict::None);
        let constrained = engine("||img.sieve-test.invalid^$image\n||fp.sieve-test.invalid^$1p\n");
        assert_eq!(verdict(&constrained, "img.sieve-test.invalid"), HostVerdict::None);
        assert_eq!(verdict(&constrained, "fp.sieve-test.invalid"), HostVerdict::None);
    }

    /// `||host^$~image` leaves images alone, so it may not close the host; the
    /// same for every type, named or negated.
    #[test]
    fn a_rule_that_leaves_any_type_open_does_not_decide_a_host() {
        let options = ["font", "image", "media", "object", "other", "ping", "script", "stylesheet", "subdocument", "websocket", "xhr"];
        assert_eq!(options.len(), OTHER_NETWORK_TYPES.len() + 1);
        for option in options {
            assert_eq!(verdict(&engine(&format!("||x.example^$~{option}\n")), "x.example"), HostVerdict::None, "$~{option}");
            assert_eq!(verdict(&engine(&format!("||x.example^${option}\n")), "x.example"), HostVerdict::None, "${option}");
        }
        assert_eq!(verdict(&engine("||x.example^$~image,~script\n"), "x.example"), HostVerdict::None);
        assert_eq!(verdict(&engine("||x.example^$~image,important\n"), "x.example"), HostVerdict::None);
    }

    /// The types are asked as a question about the host, not about one rule.
    #[test]
    fn a_host_every_type_blocks_is_decided_whichever_rules_block_it() {
        assert_eq!(verdict(&engine("||x.example^$~image\n||x.example^\n"), "x.example"), HostVerdict::Block, "a narrower rule first");
        assert_eq!(verdict(&engine("||x.example^\n||x.example^$~image\n"), "x.example"), HostVerdict::Block, "a narrower rule last");
        assert_eq!(verdict(&engine("||x.example^$~image\n||x.example^$image\n"), "x.example"), HostVerdict::Block, "together they cover every type");
        assert_eq!(verdict(&engine("||x.example^$~image\n||x.example^$image,3p\n"), "x.example"), HostVerdict::None, "first-party images stay open");
        assert_eq!(verdict(&engine("||x.example\n"), "x.example"), HostVerdict::Block, "no ^, no type constraint");
    }

    fn query<'a>(url: &'a str, initiator: &'a str, request_type: &'a str) -> RequestQuery<'a> {
        RequestQuery { url, initiator, request_type, method: "GET" }
    }

    #[test]
    fn a_request_is_decided_by_its_full_url_type_and_party() {
        let e = engine("||ads.example/banner^\n||x.example^$image\n||y.example^$third-party\n");
        let block = |url, init, kind| e.check_request(&query(url, init, kind)).verdict;
        assert_eq!(block("https://ads.example/banner/1.png", "https://news.example/", "image"), HostVerdict::Block);
        assert_eq!(block("https://ads.example/other", "https://news.example/", "image"), HostVerdict::None);
        assert_eq!(block("https://x.example/a.png", "https://news.example/", "image"), HostVerdict::Block);
        assert_eq!(block("https://x.example/a.js", "https://news.example/", "script"), HostVerdict::None);
        assert_eq!(block("https://y.example/a", "https://news.example/", "script"), HostVerdict::Block);
        assert_eq!(block("https://y.example/a", "https://y.example/", "script"), HostVerdict::None);
        let d = e.check_request(&query("https://ads.example/banner/", "https://news.example/", "script"));
        assert_eq!((d.rule.as_deref(), d.list.as_deref()), (Some("||ads.example/banner^"), Some("fixture")));
    }

    #[test]
    fn a_document_exception_on_the_initiator_yields_unless_important() {
        let e = engine("||ads.example^\n@@||news.example^$document\n");
        let ask = |init| e.check_request(&query("https://ads.example/a.js", init, "script")).verdict;
        assert_eq!(ask("https://news.example/"), HostVerdict::Allow);
        assert_eq!(ask("https://other.example/"), HostVerdict::Block);
        let e = engine("||ads.example^$important\n@@||news.example^$document\n");
        assert_eq!(e.check_request(&query("https://ads.example/a.js", "https://news.example/", "script")).verdict, HostVerdict::Block);
    }

    #[test]
    fn removeparam_rewrites_and_the_user_engine_decides_first() {
        let e = engine("||news.example^$removeparam=utm_source\n");
        let d = e.check_request(&query("https://news.example/a?utm_source=x&id=1", "", "document"));
        assert_eq!(d.verdict, HostVerdict::None);
        assert_eq!(d.rewritten.as_deref(), Some("https://news.example/a?id=1"));
        let set = set(RuleEngine::compile_user_rules(std::iter::empty(), ["@@||ads.example^", "||news.example^$removeparam=one"]), "||ads.example^\n||news.example^$removeparam=two\n");
        assert_eq!(set.check_request(&query("https://ads.example/x", "https://b.example/", "script")).verdict, HostVerdict::Allow, "the user's allow beats a list's block");
        let both = set.check_request(&query("https://news.example/a?one=1&two=2&id=3", "", "document"));
        assert_eq!(both.rewritten.as_deref(), Some("https://news.example/a?id=3"), "the lists are asked on what the user's engine left");
    }

    /// Pinned so a change of the library is seen.
    #[test]
    fn other_constraints_on_a_host_rule() {
        // The parser refuses it, so it is a skipped rule and no decision.
        let negated_document = engine("||x.example^$~document\n");
        assert_eq!(verdict(&negated_document, "x.example"), HostVerdict::None);
        assert_eq!(negated_document.reports()[0].skipped, 1);
        // The library matches any exception on a `document` request, so a partial
        // one opens the host (`after_block`): fewer blocks, never more.
        assert_eq!(verdict(&engine("||x.example^\n@@||x.example^$image\n"), "x.example"), HostVerdict::Allow);
        assert_eq!(verdict(&engine("||x.example^\n@@||x.example^$~image\n"), "x.example"), HostVerdict::Allow);
        assert_eq!(verdict(&engine("||x.example^$domain=site.example\n"), "x.example"), HostVerdict::None);
        assert_eq!(verdict(&engine("||x.example^$domain=~site.example\n"), "x.example"), HostVerdict::Block);
    }

    #[test]
    fn the_types_asked_are_every_network_type_of_the_library() {
        assert_eq!(NetworkFilterMask::FROM_NETWORK_TYPES.bits().count_ones() as usize, OTHER_NETWORK_TYPES.len() + 1, "+1 is {SYNTHETIC_TYPE}");
    }

    #[test]
    fn every_rule_is_applied_or_skipped_and_counted() {
        let e = engine(FIXTURE);
        let r = &e.reports()[0];
        assert_eq!(r.id, "fixture");
        assert_eq!((r.network + r.cosmetic, r.skipped), (5, 1), "{r:?}");
        assert_eq!(r.skip_reasons.values().sum::<usize>(), 1);
    }

    #[test]
    fn reports_are_per_list_in_order() {
        let e = RuleEngine::compile(&[
            ListText { id: "a", text: "||a.sieve-test.invalid^\n", trusted: true },
            ListText { id: "b", text: "||b.sieve-test.invalid^\n! note\n\n", trusted: false },
        ]);
        let ids: Vec<_> = e.reports().iter().map(|r| (r.id.as_str(), r.network, r.skipped)).collect();
        assert_eq!(ids, [("a", 1, 0), ("b", 1, 0)]);
        assert_eq!(verdict(&e, "b.sieve-test.invalid"), HostVerdict::Block);
    }

    #[test]
    fn a_name_that_is_not_a_host_matches_nothing() {
        let e = engine(FIXTURE);
        assert_eq!(verdict(&e, ""), HostVerdict::None);
        assert_eq!(verdict(&e, "a b"), HostVerdict::None);
    }

    #[test]
    fn the_engine_is_shareable_across_threads() {
        fn shareable<T: Send + Sync>() {}
        shareable::<RuleEngine>();
        shareable::<RuleSet>();
    }

    #[test]
    fn user_allow_beats_a_list_important_block() {
        let s = set(user(&[(DomainKind::Allow, "ads.example")]), "||ads.example^$important\n");
        assert_eq!(s.check_host("ads.example").verdict, HostVerdict::Allow);
        assert_eq!(s.check_host("ads.example").list.as_deref(), Some(USER_LIST));
        assert_eq!(set(RuleEngine::empty(), "||ads.example^$important\n").check_host("ads.example").verdict, HostVerdict::Block);
    }

    #[test]
    fn user_block_beats_a_list_exception() {
        let s = set(user(&[(DomainKind::Block, "ok.example")]), "||ok.example^\n@@||ok.example^\n");
        assert_eq!(s.check_host("ok.example").verdict, HostVerdict::Block);
        assert_eq!(set(RuleEngine::empty(), "||ok.example^\n@@||ok.example^\n").check_host("ok.example").verdict, HostVerdict::Allow);
    }

    #[test]
    fn no_user_rule_leaves_the_lists_to_decide() {
        let s = set(user(&[(DomainKind::Block, "mine.example")]), "||ads.example^\n");
        assert_eq!(s.check_host("ads.example").list.as_deref(), Some("fixture"));
        assert_eq!(s.check_host("news.example"), HostDecision::NO_RULE);
    }

    /// Finding 5: the synthetic `other` request does not match `$document`.
    #[test]
    fn document_exception_allows_a_host() {
        let e = engine("||site.example^\n@@||site.example^$document\n");
        let d = e.check_host("site.example");
        assert_eq!(d.verdict, HostVerdict::Allow);
        assert_eq!(d.rule.as_deref(), Some("@@||site.example^$document"));
        let important = engine("||site.example^$important\n@@||site.example^$document\n");
        assert_eq!(verdict(&important, "site.example"), HostVerdict::Block, "$important stands over $document");
        assert_eq!(verdict(&engine("@@||site.example^$document\n"), "site.example"), HostVerdict::None, "no block, nothing to allow");
    }

    /// Finding 5: an unbracketed IPv6 literal failed to parse and matched nothing.
    #[test]
    fn ipv6_literal_and_trailing_dot_and_case_are_normalised() {
        let e = engine("||ads.example^\n||[2001:db8::1]^\n");
        for host in ["ads.example", "ADS.Example", "ads.example.", "X.ADS.EXAMPLE."] {
            assert_eq!(verdict(&e, host), HostVerdict::Block, "{host}");
        }
        for host in ["2001:db8::1", "[2001:db8::1]", "2001:DB8::1"] {
            assert_eq!(verdict(&e, host), HostVerdict::Block, "{host}");
        }
        assert_eq!(verdict(&e, "2001:db8::2"), HostVerdict::None);
    }

    /// The log's Unblock and Block and the Filters editor write these lines.
    #[test]
    fn user_rule_lines_decide_beside_domain_entries_and_stay_untrusted() {
        let lines = ["! note", "||ads.example^", "@@||ok.ads.example^", "||two.example^\n@@||smuggled.example^", "##+js(trusted-x)"];
        let e = RuleEngine::compile_user_rules([(DomainKind::Block, "listed.example")], lines);
        assert_eq!(e.check_host("x.ads.example").verdict, HostVerdict::Block);
        assert_eq!(e.check_host("ok.ads.example").verdict, HostVerdict::Allow);
        assert_eq!(e.check_host("listed.example").verdict, HostVerdict::Block);
        assert_eq!(e.check_host("smuggled.example").verdict, HostVerdict::None, "a broken line reaches nothing");
        let r = &e.reports()[0];
        assert_eq!(r.id, USER_LIST);
        assert_eq!(r.skip_reasons.get(RULE_WITH_A_BREAK), Some(&1));
        assert_eq!(r.network, 3);
    }

    #[test]
    fn domain_rule_refuses_injection() {
        assert_eq!(domain_rule(" Ads.Example. ", DomainKind::Block).as_deref(), Some("||ads.example^"));
        assert_eq!(domain_rule("ads.example", DomainKind::Allow).as_deref(), Some("@@||ads.example^"));
        let bad = ["a.example\n||b.example^", "a.example$important", "@@a.example", "a b.example", "", ".", "a..example", "||a.example^", "-a.example", "a.example/path", "*"];
        for entry in bad {
            assert_eq!(domain_rule(entry, DomainKind::Block), None, "{entry:?}");
        }
        let e = user(&[(DomainKind::Block, "ok.example"), (DomainKind::Block, "x.example\n||other.example^"), (DomainKind::Allow, "$important")]);
        let r = &e.reports()[0];
        assert_eq!((r.id.as_str(), r.network, r.skipped), (USER_LIST, 1, 2), "{r:?}");
        assert_eq!(r.skip_reasons.get(NOT_A_HOST), Some(&2));
        assert_eq!(verdict(&e, "other.example"), HostVerdict::None, "nothing was injected");
    }

    /// One line per syntax form of plan 5.2, with what adblock-rust 0.13.3
    /// does with it. Network = parsed, Cosmetic = parsed, Skip = refused.
    #[test]
    fn report_counts_every_syntax_form() {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Is {
            Network,
            Cosmetic,
            Skip,
        }
        use Is::{Cosmetic, Network, Skip};
        let forms = [
            ("||host.example^", Network),
            ("|https://host.example/a", Network),
            ("/ads*banner/", Network),
            ("/ads[0-9]+/", Network),
            ("@@||host.example^", Network),
            ("||host.example^$third-party", Network),
            ("||host.example^$3p", Network),
            ("||host.example^$first-party", Network),
            ("||host.example^$1p", Network),
            ("||host.example^$~third-party", Network),
            ("||host.example^$domain=a.example|~b.a.example", Network),
            ("||host.example^$important", Network),
            ("/ads[0-9]+/$match-case", Network),
            ("||host.example^$match-case", Skip), // the library allows it on regex rules only
            ("||host.example^$badfilter", Network),
            ("||host.example^$script", Network),
            ("||host.example^$image", Network),
            ("||host.example^$stylesheet", Network),
            ("||host.example^$xmlhttprequest", Network),
            ("||host.example^$xhr", Network),
            ("||host.example^$media", Network),
            ("||host.example^$font", Network),
            ("||host.example^$subdocument", Network),
            ("||host.example^$frame", Network),
            ("||host.example^$document", Network),
            ("||host.example^$doc", Network),
            ("||host.example^$websocket", Network),
            ("||host.example^$ping", Network),
            ("||host.example^$object", Network),
            ("||host.example^$other", Network),
            ("||host.example^$all", Network),
            ("||host.example^$redirect=noopjs", Network),
            ("||host.example^$redirect-rule=noopjs", Network),
            ("||host.example^$removeparam=utm", Network),
            ("@@||host.example^$document", Network),
            ("@@||host.example^$generichide", Network),
            ("@@||host.example^$ghide", Network),
            // Finding 4: the exception modifiers adblock-rust does not have.
            ("||host.example^$denyallow=a.example", Skip),
            ("@@||host.example^$elemhide", Network),
            ("@@||host.example^$ehide", Network),
            ("@@||host.example^$specifichide", Network),
            ("@@||host.example^$shide", Network),
            ("@@||host.example^$genericblock", Skip),
            ("@@||host.example^$removeparam=utm", Skip),
            ("host.example##.banner", Cosmetic),
            ("##.banner", Cosmetic),
            ("host.example#@#.banner", Cosmetic),
            ("host.example##+js(set-constant, a, true)", Cosmetic),
            ("host.example#@#+js(set-constant, a, true)", Cosmetic),
            ("host.example##.a:has(.b)", Cosmetic),
            ("host.example##.a:has-text(x)", Cosmetic),
            ("host.example##.a:upward(1)", Cosmetic),
            ("host.example##:xpath(//a)", Cosmetic),
            ("host.example##.a:matches-css(color: red)", Cosmetic),
            ("host.example##.a:matches-attr(x)", Cosmetic),
            ("host.example##.a:matches-path(/x)", Cosmetic),
            ("host.example##.a:min-text-length(9)", Cosmetic),
            ("host.example##.a:remove()", Cosmetic),
            ("host.example##.a:style(color: red)", Cosmetic),
            ("host.example##.a:watch-attr(x)", Cosmetic),
            ("host.example##.a:others()", Cosmetic),
            // Not supported first (5.2): skipped and counted.
            ("||host.example^$header=x:y", Skip),
            ("||host.example^$permissions=x", Skip),
            ("||host.example^$replace=/a/b/", Skip),
            ("||host.example^$urltransform=/a/b/", Skip),
            ("||host.example^$cookie=x", Skip),
            ("host.example##^.banner", Skip),
            ("||host.example^$popup", Skip),
        ];
        let mut wrong = Vec::new();
        for (line, want) in forms {
            let r = engine(line);
            let r = &r.reports()[0];
            let got = match (r.network, r.cosmetic, r.skipped) {
                (1, 0, 0) => Network,
                (0, 1, 0) => Cosmetic,
                (0, 0, 1) => Skip,
                other => panic!("{line}: {other:?}"),
            };
            if got != want {
                wrong.push(format!("{line}: {got:?}, expected {want:?}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn every_skipped_exception_is_listed_with_its_line() {
        // $elemhide, $ehide, $specifichide and $shide are answered by page_exception, so they are not here.
        let forms = ["@@||a.example^$genericblock", "@@||a.example^$removeparam=x"];
        let text = forms.join("\n");
        let e = engine(&text);
        let r = &e.reports()[0];
        assert_eq!(r.skipped_exceptions, forms);
        assert_eq!(r.skipped_exceptions_total, forms.len());

        let many: String = (0..MAX_LISTED_EXCEPTIONS + 5).map(|i| format!("@@||a{i}.example^$genericblock\n")).collect();
        let e = engine(&many);
        let r = &e.reports()[0];
        assert_eq!(r.skipped_exceptions.len(), MAX_LISTED_EXCEPTIONS);
        assert_eq!(r.skipped_exceptions_total, MAX_LISTED_EXCEPTIONS + 5);
        assert_eq!(r.skipped_exceptions[0], "@@||a0.example^$genericblock");

        let blocks = engine("||a.example^$popup\n");
        assert!(blocks.reports()[0].skipped_exceptions.is_empty(), "a skipped block rule only under-blocks");
    }

    #[test]
    fn report_splits_network_and_cosmetic() {
        let e = engine("||a.example^\n@@||b.example^\n||c.example^$removeparam=x\n##.ad\nd.example##.ad\n");
        let r = &e.reports()[0];
        assert_eq!((r.network, r.cosmetic, r.skipped), (3, 2, 0), "{r:?}");
    }

    #[test]
    fn blocking_rule_names_its_list() {
        let e = RuleEngine::compile(&[
            ListText { id: "first", text: "! c\n||one.example^\n", trusted: true },
            ListText { id: "second", text: "ads\n||two.example^$important\n@@||ok.two.example^\n/banner\n", trusted: true },
        ]);
        let d = e.check_host("one.example");
        assert_eq!((d.verdict, d.rule.as_deref(), d.list.as_deref()), (HostVerdict::Block, Some("||one.example^"), Some("first")));
        let d = e.check_host("x.two.example");
        assert_eq!((d.verdict, d.rule.as_deref(), d.list.as_deref()), (HostVerdict::Block, Some("||two.example^$important"), Some("second")));
        let d = RuleEngine::compile(&[ListText { id: "l", text: "||x.example^\n@@||ok.x.example^\n", trusted: true }]).check_host("ok.x.example");
        assert_eq!((d.verdict, d.rule.as_deref(), d.list.as_deref()), (HostVerdict::Allow, Some("@@||ok.x.example^"), Some("l")));
        // Plain patterns would be fused by the library's optimizer, losing the rule.
        let fused = engine("/aaa/\n/bbb/\n/ccc/\n");
        assert_eq!(fused.check_url("https://h.example/bbb/x", "", "other"), HostVerdict::Block);
    }

    #[test]
    fn a_response_of_comments_or_garbage_has_no_rule() {
        assert!(has_a_rule(FIXTURE));
        assert!(!has_a_rule(""));
        assert!(!has_a_rule("! only\n[Adblock Plus 2.0]\n# note\n\n"));
    }

    /// `@@||x^$document,elemhide` says two things. The parser refuses the line
    /// or holds it as a hide exception alone, and the network half was lost.
    #[test]
    fn document_with_a_hide_option_keeps_its_network_exception() {
        const AD: &str = "https://ads.example/a.js";
        const PAGE: &str = "https://site.example/";
        for option in ["document,elemhide", "doc,ehide", "document,generichide", "document,specifichide", "shide,doc"] {
            let line = format!("@@||site.example^${option}");
            let e = engine(&format!("||site.example^\n||ads.example^\n{line}\n"));
            let host = e.check_host("site.example");
            assert_eq!((host.verdict, host.rule.as_deref()), (HostVerdict::Allow, Some(line.as_str())), "{option}");
            let request = e.check_request(&query(AD, PAGE, "script"));
            assert_eq!((request.verdict, request.rule.as_deref()), (HostVerdict::Allow, Some(line.as_str())), "{option}: by initiator");
            assert_eq!(e.check_request(&query(AD, "https://other.example/", "script")).verdict, HostVerdict::Block, "{option}: another page");

            let important = engine(&format!("||site.example^$important\n||ads.example^$important\n{line}\n"));
            assert_eq!(verdict(&important, "site.example"), HostVerdict::Block, "{option}: $important stands");
            assert_eq!(important.check_request(&query(AD, PAGE, "script")).verdict, HostVerdict::Block, "{option}: $important stands");
        }
    }

    #[test]
    fn a_hide_option_with_a_type_keeps_that_type_only() {
        let e = engine("||x.example^\n@@||x.example^$elemhide,script\n");
        let ask = |url, kind| e.check_request(&query(url, "https://news.example/", kind)).verdict;
        assert_eq!(ask("https://x.example/a.js", "script"), HostVerdict::Allow);
        assert_eq!(ask("https://x.example/a.png", "image"), HostVerdict::Block);
        let negated = engine("||x.example^\n@@||x.example^$~script,ehide\n");
        let ask = |url, kind| negated.check_request(&query(url, "https://news.example/", kind)).verdict;
        assert_eq!(ask("https://x.example/a.js", "script"), HostVerdict::Block);
        assert_eq!(ask("https://x.example/a.png", "image"), HostVerdict::Allow);
    }

    /// A hide exception never opens the network, whatever else it says.
    #[test]
    fn a_hide_exception_alone_opens_no_network() {
        for option in ["elemhide", "ehide", "specifichide", "shide", "generichide", "ghide", "elemhide,domain=news.example", "elemhide,third-party", "shide,ghide"] {
            let e = engine(&format!("||x.example^\n@@||x.example^${option}\n"));
            assert_eq!(verdict(&e, "x.example"), HostVerdict::Block, "{option}");
            assert_eq!(e.check_request(&query("https://x.example/a.js", "https://news.example/", "script")).verdict, HostVerdict::Block, "{option}");
        }
    }

    #[test]
    fn network_halves_keep_their_list_and_their_written_text() {
        let e = RuleEngine::compile(&[
            ListText { id: "first", text: "||x.example^\n", trusted: true },
            ListText { id: "second", text: "! a note\n@@||x.example^$document,elemhide", trusted: true },
        ]);
        let d = e.check_host("x.example");
        assert_eq!((d.verdict, d.rule.as_deref(), d.list.as_deref()), (HostVerdict::Allow, Some("@@||x.example^$document,elemhide"), Some("second")));
    }

    /// The same half written by two lists: each row says what its own list wrote.
    #[test]
    fn a_plain_line_in_another_list_keeps_its_own_text() {
        let e = RuleEngine::compile(&[ListText { id: "plain", text: "||x.example^\n@@||x.example^$document\n", trusted: true }, ListText { id: "both", text: "@@||x.example^$document,elemhide\n", trusted: true }]);
        let d = e.check_host("x.example");
        let written = if d.list.as_deref() == Some("plain") { "@@||x.example^$document" } else { "@@||x.example^$document,elemhide" };
        assert_eq!(d.rule.as_deref(), Some(written), "{d:?}");
    }

    #[test]
    fn network_halves_do_not_shift_a_later_lists_provenance() {
        let e = RuleEngine::compile(&[
            ListText { id: "first", text: "@@||y.example^$document,elemhide\n@@||z.example^$elemhide,script\n", trusted: true },
            ListText { id: "second", text: "||x.example^\n", trusted: true },
        ]);
        let d = e.check_host("x.example");
        assert_eq!((d.rule.as_deref(), d.list.as_deref()), (Some("||x.example^"), Some("second")));
    }

    #[test]
    fn page_exception_lines_count_once() {
        let e = engine("@@||a.example^$document,elemhide\n@@||b.example^$document,generichide\n@@||c.example^$elemhide,script\n");
        let r = &e.reports()[0];
        assert_eq!((r.network, r.cosmetic, r.skipped), (3, 0, 0), "{r:?}");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn compile_never_panics_on_arbitrary_lines(lines in proptest::collection::vec("\\PC{0,40}", 0..24), syntax in proptest::collection::vec("(\\|\\||@@|\\$|##|#@#|\\^|/|\\*|,|=|~|\\+js\\(|:has\\(|[a-z.]{1,8}){1,8}", 0..24)) {
            let text = lines.iter().chain(&syntax).cloned().collect::<Vec<_>>().join("\n");
            let e = RuleEngine::compile(&[ListText { id: "p", text: &text, trusted: false }]);
            let r = &e.reports()[0];
            prop_assert!(r.network + r.cosmetic + r.skipped <= lines.len() + syntax.len());
            let _ = e.check_host("host.example");
        }
    }
}
