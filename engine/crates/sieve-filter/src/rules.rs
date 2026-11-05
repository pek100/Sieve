//! The one rule engine (plan 5.1): uBlock Origin's dialect matched by
//! brave/adblock-rust. Every decision, full URL or host only, asks it.
//!
//! - [`RuleEngine::compile`] builds one immutable engine from list texts and
//!   reports, per list, how many rules were applied and skipped and why
//!   (S17: a skipped rule is a count, never silently partial).
//! - [`RuleEngine::check_host`] is the host-level decision for flows that
//!   carry only a name (TLS SNI, HTTP Host, QUIC SNI, DNS): a synthetic
//!   request `https://<host>/` of type `other` with no initiator, which
//!   matches exactly the `||host^` rules without type or party constraints
//!   (the DNS filter's semantics, S14 by construction).

use std::collections::BTreeMap;

use adblock::Engine;
use adblock::lists::{FilterSet, ParseOptions, parse_filter};
use adblock::request::Request;
use adblock::resources::PermissionMask;

/// The synthetic host-level request (module doc).
const SYNTHETIC_TYPE: &str = "other";
const SYNTHETIC_METHOD: &str = "GET";

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
    pub applied: usize,
    pub skipped: usize,
    /// Skip reason (the parser's own words) to count.
    pub skip_reasons: BTreeMap<String, usize>,
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

pub struct RuleEngine {
    engine: Engine,
    reports: Vec<ListReport>,
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

fn options(trusted: bool) -> ParseOptions {
    let permissions = if trusted { PermissionMask::from_bits(u8::MAX) } else { PermissionMask::default() };
    ParseOptions { permissions, ..ParseOptions::default() }
}

fn report(list: &ListText<'_>) -> ListReport {
    let mut r = ListReport { id: list.id.to_string(), ..ListReport::default() };
    for line in list.text.lines().map(str::trim).filter(|l| !l.is_empty() && !is_comment(l)) {
        match parse_filter(line, false, options(list.trusted)) {
            Ok(_) => r.applied += 1,
            Err(e) => {
                r.skipped += 1;
                *r.skip_reasons.entry(e.to_string()).or_default() += 1;
            }
        }
    }
    r
}

impl RuleEngine {
    /// Compiles every list into one engine. Rules the parser refuses are
    /// skipped and counted in [`RuleEngine::reports`].
    pub fn compile(lists: &[ListText<'_>]) -> Self {
        let mut set = FilterSet::new(true);
        let reports = lists
            .iter()
            .map(|list| {
                set.add_filter_list(list.text.to_string(), options(list.trusted));
                report(list)
            })
            .collect();
        Self { engine: Engine::new_with_filter_set(set), reports }
    }

    pub fn reports(&self) -> &[ListReport] {
        &self.reports
    }

    /// The host-level decision (module doc). A name that is not a valid URL
    /// host matches nothing.
    ///
    /// adblock-rust reads a request with no initiator as third-party, so a
    /// `$third-party` rule would decide a bare host (and block a site the
    /// user opened directly). The request is asked twice, as third-party and
    /// as first-party, and blocks only when both block: then the rule that
    /// decided carries no party constraint.
    pub fn check_host(&self, host: &str) -> HostVerdict {
        let url = format!("https://{host}/");
        let Ok(third) = Request::new(&url, "", SYNTHETIC_TYPE, SYNTHETIC_METHOD) else {
            return HostVerdict::None;
        };
        let first = Request::preparsed(&url, &host.to_ascii_lowercase(), "", SYNTHETIC_TYPE, false, SYNTHETIC_METHOD);
        let results = [third, first].map(|r| self.engine.check_network_request(&r));
        if results.iter().all(|r| r.should_block()) {
            HostVerdict::Block
        } else if results.iter().any(|r| r.exception.is_some()) {
            HostVerdict::Allow
        } else {
            HostVerdict::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The form the log's row actions write (src/core/log-actions.ts): an IPv6
    /// literal in a rule takes its URL form, in brackets; bare, it matches nothing.
    #[test]
    fn an_ipv6_rule_matches_only_in_its_bracketed_form() {
        const V6: &str = "[2001:db8::1]";
        assert_eq!(engine("||[2001:db8::1]^\n").check_host(V6), HostVerdict::Block);
        assert_eq!(engine("||2001:db8::1^\n").check_host(V6), HostVerdict::None);
        assert_eq!(engine("||[2001:db8::1]^\n@@||[2001:db8::1]^\n").check_host(V6), HostVerdict::Allow);
        assert_eq!(engine("||198.51.100.25^\n").check_host("198.51.100.25"), HostVerdict::Block);
    }

    #[test]
    fn the_fixture_list_blocks_the_test_host_and_its_subdomains() {
        let e = engine(FIXTURE);
        assert_eq!(e.check_host("ads.sieve-test.invalid"), HostVerdict::Block);
        assert_eq!(e.check_host("x.ads.sieve-test.invalid"), HostVerdict::Block);
        assert_eq!(e.check_host("ok.ads.sieve-test.invalid"), HostVerdict::Allow);
        assert_eq!(e.check_host("news.sieve-test.invalid"), HostVerdict::None);
        assert_eq!(e.check_host("sieve-test.invalid"), HostVerdict::None);
    }

    #[test]
    fn host_checks_ignore_rules_with_party_or_type_constraints() {
        // The synthetic request has no initiator, so a $third-party rule does
        // not decide a bare host (the DNS filter's semantics).
        assert_eq!(engine(FIXTURE).check_host("tracker.sieve-test.invalid"), HostVerdict::None);
        let constrained = engine("||img.sieve-test.invalid^$image\n||fp.sieve-test.invalid^$1p\n");
        assert_eq!(constrained.check_host("img.sieve-test.invalid"), HostVerdict::None);
        assert_eq!(constrained.check_host("fp.sieve-test.invalid"), HostVerdict::None);
    }

    #[test]
    fn every_rule_is_applied_or_skipped_and_counted() {
        let e = engine(FIXTURE);
        let r = &e.reports()[0];
        assert_eq!(r.id, "fixture");
        assert_eq!((r.applied, r.skipped), (5, 1), "{r:?}");
        assert_eq!(r.skip_reasons.values().sum::<usize>(), 1);
    }

    #[test]
    fn reports_are_per_list_in_order() {
        let e = RuleEngine::compile(&[
            ListText { id: "a", text: "||a.sieve-test.invalid^\n", trusted: true },
            ListText { id: "user", text: "||b.sieve-test.invalid^\n! note\n\n", trusted: false },
        ]);
        let ids: Vec<_> = e.reports().iter().map(|r| (r.id.as_str(), r.applied, r.skipped)).collect();
        assert_eq!(ids, [("a", 1, 0), ("user", 1, 0)]);
        assert_eq!(e.check_host("b.sieve-test.invalid"), HostVerdict::Block);
    }

    #[test]
    fn a_name_that_is_not_a_host_matches_nothing() {
        let e = engine(FIXTURE);
        assert_eq!(e.check_host(""), HostVerdict::None);
        assert_eq!(e.check_host("a b"), HostVerdict::None);
    }

    #[test]
    fn the_engine_is_shareable_across_threads() {
        fn shareable<T: Send + Sync>() {}
        shareable::<RuleEngine>();
    }
}
