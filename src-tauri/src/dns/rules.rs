//! Filter rules: the adblock-style DNS subset used by the AdGuard DNS filter.
//!
//! Understood syntax (everything else is counted as skipped, never applied):
//! - `||example.org^` (also `^|`): blocks example.org and every subdomain.
//! - `@@||example.org^`: allows example.org and every subdomain. An allow
//!   rule wins over every block rule, whatever the order or source.
//! - hosts lines `0.0.0.0 a.com b.com` (also `127.0.0.1`, `::`, `::1`),
//!   trailing `# comment` allowed: block exactly the names listed. A hosts
//!   line that maps to any other address is a rewrite, which is skipped.
//! - a plain `example.org` line: blocks exactly example.org (hosts-file
//!   meaning; the conservative reading, it never widens to subdomains).
//!
//! Ignored silently: blank lines, comments starting with `!` or `#`.
//! Skipped (counted): cosmetic rules (`##`, `#@#`, `#?#`, ...), anything with
//! a `$` modifier (none is understood, so none is guessed at), regex and URL
//! rules, wildcards, `||name` without `^`, and single-label names (a stray
//! `||com^` would take down a whole TLD; no real list needs one).
//!
//! Names are compared lower case with any trailing dot removed. IDNA names
//! are not converted: punycode (`xn--...`) matches punycode, as on the wire.
//! A lookup walks the label suffixes of the query through HashSets, so it
//! costs O(labels), never a regex per query.

use std::collections::HashSet;

/// What the rules say about one query name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No rule matched: forward.
    None,
    /// An allow rule matched: forward, even if a block rule also matched.
    Allow,
    /// A block rule matched and no allow rule did.
    Block,
}

/// Rule counts as loaded (distinct rules, duplicates collapse).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuleCounts {
    /// Block rules (subtree plus exact).
    pub block: usize,
    /// Allow rules.
    pub allow: usize,
    /// Lines that looked like rules but are not understood, so not applied.
    pub skipped: usize,
}

/// One parsed line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Ignored,
    Skipped,
    BlockTree(String),
    BlockExact(Vec<String>),
    AllowTree(String),
}

/// A merged set of rules from any number of sources.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    block_tree: HashSet<String>,
    block_exact: HashSet<String>,
    allow_tree: HashSet<String>,
    skipped: usize,
}

impl RuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses `text` (one rule per line) and merges it into this set.
    pub fn add_text(&mut self, text: &str) {
        for line in text.lines() {
            self.add_line(line);
        }
    }

    pub fn add_line(&mut self, raw: &str) {
        match parse_line(raw) {
            Line::Ignored => {}
            Line::Skipped => self.skipped += 1,
            Line::BlockTree(d) => {
                self.block_tree.insert(d);
            }
            Line::BlockExact(names) => self.block_exact.extend(names),
            Line::AllowTree(d) => {
                self.allow_tree.insert(d);
            }
        }
    }

    pub fn counts(&self) -> RuleCounts {
        RuleCounts {
            block: self.block_tree.len() + self.block_exact.len(),
            allow: self.allow_tree.len(),
            skipped: self.skipped,
        }
    }

    /// The verdict for a query name (any case, trailing dot allowed).
    pub fn verdict(&self, name: &str) -> Verdict {
        let name = normalize_query(name);
        if name.is_empty() {
            return Verdict::None;
        }
        if suffixes(&name).any(|s| self.allow_tree.contains(s)) {
            return Verdict::Allow;
        }
        if self.block_exact.contains(&name) || suffixes(&name).any(|s| self.block_tree.contains(s)) {
            return Verdict::Block;
        }
        Verdict::None
    }

    /// A name these rules block, chosen deterministically (the smallest in
    /// byte order), for the self check. None when nothing is blocked.
    pub fn sample_blocked(&self) -> Option<String> {
        self.block_tree
            .iter()
            .chain(self.block_exact.iter())
            .filter(|d| self.verdict(d) == Verdict::Block)
            .min()
            .cloned()
    }
}

/// The name and each parent: `a.b.c`, `b.c`, `c`.
fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    let mut next = Some(name);
    std::iter::from_fn(move || {
        let current = next?;
        next = current.find('.').map(|i| &current[i + 1..]);
        Some(current)
    })
}

/// Query-side normalization: lower case, no trailing dot. No validation: a
/// name that no rule could contain simply matches nothing.
pub fn normalize_query(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}

/// Rule-side normalization: lower case, no trailing dot, at least two
/// labels, each 1 to 63 characters of letters, digits, `-` or `_`.
fn normalize_domain(raw: &str) -> Option<String> {
    let d = raw.trim().trim_end_matches('.').to_lowercase();
    if d.is_empty() || d.len() > 253 || !d.contains('.') {
        return None;
    }
    let labels_ok = d.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    });
    labels_ok.then_some(d)
}

const COSMETIC_MARKERS: [&str; 6] = ["##", "#@#", "#?#", "#$#", "#%#", "#@$#"];

fn parse_line(raw: &str) -> Line {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
        return Line::Ignored;
    }
    if COSMETIC_MARKERS.iter().any(|m| line.contains(m)) || line.contains('$') {
        return Line::Skipped;
    }
    if let Some(rest) = line.strip_prefix("@@||") {
        return anchored(rest).map_or(Line::Skipped, Line::AllowTree);
    }
    if let Some(rest) = line.strip_prefix("||") {
        return anchored(rest).map_or(Line::Skipped, Line::BlockTree);
    }
    if let Some(hosts) = parse_hosts(line) {
        return hosts;
    }
    normalize_domain(line).map_or(Line::Skipped, |d| Line::BlockExact(vec![d]))
}

/// `domain^` or `domain^|` -> domain.
fn anchored(rest: &str) -> Option<String> {
    let body = rest.strip_suffix("^|").or_else(|| rest.strip_suffix('^'))?;
    normalize_domain(body)
}

/// A hosts line, or None when the first token is not an IP address.
fn parse_hosts(line: &str) -> Option<Line> {
    let without_comment = line.split_once('#').map_or(line, |(head, _)| head);
    let mut tokens = without_comment.split_whitespace();
    let ip: std::net::IpAddr = tokens.next()?.parse().ok()?;
    if !(ip.is_unspecified() || ip.is_loopback()) {
        return Some(Line::Skipped);
    }
    let names: Option<Vec<String>> = tokens.map(normalize_domain).collect();
    match names {
        Some(names) if !names.is_empty() => Some(Line::BlockExact(names)),
        _ => Some(Line::Skipped),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> RuleSet {
        let mut r = RuleSet::new();
        r.add_text(text);
        r
    }

    #[test]
    fn subtree_rule_blocks_domain_and_subdomains_only() {
        let r = rules("||ads.example.com^");
        assert_eq!(r.verdict("ads.example.com"), Verdict::Block);
        assert_eq!(r.verdict("x.y.ads.example.com"), Verdict::Block);
        assert_eq!(r.verdict("example.com"), Verdict::None);
        assert_eq!(r.verdict("badads.example.com"), Verdict::None);
        assert_eq!(r.verdict("ads.example.com.evil.net"), Verdict::None);
    }

    #[test]
    fn allow_wins_over_block_in_any_order() {
        for text in [
            "||tracker.net^\n@@||ok.tracker.net^",
            "@@||ok.tracker.net^\n||tracker.net^",
        ] {
            let r = rules(text);
            assert_eq!(r.verdict("ok.tracker.net"), Verdict::Allow, "{text}");
            assert_eq!(r.verdict("a.ok.tracker.net"), Verdict::Allow, "{text}");
            assert_eq!(r.verdict("bad.tracker.net"), Verdict::Block, "{text}");
        }
        let r = rules("ads.site.org\n@@||site.org^");
        assert_eq!(r.verdict("ads.site.org"), Verdict::Allow);
    }

    #[test]
    fn hosts_lines_block_exact_names_from_null_addresses_only() {
        let r = rules(
            "0.0.0.0 a.com b.com # trailing comment\n127.0.0.1 c.com\n:: d.com\n::1 e.com\n10.0.0.1 rewrite.com",
        );
        for n in ["a.com", "b.com", "c.com", "d.com", "e.com"] {
            assert_eq!(r.verdict(n), Verdict::Block, "{n}");
        }
        assert_eq!(r.verdict("sub.a.com"), Verdict::None);
        assert_eq!(r.verdict("rewrite.com"), Verdict::None);
        assert_eq!(r.counts(), RuleCounts { block: 5, allow: 0, skipped: 1 });
    }

    #[test]
    fn plain_domain_line_blocks_exactly_that_name() {
        let r = rules("plain.example.net");
        assert_eq!(r.verdict("plain.example.net"), Verdict::Block);
        assert_eq!(r.verdict("sub.plain.example.net"), Verdict::None);
    }

    #[test]
    fn comments_and_blanks_are_ignored_not_counted() {
        let r = rules("! Title: x\n# hosts comment\n\n   \n!||not.a.rule^");
        assert_eq!(r.counts(), RuleCounts::default());
    }

    #[test]
    fn cosmetic_modifier_and_unknown_rules_are_skipped_never_applied() {
        let text = [
            "example.com##.banner",
            "example.com#@#.ad",
            "example.com#?#div:has(.ad)",
            "||mod.example.com^$important",
            "||mod2.example.com^$dnstype=AAAA",
            "@@||allowmod.example.com^$client=1.2.3.4",
            "/ads[0-9]+\\.com/",
            "||wild*.example.com^",
            "||noanchor.example.com",
            "|http://url.example.com/",
            "||com^",
            "localhost",
            "127.0.0.1 localhost",
        ]
        .join("\n");
        let r = rules(&text);
        assert_eq!(r.counts(), RuleCounts { block: 0, allow: 0, skipped: 13 });
        for n in ["example.com", "mod.example.com", "mod2.example.com", "noanchor.example.com", "x.com"] {
            assert_eq!(r.verdict(n), Verdict::None, "{n}");
        }
    }

    #[test]
    fn matching_is_case_insensitive_and_trailing_dot_tolerant() {
        let r = rules("||MiXeD.Example.COM.^\n0.0.0.0 Host.Example.ORG.");
        assert_eq!(r.verdict("mixed.example.com"), Verdict::Block);
        assert_eq!(r.verdict("A.MIXED.EXAMPLE.COM."), Verdict::Block);
        assert_eq!(r.verdict("host.example.org."), Verdict::Block);
    }

    #[test]
    fn punycode_passes_through_unchanged() {
        let r = rules("||xn--80ak6aa92e.com^");
        assert_eq!(r.verdict("ads.xn--80ak6aa92e.com."), Verdict::Block);
        assert_eq!(r.verdict("xn--80ak6aa92e.net"), Verdict::None);
    }

    #[test]
    fn trailing_pipe_anchor_is_understood() {
        let r = rules("||pipe.example.com^|");
        assert_eq!(r.verdict("pipe.example.com"), Verdict::Block);
    }

    #[test]
    fn counts_are_distinct_rules() {
        let r = rules("||a.com^\n||a.com^\n@@||b.com^\nc.com\n0.0.0.0 c.com\n$bad");
        assert_eq!(r.counts(), RuleCounts { block: 2, allow: 1, skipped: 1 });
    }

    #[test]
    fn sample_blocked_is_deterministic_and_actually_blocked() {
        let r = rules("||zz.com^\n||aa.com^\n@@||aa.com^\nmm.com");
        assert_eq!(r.sample_blocked().as_deref(), Some("mm.com"));
        assert_eq!(RuleSet::new().sample_blocked(), None);
    }

    #[test]
    fn empty_and_root_queries_match_nothing() {
        let r = rules("||a.com^");
        assert_eq!(r.verdict(""), Verdict::None);
        assert_eq!(r.verdict("."), Verdict::None);
    }
}
