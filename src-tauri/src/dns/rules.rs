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
//! Skipped (counted, by `SkipReason`): cosmetic rules (`##`, `#@#`, `#?#`,
//! ...), anything with a `$` modifier (none is understood, so none is guessed
//! at), regex and URL rules, `||name` without `^`, hosts lines mapping to a
//! real address, and every name that is not a host name (`host_name`).
//!
//! A rule name must be a host name: at least two labels, at most 253
//! characters, each label 1 to 63 of `a-z`, `0-9` and `-`, not starting or
//! ending with `-` (punycode `xn--` is fine), and a top-level label that is not
//! all digits (that is an IPv4 address). So URL fragments such as
//! `-tototix.gif`, wildcards, underscores and a stray `||com^` (which would
//! take down a whole TLD) never become rules. A rule the proxy loaded can
//! always be asked for.
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

/// Why a line was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Element hiding (`##` and friends): not a DNS rule.
    Cosmetic,
    /// A `$` modifier: none is understood.
    Modifier,
    /// Regex, URL or `||name` without `^`.
    Syntax,
    /// A hosts line mapping to an address other than a null or loopback one.
    Rewrite,
    /// A label is empty, too long, has a character outside `a-z0-9-`, or
    /// starts or ends with `-`; or the whole name is longer than 253.
    BadLabel,
    /// One label only (`com`, `localhost`).
    SingleLabel,
    /// The top-level label is all digits (an IPv4 address, not a name).
    NumericTld,
}

impl SkipReason {
    pub const ALL: [SkipReason; 7] = [
        SkipReason::Cosmetic,
        SkipReason::Modifier,
        SkipReason::Syntax,
        SkipReason::Rewrite,
        SkipReason::BadLabel,
        SkipReason::SingleLabel,
        SkipReason::NumericTld,
    ];

    fn index(self) -> usize {
        self as usize
    }
}

/// One parsed line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Ignored,
    Skipped(SkipReason),
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
    /// Skipped lines per `SkipReason` (indexed by `SkipReason::index`).
    skipped: [usize; SkipReason::ALL.len()],
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
            Line::Skipped(reason) => self.skipped[reason.index()] += 1,
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
            skipped: self.skipped.iter().sum(),
        }
    }

    /// Lines skipped for `reason`; they add up to `counts().skipped`.
    pub fn skipped(&self, reason: SkipReason) -> usize {
        self.skipped[reason.index()]
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

/// Longest host name, in characters, without the trailing dot (RFC 1035).
pub const MAX_NAME_LEN: usize = 253;
/// Longest label (RFC 1035).
pub const MAX_LABEL_LEN: usize = 63;

/// Rule-side normalization: the host name, lower case, no trailing dot, or
/// why it is not one (see the module doc for the rule).
pub fn host_name(raw: &str) -> Result<String, SkipReason> {
    let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.len() > MAX_NAME_LEN {
        return Err(SkipReason::BadLabel);
    }
    let label_ok = |l: &str| {
        (1..=MAX_LABEL_LEN).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if !d.split('.').all(label_ok) {
        return Err(SkipReason::BadLabel);
    }
    let Some((_, tld)) = d.rsplit_once('.') else {
        return Err(SkipReason::SingleLabel);
    };
    if tld.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SkipReason::NumericTld);
    }
    Ok(d)
}

const COSMETIC_MARKERS: [&str; 6] = ["##", "#@#", "#?#", "#$#", "#%#", "#@$#"];

fn parse_line(raw: &str) -> Line {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
        return Line::Ignored;
    }
    if COSMETIC_MARKERS.iter().any(|m| line.contains(m)) {
        return Line::Skipped(SkipReason::Cosmetic);
    }
    if line.contains('$') {
        return Line::Skipped(SkipReason::Modifier);
    }
    if let Some(rest) = line.strip_prefix("@@||") {
        return anchored(rest).map_or_else(Line::Skipped, Line::AllowTree);
    }
    if let Some(rest) = line.strip_prefix("||") {
        return anchored(rest).map_or_else(Line::Skipped, Line::BlockTree);
    }
    if let Some(hosts) = parse_hosts(line) {
        return hosts;
    }
    if line.contains(['/', '|', '^', '*']) {
        return Line::Skipped(SkipReason::Syntax);
    }
    host_name(line).map_or_else(Line::Skipped, |d| Line::BlockExact(vec![d]))
}

/// `domain^` or `domain^|` -> domain.
fn anchored(rest: &str) -> Result<String, SkipReason> {
    let body = rest.strip_suffix("^|").or_else(|| rest.strip_suffix('^')).ok_or(SkipReason::Syntax)?;
    host_name(body)
}

/// A hosts line, or None when the first token is not an IP address. One
/// name that is not a host name skips the whole line.
fn parse_hosts(line: &str) -> Option<Line> {
    let without_comment = line.split_once('#').map_or(line, |(head, _)| head);
    let mut tokens = without_comment.split_whitespace();
    let ip: std::net::IpAddr = tokens.next()?.parse().ok()?;
    if !(ip.is_unspecified() || ip.is_loopback()) {
        return Some(Line::Skipped(SkipReason::Rewrite));
    }
    match tokens.map(host_name).collect::<Result<Vec<_>, _>>() {
        Ok(names) if !names.is_empty() => Some(Line::BlockExact(names)),
        Ok(_) => Some(Line::Skipped(SkipReason::Syntax)),
        Err(reason) => Some(Line::Skipped(reason)),
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

    /// Not a law: parses the list file named by `SIEVE_LIST_FILE` (read
    /// only) and prints its counts.
    #[test]
    #[ignore = "report: set SIEVE_LIST_FILE to a cached list"]
    fn report_list_counts() {
        let Ok(path) = std::env::var("SIEVE_LIST_FILE") else {
            println!("SIEVE_LIST_FILE is not set");
            return;
        };
        let text = std::fs::read_to_string(&path).expect("read list");
        let r = rules(&text);
        println!("{path}: {:?}", r.counts());
        for reason in SkipReason::ALL {
            println!("  skipped {reason:?}: {}", r.skipped(reason));
        }
    }

    #[test]
    fn names_that_are_not_host_names_are_skipped_never_inserted() {
        let long_label = "a".repeat(64);
        let too_long = format!("{}.com", ["abcdefghij"; 23].join("."));
        assert!(too_long.len() > MAX_NAME_LEN);
        let cases = [
            ("-tototix.gif", SkipReason::BadLabel),
            ("a..b", SkipReason::BadLabel),
            ("foo-.com", SkipReason::BadLabel),
            ("under_score.example.com", SkipReason::BadLabel),
            ("caf\u{e9}.example", SkipReason::BadLabel),
            (long_label.as_str(), SkipReason::BadLabel),
            (too_long.as_str(), SkipReason::BadLabel),
            ("1.2.3.4", SkipReason::NumericTld),
            ("localhost", SkipReason::SingleLabel),
        ];
        for (name, reason) in &cases {
            assert_eq!(host_name(name), Err(*reason), "{name}");
            for line in [name.to_string(), format!("||{name}^"), format!("@@||{name}^"), format!("0.0.0.0 ok.example {name}")] {
                let r = rules(&line);
                assert_eq!(r.counts().block + r.counts().allow, 0, "{line} must not be inserted");
                assert_eq!(r.counts().skipped, 1, "{line}");
                assert_eq!(r.verdict(name), Verdict::None, "{line}");
            }
        }
        let labelled = format!("{long_label}.example.com");
        assert_eq!(host_name(&labelled), Err(SkipReason::BadLabel), "a 64-character label");
        assert_eq!(rules(&format!("||{labelled}^")).counts().skipped, 1);
    }

    #[test]
    fn host_names_are_accepted_including_punycode() {
        let max_label = format!("{}.example", "a".repeat(MAX_LABEL_LEN));
        for name in ["xn--bcher-kva.example", "ads.example.com", "a-b.c0.example", "3com.com", max_label.as_str()] {
            assert_eq!(host_name(name).as_deref(), Ok(name), "{name}");
            let r = rules(&format!("||{name}^"));
            assert_eq!(r.counts(), RuleCounts { block: 1, allow: 0, skipped: 0 }, "{name}");
            assert_eq!(r.verdict(name), Verdict::Block, "{name}");
        }
    }

    #[test]
    fn skips_are_counted_by_reason_and_add_up() {
        let r = rules(
            "a.com##.x\n||a.com^$third-party\n/regex/\n||noanchor.com\n10.0.0.1 r.com\n-x.gif\n||com^\n||1.2.3.4^\n||ok.com^",
        );
        let by_reason: Vec<usize> = SkipReason::ALL.iter().map(|&s| r.skipped(s)).collect();
        assert_eq!(by_reason, vec![1, 1, 2, 1, 1, 1, 1]);
        assert_eq!(r.counts(), RuleCounts { block: 1, allow: 0, skipped: 8 });
    }

    #[test]
    fn empty_and_root_queries_match_nothing() {
        let r = rules("||a.com^");
        assert_eq!(r.verdict(""), Verdict::None);
        assert_eq!(r.verdict("."), Verdict::None);
    }
}
