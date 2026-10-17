//! The DNS filter's rule syntax and matcher, COPIED from
//! `src-tauri/src/dns/rules.rs` at commit 949dbf5 (file SHA-256
//! cf92d52a...87bb10), minus `sample_blocked`. Copied, not depended on:
//! the spike must build while another builder edits src-tauri, and a path
//! dependency on the `sieve` crate would pull Tauri, rusqlite and the whole
//! app into the spike's build. If the probe passes, integration moves this
//! module into a small shared crate both the app and the filter service
//! use (one matcher, one place; the copy is temporary).
//!
//! Understood syntax (everything else is counted as skipped, never applied):
//! - `||example.org^` (also `^|`): blocks example.org and every subdomain.
//! - `@@||example.org^`: allows example.org and every subdomain; an allow
//!   rule wins over every block rule.
//! - hosts lines `0.0.0.0 a.com b.com` (also `127.0.0.1`, `::`, `::1`):
//!   block exactly the names listed; other addresses are rewrites, skipped.
//! - a plain `example.org` line: blocks exactly example.org.
//!
//! A lookup walks the label suffixes of the name through HashSets: O(labels).

use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    None,
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuleCounts {
    pub block: usize,
    pub allow: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Ignored,
    Skipped,
    BlockTree(String),
    BlockExact(Vec<String>),
    AllowTree(String),
}

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
}

fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    let mut next = Some(name);
    std::iter::from_fn(move || {
        let current = next?;
        next = current.find('.').map(|i| &current[i + 1..]);
        Some(current)
    })
}

pub fn normalize_query(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}

fn normalize_domain(raw: &str) -> Option<String> {
    let d = raw.trim().trim_end_matches('.').to_lowercase();
    if d.is_empty() || d.len() > 253 || !d.contains('.') {
        return None;
    }
    let labels_ok = d.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && label.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
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

fn anchored(rest: &str) -> Option<String> {
    let body = rest.strip_suffix("^|").or_else(|| rest.strip_suffix('^'))?;
    normalize_domain(body)
}

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
    //! The parity subset of the src-tauri tests: same inputs, same answers.
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
        for text in ["||tracker.net^\n@@||ok.tracker.net^", "@@||ok.tracker.net^\n||tracker.net^"] {
            let r = rules(text);
            assert_eq!(r.verdict("ok.tracker.net"), Verdict::Allow, "{text}");
            assert_eq!(r.verdict("bad.tracker.net"), Verdict::Block, "{text}");
        }
    }

    #[test]
    fn hosts_and_plain_lines_block_exact_names() {
        let r = rules("0.0.0.0 a.com b.com # c\n10.0.0.1 rewrite.com\nplain.example.net");
        assert_eq!(r.verdict("a.com"), Verdict::Block);
        assert_eq!(r.verdict("sub.a.com"), Verdict::None);
        assert_eq!(r.verdict("rewrite.com"), Verdict::None);
        assert_eq!(r.verdict("plain.example.net"), Verdict::Block);
        assert_eq!(r.verdict("x.plain.example.net"), Verdict::None);
        assert_eq!(r.counts(), RuleCounts { block: 3, allow: 0, skipped: 1 });
    }

    #[test]
    fn unknown_syntax_is_skipped_never_applied() {
        let r = rules("example.com##.banner\n||mod.example.com^$important\n||com^\n||noanchor.example.com");
        assert_eq!(r.counts(), RuleCounts { block: 0, allow: 0, skipped: 4 });
        assert_eq!(r.verdict("mod.example.com"), Verdict::None);
    }

    #[test]
    fn case_and_trailing_dot() {
        let r = rules("||MiXeD.Example.COM.^");
        assert_eq!(r.verdict("A.MIXED.EXAMPLE.COM."), Verdict::Block);
    }
}
