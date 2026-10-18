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

use std::net::IpAddr;

const COMMENT: &str = "//";
const APP_MODIFIER: &str = "app=";
const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq)]
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
