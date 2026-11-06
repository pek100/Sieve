//! Makes a page's `Content-Security-Policy` admit Sieve's two elements (plan 5.6
//! item 5). Each header, and each comma-separated policy inside one, is enforced
//! on its own, so each is rewritten. Nothing is ever removed from a policy.
//!
//! For scripts the governing directive is the first of `script-src-elem`,
//! `script-src`, `default-src`; for styles the same with `style`:
//! - none present: the policy already allows the element, no change;
//! - it relies on `'unsafe-inline'`, with no nonce or hash: no change, because
//!   a nonce there would switch `'unsafe-inline'` off and break the site;
//! - a specific directive: gets the nonce;
//! - only `default-src`: left alone, and a new specific directive copied from
//!   it, plus the nonce, is added.
//!
//! `Content-Security-Policy-Report-Only` is never touched: it blocks nothing.

use http::HeaderMap;
use http::header::{CONTENT_SECURITY_POLICY, HeaderValue};

const DEFAULT_SRC: &str = "default-src";
const SCRIPT_CHAIN: [&str; 3] = ["script-src-elem", "script-src", DEFAULT_SRC];
const STYLE_CHAIN: [&str; 3] = ["style-src-elem", "style-src", DEFAULT_SRC];
/// What a directive added for a `default-src`-only policy is called.
const SCRIPT_SRC: &str = "script-src";
const STYLE_SRC: &str = "style-src";
const UNSAFE_INLINE: &str = "'unsafe-inline'";
const NONCE_PREFIX: &str = "'nonce-";
const HASH_PREFIXES: [&str; 3] = ["'sha256-", "'sha384-", "'sha512-"];

fn has_prefix(token: &str, prefix: &str) -> bool {
    token.get(..prefix.len()).is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

/// Would a nonce here disable `'unsafe-inline'`? True when it is what lets inline
/// code run today, so the site's own inline code depends on it.
fn relies_on_unsafe_inline(sources: &[&str]) -> bool {
    let inline = sources.iter().any(|s| s.eq_ignore_ascii_case(UNSAFE_INLINE));
    let keyed = sources.iter().any(|s| has_prefix(s, NONCE_PREFIX) || HASH_PREFIXES.iter().any(|p| has_prefix(s, p)));
    inline && !keyed
}

fn tokens(directive: &str) -> impl Iterator<Item = &str> {
    directive.split_ascii_whitespace()
}

/// Rewrites one policy for one element kind, given as directive texts.
fn admit(directives: &mut Vec<String>, chain: &[&str; 3], added_name: &str, nonce_source: &str) {
    let find = |directives: &[String], name: &str| directives.iter().position(|d| tokens(d).next().is_some_and(|n| n.eq_ignore_ascii_case(name)));
    let Some((index, name)) = chain.iter().find_map(|name| find(directives, name).map(|i| (i, *name))) else {
        return;
    };
    let sources: Vec<&str> = tokens(&directives[index]).skip(1).collect();
    if relies_on_unsafe_inline(&sources) {
        return;
    }
    if name == DEFAULT_SRC {
        let copied = format!("{added_name} {} {nonce_source}", sources.join(" "));
        directives.push(copied.split_ascii_whitespace().collect::<Vec<_>>().join(" "));
    } else {
        let directive = &mut directives[index];
        directive.truncate(directive.trim_end().len());
        directive.push(' ');
        directive.push_str(nonce_source);
    }
}

fn add_nonce_to_policy(policy: &str, nonce_source: &str) -> String {
    let mut directives: Vec<String> = policy.split(';').filter(|d| !d.trim().is_empty()).map(str::to_string).collect();
    let before = directives.clone();
    admit(&mut directives, &SCRIPT_CHAIN, SCRIPT_SRC, nonce_source);
    admit(&mut directives, &STYLE_CHAIN, STYLE_SRC, nonce_source);
    if directives == before {
        return policy.to_string();
    }
    let joined: Vec<&str> = directives.iter().map(|d| d.trim()).collect();
    joined.join("; ")
}

/// Returns `policy_value` (one header value, possibly several policies) with the
/// nonce added where the module doc says. Text that is not visible ASCII is left
/// alone: the browser then blocks our element, which is harmless.
pub fn add_nonce(policy_value: &str, nonce: &str) -> String {
    if !policy_value.bytes().all(|b| b == b'\t' || (b' '..=b'~').contains(&b)) {
        return policy_value.to_string();
    }
    let nonce_source = format!("{NONCE_PREFIX}{nonce}'");
    let policies: Vec<String> = policy_value.split(',').map(|policy| add_nonce_to_policy(policy, &nonce_source)).collect();
    policies.join(",")
}

/// Rewrites every enforcing CSP header of a response in place, keeping their order.
pub fn rewrite_headers(headers: &mut HeaderMap, nonce: &str) {
    let values: Vec<HeaderValue> = headers.get_all(CONTENT_SECURITY_POLICY).iter().cloned().collect();
    headers.remove(CONTENT_SECURITY_POLICY);
    for value in values {
        let rewritten = value.to_str().ok().and_then(|text| HeaderValue::from_str(&add_nonce(text, nonce)).ok());
        headers.append(CONTENT_SECURITY_POLICY, rewritten.unwrap_or(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const N: &str = "abc";
    const ADDED: &str = "'nonce-abc'";

    fn rewrite(policy: &str) -> String {
        add_nonce(policy, N)
    }

    #[test]
    fn unsafe_inline_is_left_alone() {
        for policy in ["script-src 'unsafe-inline'; style-src 'UNSAFE-INLINE' https:", "default-src 'unsafe-inline'"] {
            assert_eq!(rewrite(policy), policy);
        }
    }

    #[test]
    fn the_nonce_is_added_to_the_specific_directive() {
        assert_eq!(rewrite("script-src 'self'"), format!("script-src 'self' {ADDED}"));
        assert_eq!(rewrite("style-src https:"), format!("style-src https: {ADDED}"));
        assert_eq!(rewrite("script-src-elem 'self'"), format!("script-src-elem 'self' {ADDED}"));
        assert_eq!(rewrite("style-src-elem 'self'"), format!("style-src-elem 'self' {ADDED}"));
    }

    #[test]
    fn the_most_specific_directive_governs() {
        assert_eq!(rewrite("script-src 'self'; script-src-elem https:"), format!("script-src 'self'; script-src-elem https: {ADDED}"));
        // script-src-elem relies on unsafe-inline, so it allows us; script-src is not asked.
        let policy = "script-src 'self'; script-src-elem 'unsafe-inline'";
        assert_eq!(rewrite(policy), policy);
    }

    #[test]
    fn unsafe_inline_with_a_nonce_or_hash_is_already_off_so_it_gets_the_nonce() {
        assert_eq!(rewrite("script-src 'unsafe-inline' 'nonce-x'"), format!("script-src 'unsafe-inline' 'nonce-x' {ADDED}"));
        assert_eq!(rewrite("style-src 'unsafe-inline' 'sha256-x'"), format!("style-src 'unsafe-inline' 'sha256-x' {ADDED}"));
    }

    #[test]
    fn default_src_alone_is_copied_into_new_script_and_style_directives() {
        assert_eq!(rewrite("default-src 'self' https:"), format!("default-src 'self' https:; script-src 'self' https: {ADDED}; style-src 'self' https: {ADDED}"));
    }

    #[test]
    fn default_src_is_copied_only_for_the_kind_with_no_directive_of_its_own() {
        assert_eq!(rewrite("default-src 'self'; style-src https:"), format!("default-src 'self'; style-src https: {ADDED}; script-src 'self' {ADDED}"));
    }

    #[test]
    fn none_gets_the_nonce_and_keeps_none() {
        assert_eq!(rewrite("script-src 'none'"), format!("script-src 'none' {ADDED}"));
        assert_eq!(rewrite("default-src 'none'"), format!("default-src 'none'; script-src 'none' {ADDED}; style-src 'none' {ADDED}"));
    }

    #[test]
    fn strict_dynamic_is_kept() {
        assert_eq!(rewrite("script-src 'strict-dynamic' 'nonce-page'"), format!("script-src 'strict-dynamic' 'nonce-page' {ADDED}"));
    }

    #[test]
    fn no_governing_directive_means_no_change() {
        for policy in ["img-src 'self'", "script-src-attr 'none'; require-trusted-types-for 'script'", ""] {
            assert_eq!(rewrite(policy), policy);
        }
    }

    #[test]
    fn two_policies_in_one_value_are_both_rewritten() {
        assert_eq!(rewrite("script-src 'self', style-src https:"), format!("script-src 'self' {ADDED},style-src https: {ADDED}"));
    }

    #[test]
    fn directive_names_match_in_any_case_and_a_trailing_semicolon_is_fine() {
        assert_eq!(rewrite("SCRIPT-SRC 'self';  "), format!("SCRIPT-SRC 'self' {ADDED}"));
    }

    #[test]
    fn the_first_of_duplicate_directives_is_the_one_that_counts() {
        assert_eq!(rewrite("script-src 'self'; script-src https:"), format!("script-src 'self' {ADDED}; script-src https:"));
    }

    #[test]
    fn a_non_ascii_value_is_untouched() {
        let policy = "script-src 'self' https://caf\u{e9}.invalid";
        assert_eq!(rewrite(policy), policy);
    }

    fn headers_of(pairs: &[(&'static str, &[u8])]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_bytes(value).unwrap());
        }
        map
    }

    #[test]
    fn every_enforcing_header_is_rewritten_in_order_and_report_only_is_untouched() {
        let mut headers = headers_of(&[
            ("content-security-policy", b"script-src 'self'"),
            ("content-security-policy", b"style-src 'self'"),
            ("content-security-policy-report-only", b"script-src 'self'"),
        ]);
        rewrite_headers(&mut headers, N);
        let enforcing: Vec<_> = headers.get_all(CONTENT_SECURITY_POLICY).iter().map(|v| v.to_str().unwrap().to_string()).collect();
        assert_eq!(enforcing, [format!("script-src 'self' {ADDED}"), format!("style-src 'self' {ADDED}")]);
        assert_eq!(headers.get("content-security-policy-report-only").unwrap(), "script-src 'self'");
    }

    #[test]
    fn a_header_value_that_is_not_text_is_untouched() {
        let mut headers = headers_of(&[("content-security-policy", b"script-src \xe9")]);
        rewrite_headers(&mut headers, N);
        assert_eq!(headers.get(CONTENT_SECURITY_POLICY).unwrap().as_bytes(), b"script-src \xe9");
    }

    #[test]
    fn no_csp_header_stays_no_csp_header() {
        let mut headers = HeaderMap::new();
        rewrite_headers(&mut headers, N);
        assert!(headers.is_empty());
    }

    fn policy_strategy() -> impl Strategy<Value = String> {
        let name = prop::sample::select(vec!["default-src", "script-src", "script-src-elem", "style-src", "style-src-elem", "img-src", "sandbox"]);
        let source = prop::sample::select(vec!["'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'nonce-page'", "'sha256-x'", "https:", "a.invalid"]);
        let directive = (name, prop::collection::vec(source, 0..4)).prop_map(|(n, s)| format!("{n} {}", s.join(" ")));
        let policy = prop::collection::vec(directive, 0..5).prop_map(|d| d.join("; "));
        prop::collection::vec(policy, 1..3).prop_map(|p| p.join(", "))
    }

    proptest! {
        #[test]
        fn every_source_token_of_the_input_survives(policy in policy_strategy()) {
            let output = rewrite(&policy);
            for (before, after) in policy.split(',').zip(output.split(',')) {
                let kept: Vec<&str> = after.split(|c: char| c == ';' || c.is_ascii_whitespace()).collect();
                for token in before.split(|c: char| c == ';' || c.is_ascii_whitespace()).filter(|t| !t.is_empty()) {
                    prop_assert!(kept.contains(&token), "{token} lost from {before:?} in {after:?}");
                }
            }
        }

        #[test]
        fn a_second_rewrite_with_another_nonce_loses_nothing(policy in policy_strategy()) {
            let once = rewrite(&policy);
            let twice = add_nonce(&once, "second");
            for token in once.split(|c: char| c == ';' || c == ',' || c.is_ascii_whitespace()).filter(|t| !t.is_empty()) {
                prop_assert!(twice.contains(token));
            }
        }
    }
}
