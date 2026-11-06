//! The law for site names in engine source (plan 5.7): engine logic is derived
//! from lists and rules, so a name of a real site in it is a special case waiting
//! to rot. Scanned: string literals and comments of `engine/crates/**/*.rs` and
//! `engine/injected/bootstrap.js`, by a small lexer, so a Rust field access such
//! as `self.app` is no hit. Not scanned: `sieve-filter/data/sensitive.txt`, data
//! the user decided Sieve ships, and the vendored applier at its pinned hash.
//!
//! A hit is a host-shaped token ending in one of [`SITE_TLDS`], or a bare word
//! from [`SITE_WORDS`]. Reserved names (RFC 2606, 6761) are not sites. Each
//! exception is a row with its reason, and a row that stops occurring fails, so
//! an exemption cannot outlive its cause. A new hit gets fixed, or a row here
//! that says why not.

use std::path::{Path, PathBuf};

const SITE_TLDS: [&str; 8] = ["com", "net", "org", "io", "tv", "dev", "gov", "edu"];
/// The sites plan 5.7 names, in the forms they appear in without a TLD.
const SITE_WORDS: [&str; 4] = ["youtube", "googlevideo", "ytimg", "doubleclick"];
const RESERVED_SUFFIXES: [&str; 4] = [".example", ".invalid", ".test", ".localhost"];
const RESERVED_NAMES: [&str; 3] = ["example.com", "example.org", "example.net"];

/// Scanned below `engine/crates` for Rust, and this one file beside it.
const SCANNED_SCRIPT: &str = "injected/bootstrap.js";
/// The spike's developer tool, never bundled, whose subject is a named test domain.
const EXEMPT_PATH: &str = "sieve-engine/src/bin/probe/";
/// This law's file is not under `crates`, and its control strings are not scanned.
const CRATES: &str = "crates";

/// (file below `crates`, token, why).
const EXCEPTIONS: [(&str, &str, &str); 9] = [
    ("sieve-engine/src/dns/upstream.rs", "cloudflare-dns.com", "a decided DoH default (plan decision table, encrypted DNS)"),
    ("sieve-engine/src/dns/upstream.rs", "dns.quad9.net", "a decided DoH default (plan decision table, encrypted DNS)"),
    ("sieve-filter/src/catalogue.rs", "filters.adtidy.org", "a list's URL is its identity (plan 5.4)"),
    ("sieve-filter/src/catalogue.rs", "ublockorigin.github.io", "a list's URL is its identity (plan 5.4)"),
    ("sieve-filter/src/catalogue.rs", "adguardteam.github.io", "a list's URL is its identity (plan 5.4)"),
    ("sieve-filter/src/catalogue.rs", "github.com", "a list's project page, which its report link derives from (plan 8.4)"),
    ("sieve-engine/src/exclusions/lists.rs", "raw.githubusercontent.com", "a list URL like the catalogue's, disabled until Q1 of the TLS task"),
    ("sieve-filter/src/exclusions.rs", "go.com", "the test's subject is the public suffix table, and .example is no suffix"),
    ("sieve-filter/src/exclusions.rs", "example.gov", "the test's subject is the public suffix table, and .example is no suffix"),
];

fn engine_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is engine/crates/sieve-filter.
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).expect("the engine directory").to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The text inside string literals and comments of Rust or JavaScript source.
/// Rust's raw strings, byte strings and char literals are read by their real
/// rules; a lifetime is not a string.
fn literals_and_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut keep = |from: usize, to: usize| {
        out.push_str(&String::from_utf8_lossy(&bytes[from..to]));
        out.push('\n');
    };
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let end = source[i..].find('\n').map_or(bytes.len(), |n| i + n);
                keep(i + 2, end);
                i = end;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let end = source[i + 2..].find("*/").map_or(bytes.len(), |n| i + 2 + n);
                keep(i + 2, end);
                i = end + 2;
            }
            b'r' if raw_string_start(bytes, i).is_some() => {
                let (body, hashes) = raw_string_start(bytes, i).unwrap();
                let closer = format!("\"{}", "#".repeat(hashes));
                let end = source[body..].find(&closer).map_or(bytes.len(), |n| body + n);
                keep(body, end);
                i = end + closer.len();
            }
            quote @ (b'"' | b'`') => {
                let end = string_end(bytes, i + 1, quote);
                keep(i + 1, end);
                i = end + 1;
            }
            b'\'' => i = after_char_or_lifetime(bytes, i, &mut keep),
            _ => i += 1,
        }
    }
    out
}

/// At an `r` opening a raw string, where its body starts and how many `#` it has.
/// An `r` ending an identifier opens nothing.
fn raw_string_start(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
        return None;
    }
    let hashes = bytes[at + 1..].iter().take_while(|b| **b == b'#').count();
    (bytes.get(at + 1 + hashes) == Some(&b'"')).then_some((at + 2 + hashes, hashes))
}

fn string_end(bytes: &[u8], from: usize, quote: u8) -> usize {
    let mut i = from;
    while i < bytes.len() && bytes[i] != quote {
        i += if bytes[i] == b'\\' { 2 } else { 1 };
    }
    i
}

/// A `'` starts a JavaScript string, a Rust char, or a Rust lifetime. A lifetime
/// has no closing quote on its own word; a short run to the next `'` is a literal.
fn after_char_or_lifetime(bytes: &[u8], at: usize, keep: &mut impl FnMut(usize, usize)) -> usize {
    let word = bytes[at + 1..].iter().take_while(|b| b.is_ascii_alphanumeric() || **b == b'_').count();
    if word > 0 && bytes.get(at + 1 + word) != Some(&b'\'') {
        // In JavaScript a word after a quote can open a string: look for its close
        // on this line, and take it only when the rest reads as one.
        let line_end = bytes[at..].iter().position(|b| *b == b'\n').map_or(bytes.len(), |n| at + n);
        let close = string_end(bytes, at + 1, b'\'');
        if close < line_end && bytes[at + 1..close].iter().all(|b| b.is_ascii_graphic()) && bytes[at + 1 + word] == b'.' {
            keep(at + 1, close);
            return close + 1;
        }
        return at + 1;
    }
    let end = string_end(bytes, at + 1, b'\'');
    if end - at > CHAR_LITERAL_MAX {
        return at + 1;
    }
    end + 1
}

/// `'\u{10ffff}'` is the longest char literal.
const CHAR_LITERAL_MAX: usize = 11;

fn host_tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')).map(|t| t.trim_matches(|c| c == '.' || c == '-')).filter(|t| !t.is_empty())
}

fn is_reserved(token: &str) -> bool {
    RESERVED_SUFFIXES.iter().any(|s| token.ends_with(s)) || RESERVED_NAMES.iter().any(|name| token == *name || token.ends_with(&format!(".{name}")))
}

/// What in this text names a site.
fn site_names(text: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for token in host_tokens(text) {
        let lower = token.to_ascii_lowercase();
        let host_shaped = lower.rsplit_once('.').is_some_and(|(name, tld)| !name.is_empty() && SITE_TLDS.contains(&tld));
        if host_shaped && !is_reserved(&lower) {
            hits.push(lower.clone());
        }
        if SITE_WORDS.iter().any(|word| lower.split(['.', '-']).any(|part| part == *word)) && !is_reserved(&lower) {
            hits.push(lower);
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

fn relative(path: &Path, base: &Path) -> String {
    path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/")
}

/// Every scanned file's text, by its path below `crates` or the engine directory.
fn scanned() -> Vec<(String, String)> {
    let engine = engine_dir();
    let crates = engine.join(CRATES);
    let mut files = Vec::new();
    rust_files(&crates, &mut files);
    let mut texts: Vec<(String, String)> = files.iter().map(|p| (relative(p, &crates), literals_and_comments(&std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))))).filter(|(name, _)| !name.starts_with(EXEMPT_PATH)).collect();
    let script = engine.join(SCANNED_SCRIPT);
    texts.push((SCANNED_SCRIPT.to_string(), literals_and_comments(&std::fs::read_to_string(&script).unwrap_or_else(|e| panic!("{}: {e}", script.display())))));
    texts
}

fn is_excepted(file: &str, token: &str) -> bool {
    EXCEPTIONS.iter().any(|(f, t, _)| *f == file && (token == *t || token.ends_with(&format!(".{t}"))))
}

#[test]
fn engine_source_names_no_site() {
    let found: Vec<String> = scanned().iter().flat_map(|(file, text)| site_names(text).into_iter().filter(move |t| !is_excepted(file, t)).map(move |t| format!("{file}: {t}"))).collect();
    assert!(found.is_empty(), "{} site name(s) in engine source; fix it or add a row saying why:\n{}", found.len(), found.join("\n"));
}

#[test]
fn every_declared_exception_still_occurs() {
    let files = scanned();
    for (file, token, why) in EXCEPTIONS {
        assert!(!why.is_empty(), "{file} {token}: a row says why");
        let text = &files.iter().find(|(name, _)| name == file).unwrap_or_else(|| panic!("{file}: no such file")).1;
        assert!(site_names(text).iter().any(|hit| hit == token || hit.ends_with(&format!(".{token}"))), "{file}: {token} no longer occurs, so its row goes");
    }
}

#[test]
fn the_scanner_catches_a_site_and_skips_reserved_names_and_field_access() {
    let in_a_string = "let host = \"ads.site.com\";";
    let in_a_comment = "// see ads.site.com\nlet x = 1;";
    let in_a_block = "/* ads.site.com */";
    let in_a_raw = "let r = r#\"https://ads.site.com/x\"#;";
    let in_a_template = "const a = `https://ads.site.com/`;";
    let in_a_single_quote = "const a = 'ads.site.com';";
    for source in [in_a_string, in_a_comment, in_a_block, in_a_raw, in_a_template, in_a_single_quote] {
        assert_eq!(site_names(&literals_and_comments(source)), ["ads.site.com"], "{source}");
    }
    for word in ["let s = \"YouTube\";", "// googlevideo", "let s = \"x.ytimg.example\"; // ytimg"] {
        assert!(!site_names(&literals_and_comments(word)).is_empty(), "{word}");
    }
    for clean in [
        "self.app.x(); entry.app; e.app",
        "let s = \"x.example\";",
        "let s = \"page.sieve-test.invalid\";",
        "let s = \"example.com example.org www.example.net\";",
        "let s = \"a.test b.localhost\";",
        "fn f<'a>(x: &'a str) -> &'a str { let c = 'x'; let q = '\\''; x }",
        "let v = \"youtubers are people\";",
    ] {
        assert_eq!(site_names(&literals_and_comments(clean)), Vec::<String>::new(), "{clean}");
    }
}
