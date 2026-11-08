//! Content injection (plan 5.6, slice 9): given a rule snapshot, a page URL and a
//! response, produce the rewritten response: [`begin`], then
//! [`PageRewriter::push`] per body chunk, then [`PageRewriter::finish`]. Decrypted
//! responses reach it through [`content::ContentHook`], while `filtering.content`
//! is on; everything but that one type is a pure library.
//!
//! - [`content`]: the HTTP path's hook, and the one consumer of [`begin`];
//! - [`response`]: which responses qualify, and which headers a rewrite falsifies;
//! - [`decode`]: streaming, capped decoding;
//! - [`html`]: where the payload goes, with lol_html;
//! - [`csp`]: the nonce rules;
//! - [`payload`]: the injected elements, safe by construction;
//! - [`privacy`]: tracking protection's page script.
//!
//! On an [`InjectError`] the caller resets the connection: part of a rewritten
//! body has gone out, so it can neither pass the original nor finish cleanly.

pub mod content;
pub mod csp;
pub mod decode;
pub mod html;
pub mod payload;
pub mod privacy;
pub mod response;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::{HeaderMap, StatusCode};
use sieve_filter::rules::RuleSet;
use sieve_ipc::LogChange;

use self::decode::{BodyDecoder, ContentEncoding};
use self::html::{HtmlInjector, has_utf16_bom};
use self::privacy::PageScript;
pub use self::response::PageRequest;

const MIB: u64 = 1024 * 1024;
/// 128 bits from the OS; CSP3 asks for at least that much.
const NONCE_BYTES: usize = 16;

/// Every dial of a rewrite. The ratio, floor and memory numbers are this plan's
/// choice, not measured; the live budgets of slice 9 may move them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InjectLimits {
    /// `inject.maxDecodedBytes` (plan 5.6): most output one body may decode to.
    pub max_decoded_bytes: u64,
    /// Decoded over encoded bytes at which a body is called a bomb.
    pub max_ratio: u64,
    /// Below this much output the ratio is not asked, so small repetitive pages
    /// are not reset.
    pub ratio_floor_bytes: u64,
    /// log2 of the largest zstd window accepted: 23 is 8 MiB, the size RFC 8878
    /// recommends decoders support.
    pub zstd_window_log_max: u32,
    /// lol_html's buffer limit: the most one start tag split across chunks may hold.
    pub rewriter_max_memory_bytes: usize,
}

impl Default for InjectLimits {
    fn default() -> Self {
        Self { max_decoded_bytes: 64 * MIB, max_ratio: 256, ratio_floor_bytes: MIB, zstd_window_log_max: 23, rewriter_max_memory_bytes: MIB as usize }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InjectError {
    #[error("the body decodes past the {cap}-byte cap")]
    DecodedTooLarge { cap: u64 },
    #[error("the body decodes past the {cap}:1 ratio cap")]
    RatioExceeded { cap: u64 },
    #[error("the {encoding:?} body is corrupt or truncated: {reason}")]
    Corrupt { encoding: ContentEncoding, reason: String },
    #[error("the HTML rewriter failed: {0}")]
    Rewriter(String),
}

impl InjectError {
    fn corrupt(encoding: ContentEncoding, reason: &dyn std::fmt::Display) -> Self {
        Self::Corrupt { encoding, reason: reason.to_string() }
    }
}

/// One response body being rewritten. `Send`: the HTTP path holds it across awaits.
pub struct PageRewriter {
    decoder: BodyDecoder,
    html: HtmlInjector,
    has_scriptlets: bool,
    has_procedural: bool,
    /// What Sieve's own script put in this page, for the log.
    own_changes: Vec<LogChange>,
}

impl PageRewriter {
    /// What Sieve's own script changes in this page.
    pub fn own_changes(&self) -> &[LogChange] {
        &self.own_changes
    }

    /// This page gets scriptlets.
    pub fn has_scriptlets(&self) -> bool {
        self.has_scriptlets
    }

    /// This page gets the procedural applier.
    pub fn has_procedural(&self) -> bool {
        self.has_procedural
    }

    /// Feeds one body chunk and returns what is ready to send.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, InjectError> {
        let decoded = self.decoder.push(chunk)?;
        self.html.push(&decoded)
    }

    /// Ends the body and returns the last bytes to send.
    pub fn finish(mut self) -> Result<Vec<u8>, InjectError> {
        let decoded = self.decoder.finish()?;
        let mut out = self.html.push(&decoded)?;
        out.extend(self.html.finish()?);
        Ok(out)
    }
}

fn fresh_nonce() -> Option<String> {
    let mut bytes = [0u8; NONCE_BYTES];
    getrandom::fill(&mut bytes).ok()?;
    Some(STANDARD.encode(bytes))
}

/// Decides on a response from its head. With a rewriter, the headers have been
/// adjusted (CSP nonce, falsified headers gone) and the body must go through it.
/// `None` means the response passes through byte for byte, with `headers`
/// unchanged and without having been decoded.
///
/// `body_start` is the body's first bytes if the caller has any: a UTF-16 BOM
/// overrides the header. A compressed body's start says nothing, so there the
/// BOM is caught once decoded, and the body then passes through uninjected.
pub fn begin(
    rules: &RuleSet,
    request: &PageRequest<'_>,
    status: StatusCode,
    headers: &mut HeaderMap,
    body_start: &[u8],
    limits: &InjectLimits,
) -> Option<PageRewriter> {
    begin_with(rules, &PageScript::default(), request, status, headers, body_start, limits)
}

/// [`begin`] with `own`, Sieve's own code (tracking protection's
/// [`privacy::script`]), run with the page's scriptlets. A page with only its
/// `script` to inject is rewritten for it; its `signals` ride along only on a
/// page rewritten anyway. A page a `$document` exception holds for (the user's
/// or a list's) gets none of it, as AdGuard's `$document` turns its stealth mode
/// off; `$elemhide` does not, as it is about hiding elements only.
pub fn begin_with(
    rules: &RuleSet,
    own: &PageScript,
    request: &PageRequest<'_>,
    status: StatusCode,
    headers: &mut HeaderMap,
    body_start: &[u8],
    limits: &InjectLimits,
) -> Option<PageRewriter> {
    let format = response::body_format(request, status, headers)?;
    if format.encoding == ContentEncoding::Identity && has_utf16_bom(body_start) {
        return None;
    }
    let mut cosmetics = rules.page_cosmetics(request.url);
    let has_scriptlets = !cosmetics.scriptlets.is_empty();
    let has_own = !own.script.is_empty() || !own.signals.is_empty();
    let own_allowed = has_own && !rules.has_document_exception(request.url);
    let mut own_changes = Vec::new();
    if own_allowed && !own.script.is_empty() {
        cosmetics.scriptlets.push_str(&own.script);
        own_changes.clone_from(&own.changes);
    }
    if cosmetics.is_empty() {
        return None;
    }
    if own_allowed {
        cosmetics.scriptlets.push_str(&own.signals);
    }
    let nonce = fresh_nonce()?;
    let decoder = BodyDecoder::new(format.encoding, *limits).ok()?;
    let html = HtmlInjector::new(payload::render(&cosmetics, &nonce), format.charset, limits);
    csp::rewrite_headers(headers, &nonce);
    response::strip_falsified_headers(headers);
    Some(PageRewriter { decoder, html, has_scriptlets, has_procedural: !cosmetics.procedural.is_empty(), own_changes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::CONTENT_SECURITY_POLICY;
    use sieve_filter::rules::{ListText, RuleEngine};
    use std::sync::Arc;

    #[test]
    fn a_page_rewriter_is_send() {
        fn send<T: Send>() {}
        send::<PageRewriter>();
    }

    #[test]
    fn each_response_gets_a_fresh_nonce_of_sixteen_bytes() {
        let (a, b) = (fresh_nonce().unwrap(), fresh_nonce().unwrap());
        assert_ne!(a, b);
        assert_eq!(STANDARD.decode(a).unwrap().len(), NONCE_BYTES);
    }

    #[test]
    fn a_rewrite_end_to_end_decodes_injects_and_adds_the_nonce() {
        let engine = RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(RuleEngine::compile(&[ListText { id: "l", text: "##.x\n", trusted: true }])) };
        let get = http::Method::GET;
        let request = PageRequest { url: "https://sieve-test.invalid/", method: &get, is_document: true };
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/html".parse().unwrap());
        headers.insert("content-encoding", "zstd".parse().unwrap());
        headers.insert(CONTENT_SECURITY_POLICY, "style-src 'self'".parse().unwrap());
        let mut rewriter = begin(&engine, &request, StatusCode::OK, &mut headers, b"", &InjectLimits::default()).unwrap();

        let body = zstd::stream::encode_all(&b"<head><title>t</title>"[..], 3).unwrap();
        let mut out = rewriter.push(&body).unwrap();
        out.extend(rewriter.finish().unwrap());

        let policy = headers.get(CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap();
        let nonce = policy.split("'nonce-").nth(1).unwrap().trim_end_matches('\'');
        assert_eq!(String::from_utf8(out).unwrap(), format!("<head><style nonce=\"{nonce}\">.x{{display:none!important}}</style><title>t</title>"));
    }

    fn page_with(lists: &str, own: &PageScript) -> Option<String> {
        let engine = RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(RuleEngine::compile(&[ListText { id: "l", text: lists, trusted: true }])) };
        let get = http::Method::GET;
        let request = PageRequest { url: "https://sieve-test.invalid/", method: &get, is_document: true };
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/html".parse().unwrap());
        let mut rewriter = begin_with(&engine, own, &request, StatusCode::OK, &mut headers, b"", &InjectLimits::default())?;
        let mut out = rewriter.push(b"<head></head>").unwrap();
        out.extend(rewriter.finish().unwrap());
        Some(String::from_utf8(out).unwrap())
    }

    fn own() -> PageScript {
        PageScript { script: "window.own=1;".into(), changes: vec![LogChange { what: "webRtc".into(), count: 1 }], signals: "window.signals=1;".into() }
    }

    #[test]
    fn a_document_exception_keeps_sieves_own_script_out_and_elemhide_does_not() {
        let page = page_with("", &own()).expect("the own script alone rewrites the page");
        assert!(page.contains("window.own=1;") && page.contains("window.signals=1;"), "{page}");
        for exception in ["@@||sieve-test.invalid^$document", "@@||sieve-test.invalid^$document\n##.x"] {
            let text: &'static str = Box::leak(format!("{exception}\n").into_boxed_str());
            assert!(page_with(text, &own()).is_none_or(|p| !p.contains("window.own") && !p.contains("window.signals")), "{exception}");
        }
        let page = page_with("@@||sieve-test.invalid^$elemhide\n", &own()).unwrap();
        assert!(page.contains("window.own=1;"), "{page}");
    }

    #[test]
    fn the_signals_ride_along_only_on_a_page_rewritten_anyway() {
        let signals_only = PageScript { signals: "window.signals=1;".into(), ..PageScript::default() };
        assert_eq!(page_with("", &signals_only), None, "nothing else to inject: the page passes");
        let page = page_with("##.x\n", &signals_only).unwrap();
        assert!(page.contains("window.signals=1;"), "{page}");
    }
}
