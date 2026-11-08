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

use self::decode::{BodyDecoder, ContentEncoding};
use self::html::{HtmlInjector, has_utf16_bom};
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
}

impl PageRewriter {
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
    begin_with(rules, "", request, status, headers, body_start, limits)
}

/// [`begin`] with `own_script`, Sieve's own code (tracking protection's
/// [`privacy::script`]), run with the page's scriptlets. A page with only that
/// to inject is rewritten for it.
pub fn begin_with(
    rules: &RuleSet,
    own_script: &str,
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
    cosmetics.scriptlets.push_str(own_script);
    if cosmetics.is_empty() {
        return None;
    }
    let nonce = fresh_nonce()?;
    let decoder = BodyDecoder::new(format.encoding, *limits).ok()?;
    let html = HtmlInjector::new(payload::render(&cosmetics, &nonce), format.charset, limits);
    csp::rewrite_headers(headers, &nonce);
    response::strip_falsified_headers(headers);
    Some(PageRewriter { decoder, html, has_scriptlets, has_procedural: !cosmetics.procedural.is_empty() })
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
}
