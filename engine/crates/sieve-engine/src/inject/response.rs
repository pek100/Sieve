//! Which responses are rewritten, and how the head changes (plan 5.6). Anything
//! not plainly a whole HTML document Sieve can read passes through byte for byte.
//!
//! Status: 200 to 299 except 204 and 205 (no body) and 206 (a fragment, which an
//! injection would corrupt). The document/subdocument classification is the
//! caller's (plan 5.2).

use http::header::{ACCEPT_RANGES, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HeaderName, LAST_MODIFIED};
use http::{HeaderMap, Method, StatusCode};
use lol_html::AsciiCompatibleEncoding;

use super::decode::ContentEncoding;

const HTML_MEDIA_TYPE: &str = "text/html";
const CHARSET_PARAMETER: &str = "charset";
const INLINE_DISPOSITION: &str = "inline";
/// Headers a rewritten body falsifies, beside the ones `http` has constants for.
const FALSIFIED_NAMES: [&str; 2] = ["content-digest", "repr-digest"];

/// What the request side knows about a response being considered.
#[derive(Debug, Clone, Copy)]
pub struct PageRequest<'a> {
    pub url: &'a str,
    pub method: &'a Method,
    /// A `document` or `subdocument` request.
    pub is_document: bool,
}

/// How to read a response Sieve may rewrite.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BodyFormat {
    pub encoding: ContentEncoding,
    pub charset: AsciiCompatibleEncoding,
}

fn rewritable_status(status: StatusCode) -> bool {
    status.is_success() && ![StatusCode::NO_CONTENT, StatusCode::RESET_CONTENT, StatusCode::PARTIAL_CONTENT].contains(&status)
}

/// The header's one value as text. Several values, or bytes that are not text,
/// are not something Sieve can be sure it understands.
fn single_value<'h>(headers: &'h HeaderMap, name: &HeaderName) -> Result<Option<&'h str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    first.to_str().map(Some).map_err(drop)
}

/// A `text/html` charset parameter as the parser needs it. `None` for one the
/// rewriter cannot read. An unknown label is ignored, as browsers ignore it, and
/// the page parses as UTF-8: tag syntax is the same in every encoding accepted.
fn html_charset(content_type: &str) -> Option<AsciiCompatibleEncoding> {
    let mut parts = content_type.split(';');
    if !parts.next()?.trim().eq_ignore_ascii_case(HTML_MEDIA_TYPE) {
        return None;
    }
    let label = parts.find_map(|part| {
        let (name, value) = part.split_once('=')?;
        name.trim().eq_ignore_ascii_case(CHARSET_PARAMETER).then(|| value.trim().trim_matches('"'))
    });
    match label.and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes())) {
        Some(encoding) => AsciiCompatibleEncoding::new(encoding),
        None => Some(AsciiCompatibleEncoding::utf_8()),
    }
}

/// Whether the browser shows this response rather than saving it. A saved file
/// must keep its bytes. Only a missing header or the `inline` type says "shown":
/// RFC 6266 has an unknown type handled as `attachment`.
fn displayed_inline(headers: &HeaderMap) -> bool {
    match single_value(headers, &CONTENT_DISPOSITION) {
        Ok(None) => true,
        Ok(Some(value)) => value.split(';').next().is_some_and(|kind| kind.trim().eq_ignore_ascii_case(INLINE_DISPOSITION)),
        Err(()) => false,
    }
}

/// How to read this response if it may be rewritten, from its head alone.
pub fn body_format(request: &PageRequest<'_>, status: StatusCode, headers: &HeaderMap) -> Option<BodyFormat> {
    if !request.is_document || *request.method == Method::HEAD || !rewritable_status(status) || !displayed_inline(headers) {
        return None;
    }
    let charset = html_charset(single_value(headers, &CONTENT_TYPE).ok()??)?;
    let encoding = match single_value(headers, &CONTENT_ENCODING).ok()? {
        None => ContentEncoding::Identity,
        Some(value) => ContentEncoding::from_header(value)?,
    };
    Some(BodyFormat { encoding, charset })
}

/// Removes every header the rewritten body falsifies. The CSP is `csp`'s. A
/// validator describes the origin's bytes, and the bytes differ per response by
/// the nonce: a 304 would reuse a page whose nonce matches no CSP in that 304.
pub fn strip_falsified_headers(headers: &mut HeaderMap) {
    for name in [CONTENT_ENCODING, CONTENT_LENGTH, ACCEPT_RANGES, ETAG, LAST_MODIFIED] {
        headers.remove(name);
    }
    for name in FALSIFIED_NAMES {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{InjectLimits, begin};
    use super::*;
    use http::HeaderValue;
    use sieve_filter::rules::{ListText, RuleEngine, RuleSet};
    use std::sync::Arc;

    const URL: &str = "https://sieve-test.invalid/";

    fn list_rules(text: &str) -> RuleSet {
        RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(RuleEngine::compile(&[ListText { id: "l", text, trusted: true }])) }
    }

    fn rules() -> RuleSet {
        list_rules("##.x\n")
    }

    fn headers_of(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_static(value));
        }
        map
    }

    const HTML: (&str, &str) = ("content-type", "text/html; charset=utf-8");

    fn request(method: &Method) -> PageRequest<'_> {
        PageRequest { url: URL, method, is_document: true }
    }

    /// `begin` on this head: the rewriter's existence, and the head afterwards.
    fn attempt(request: &PageRequest<'_>, engine: &RuleSet, status: u16, pairs: &[(&'static str, &'static str)], start: &[u8]) -> (bool, HeaderMap) {
        let mut headers = headers_of(pairs);
        let rewriter = begin(engine, request, StatusCode::from_u16(status).unwrap(), &mut headers, start, &InjectLimits::default());
        (rewriter.is_some(), headers)
    }

    #[track_caller]
    fn assert_passes_through(request: &PageRequest<'_>, engine: &RuleSet, status: u16, pairs: &[(&'static str, &'static str)], start: &[u8]) {
        let (rewriting, headers) = attempt(request, engine, status, pairs, start);
        assert!(!rewriting, "{status} {pairs:?}");
        assert_eq!(headers, headers_of(pairs), "headers must not change");
    }

    #[test]
    fn a_plain_html_document_is_rewritten() {
        for status in [200, 201, 203, 226] {
            assert!(attempt(&request(&Method::GET), &rules(), status, &[HTML], b"").0, "{status}");
        }
        assert!(attempt(&request(&Method::POST), &rules(), 200, &[HTML], b"").0);
    }

    #[test]
    fn head_and_statuses_without_a_whole_body_pass_through() {
        let engine = rules();
        assert_passes_through(&request(&Method::HEAD), &engine, 200, &[HTML, ("content-length", "5")], b"");
        for status in [204, 205, 206, 301, 304, 404, 500] {
            assert_passes_through(&request(&Method::GET), &engine, status, &[HTML, ("content-length", "5")], b"");
        }
    }

    #[test]
    fn a_response_that_is_not_html_passes_through() {
        let engine = rules();
        let get = Method::GET;
        for value in ["application/json", "text/plain", "application/xhtml+xml", "text/htmlx", "\u{0}"] {
            if let Ok(parsed) = HeaderValue::from_str(value) {
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, parsed);
                let before = headers.clone();
                assert!(begin(&engine, &request(&get), StatusCode::OK, &mut headers, b"", &InjectLimits::default()).is_none(), "{value}");
                assert_eq!(headers, before);
            }
        }
        assert_passes_through(&request(&get), &engine, 200, &[], b"");
        assert_passes_through(&request(&get), &engine, 200, &[HTML, HTML], b"");
    }

    #[test]
    fn a_charset_the_rewriter_cannot_read_passes_through() {
        let engine = rules();
        let get = Method::GET;
        for value in ["text/html; charset=utf-16", "text/html;charset=UTF-16BE", "text/html; charset=\"iso-2022-jp\"", "TEXT/HTML; CHARSET=replacement"] {
            let value: &'static str = value;
            assert_passes_through(&request(&get), &engine, 200, &[("content-type", value)], b"");
        }
    }

    #[test]
    fn ascii_compatible_charsets_are_rewritten_and_an_unknown_label_is_ignored() {
        let engine = rules();
        for value in ["TEXT/HTML", "text/html; charset=shift_jis", "text/html; charset=\"windows-1252\"", "text/html; charset=bogus", "text/html; boundary=x; charset=euc-kr"] {
            let value: &'static str = value;
            assert!(attempt(&request(&Method::GET), &engine, 200, &[("content-type", value)], b"").0, "{value}");
        }
    }

    #[test]
    fn a_utf16_bom_passes_through_whatever_the_header_says() {
        let engine = rules();
        assert_passes_through(&request(&Method::GET), &engine, 200, &[HTML], &[0xff, 0xfe, b'<']);
        assert_passes_through(&request(&Method::GET), &engine, 200, &[HTML], &[0xfe, 0xff, 0]);
    }

    #[test]
    fn a_compressed_start_is_not_mistaken_for_a_bom() {
        let (rewriting, _) = attempt(&request(&Method::GET), &rules(), 200, &[HTML, ("content-encoding", "br")], &[0xff, 0xfe]);
        assert!(rewriting);
    }

    #[test]
    fn two_or_unknown_encodings_pass_through() {
        let engine = rules();
        for value in ["gzip, br", "compress", "identity", "aes128gcm"] {
            let value: &'static str = value;
            assert_passes_through(&request(&Method::GET), &engine, 200, &[HTML, ("content-encoding", value)], b"");
        }
        assert_passes_through(&request(&Method::GET), &engine, 200, &[HTML, ("content-encoding", "gzip"), ("content-encoding", "br")], b"");
    }

    #[test]
    fn a_request_that_is_not_a_document_passes_through() {
        let get = Method::GET;
        let subresource = PageRequest { url: URL, method: &get, is_document: false };
        assert_passes_through(&subresource, &rules(), 200, &[HTML], b"");
    }

    #[test]
    fn a_download_passes_through() {
        let engine = rules();
        let get = Method::GET;
        for value in [
            "attachment",
            "ATTACHMENT",
            "attachment; filename=\"report.html\"",
            "attachment ; filename=report.html",
            "attachment;filename*=UTF-8''report.html",
            "x-unknown-type; filename=report.html",
        ] {
            let value: &'static str = value;
            assert_passes_through(&request(&get), &engine, 200, &[HTML, ("content-disposition", value)], b"");
        }
        assert_passes_through(&request(&get), &engine, 200, &[HTML, ("content-disposition", "inline"), ("content-disposition", "attachment")], b"");

        let mut not_text = headers_of(&[HTML]);
        not_text.insert(CONTENT_DISPOSITION, HeaderValue::from_bytes(b"attachment; filename=\"\xff.html\"").unwrap());
        let before = not_text.clone();
        assert!(begin(&engine, &request(&get), StatusCode::OK, &mut not_text, b"", &InjectLimits::default()).is_none());
        assert_eq!(not_text, before, "headers must not change");
    }

    #[test]
    fn an_inline_disposition_is_rewritten() {
        for value in ["inline", "INLINE", "inline; filename=\"report.html\"", " inline ;filename=report.html"] {
            let value: &'static str = value;
            assert!(attempt(&request(&Method::GET), &rules(), 200, &[HTML, ("content-disposition", value)], b"").0, "{value}");
        }
    }

    #[test]
    fn a_document_exception_passes_through() {
        let engine = list_rules("##.x\n@@||sieve-test.invalid^$document\n");
        assert_passes_through(&request(&Method::GET), &engine, 200, &[HTML, ("content-encoding", "gzip")], b"");
    }

    #[test]
    fn a_page_with_nothing_to_inject_passes_through() {
        let engine = list_rules("||ads.invalid^\n");
        assert_passes_through(&request(&Method::GET), &engine, 200, &[HTML, ("content-encoding", "gzip"), ("content-length", "9")], b"");
    }

    #[test]
    fn a_rewrite_removes_exactly_the_headers_it_falsifies() {
        let (rewriting, headers) = attempt(
            &request(&Method::GET),
            &rules(),
            200,
            &[
                HTML,
                ("content-encoding", "gzip"),
                ("content-length", "9"),
                ("accept-ranges", "bytes"),
                ("content-digest", "sha-256=:x:"),
                ("repr-digest", "sha-256=:x:"),
                ("etag", "\"gone\""),
                ("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ("cache-control", "max-age=60"),
                ("set-cookie", "a=b"),
                ("content-security-policy-report-only", "script-src 'self'"),
            ],
            b"",
        );
        assert!(rewriting);
        let mut names: Vec<&str> = headers.keys().map(|k| k.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["cache-control", "content-security-policy-report-only", "content-type", "set-cookie"]);
        assert_eq!(headers.get("content-security-policy-report-only").unwrap(), "script-src 'self'");
    }
}
