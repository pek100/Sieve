//! Puts the payload at the start of the document, with lol_html (plan 5.6 item 3).
//!
//! On the first element in parser order:
//! - `head`: prepended inside it;
//! - `html`: wait for the next element;
//! - anything else: inserted before it.
//!
//! So the payload comes before any `<meta>` CSP and a document with no element
//! gets nothing. Comments, doctypes and script text are the tokenizer's business;
//! nothing here searches bytes.
//!
//! lol_html only locates: the handler records a byte offset and changes nothing,
//! so its output is its input, and the output sink puts the payload in at that
//! offset. A 1 MB stylesheet therefore costs one copy, not one per rewriter layer
//! (measured: 2.4 ms to the first byte through `Element::prepend`).
//!
//! The rewriter stops once the injection is found: it is ended, which flushes any
//! partial token it held unchanged, and later bytes pass through untouched. That
//! bounds memory, gives the throughput budget, and leaves no way for a rewriter
//! bug to touch the body.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use lol_html::send::{HtmlRewriter, Settings};
use lol_html::{AsciiCompatibleEncoding, MemorySettings, OutputSink, element};

use super::payload::Payload;
use super::{InjectError, InjectLimits};

/// The rewriter gets input this size at a time, so it stops soon after the
/// injection even when one chunk holds a whole document.
const REWRITE_SLICE_BYTES: usize = 4096;
const HTML_TAG: &str = "html";
const HEAD_TAG: &str = "head";
const UTF16_BOMS: [[u8; 2]; 2] = [[0xff, 0xfe], [0xfe, 0xff]];
const BOM_BYTES: usize = 2;

/// True when a browser would read `start` as UTF-16 whatever the header says.
pub fn has_utf16_bom(start: &[u8]) -> bool {
    UTF16_BOMS.iter().any(|bom| start.starts_with(bom))
}

/// The bytes on their way out, with the payload going in at the found offset.
#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    /// Input bytes the rewriter has handed over so far.
    emitted: usize,
    insertion: Option<(usize, Payload)>,
}

impl Output {
    fn accept(&mut self, chunk: &[u8]) {
        let end = self.emitted + chunk.len();
        let here = self.insertion.as_ref().is_some_and(|(offset, _)| *offset <= end);
        if let (true, Some((offset, payload))) = (here, self.insertion.take()) {
            let (before, after) = chunk.split_at(offset.saturating_sub(self.emitted));
            self.bytes.reserve(chunk.len() + payload.len());
            self.bytes.extend_from_slice(before);
            payload.write_to(&mut self.bytes);
            self.bytes.extend_from_slice(after);
        } else {
            self.bytes.extend_from_slice(chunk);
        }
        self.emitted = end;
    }
}

/// Lets the rewriter's sink live inside the rewriter while its owner drains it.
#[derive(Clone, Default)]
struct SharedOutput(Arc<Mutex<Output>>);

impl SharedOutput {
    fn with<T>(&self, action: impl FnOnce(&mut Output) -> T) -> T {
        action(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn take(&self) -> Vec<u8> {
        self.with(|output| std::mem::take(&mut output.bytes))
    }
}

impl OutputSink for SharedOutput {
    fn handle_chunk(&mut self, chunk: &[u8]) {
        self.with(|output| output.accept(chunk));
    }
}

enum Stage {
    /// Holding the first bytes until a UTF-16 BOM can be ruled out.
    Start(Vec<u8>, Box<Pending>),
    Rewriting(Box<HtmlRewriter<'static, SharedOutput>>),
    Passthrough,
}

struct Pending {
    payload: Payload,
    encoding: AsciiCompatibleEncoding,
    memory_bytes: usize,
}

/// The document half of a page's rewrite.
pub struct HtmlInjector {
    stage: Stage,
    output: SharedOutput,
    injected: Arc<AtomicBool>,
}

fn rewriter_error(error: &lol_html::errors::RewritingError) -> InjectError {
    InjectError::Rewriter(error.to_string())
}

impl HtmlInjector {
    pub fn new(payload: Payload, encoding: AsciiCompatibleEncoding, limits: &InjectLimits) -> Self {
        let pending = Pending { payload, encoding, memory_bytes: limits.rewriter_max_memory_bytes };
        Self { stage: Stage::Start(Vec::new(), Box::new(pending)), output: SharedOutput::default(), injected: Arc::new(AtomicBool::new(false)) }
    }

    fn start_rewriter(&self, pending: Pending) -> HtmlRewriter<'static, SharedOutput> {
        let Pending { payload, encoding, memory_bytes } = pending;
        let injected = Arc::clone(&self.injected);
        let output = self.output.clone();
        let mut payload = Some(payload);
        let handler = element!("*", move |el| {
            let tag = el.tag_name();
            if tag == HTML_TAG {
                return Ok(());
            }
            let Some(payload) = payload.take() else {
                return Ok(());
            };
            let start_tag = el.source_location().bytes();
            let offset = if tag == HEAD_TAG { start_tag.end } else { start_tag.start };
            output.with(|output| output.insertion = Some((offset, payload)));
            injected.store(true, Ordering::Relaxed);
            Ok(())
        });
        // Not strict: strict mode refuses markup it cannot place without a tree
        // builder, and this rewriter only needs the first element's start tag.
        let settings = Settings::new_send()
            .append_element_content_handler(handler)
            .with_encoding(encoding)
            .with_strict(false)
            .with_memory_settings(MemorySettings::new().with_max_allowed_memory_usage(memory_bytes));
        HtmlRewriter::new(settings, self.output.clone())
    }

    /// Feeds decoded bytes and returns what is ready to send.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, InjectError> {
        let Stage::Start(start, _) = &mut self.stage else {
            return self.write_body(chunk);
        };
        start.extend_from_slice(chunk);
        if start.len() < BOM_BYTES {
            return Ok(Vec::new());
        }
        let held = std::mem::take(start);
        self.leave_start(has_utf16_bom(&held));
        self.write_body(&held)
    }

    fn write_body(&mut self, chunk: &[u8]) -> Result<Vec<u8>, InjectError> {
        let mut rest = chunk;
        if let Stage::Rewriting(rewriter) = &mut self.stage {
            while !rest.is_empty() && !self.injected.load(Ordering::Relaxed) {
                let (slice, after) = rest.split_at(rest.len().min(REWRITE_SLICE_BYTES));
                rewriter.write(slice).map_err(|e| rewriter_error(&e))?;
                rest = after;
            }
            if self.injected.load(Ordering::Relaxed) {
                self.end_rewriter()?;
            }
        }
        let mut out = self.output.take();
        out.extend_from_slice(rest);
        Ok(out)
    }

    fn leave_start(&mut self, utf16: bool) {
        let stage = std::mem::replace(&mut self.stage, Stage::Passthrough);
        if let (Stage::Start(_, pending), false) = (stage, utf16) {
            self.stage = Stage::Rewriting(Box::new(self.start_rewriter(*pending)));
        }
    }

    fn end_rewriter(&mut self) -> Result<(), InjectError> {
        if let Stage::Rewriting(rewriter) = std::mem::replace(&mut self.stage, Stage::Passthrough) {
            rewriter.end().map_err(|e| rewriter_error(&e))?;
        }
        Ok(())
    }

    /// Ends the document and returns the last bytes.
    pub fn finish(&mut self) -> Result<Vec<u8>, InjectError> {
        if let Stage::Start(start, _) = &mut self.stage {
            let held = std::mem::take(start);
            self.stage = Stage::Passthrough;
            return Ok(held);
        }
        self.end_rewriter()?;
        Ok(self.output.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const P: &str = "<!--P-->";

    fn injector() -> HtmlInjector {
        HtmlInjector::new(Payload::from(P), AsciiCompatibleEncoding::utf_8(), &InjectLimits::default())
    }

    fn run<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
        let mut i = injector();
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(i.push(chunk).unwrap());
        }
        out.extend(i.finish().unwrap());
        out
    }

    fn rewrite(page: &str) -> String {
        String::from_utf8(run([page.as_bytes()])).unwrap()
    }

    const META: &str = r#"<meta http-equiv="Content-Security-Policy" content="default-src 'none'">"#;

    #[test]
    fn inside_an_explicit_head_before_a_meta_csp() {
        assert_eq!(rewrite(&format!("<!doctype html><html><head>{META}</head><body></body></html>")), format!("<!doctype html><html><head>{P}{META}</head><body></body></html>"));
    }

    #[test]
    fn before_a_meta_csp_with_an_implicit_head() {
        assert_eq!(rewrite(&format!("<html>{META}<body></body>")), format!("<html>{P}{META}<body></body>"));
    }

    #[test]
    fn before_a_meta_csp_with_no_html_element() {
        assert_eq!(rewrite(&format!("<!doctype html>{META}<p>x")), format!("<!doctype html>{P}{META}<p>x"));
    }

    #[test]
    fn before_the_body_when_there_is_no_head() {
        assert_eq!(rewrite("<html><body>x</body></html>"), format!("<html>{P}<body>x</body></html>"));
    }

    #[test]
    fn an_upper_case_head_with_attributes_is_a_head() {
        assert_eq!(rewrite("<HTML><HEAD lang=x><TITLE>t</TITLE>"), format!("<HTML><HEAD lang=x>{P}<TITLE>t</TITLE>"));
    }

    #[test]
    fn a_head_in_a_comment_is_ignored() {
        assert_eq!(rewrite("<!-- <head> --><head><title>t</title>"), format!("<!-- <head> --><head>{P}<title>t</title>"));
    }

    #[test]
    fn a_head_in_script_text_is_ignored() {
        let page = "<script>var a = '<head>';</script><head></head>";
        assert_eq!(rewrite(page), format!("{P}{page}"));
    }

    #[test]
    fn a_document_with_no_element_gets_nothing() {
        for page in ["", "just text", "<!-- only a comment -->", "<!doctype html>", "<html></html>", "<html>"] {
            assert_eq!(rewrite(page), page, "{page}");
        }
    }

    #[test]
    fn only_the_first_head_gets_it() {
        assert_eq!(rewrite("<head></head><head></head>"), format!("<head>{P}</head><head></head>"));
        assert_eq!(rewrite("<div></div><head></head><p></p>"), format!("{P}<div></div><head></head><p></p>"));
    }

    #[test]
    fn bytes_after_the_injection_are_identical_to_the_input() {
        let tail: Vec<u8> = (0..=255u8).cycle().take(40_000).collect();
        let mut page = b"<head>".to_vec();
        page.extend_from_slice(&tail);
        let out = run([&page[..]]);
        assert_eq!(&out[..6 + P.len()], format!("<head>{P}").as_bytes());
        assert_eq!(&out[6 + P.len()..], &tail[..]);
    }

    #[test]
    fn malformed_markup_after_the_injection_survives_byte_for_byte() {
        let page = "<head><p <<<>>> </select><![CDATA[ <div cla";
        assert_eq!(rewrite(page), format!("<head>{P}<p <<<>>> </select><![CDATA[ <div cla"));
    }

    #[test]
    fn a_page_starting_with_a_utf16_bom_passes_through() {
        for bom in UTF16_BOMS {
            let mut page = bom.to_vec();
            page.extend_from_slice(b"<\0h\0e\0a\0d\0>\0");
            assert_eq!(run([&page[..]]), page);
            assert_eq!(run(page.chunks(1)), page);
        }
    }

    #[test]
    fn a_page_of_one_byte_survives() {
        assert_eq!(run([&b"x"[..]]), b"x");
    }

    #[test]
    fn output_appears_before_finish_once_the_head_was_seen() {
        let mut i = injector();
        let out = i.push(b"<head><title>streaming").unwrap();
        assert!(String::from_utf8_lossy(&out).contains(P), "{out:?}");
        assert_eq!(i.push(b" rest").unwrap(), b" rest");
    }

    #[test]
    fn a_tag_longer_than_the_memory_limit_errors() {
        let limits = InjectLimits { rewriter_max_memory_bytes: 4096, ..InjectLimits::default() };
        let mut i = HtmlInjector::new(Payload::from(P), AsciiCompatibleEncoding::utf_8(), &limits);
        let tag = format!("<div a=\"{}", "x".repeat(64 * 1024));
        let result = tag.as_bytes().chunks(512).try_for_each(|c| i.push(c).map(drop));
        assert!(matches!(result, Err(InjectError::Rewriter(_))), "{result:?}");
    }

    #[test]
    fn a_legacy_ascii_compatible_encoding_keeps_its_bytes() {
        let encoding = AsciiCompatibleEncoding::new(encoding_rs::SHIFT_JIS).unwrap();
        let mut i = HtmlInjector::new(Payload::from(P), encoding, &InjectLimits::default());
        let page = b"<head><title>\x83\x5c</title>";
        let mut out = i.push(page).unwrap();
        out.extend(i.finish().unwrap());
        assert_eq!(out, [b"<head>".as_slice(), P.as_bytes(), b"<title>\x83\x5c</title>"].concat());
    }

    const SPLIT_PAGES: [&str; 5] = [
        "<!doctype html><!-- c --><html lang=en><head><meta charset=utf-8><title>t</title></head><body><div class=a>x</div></body></html>",
        "<html><body class='a b'><p>text</p>",
        "<div>no head</div>",
        "text only",
        "<head><div cla",
    ];

    #[test]
    fn one_byte_chunks_give_the_same_output_as_one_chunk() {
        for page in SPLIT_PAGES {
            assert_eq!(String::from_utf8(run(page.as_bytes().chunks(1))).unwrap(), rewrite(page), "{page}");
        }
    }

    #[test]
    fn every_split_point_gives_the_same_output_as_one_chunk() {
        for page in SPLIT_PAGES {
            let bytes = page.as_bytes();
            for point in 0..=bytes.len() {
                let (a, b) = bytes.split_at(point);
                assert_eq!(String::from_utf8(run([a, b])).unwrap(), rewrite(page), "{page} at {point}");
            }
        }
    }

    proptest! {
        #[test]
        fn any_chunking_gives_the_same_output(cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..8), which in 0..SPLIT_PAGES.len()) {
            let bytes = SPLIT_PAGES[which].as_bytes();
            let mut points: Vec<usize> = cuts.iter().map(|c| c.index(bytes.len() + 1)).collect();
            points.sort_unstable();
            let mut chunks = Vec::new();
            let mut last = 0;
            for p in points {
                chunks.push(&bytes[last..p]);
                last = p;
            }
            chunks.push(&bytes[last..]);
            prop_assert_eq!(String::from_utf8(run(chunks)).unwrap(), rewrite(SPLIT_PAGES[which]));
        }
    }
}
