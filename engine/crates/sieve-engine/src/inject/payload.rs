//! The bytes injected into a page: one `<style>` and one `<script>`, both with
//! the response's nonce (plan 5.6 item 4).
//!
//! Safety is structural, at this emitter, and does not trust the list parser
//! (S30): CSS comes through `sieve_filter::cosmetic::css_text`, and everything in
//! the script through [`js_text`], so no rule text can close its element. The
//! payload is pure ASCII, so it is valid in every encoding the rewriter accepts
//! and lol_html never transcodes it.

use std::fmt::Write as _;
use std::sync::Arc;

use sieve_filter::cosmetic::PageCosmetics;

/// Brave's procedural filter applier, transpiled once and checked in
/// (`pnpm injected:build`, `engine/injected/README.md`).
const APPLIER: &str = include_str!("../../../../injected/procedural-applier.js");
/// Sieve's runner around it: actions, first run, MutationObserver.
const BOOTSTRAP: &str = include_str!("../../../../injected/bootstrap.js");

const SCRIPT_CLOSE: &[u8] = b"</script";
const COMMENT_OPEN: &[u8] = b"<!--";

/// Makes text safe inside a `<script>` element: `</script` and `<!--`, in any
/// case, get `<` as `\x3c`, and non-ASCII becomes `\uXXXX`. `<script` alone is
/// left: without `<!--` the double-escape state cannot start, and code like
/// `i<script.length` must stay valid.
pub fn js_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (index, c) in text.char_indices() {
        let rest = text.as_bytes().get(index..).unwrap_or_default();
        let closes = |marker: &[u8]| rest.get(..marker.len()).is_some_and(|start| start.eq_ignore_ascii_case(marker));
        if c == '<' && (closes(SCRIPT_CLOSE) || closes(COMMENT_OPEN)) {
            out.push_str("\\x3c");
        } else if c.is_ascii() {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    out
}

/// The script's source: one function scope, so no helper leaks into page globals.
fn script_source(cosmetics: &PageCosmetics) -> String {
    let mut js = String::from("(function(){\n");
    js.push_str(&cosmetics.scriptlets);
    if !cosmetics.procedural.is_empty() {
        let _ = write!(js, "\nvar sieveApplier=(function(){{var exports={{}};\n{APPLIER}\nreturn exports;}})();\n{BOOTSTRAP}\nsieveRunProcedural(sieveApplier,[{}]);", cosmetics.procedural.join(","));
    }
    js.push_str("\n})();");
    js_text(&js)
}

/// A page's elements, in parts: the generic stylesheet is shared by the snapshot
/// and can be a megabyte, so it is written out once, not copied here first.
#[derive(Debug, Default)]
pub struct Payload {
    before_generic: String,
    generic_css: Arc<str>,
    after_generic: String,
}

impl From<&str> for Payload {
    fn from(text: &str) -> Self {
        Self { before_generic: text.to_string(), ..Self::default() }
    }
}

impl Payload {
    pub fn len(&self) -> usize {
        self.before_generic.len() + self.generic_css.len() + self.after_generic.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.before_generic.as_bytes());
        out.extend_from_slice(self.generic_css.as_bytes());
        out.extend_from_slice(self.after_generic.as_bytes());
    }
}

/// The elements for a page; empty when it has nothing to inject.
pub fn render(cosmetics: &PageCosmetics, nonce: &str) -> Payload {
    let mut payload = Payload::default();
    if !cosmetics.generic_css.is_empty() || !cosmetics.specific_css.is_empty() {
        payload.before_generic = format!("<style nonce=\"{nonce}\">");
        payload.generic_css = cosmetics.generic_css.clone();
        let _ = write!(payload.after_generic, "{}</style>", cosmetics.specific_css);
    }
    if !cosmetics.scriptlets.is_empty() || !cosmetics.procedural.is_empty() {
        let _ = write!(payload.after_generic, "<script nonce=\"{nonce}\">{}</script>", script_source(cosmetics));
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use sieve_filter::resources::{load_bundle, sha256_hex};
    use sieve_filter::rules::{ListText, RuleEngine};
    use std::cell::RefCell;
    use std::rc::Rc;

    const URL: &str = "https://sieve-test.invalid/";
    const BUNDLE: &[u8] = include_bytes!("../../../sieve-filter/testdata/resources-fixture.json");

    fn rendered(cosmetics: &PageCosmetics, nonce: &str) -> String {
        let mut out = Vec::new();
        let payload = render(cosmetics, nonce);
        payload.write_to(&mut out);
        assert_eq!(out.len(), payload.len());
        String::from_utf8(out).unwrap()
    }

    fn page_for(rules: &str) -> PageCosmetics {
        let mut engine = RuleEngine::compile(&[ListText { id: "l", text: rules, trusted: true }]);
        engine.use_resources(&load_bundle(BUNDLE, &sha256_hex(BUNDLE)).unwrap());
        engine.page_cosmetics(URL)
    }

    /// What a parser sees in the payload: element names, and text outside them.
    #[derive(Default, Debug)]
    struct Parsed {
        elements: Vec<String>,
        style_text: String,
        script_text: String,
    }

    fn parse(payload: &str) -> Parsed {
        let parsed = Rc::new(RefCell::new(Parsed::default()));
        let (elements, styles, scripts) = (parsed.clone(), parsed.clone(), parsed.clone());
        lol_html::rewrite_str(
            payload,
            lol_html::RewriteStrSettings::new()
                .append_element_content_handler(lol_html::element!("*", move |el| {
                    elements.borrow_mut().elements.push(el.tag_name());
                    Ok(())
                }))
                .append_element_content_handler(lol_html::text!("style", move |t| {
                    styles.borrow_mut().style_text.push_str(t.as_str());
                    Ok(())
                }))
                .append_element_content_handler(lol_html::text!("script", move |t| {
                    scripts.borrow_mut().script_text.push_str(t.as_str());
                    Ok(())
                })),
        )
        .unwrap();
        Rc::try_unwrap(parsed).unwrap().into_inner()
    }

    const ATTACK: &str = "</style><script>alert(1)</script>";

    fn assert_contained(payload: &str) {
        let parsed = parse(payload);
        assert_eq!(parsed.elements, ["style", "script"], "{payload}");
        assert!(payload.is_ascii(), "{payload}");
        assert!(payload.ends_with("</script>"), "{payload}");
    }

    #[test]
    fn a_selector_cannot_close_the_style_element() {
        let cosmetics = page_for(&format!("sieve-test.invalid##[title=\"{ATTACK}\"]\nsieve-test.invalid##+js(sieve-set-flag, a, b)\n"));
        assert!(cosmetics.specific_css.contains("\\3c "), "the rule must reach the CSS: {cosmetics:?}");
        let payload = rendered(&cosmetics, "n");
        assert_contained(&payload);
        assert!(parse(&payload).style_text.contains("\\3c /style>"), "{payload}");
    }

    #[test]
    fn a_style_value_cannot_close_the_style_element() {
        let cosmetics = page_for(&format!("sieve-test.invalid##.x:style(content: \"{ATTACK}\")\nsieve-test.invalid##+js(sieve-set-flag, a, b)\n"));
        assert!(cosmetics.specific_css.contains("content"), "{cosmetics:?}");
        assert_contained(&rendered(&cosmetics, "n"));
    }

    #[test]
    fn a_scriptlet_argument_cannot_close_the_script_element() {
        let cosmetics = page_for(&format!("##.x\nsieve-test.invalid##+js(sieve-set-flag, a, {ATTACK})\n"));
        assert!(cosmetics.scriptlets.contains("</script>"), "the attack must reach the emitter: {cosmetics:?}");
        let payload = rendered(&cosmetics, "n");
        assert_contained(&payload);
        assert!(parse(&payload).script_text.contains("\\x3c/script>"), "{payload}");
    }

    #[test]
    fn a_procedural_argument_cannot_close_the_script_element() {
        let cosmetics = page_for(&format!("##.x\nsieve-test.invalid##.a:has-text({ATTACK})\n"));
        assert_eq!(cosmetics.procedural.len(), 1, "{cosmetics:?}");
        assert_contained(&rendered(&cosmetics, "n"));
    }

    #[test]
    fn comment_open_cannot_start_the_double_escape_state() {
        let cosmetics = page_for("##.x\nsieve-test.invalid##+js(sieve-set-flag, a, <!--<script>)\n");
        let payload = rendered(&cosmetics, "n");
        assert_contained(&payload);
        assert!(!payload.contains("<!--"), "{payload}");
    }

    #[test]
    fn non_ascii_rule_text_becomes_escapes() {
        let cosmetics = page_for("##.caf\u{e9}\nsieve-test.invalid##+js(sieve-set-flag, a, caf\u{e9}\u{1f600})\n");
        let payload = rendered(&cosmetics, "n");
        assert_contained(&payload);
        assert!(payload.contains(".caf\\e9 {"), "{payload}");
        assert!(payload.contains("caf\\u00e9\\ud83d\\ude00"), "{payload}");
    }

    #[test]
    fn js_text_cases() {
        assert_eq!(js_text("a</SCRIPT>b"), "a\\x3c/SCRIPT>b");
        assert_eq!(js_text("<!--"), "\\x3c!--");
        assert_eq!(js_text("i<script.length"), "i<script.length");
        assert_eq!(js_text("a<b"), "a<b");
        assert_eq!(js_text("\u{e9}"), "\\u00e9");
        assert_eq!(js_text("\u{1f600}"), "\\ud83d\\ude00");
    }

    #[test]
    fn each_element_appears_only_when_it_has_content() {
        assert_eq!(rendered(&PageCosmetics::default(), "n"), "");
        assert_eq!(parse(&rendered(&page_for("##.x\n"), "n")).elements, ["style"]);
        assert_eq!(parse(&rendered(&page_for("sieve-test.invalid##+js(sieve-set-flag, a)\n"), "n")).elements, ["script"]);
    }

    #[test]
    fn the_applier_ships_only_with_procedural_filters() {
        assert!(!rendered(&page_for("sieve-test.invalid##+js(sieve-set-flag, a)\n"), "n").contains("compileProceduralSelector"));
        let payload = rendered(&page_for("sieve-test.invalid##.a:has-text(ad)\n"), "n");
        assert!(payload.contains("compileProceduralSelector") && payload.contains("sieveRunProcedural(sieveApplier,["), "{payload}");
    }

    #[test]
    fn both_elements_carry_the_nonce() {
        let payload = rendered(&page_for("##.x\nsieve-test.invalid##+js(sieve-set-flag, a)\n"), "abc+/=");
        assert!(payload.starts_with("<style nonce=\"abc+/=\">"), "{payload}");
        assert!(payload.contains("<script nonce=\"abc+/=\">"), "{payload}");
    }
}
