//! What one page gets (plan 5.2, 5.6): cosmetic CSS, procedural filters and
//! scriptlets, with the page-level exceptions applied. Decides only: no I/O and
//! no HTML; `sieve-engine`'s `inject` module applies the answer.
//!
//! Three things adblock-rust does not give directly (read from its 0.13.3
//! source, docs/tasks/2026-11-02-content.md F4 to F7):
//! - `$elemhide`, `$specifichide` and their aliases are refused by its parser,
//!   and `$document` does not reach `url_cosmetic_resources`. Each such line is
//!   rewritten to a `$generichide` exception in a small private engine, so
//!   asking that engine reuses adblock-rust's matcher: no second one exists.
//! - It has no API that lists generic `.class` and `#id` selectors, so they
//!   are enumerated here, at compile, from the parsed lines.
//! - Its selector check does not make text safe inside a `<style>` element,
//!   so [`css_text`] does, at the emitter.
//!
//! | Exception on the URL | specific CSS | generic CSS | procedural | scriptlets |
//! |---|---|---|---|---|
//! | none                 | yes | yes | yes | yes |
//! | `$generichide`       | yes | no  | yes | yes |
//! | `$specifichide`      | no  | yes | no  | yes |
//! | `$elemhide`          | no  | no  | no  | yes |
//! | `$document`          | no  | no  | no  | no  |
//!
//! Limit: a proxy has no frame tree, so `$document` on a subdocument is judged
//! on that frame's own URL, not on its parent's.
//!
//! [`RuleSet::page_cosmetics`] is what a flow asks. The table holds per engine,
//! and the user's exceptions also cut the lists' part ([`UserGates`]), so the
//! user wins both ways: a list's `$document` never silences the user's own `##`
//! rules. Limits: a user's own `##+js()` stays inert, since the user's engine
//! never gets the bundle; a user's `#@#` on a list's procedural rule cuts
//! nothing, since adblock-rust reports procedural exceptions to no caller.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::ops::Range;
use std::sync::Arc;

use adblock::Engine;
use adblock::cosmetic_filter_cache::ProceduralOrActionFilter;
use adblock::filters::cosmetic::{CosmeticFilter, CosmeticFilterMask};
use adblock::filters::network::NetworkFilterMask;
use adblock::lists::{FilterSet, ParseOptions, ParsedLine, parse_filter};
use adblock::request::Request;

use crate::resources::ResourceBundle;
use crate::rules::{RuleEngine, RuleSet};

const HIDE_DECLARATION: &str = "display:none!important";
const EXCEPTION_PREFIX: &str = "@@";
const OPTIONS_SEPARATOR: char = '$';
const GENERICHIDE_OPTION: &str = "generichide";
/// Every option that speaks about hiding and not about the network.
const HIDE_OPTIONS: [&str; 6] = ["elemhide", "ehide", "specifichide", "shide", "generichide", "ghide"];
const UNHIDE_SEPARATOR: &str = "#@#";
const NEGATED_HOST: char = '~';
const SCRIPTLET_EXTENSION: &str = ".js";
/// adblock-rust asks with these when it matches `url_cosmetic_resources`.
const DOCUMENT_TYPE: &str = "document";
const DOCUMENT_METHOD: &str = "get";

/// One page's cosmetic work, ready for the emitter. Empty when `$document`
/// applies, or when nothing matches.
#[derive(Debug, Clone, Default)]
pub struct PageCosmetics {
    /// The snapshot's generic stylesheet, shared when no exception cuts it.
    pub generic_css: Arc<str>,
    /// Site-specific hide rules and pure `:style` rules.
    pub specific_css: String,
    /// JSON `ProceduralOrActionFilter` values needing the in-page applier.
    pub procedural: Vec<String>,
    /// Scriptlet code, from adblock-rust. Not yet safe inside `<script>`.
    pub scriptlets: String,
    /// Rules whose text could not be made safe (S17: a count, not silence).
    pub dropped_rules: usize,
}

impl PageCosmetics {
    pub fn is_empty(&self) -> bool {
        self.generic_css.is_empty() && self.specific_css.is_empty() && self.procedural.is_empty() && self.scriptlets.is_empty()
    }

    /// `self` with `other`'s work added. Generic CSS stays the shared stylesheet
    /// unless both parts hold some.
    fn merged_with(mut self, other: Self) -> Self {
        self.generic_css = match (self.generic_css.is_empty(), other.generic_css.is_empty()) {
            (_, true) => self.generic_css,
            (true, false) => other.generic_css,
            (false, false) => format!("{}{}", self.generic_css, other.generic_css).into(),
        };
        self.specific_css.push_str(&other.specific_css);
        self.procedural.extend(other.procedural);
        self.scriptlets.push_str(&other.scriptlets);
        self.dropped_rules += other.dropped_rules;
        self
    }
}

/// What the user's engine says about one page, applied to the lists' part.
#[derive(Debug, Default)]
struct UserGates {
    generichide: bool,
    specifichide: bool,
    /// The selectors the user's `#@#` lines cut on this page.
    exceptions: HashSet<String>,
    no_scriptlets: bool,
}

/// Makes text safe inside a `<style>` element and valid in any ASCII-compatible
/// page encoding: `<` and non-ASCII become CSS escapes. `None` for what no
/// escape repairs: control characters, or text [`css_is_self_contained`] refuses.
pub fn css_text(text: &str) -> Option<String> {
    if text.chars().any(char::is_control) || !css_is_self_contained(text) {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '<' || !c.is_ascii() {
            // The trailing space ends the escape (CSS Syntax 4.3.7).
            let _ = write!(out, "\\{:x} ", c as u32);
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// Rules are concatenated, so a string, comment, bracket or escape left open by
/// one (CSS Syntax 4) would swallow every rule after it, and a stray closer would
/// end its own early. True when the text opens and closes all of them itself.
fn css_is_self_contained(text: &str) -> bool {
    let mut closers = Vec::new();
    let mut quote = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if chars.next().is_none() {
                return false;
            }
        } else if let Some(open) = quote {
            if c == open {
                quote = None;
            }
        } else if c == '/' && chars.as_str().starts_with('*') {
            let Some((_, after)) = chars.as_str()[1..].split_once("*/") else {
                return false;
            };
            chars = after.chars();
        } else {
            match c {
                '"' | '\'' => quote = Some(c),
                '{' => closers.push('}'),
                '(' => closers.push(')'),
                '[' => closers.push(']'),
                '}' | ')' | ']' if closers.pop() != Some(c) => return false,
                _ => {}
            }
        }
    }
    quote.is_none() && closers.is_empty()
}

/// Appends `selector{declarations}`, or returns false when either part is unsafe.
fn push_css_rule(out: &mut String, selector: &str, declarations: &str) -> bool {
    let (Some(selector), Some(declarations)) = (css_text(selector), css_text(declarations)) else {
        return false;
    };
    let _ = write!(out, "{selector}{{{declarations}}}");
    true
}

/// Which private engine a page-level exception line belongs to (module doc).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct PageException {
    document: bool,
    elemhide: bool,
    specifichide: bool,
    /// The line as a `$generichide` exception, with its other options kept.
    rule: String,
}

impl PageException {
    pub(crate) fn rule(&self) -> &str {
        &self.rule
    }
}

/// Rewrites a line naming a page-level option adblock-rust cannot answer for
/// (module doc). `None` for every other line.
pub(crate) fn page_exception(line: &str) -> Option<PageException> {
    if !line.starts_with(EXCEPTION_PREFIX) {
        return None;
    }
    // Reverse, as adblock-rust's own parser finds the options.
    let (pattern, raw_options) = line.rsplit_once(OPTIONS_SEPARATOR)?;
    let mut exception = PageException::default();
    let mut generichide = false;
    let mut kept = Vec::new();
    for option in raw_options.split(',') {
        match option {
            "document" | "doc" => exception.document = true,
            "elemhide" | "ehide" => exception.elemhide = true,
            "specifichide" | "shide" => exception.specifichide = true,
            "generichide" | "ghide" => generichide = true,
            other => kept.push(other),
        }
    }
    if !(exception.document || exception.elemhide || exception.specifichide) {
        return None;
    }
    // Both halves named together are `$elemhide`.
    exception.elemhide |= exception.specifichide && generichide;
    exception.specifichide &= !exception.elemhide;
    kept.push(GENERICHIDE_OPTION);
    exception.rule = format!("{pattern}{OPTIONS_SEPARATOR}{}", kept.join(","));
    Some(exception)
}

/// The request types a parsed line matches.
fn type_mask(line: &str, options: ParseOptions) -> Option<NetworkFilterMask> {
    match parse_filter(line, false, options).ok()? {
        ParsedLine::Network(filter) => Some(filter.mask & NetworkFilterMask::FROM_ALL_TYPES),
        ParsedLine::Cosmetic(_) => None,
    }
}

/// What an exception line naming a hide option says about the network: the line
/// without those options, when what is left still constrains the request type
/// (`$document`, `$script`). `@@||x^$elemhide` has no such half, so a hide
/// exception can never open the network. The parser's own mask decides, read
/// against the pattern alone, and not a second list of type names.
pub(crate) fn network_half(line: &str, options: ParseOptions) -> Option<String> {
    if !line.starts_with(EXCEPTION_PREFIX) {
        return None;
    }
    let (pattern, raw_options) = line.rsplit_once(OPTIONS_SEPARATOR)?;
    let named: Vec<&str> = raw_options.split(',').collect();
    let kept: Vec<&str> = named.iter().copied().filter(|option| !HIDE_OPTIONS.contains(option)).collect();
    if kept.is_empty() || kept.len() == named.len() {
        return None;
    }
    let half = format!("{pattern}{OPTIONS_SEPARATOR}{}", kept.join(","));
    (type_mask(&half, options)? != type_mask(pattern, options)?).then_some(half)
}

/// The hosts of a `host,other#@#+js(...)` line, each as a `$generichide` line for
/// the private engine that says "a user's scriptlet exception holds here". It
/// stops all list scriptlets on such a page: adblock-rust assembles them into
/// one string, so a named one cannot be cut. Over-broad in the safe direction,
/// since the page is changed less. A negated host names no page.
fn scriptlet_exception_rules(line: &str) -> impl Iterator<Item = String> + '_ {
    let hosts = line.split_once(UNHIDE_SEPARATOR).map_or("", |(hosts, _)| hosts);
    hosts.split(',').filter(|host| !host.is_empty() && !host.starts_with(NEGATED_HOST)).map(|host| format!("{EXCEPTION_PREFIX}||{host}^{OPTIONS_SEPARATOR}{GENERICHIDE_OPTION}"))
}

/// The cosmetic facts `RuleEngine::compile` collects from the parsed lines.
#[derive(Default)]
pub(crate) struct CosmeticBuilder {
    generic: BTreeSet<String>,
    document: Vec<String>,
    elemhide: Vec<String>,
    specifichide: Vec<String>,
    no_scriptlets: Vec<String>,
}

impl CosmeticBuilder {
    pub(crate) fn add_exception(&mut self, exception: PageException) {
        let targets = [(exception.document, &mut self.document), (exception.elemhide, &mut self.elemhide), (exception.specifichide, &mut self.specifichide)];
        for (named, rules) in targets {
            if named {
                rules.push(exception.rule.clone());
            }
        }
    }

    /// Files a parsed line and returns the scriptlet it names, if any.
    pub(crate) fn observe(&mut self, line: &str, parsed: &ParsedLine<'_>) -> Option<String> {
        let ParsedLine::Cosmetic(filter) = parsed else {
            return None;
        };
        if filter.mask.contains(CosmeticFilterMask::UNHIDE) {
            if filter.mask.contains(CosmeticFilterMask::SCRIPT_INJECT) {
                self.no_scriptlets.extend(scriptlet_exception_rules(line));
            }
            return None;
        }
        if filter.mask.contains(CosmeticFilterMask::SCRIPT_INJECT) {
            return scriptlet_identifier(filter);
        }
        let hidden = filter.hidden_generic_rule();
        let generic = if filter.has_hostname_constraint() { hidden.as_ref()? } else { filter };
        if let Some(selector) = generic.plain_css_selector() {
            self.generic.insert(selector.to_string());
        }
        None
    }

    pub(crate) fn build(self) -> CosmeticIndex {
        let mut css = String::new();
        let mut dropped = 0;
        let mut generic = BTreeMap::new();
        // One rule per selector: one bad selector in a group would kill the group.
        for selector in self.generic {
            let start = css.len();
            dropped += usize::from(!push_css_rule(&mut css, &selector, HIDE_DECLARATION));
            generic.insert(selector, start..css.len());
        }
        CosmeticIndex {
            generic_css: css.into(),
            generic_dropped: dropped,
            generic,
            document: exception_engine(self.document),
            elemhide: exception_engine(self.elemhide),
            specifichide: exception_engine(self.specifichide),
            no_scriptlets: exception_engine(self.no_scriptlets),
        }
    }
}

/// `+js(name, args...)` is stored as `name, args...`.
fn scriptlet_identifier(filter: &CosmeticFilter) -> Option<String> {
    let args = filter.plain_css_selector()?;
    let name = args.split(',').next()?.trim();
    if name.is_empty() {
        return None;
    }
    Some(if name.ends_with(SCRIPTLET_EXTENSION) { name.to_string() } else { format!("{name}{SCRIPTLET_EXTENSION}") })
}

fn exception_engine(rules: Vec<String>) -> Engine {
    let mut set = FilterSet::new(false);
    set.add_filter_list(rules.join("\n"), ParseOptions::default());
    Engine::new_with_filter_set(set)
}

/// The snapshot's cosmetic facts beside its engine.
pub(crate) struct CosmeticIndex {
    /// Every plain generic selector, sorted (stable output, S15), with where its
    /// rule sits in `generic_css`. A dropped selector has an empty range.
    generic: BTreeMap<String, Range<usize>>,
    generic_css: Arc<str>,
    generic_dropped: usize,
    document: Engine,
    elemhide: Engine,
    specifichide: Engine,
    no_scriptlets: Engine,
}

impl CosmeticIndex {
    /// The stylesheet this page gets: the shared one, or a copy with the page's
    /// exceptions cut out.
    fn generic_for_page(&self, exceptions: &HashSet<String>) -> Arc<str> {
        let mut cuts: Vec<&Range<usize>> = exceptions.iter().filter_map(|selector| self.generic.get(selector)).collect();
        if cuts.is_empty() {
            return self.generic_css.clone();
        }
        cuts.sort_unstable_by_key(|cut| cut.start);
        let mut css = String::with_capacity(self.generic_css.len());
        let mut kept_from = 0;
        for cut in cuts {
            css.push_str(&self.generic_css[kept_from..cut.start]);
            kept_from = cut.end;
        }
        css.push_str(&self.generic_css[kept_from..]);
        css.into()
    }
}

/// Does this private engine hold an exception matching the URL (module doc)?
fn exception_applies(engine: &Engine, url: &str) -> bool {
    engine.url_cosmetic_resources(url).generichide
}

impl RuleEngine {
    /// Loads a verified bundle. A refused bundle never gets here, so the
    /// engine keeps what it had. Recounts the rules the bundle cannot serve.
    pub fn use_resources(&mut self, bundle: &ResourceBundle) {
        self.engine.use_resource_storage(bundle.storage.clone());
        for (report, scriptlets) in self.reports.iter_mut().zip(&self.scriptlets) {
            let missing = scriptlets.iter().filter(|(name, _)| !bundle.contains(name)).map(|(_, rules)| rules);
            report.missing_scriptlets = Some(missing.sum());
        }
    }

    /// What the page at `url` gets from this engine alone (module doc). A URL
    /// adblock-rust cannot parse has no page context and gets nothing.
    pub fn page_cosmetics(&self, url: &str) -> PageCosmetics {
        self.page_cosmetics_under(url, &UserGates::default())
    }

    /// What this engine's page-level exceptions say, for the other engine to obey.
    /// `None` when `$document` holds, or for a URL with no page context.
    fn user_gates(&self, url: &str) -> Option<UserGates> {
        if Request::new(url, url, DOCUMENT_TYPE, DOCUMENT_METHOD).is_err() || exception_applies(&self.cosmetic.document, url) {
            return None;
        }
        let elemhide = exception_applies(&self.cosmetic.elemhide, url);
        let resources = self.engine.url_cosmetic_resources(url);
        Some(UserGates {
            generichide: elemhide || resources.generichide,
            specifichide: elemhide || exception_applies(&self.cosmetic.specifichide, url),
            exceptions: resources.exceptions,
            no_scriptlets: exception_applies(&self.cosmetic.no_scriptlets, url),
        })
    }

    fn page_cosmetics_under(&self, url: &str, gates: &UserGates) -> PageCosmetics {
        if Request::new(url, url, DOCUMENT_TYPE, DOCUMENT_METHOD).is_err() || exception_applies(&self.cosmetic.document, url) {
            return PageCosmetics::default();
        }
        let elemhide = exception_applies(&self.cosmetic.elemhide, url);
        let specifichide = elemhide || gates.specifichide || exception_applies(&self.cosmetic.specifichide, url);
        let mut resources = self.engine.url_cosmetic_resources(url);
        let generichide = elemhide || gates.generichide || resources.generichide;
        // A set, so a selector both engines except is cut once.
        resources.exceptions.extend(gates.exceptions.iter().cloned());

        let mut page = PageCosmetics::default();
        if !gates.no_scriptlets {
            page.scriptlets = std::mem::take(&mut resources.injected_script);
        }
        if !generichide {
            page.generic_css = self.cosmetic.generic_for_page(&resources.exceptions);
            page.dropped_rules = self.cosmetic.generic_dropped;
        }
        if specifichide {
            return page;
        }

        // Without `$generichide`, adblock-rust mixes generic selectors into
        // `hide_selectors`. The generic stylesheet already holds them. Under the
        // user's `$generichide` alone the mix is still there, so a selector a
        // list holds both ways goes too: the page is changed less, never more.
        let is_specific = |selector: &String| !gates.exceptions.contains(selector) && (resources.generichide || !self.cosmetic.generic.contains_key(selector));
        let specific: BTreeSet<_> = resources.hide_selectors.iter().filter(|s| is_specific(s)).collect();
        for selector in specific {
            page.dropped_rules += usize::from(!push_css_rule(&mut page.specific_css, selector, HIDE_DECLARATION));
        }
        let actions: BTreeSet<_> = resources.procedural_actions.iter().collect();
        for json in actions {
            // adblock-rust wrote this JSON itself at compile.
            let css = serde_json::from_str::<ProceduralOrActionFilter>(json).ok().and_then(|f| f.as_css());
            match css {
                Some((selector, style)) => page.dropped_rules += usize::from(!push_css_rule(&mut page.specific_css, &selector, &style)),
                None => page.procedural.push(json.clone()),
            }
        }
        page
    }
}

impl RuleSet {
    /// What the page at `url` gets from both engines (module doc). The user's
    /// `$document` empties the page, the user's own rules included, as the table
    /// has it for one engine.
    pub fn page_cosmetics(&self, url: &str) -> PageCosmetics {
        let Some(gates) = self.user.user_gates(url) else {
            return PageCosmetics::default();
        };
        self.lists.page_cosmetics_under(url, &gates).merged_with(self.user.page_cosmetics(url))
    }
}

/// Per-list scriptlet names, kept to recount when a bundle changes.
pub(crate) type ScriptletUse = BTreeMap<String, usize>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::{load_bundle, sha256_hex};
    use crate::rules::ListText;

    const HOST: &str = "sieve-test.invalid";
    const URL: &str = "https://sieve-test.invalid/page";
    const OTHER_URL: &str = "https://other.invalid/page";
    const BUNDLE: &[u8] = include_bytes!("../testdata/resources-fixture.json");

    /// One rule of each output kind, on one host.
    const RULES: &str = "\
##.generic-class
###generic-id
##div[data-generic]
sieve-test.invalid##.specific
sieve-test.invalid##.has-text:has-text(ad)
sieve-test.invalid##+js(sieve-set-flag, a, b)
";

    fn bundle() -> ResourceBundle {
        load_bundle(BUNDLE, &sha256_hex(BUNDLE)).unwrap()
    }

    fn engine_with(text: &str, trusted: bool) -> RuleEngine {
        let mut engine = RuleEngine::compile(&[ListText { id: "l", text, trusted }]);
        engine.use_resources(&bundle());
        engine
    }

    fn page(extra: &str) -> PageCosmetics {
        engine_with(&format!("{RULES}{extra}"), true).page_cosmetics(URL)
    }

    /// (specific CSS, generic CSS, procedural, scriptlets)
    fn row(p: &PageCosmetics) -> (bool, bool, bool, bool) {
        (!p.specific_css.is_empty(), !p.generic_css.is_empty(), !p.procedural.is_empty(), !p.scriptlets.is_empty())
    }

    #[test]
    fn no_exception_gets_everything() {
        let p = page("");
        assert_eq!(row(&p), (true, true, true, true), "{p:?}");
    }

    #[test]
    fn generichide_keeps_specific_procedural_and_scriptlets() {
        for option in ["generichide", "ghide"] {
            let p = page(&format!("@@||{HOST}^${option}\n"));
            assert_eq!(row(&p), (true, false, true, true), "{option}: {p:?}");
        }
    }

    #[test]
    fn specifichide_keeps_generic_and_scriptlets() {
        for option in ["specifichide", "shide"] {
            let p = page(&format!("@@||{HOST}^${option}\n"));
            assert_eq!(row(&p), (false, true, false, true), "{option}: {p:?}");
        }
    }

    #[test]
    fn elemhide_keeps_only_scriptlets() {
        for option in ["elemhide", "ehide", "specifichide,generichide", "shide,ghide"] {
            let p = page(&format!("@@||{HOST}^${option}\n"));
            assert_eq!(row(&p), (false, false, false, true), "{option}: {p:?}");
        }
    }

    #[test]
    fn document_gets_nothing() {
        for option in ["document", "doc"] {
            let p = page(&format!("@@||{HOST}^${option}\n"));
            assert!(p.is_empty(), "{option}: {p:?}");
        }
    }

    #[test]
    fn exceptions_keep_their_other_options_and_only_apply_where_they_match() {
        let engine = engine_with(&format!("{RULES}@@||{HOST}/page$elemhide,domain=elsewhere.invalid\n@@||{HOST}/other$document\n"), true);
        assert_eq!(row(&engine.page_cosmetics(URL)), (true, true, true, true));
        assert!(engine.page_cosmetics(&format!("https://{HOST}/other")).is_empty());
        let generic_only = engine.page_cosmetics(OTHER_URL);
        assert_eq!(row(&generic_only), (false, true, false, false), "{generic_only:?}");
    }

    #[test]
    fn a_block_rule_naming_these_options_is_not_an_exception() {
        let p = page(&format!("||{HOST}^$elemhide\n"));
        assert_eq!(row(&p), (true, true, true, true));
    }

    #[test]
    fn generic_class_and_id_selectors_are_in_the_stylesheet() {
        // F6: adblock-rust's hide_selectors holds only the "misc" generic ones.
        let css = page("").generic_css;
        assert!(css.contains(".generic-class{display:none!important}"), "{css}");
        assert!(css.contains("#generic-id{display:none!important}"), "{css}");
        assert!(css.contains("div[data-generic]{display:none!important}"), "{css}");
    }

    #[test]
    fn a_specific_rule_is_not_in_the_generic_stylesheet() {
        let p = page("");
        assert!(!p.generic_css.contains(".specific"), "{p:?}");
        assert!(p.specific_css.contains(".specific{display:none!important}"), "{p:?}");
        assert!(!p.specific_css.contains("data-generic"), "misc generic selectors stay out: {p:?}");
    }

    #[test]
    fn unhide_removes_a_generic_and_a_specific_selector() {
        let p = page(&format!("{HOST}#@#.generic-class\n{HOST}#@#.specific\n"));
        assert!(!p.generic_css.contains(".generic-class"), "{p:?}");
        assert!(p.generic_css.contains("#generic-id"), "{p:?}");
        assert!(!p.specific_css.contains(".specific"), "{p:?}");
        let elsewhere = engine_with(&format!("{RULES}{HOST}#@#.generic-class\n"), true).page_cosmetics(OTHER_URL);
        assert!(elsewhere.generic_css.contains(".generic-class"), "{elsewhere:?}");
    }

    #[test]
    fn cutting_several_exceptions_leaves_exactly_the_other_rules() {
        let exceptions = format!("{HOST}#@#.a\n{HOST}#@#.c\n{HOST}#@#.e\n");
        let p = engine_with(&format!("##.a\n##.b\n##.c\n##.d\n##.e\n{exceptions}"), true).page_cosmetics(URL);
        assert_eq!(&*p.generic_css, ".b{display:none!important}.d{display:none!important}");
    }

    #[test]
    fn a_negated_host_rule_is_generic_except_on_that_host() {
        let engine = engine_with(&format!("~{HOST}##.not-here\n"), true);
        assert!(!engine.page_cosmetics(URL).generic_css.contains(".not-here"));
        assert!(engine.page_cosmetics(OTHER_URL).generic_css.contains(".not-here"));
    }

    #[test]
    fn a_selector_both_generic_and_specific_survives_generichide() {
        let p = engine_with(&format!("##.both\n{HOST}##.both\n@@||{HOST}^$generichide\n"), true).page_cosmetics(URL);
        assert!(p.generic_css.is_empty(), "{p:?}");
        assert!(p.specific_css.contains(".both"), "{p:?}");
    }

    #[test]
    fn a_scriptlet_exception_removes_it() {
        assert!(page(&format!("{HOST}#@#+js(sieve-set-flag, a, b)\n")).scriptlets.is_empty());
        assert!(page(&format!("{HOST}#@#+js()\n")).scriptlets.is_empty());
    }

    #[test]
    fn a_trusted_scriptlet_runs_only_from_a_trusted_list() {
        let rule = format!("{HOST}##+js(trusted-sieve-flag, a)\n");
        assert!(engine_with(&rule, false).page_cosmetics(URL).scriptlets.is_empty());
        assert!(engine_with(&rule, true).page_cosmetics(URL).scriptlets.contains("sieveTrustedFlag"));
    }

    #[test]
    fn an_alias_serves_the_rule_and_is_not_missing() {
        let engine = engine_with(&format!("{HOST}##+js(ssf, a, b)\n"), false);
        assert!(engine.page_cosmetics(URL).scriptlets.contains("sieveSetFlag"));
        assert_eq!(engine.reports()[0].missing_scriptlets, Some(0));
    }

    #[test]
    fn a_scriptlet_missing_from_the_bundle_is_counted_per_list() {
        let lists = [
            ListText { id: "a", text: "x.invalid##+js(newer-than-the-pin, 1)\ny.invalid##+js(newer-than-the-pin, 2)\nz.invalid##+js(sieve-set-flag, a)\n", trusted: true },
            ListText { id: "b", text: "x.invalid##+js(sieve-set-flag, a)\n", trusted: true },
        ];
        let mut engine = RuleEngine::compile(&lists);
        assert_eq!(engine.reports()[0].missing_scriptlets, None, "no bundle is not zero missing");
        engine.use_resources(&bundle());
        assert_eq!(engine.reports()[0].missing_scriptlets, Some(2));
        assert_eq!(engine.reports()[1].missing_scriptlets, Some(0));
    }

    #[test]
    fn page_exception_lines_count_as_applied_with_no_skip_reason() {
        let text = format!("@@||{HOST}^$elemhide\n@@||{HOST}^$ehide\n@@||{HOST}^$specifichide\n@@||{HOST}^$shide\n@@||{HOST}^$document\n@@||{HOST}^$generichide\n");
        let engine = engine_with(&text, true);
        let report = &engine.reports()[0];
        assert_eq!((report.network + report.cosmetic, report.skipped), (6, 0), "{report:?}");
        assert!(report.skip_reasons.is_empty());
    }

    #[test]
    fn a_page_exception_with_an_unknown_option_stays_skipped() {
        let engine = engine_with(&format!("@@||{HOST}^$elemhide,unknown-option-xyz\n"), true);
        let report = &engine.reports()[0];
        assert_eq!((report.network + report.cosmetic, report.skipped), (0, 1), "{report:?}");
        assert_eq!(row(&engine.page_cosmetics(URL)), (false, false, false, false));
    }

    #[test]
    fn a_procedural_rule_reaches_procedural_and_a_pure_style_reaches_the_css() {
        // F7: without css-validation every one of these was a plain selector.
        let p = engine_with(&format!("{HOST}##.a:has-text(ad)\n{HOST}##.b:remove()\n{HOST}##.c:style(color: red)\n"), true).page_cosmetics(URL);
        assert_eq!(p.procedural.len(), 2, "{p:?}");
        // The exact shape tests/laws/injected.test.ts feeds the in-page applier.
        assert!(p.procedural.iter().any(|j| j == r#"{"selector":[{"type":"css-selector","arg":".a"},{"type":"has-text","arg":"ad"}]}"#), "{p:?}");
        assert!(p.procedural.iter().any(|j| j == r#"{"selector":[{"type":"css-selector","arg":".b"}],"action":{"type":"remove"}}"#), "{p:?}");
        assert!(p.specific_css.contains(".c{color: red}"), "{p:?}");
    }

    #[test]
    fn an_invalid_selector_is_skipped_by_the_validator() {
        let engine = engine_with(&format!("{HOST}##</style><script>alert(1)</script>\n##a{{}}b\n"), true);
        let report = &engine.reports()[0];
        assert_eq!(report.skipped, 2, "{report:?}");
        assert!(engine.page_cosmetics(URL).is_empty());
    }

    #[test]
    fn a_url_with_no_page_context_gets_nothing() {
        assert!(!page("").is_empty());
        assert!(engine_with(RULES, true).page_cosmetics("not a url").is_empty());
    }

    #[test]
    fn css_text_escapes_what_could_close_the_element() {
        assert_eq!(css_text("[a=\"</style>\"]").unwrap(), "[a=\"\\3c /style>\"]");
        assert_eq!(css_text(".caf\u{e9}").unwrap(), ".caf\\e9 ");
        assert_eq!(css_text(".\u{1f600}").unwrap(), ".\\1f600 ");
        assert_eq!(css_text("[a=\"{}\"]").unwrap(), "[a=\"{}\"]");
    }

    #[test]
    fn css_text_refuses_what_no_escape_repairs() {
        for bad in ["a{", "a}", "}a{", "a}b{c", "a\nb", "a\u{0}b", "a\u{9f}"] {
            assert_eq!(css_text(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn css_text_refuses_what_would_swallow_the_rules_after_it() {
        for bad in ["content:\"", "content:'", "content:\"a\\\"", "a:\"b'", "width:calc(1px", "[a", "a)", "a]", "(]", "(}", "{)", "a\\", "a/*", "a/*/", "/* a"] {
            assert_eq!(css_text(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn css_text_reads_strings_escapes_and_comments_as_css_does() {
        for good in ["content:\"}\"", "content:'\"'", "content:\"\\\"\"", "[a=\"(\"]", ".a\\{", ".a\\\"b", "a:not(.b[c])", "a/* ) \" */b", "a/*\\*/b", "\"/*\"", "a/b*c"] {
            assert_eq!(css_text(good).as_deref(), Some(good), "{good:?}");
        }
    }

    #[test]
    fn a_poisoned_style_is_counted_and_leaves_the_next_rule_intact() {
        for poison in ["content:\"", "content:'", "width:calc(1px"] {
            let p = engine_with(&format!("{HOST}##.y:style({poison})\n{HOST}##.z:style(color: red)\n"), true).page_cosmetics(URL);
            assert!(p.specific_css.contains(".z{color: red}"), "{poison}: {p:?}");
            assert!(!p.specific_css.contains(".y"), "{poison}: {p:?}");
            assert_eq!(p.dropped_rules, 1, "{poison}: {p:?}");
        }
    }

    /// `RULES` as the lists, `lines` as the user's own, as a flow asks.
    fn set_with(lines: &[&str]) -> RuleSet {
        RuleSet { user: Arc::new(RuleEngine::compile_user_rules(std::iter::empty(), lines.iter().copied())), lists: Arc::new(engine_with(RULES, true)) }
    }

    #[test]
    fn a_users_hide_rule_reaches_the_page() {
        let p = set_with(&[&format!("{HOST}##.mine"), "##.mine-everywhere"]).page_cosmetics(URL);
        assert!(p.specific_css.contains(".mine{display:none!important}"), "{p:?}");
        assert!(p.specific_css.contains(".specific{display:none!important}"), "the lists' part stays: {p:?}");
        assert!(p.generic_css.contains(".generic-class"), "{p:?}");
        assert!(p.generic_css.contains(".mine-everywhere{display:none!important}"), "{p:?}");
    }

    #[test]
    fn a_users_document_exception_empties_the_page() {
        for line in ["document", "doc", "document,elemhide"] {
            let p = set_with(&[&format!("@@||{HOST}^${line}"), &format!("{HOST}##.mine")]).page_cosmetics(URL);
            assert!(p.is_empty(), "{line}: {p:?}");
        }
        assert!(!set_with(&[&format!("@@||{HOST}^$document")]).page_cosmetics(OTHER_URL).is_empty(), "another page");
    }

    #[test]
    fn a_users_elemhide_cuts_the_lists_css_and_keeps_scriptlets() {
        let p = set_with(&[&format!("@@||{HOST}^$elemhide")]).page_cosmetics(URL);
        assert_eq!(row(&p), (false, false, false, true), "{p:?}");
    }

    #[test]
    fn a_users_generichide_and_specifichide_cut_their_part_of_the_lists() {
        let p = set_with(&[&format!("@@||{HOST}^$generichide")]).page_cosmetics(URL);
        assert_eq!(row(&p), (true, false, true, true), "{p:?}");
        assert!(!p.specific_css.contains("data-generic"), "{p:?}");
        let p = set_with(&[&format!("@@||{HOST}^$specifichide")]).page_cosmetics(URL);
        assert_eq!(row(&p), (false, true, false, true), "{p:?}");
    }

    #[test]
    fn a_users_unhide_cuts_a_lists_selector_generic_and_specific() {
        let p = set_with(&[&format!("{HOST}#@#.generic-class"), &format!("{HOST}#@#.specific")]).page_cosmetics(URL);
        assert!(!p.generic_css.contains(".generic-class"), "{p:?}");
        assert!(p.generic_css.contains("#generic-id"), "{p:?}");
        assert!(!p.specific_css.contains(".specific"), "{p:?}");
    }

    /// Both engines except one selector: it is cut once, and nothing else goes.
    #[test]
    fn a_selector_both_engines_except_is_cut_once() {
        let lists = RuleEngine::compile(&[ListText { id: "l", text: &format!("##.a\n##.b\n{HOST}#@#.a\n"), trusted: true }]);
        let user = RuleEngine::compile_user_rules(std::iter::empty(), [format!("{HOST}#@#.a").as_str()]);
        let p = RuleSet { user: Arc::new(user), lists: Arc::new(lists) }.page_cosmetics(URL);
        assert_eq!(&*p.generic_css, ".b{display:none!important}");
    }

    #[test]
    fn a_lists_document_exception_keeps_the_users_rules() {
        let lists = engine_with(&format!("{RULES}@@||{HOST}^$document\n"), true);
        let user = RuleEngine::compile_user_rules(std::iter::empty(), [format!("{HOST}##.mine").as_str(), "##.anywhere"]);
        let p = RuleSet { user: Arc::new(user), lists: Arc::new(lists) }.page_cosmetics(URL);
        assert_eq!(p.specific_css, ".mine{display:none!important}", "{p:?}");
        assert_eq!(&*p.generic_css, ".anywhere{display:none!important}", "{p:?}");
        assert!(p.scriptlets.is_empty() && p.procedural.is_empty(), "{p:?}");
    }

    #[test]
    fn a_users_scriptlet_exception_drops_the_lists_scriptlets_there_only() {
        for line in [format!("{HOST}#@#+js(sieve-set-flag, a, b)"), format!("{HOST}#@#+js()"), format!("other.invalid,{HOST}#@#+js()"), "sieve-test.*#@#+js()".to_string()] {
            let set = set_with(&[&line]);
            let p = set.page_cosmetics(URL);
            assert_eq!(row(&p), (true, true, true, false), "{line}: {p:?}");
        }
        let lists = engine_with(&format!("{RULES}other.invalid##+js(sieve-set-flag, a, b)\n"), true);
        let user = RuleEngine::compile_user_rules(std::iter::empty(), [format!("{HOST}#@#+js()").as_str()]);
        assert!(!RuleSet { user: Arc::new(user), lists: Arc::new(lists) }.page_cosmetics(OTHER_URL).scriptlets.is_empty(), "another page keeps them");
        let negated = set_with(&[&format!("~{HOST},other.invalid#@#+js()")]);
        assert!(!negated.page_cosmetics(URL).scriptlets.is_empty(), "a negated host names no page");
    }

    /// `user_engine` never gets the bundle. A deferral, pinned so its end is seen.
    #[test]
    fn a_users_own_scriptlet_stays_inert_for_now() {
        let p = set_with(&["other.invalid##+js(sieve-set-flag, a, b)"]).page_cosmetics(OTHER_URL);
        assert!(p.scriptlets.is_empty(), "{p:?}");
    }

    #[test]
    fn no_user_rules_shares_the_lists_stylesheet() {
        let set = set_with(&[]);
        let shared = set.lists.page_cosmetics(URL).generic_css;
        assert!(Arc::ptr_eq(&set.page_cosmetics(URL).generic_css, &shared));
        let specific_only = set_with(&[&format!("{HOST}##.mine")]);
        let shared = specific_only.lists.page_cosmetics(URL).generic_css;
        assert!(Arc::ptr_eq(&specific_only.page_cosmetics(URL).generic_css, &shared), "the user's part holds no generic CSS");
        let generic_too = set_with(&["##.mine"]);
        let shared = generic_too.lists.page_cosmetics(URL).generic_css;
        assert!(!Arc::ptr_eq(&generic_too.page_cosmetics(URL).generic_css, &shared), "the control: both parts hold some");
    }

    #[test]
    fn page_exception_keeps_other_options_and_ignores_other_lines() {
        let e = page_exception("@@||a.invalid^$domain=b.invalid,elemhide,~third-party").unwrap();
        assert_eq!(e.rule, "@@||a.invalid^$domain=b.invalid,~third-party,generichide");
        assert!(e.elemhide && !e.document && !e.specifichide);
        for other in ["||a.invalid^$elemhide", "@@||a.invalid^", "@@||a.invalid^$generichide", "a.invalid##.x"] {
            assert_eq!(page_exception(other), None, "{other}");
        }
    }
}
