//! The content hook (plan 5.6, slice 9): decrypted documents and frames through
//! [`super::begin`], while the snapshot says `filtering.content` is on. The switch
//! and the rules are one atomic snapshot read per response, so off reaches the
//! next response with no rebuild of interception; a body already being rewritten
//! finishes, since cutting it would break a page. `filtering.https` off means no
//! interception, and so no hook, by structure. Forwarded flows never get here.

use std::sync::Arc;

use http::header::ACCEPT_ENCODING;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use sieve_ipc::LogChange;

use super::decode::readable_accept_encoding;
use super::privacy;
use super::response::{PageRequest, body_format};
use super::{InjectError, InjectLimits, PageRewriter, begin_with};
use crate::domain::{DomainFilter, FilterSlot};
use crate::http::facts::RequestFacts;
use crate::http::hook::{BodyRewrite, HookError, ResponseHook};
use crate::stack::Meters;

const VALUE_SEPARATOR: &str = ", ";

pub struct ContentHook {
    filter: Arc<FilterSlot>,
    meters: Arc<Meters>,
    limits: InjectLimits,
}

impl ContentHook {
    pub fn new(filter: Arc<FilterSlot>, meters: Arc<Meters>, limits: InjectLimits) -> Self {
        Self { filter, meters, limits }
    }

    /// The snapshot, when it rewrites this request's response at all.
    fn page_snapshot(&self, req: &RequestFacts<'_>) -> Option<Arc<DomainFilter>> {
        if !req.is_page() {
            return None;
        }
        let snapshot = self.filter.get();
        (snapshot.enabled && snapshot.content).then_some(snapshot)
    }
}

/// `is_document` holds by the caller's `page_snapshot`. A method hyper accepted
/// always parses; one that did not is no page.
fn page_method(req: &RequestFacts<'_>) -> Option<Method> {
    Method::from_bytes(req.method.as_bytes()).ok()
}

impl ResponseHook for ContentHook {
    /// A body in an encoding `inject` cannot read would pass through uninjected,
    /// so a page is asked for only what it can. Subresources are not rewritten,
    /// so narrowing theirs would only cost bytes.
    fn prepare_request(&self, req: &RequestFacts<'_>, headers: &mut HeaderMap) {
        if self.page_snapshot(req).is_none() || !headers.contains_key(ACCEPT_ENCODING) {
            return;
        }
        let offered: Vec<&str> = headers.get_all(ACCEPT_ENCODING).iter().filter_map(|value| value.to_str().ok()).collect();
        let narrowed = readable_accept_encoding(&offered.join(VALUE_SEPARATOR));
        if let Ok(value) = HeaderValue::from_str(&narrowed) {
            headers.insert(ACCEPT_ENCODING, value);
        }
    }

    fn wants(&self, req: &RequestFacts<'_>, status: StatusCode, headers: &HeaderMap) -> bool {
        let Some(method) = page_method(req) else { return false };
        self.page_snapshot(req).is_some() && body_format(&PageRequest { url: req.url, method: &method, is_document: true }, status, headers).is_some()
    }

    /// Asks the snapshot again: a swap since `wants` answers None, and the body
    /// passes, which is safe.
    fn begin(&self, req: &RequestFacts<'_>, status: StatusCode, headers: &mut HeaderMap, body_start: &[u8]) -> Option<Box<dyn BodyRewrite>> {
        let method = page_method(req)?;
        let snapshot = self.page_snapshot(req)?;
        let request = PageRequest { url: req.url, method: &method, is_document: true };
        let rewriter = begin_with(&snapshot.rules, &privacy::script(snapshot.tracking_in_force()), &request, status, headers, body_start, &self.limits)?;
        let changes = rewriter.own_changes().to_vec();
        let meters = &self.meters.content;
        Meters::bump(&meters.rewritten);
        if rewriter.has_scriptlets() {
            Meters::bump(&meters.with_scriptlets);
        }
        if rewriter.has_procedural() {
            Meters::bump(&meters.with_procedural);
        }
        Some(Box::new(Page { rewriter, meters: self.meters.clone(), changes }))
    }
}

/// One page being rewritten, counted when it resets.
struct Page {
    rewriter: PageRewriter,
    meters: Arc<Meters>,
    /// The tracking protections its script carries.
    changes: Vec<LogChange>,
}

impl Page {
    fn reset(meters: &Meters, error: &InjectError) -> HookError {
        Meters::bump(&meters.content.resets);
        HookError(error.to_string())
    }
}

impl BodyRewrite for Page {
    fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, HookError> {
        self.rewriter.push(chunk).map_err(|e| Self::reset(&self.meters, &e))
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, HookError> {
        let Self { rewriter, meters, .. } = *self;
        rewriter.finish().map_err(|e| Self::reset(&meters, &e))
    }

    fn changes(&self) -> Vec<LogChange> {
        self.changes.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use sieve_filter::rules::{ListText, RuleEngine, RuleSet};
    use sieve_ipc::Policy;

    use super::*;

    const URL: &str = "https://sieve-test.invalid/";

    fn hook(content: bool) -> ContentHook {
        let lists = RuleEngine::compile(&[ListText { id: "l", text: "##.x\n", trusted: true }]);
        let rules = RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(lists) };
        let filter = DomainFilter::new(&Policy { sieving: true, content, ..Policy::default() }, rules);
        ContentHook::new(Arc::new(FilterSlot::new(filter)), Arc::default(), InjectLimits::default())
    }

    fn facts(request_type: &'static str) -> RequestFacts<'static> {
        RequestFacts { url: URL, method: "GET", is_document: request_type == "document", request_type, initiator: "" }
    }

    fn html() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        headers
    }

    #[test]
    fn it_wants_a_page_it_can_read_with_the_switch_on_only() {
        assert!(hook(true).wants(&facts("document"), StatusCode::OK, &html()));
        assert!(hook(true).wants(&facts("sub_frame"), StatusCode::OK, &html()));
        assert!(!hook(false).wants(&facts("document"), StatusCode::OK, &html()));
        assert!(!hook(true).wants(&facts("script"), StatusCode::OK, &html()));
        assert!(!hook(true).wants(&facts("document"), StatusCode::NOT_MODIFIED, &html()));
        assert!(!hook(true).wants(&facts("document"), StatusCode::OK, &HeaderMap::new()));
    }

    #[test]
    fn a_swap_after_wants_passes_the_body() {
        let hook = hook(true);
        assert!(hook.wants(&facts("document"), StatusCode::OK, &html()));
        hook.filter.update(|f| DomainFilter::new(&Policy { sieving: true, ..Policy::default() }, f.rules.clone()));
        let mut headers = html();
        assert!(hook.begin(&facts("document"), StatusCode::OK, &mut headers, b"").is_none());
        assert_eq!(headers, html(), "the head is untouched");
        assert_eq!(hook.meters.content.rewritten.load(Ordering::Relaxed), 0);
    }

    /// Several values, as a proxy before the browser may have split them.
    #[test]
    fn accept_encoding_values_are_narrowed_as_one() {
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT_ENCODING, HeaderValue::from_static("gzip, dcb"));
        headers.append(ACCEPT_ENCODING, HeaderValue::from_static("dcz, br"));
        hook(true).prepare_request(&facts("document"), &mut headers);
        assert_eq!(headers.get_all(ACCEPT_ENCODING).iter().collect::<Vec<_>>(), ["gzip, br"]);
    }

    #[test]
    fn no_accept_encoding_stays_absent() {
        let mut headers = HeaderMap::new();
        hook(true).prepare_request(&facts("document"), &mut headers);
        assert!(headers.is_empty());
    }

    /// Source level: production must not be the hook that rewrites nothing.
    #[test]
    fn the_hook_is_what_build_interception_wires() {
        let routing = include_str!("../control/routing.rs");
        assert!(routing.contains("hook: Arc::new(ContentHook::new(engine.filter.clone(), engine.meters.clone(), InjectLimits::default()))"));
        assert!(!routing.contains("NoRewrite"));
    }
}
