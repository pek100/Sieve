//! What the rules make of one request (plan 5.3, task D13):
//! - **Block:** 403, empty, `no-store`; nothing goes upstream.
//! - **Redirect:** the resource, decoded, as a 200; nothing goes upstream. A
//!   rule whose resource is missing stays a block.
//! - **Removeparam:** a GET or HEAD document gets a 307 to the clean URL, so
//!   page script cannot read the parameter either; anything else is rewritten
//!   in place. The rewritten URL has no parameter, so it cannot loop by itself;
//!   a site that redirects back to the parameter is met by [`clean_location`]
//!   and [`super::serve`]'s memory of its redirects. Tracking protection's
//!   `queryParams` removes the built-in parameters the same way, from pages and
//!   frames only, unless an exception holds for the request.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sieve_filter::params::ParamList;
use sieve_filter::rules::{HostVerdict, RequestQuery};
use sieve_ipc::LogOutcome;

use super::facts::RequestFacts;
use super::tracking::{Changes, Protection};
use crate::domain::DomainFilter;

const DATA_SCHEME: &str = "data:";
const BASE64_MARK: &str = ";base64";
const NO_RULE: &str = "no_rule";
const EXCEPTION: &str = "exception";
const DISABLED: &str = "disabled";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Forward { rewritten: Option<String> },
    Block,
    Serve { content_type: String, body: Vec<u8> },
    RedirectTo(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruling {
    pub action: Action,
    pub outcome: LogOutcome,
    pub rule: Option<String>,
    pub list: Option<String>,
    /// What tracking protection changed in the URL.
    pub changes: Changes,
}

/// A `data:` URL as a type and its bytes; None when it is not one.
fn decode_data_url(url: &str) -> Option<(String, Vec<u8>)> {
    let (head, data) = url.strip_prefix(DATA_SCHEME)?.split_once(',')?;
    match head.strip_suffix(BASE64_MARK) {
        Some(kind) => Some((kind.to_string(), STANDARD.decode(data).ok()?)),
        None => Some((head.to_string(), data.as_bytes().to_vec())),
    }
}

const SAFE_METHODS: [&str; 2] = ["GET", "HEAD"];

/// The ruling on one request. With the global switch off no rule is asked.
pub fn rule(filter: &DomainFilter, facts: &RequestFacts<'_>) -> Ruling {
    let passed = |reason: &str| LogOutcome::Passed { reason: reason.to_string() };
    if !filter.enabled {
        return Ruling { action: Action::Forward { rewritten: None }, outcome: passed(DISABLED), rule: None, list: None, changes: Changes::default() };
    }
    let d = filter.rules.check_request(&query_of(facts));
    let mut changes = Changes::default();
    let (action, outcome) = match d.verdict {
        HostVerdict::Block => match d.redirect.as_deref().and_then(decode_data_url) {
            Some((content_type, body)) => (Action::Serve { content_type, body }, LogOutcome::Redirected),
            None => (Action::Block, LogOutcome::Blocked),
        },
        verdict => match strip_tracking(filter, facts, verdict, d.rewritten, &mut changes) {
            Some(clean) if facts.is_document && SAFE_METHODS.contains(&facts.method) => (Action::RedirectTo(clean), LogOutcome::ParamsRemoved),
            Some(clean) => (Action::Forward { rewritten: Some(clean) }, LogOutcome::ParamsRemoved),
            None => (Action::Forward { rewritten: None }, passed(if verdict == HostVerdict::Allow { EXCEPTION } else { NO_RULE })),
        },
    };
    Ruling { action, outcome, rule: d.rule, list: d.list, changes }
}

/// The URL after the lists' `$removeparam`, then, for a page or frame with
/// `queryParams` on, without the built-in tracking parameters. Only a page: a
/// subresource's URL can be signed, and its parameters are not what a link carried.
/// The user's and the lists' exceptions hold: an `@@` rule for the request
/// (`HostVerdict::Allow`) leaves the built-in list out, and a `$removeparam`
/// exception keeps the names it names.
fn strip_tracking(filter: &DomainFilter, facts: &RequestFacts<'_>, verdict: HostVerdict, rewritten: Option<String>, changes: &mut Changes) -> Option<String> {
    if verdict == HostVerdict::Allow || !strips_built_in(filter, facts) {
        return rewritten;
    }
    match strip_built_in(filter, facts, rewritten.as_deref().unwrap_or(facts.url)) {
        Some((clean, removed)) => {
            changes.add(Protection::QueryParams, removed);
            Some(clean)
        }
        None => rewritten,
    }
}

fn strips_built_in(filter: &DomainFilter, facts: &RequestFacts<'_>) -> bool {
    facts.is_page() && filter.tracking_in_force().has(Protection::QueryParams)
}

/// `url` without the built-in parameters the exceptions for `facts` do not keep.
fn strip_built_in(filter: &DomainFilter, facts: &RequestFacts<'_>, url: &str) -> Option<(String, u32)> {
    let list = ParamList::built_in();
    // The exceptions are asked only when there is something to keep.
    list.strip(url)?;
    let kept = filter.rules.kept_params(&query_of(facts));
    list.strip_keeping(url, |name| kept.keeps(name))
}

fn query_of<'a>(facts: &RequestFacts<'a>) -> RequestQuery<'a> {
    RequestQuery { url: facts.url, initiator: facts.initiator, request_type: facts.request_type, method: facts.method }
}

/// The `Location` of an upstream redirect answering a page, without the built-in
/// parameters (queryParams on), and how many went; None to leave it as it is.
/// Without this a site that redirects to an address carrying them would be sent
/// there, 307'd back, and so on. The target's own exceptions hold, as they will
/// when it is asked for. A redirect to this very request's address is the site
/// insisting on the parameters: it is left alone, and [`super::serve`] stops
/// redirecting that address.
pub fn clean_location(filter: &DomainFilter, facts: &RequestFacts<'_>, location: &str) -> Option<(String, u32)> {
    if !(filter.enabled && strips_built_in(filter, facts)) {
        return None;
    }
    let here = url::Url::parse(facts.url).ok()?;
    let target = here.join(location.trim()).ok()?;
    let target_facts = RequestFacts { url: target.as_str(), ..*facts };
    if filter.rules.check_request(&query_of(&target_facts)).verdict != HostVerdict::None {
        // An exception keeps them; a block answers the target anyway.
        return None;
    }
    let (clean, removed) = strip_built_in(filter, &target_facts, location.trim())?;
    (here.join(&clean).ok()? != here).then_some((clean, removed))
}
