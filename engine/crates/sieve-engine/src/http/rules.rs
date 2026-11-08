//! What the rules make of one request (plan 5.3, task D13):
//! - **Block:** 403, empty, `no-store`; nothing goes upstream.
//! - **Redirect:** the resource, decoded, as a 200; nothing goes upstream. A
//!   rule whose resource is missing stays a block.
//! - **Removeparam:** a GET or HEAD document gets a 307 to the clean URL, so
//!   page script cannot read the parameter either; anything else is rewritten
//!   in place. The rewritten URL has no parameter, so it cannot loop. Tracking
//!   protection's `queryParams` removes the built-in parameters the same way,
//!   from pages and frames only.

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
    let d = filter.rules.check_request(&RequestQuery { url: facts.url, initiator: facts.initiator, request_type: facts.request_type, method: facts.method });
    let mut changes = Changes::default();
    let (action, outcome) = match d.verdict {
        HostVerdict::Block => match d.redirect.as_deref().and_then(decode_data_url) {
            Some((content_type, body)) => (Action::Serve { content_type, body }, LogOutcome::Redirected),
            None => (Action::Block, LogOutcome::Blocked),
        },
        verdict => match strip_tracking(filter, facts, d.rewritten, &mut changes) {
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
fn strip_tracking(filter: &DomainFilter, facts: &RequestFacts<'_>, rewritten: Option<String>, changes: &mut Changes) -> Option<String> {
    if !(facts.is_page() && filter.tracking_in_force().has(Protection::QueryParams)) {
        return rewritten;
    }
    match ParamList::built_in().strip(rewritten.as_deref().unwrap_or(facts.url)) {
        Some((clean, removed)) => {
            changes.add(Protection::QueryParams, removed);
            Some(clean)
        }
        None => rewritten,
    }
}
