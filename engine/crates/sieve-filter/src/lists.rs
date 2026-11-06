//! Download state of one list (plan 5.4). The refresh interval is read from
//! the list's own `! Expires:` header and clamped, so it is derived from the
//! data, not a per-list table (S49). Requests are conditional. A response is
//! judged here, and only a good one replaces the copy: a captive portal's 200
//! must not erase a list. No I/O: the engine fetches, stores and compiles.

use std::time::Duration;

use adblock::lists::{ExpiresInterval, read_list_metadata};
use serde::{Deserialize, Serialize};

use crate::rules::has_a_rule;

const HOUR: Duration = Duration::from_secs(3_600);
/// Never refresh more often than this, whatever the list says.
pub const MIN_REFRESH: Duration = HOUR;
/// Never wait longer than this, whatever the list says.
pub const MAX_REFRESH: Duration = Duration::from_secs(4 * 24 * 3_600);
/// A list without a readable `Expires` header refreshes at the slowest rate.
pub const DEFAULT_REFRESH: Duration = MAX_REFRESH;
/// A list with no copy at all filters nothing, so it retries this soon: often
/// enough to recover from a network that was down at start, far below any
/// list host's rate limits (one request per list per 5 minutes).
pub const NO_COPY_RETRY: Duration = Duration::from_secs(5 * 60);
/// A larger response is refused. The largest default list is about 10 MiB, so
/// this leaves room to grow and still bounds what a bad server can make the
/// engine hold.
pub const MAX_LIST_BYTES: usize = 32 * 1024 * 1024;

const HTML_TYPE: &str = "text/html";
const HTML_STARTS: [&str; 2] = ["<!doctype", "<html"];
const BOM: char = '\u{feff}';

/// How long a downloaded copy of `text` stays fresh.
pub fn refresh_interval(text: &str) -> Duration {
    let declared = match read_list_metadata(text).expires {
        Some(ExpiresInterval::Hours(h)) => HOUR * u32::from(h),
        Some(ExpiresInterval::Days(d)) => HOUR * 24 * u32::from(d),
        None => DEFAULT_REFRESH,
    };
    declared.clamp(MIN_REFRESH, MAX_REFRESH)
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// What a fetcher got back for a list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchResponse {
    pub status: u16,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// What a response meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// A good new copy, to store and compile.
    Replaced(String),
    /// The copy is still current.
    NotModified,
    /// Nothing changes; the state says why.
    Refused,
}

/// Why a 200 is not a list, or None when it is one.
fn refuse_body(response: &FetchResponse) -> Result<&str, String> {
    if response.body.len() > MAX_LIST_BYTES {
        return Err(format!("{} bytes is over the {MAX_LIST_BYTES} byte limit", response.body.len()));
    }
    let text = std::str::from_utf8(&response.body).map_err(|e| format!("not UTF-8: {e}"))?;
    let text = text.strip_prefix(BOM).unwrap_or(text);
    let declared_html = response.content_type.as_deref().is_some_and(|t| t.to_ascii_lowercase().starts_with(HTML_TYPE));
    let head = text.trim_start().as_bytes();
    if declared_html || HTML_STARTS.iter().any(|start| head.get(..start.len()).is_some_and(|h| h.eq_ignore_ascii_case(start.as_bytes()))) {
        return Err("an HTML page, not a filter list".into());
    }
    if !has_a_rule(text) {
        return Err("no rule in the response".into());
    }
    Ok(text)
}

/// What the engine remembers about the downloads of a list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FetchState {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// Milliseconds since the Unix epoch of the last good download or 304.
    pub fetched_at_ms: Option<u64>,
    /// Why the last attempt failed, cleared by the next good one.
    pub last_error: Option<String>,
    pub failed_at_ms: Option<u64>,
    /// The refresh interval read from the copy, never stored (S23).
    #[serde(skip)]
    pub refresh: Duration,
}

impl FetchState {
    /// The state after a good download of `text` at `now_ms`.
    pub fn fetched(text: &str, etag: Option<String>, last_modified: Option<String>, now_ms: u64) -> Self {
        Self { etag, last_modified, fetched_at_ms: Some(now_ms), refresh: refresh_interval(text), ..Self::default() }
    }

    /// A saved state joined with what its copy holds now. No copy means
    /// nothing in the state may be believed: an ETag sent without a copy
    /// would earn a 304 and leave the list empty.
    pub fn restored(self, copy: Option<&str>) -> Self {
        let Some(text) = copy else { return Self::default() };
        Self { refresh: refresh_interval(text), ..self }
    }

    /// When the next attempt is due, in ms since the epoch. A failed attempt
    /// waits [`MIN_REFRESH`], or [`NO_COPY_RETRY`] with no copy to fall back on.
    pub fn due_at_ms(&self) -> u64 {
        let fresh_until = self.fetched_at_ms.map(|t| t.saturating_add(millis(self.refresh)));
        let retry = if self.fetched_at_ms.is_some() { MIN_REFRESH } else { NO_COPY_RETRY };
        let retry_at = self.failed_at_ms.map(|t| t.saturating_add(millis(retry)));
        fresh_until.into_iter().chain(retry_at).max().unwrap_or(0)
    }

    /// True when a download should be attempted now.
    pub fn is_due(&self, now_ms: u64) -> bool {
        now_ms >= self.due_at_ms()
    }

    /// The headers that make the next request conditional.
    pub fn conditional_headers(&self) -> Vec<(&'static str, String)> {
        let etag = self.etag.clone().map(|v| ("If-None-Match", v));
        let modified = self.last_modified.clone().map(|v| ("If-Modified-Since", v));
        etag.into_iter().chain(modified).collect()
    }

    /// The attempt failed before a response (timeout, TLS, connect).
    pub fn failed(&mut self, why: String, now_ms: u64) {
        self.last_error = Some(why);
        self.failed_at_ms = Some(now_ms);
    }

    /// Judges a response at `now_ms`.
    pub fn apply(&mut self, response: FetchResponse, now_ms: u64) -> Applied {
        match response.status {
            200 => match refuse_body(&response).map(str::to_string) {
                Ok(text) => {
                    *self = Self::fetched(&text, response.etag, response.last_modified, now_ms);
                    Applied::Replaced(text)
                }
                Err(why) => self.refuse(why, now_ms),
            },
            304 if self.fetched_at_ms.is_some() => {
                self.fetched_at_ms = Some(now_ms);
                self.last_error = None;
                self.failed_at_ms = None;
                Applied::NotModified
            }
            status => self.refuse(format!("HTTP {status}"), now_ms),
        }
    }

    fn refuse(&mut self, why: String, now_ms: u64) -> Applied {
        self.failed(why, now_ms);
        Applied::Refused
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_MS: u64 = 24 * 3_600_000;

    fn list(expires: &str) -> String {
        format!("[Adblock Plus 2.0]\n! Title: Test\n! Expires: {expires}\n||ads.example^\n")
    }

    fn ok(body: &str) -> FetchResponse {
        FetchResponse { status: 200, body: body.as_bytes().to_vec(), etag: Some("\"v1\"".into()), ..FetchResponse::default() }
    }

    #[test]
    fn expires_is_read_and_clamped_to_one_hour_to_four_days() {
        assert_eq!(refresh_interval(&list("12 hours")), HOUR * 12);
        assert_eq!(refresh_interval(&list("2 days")), HOUR * 48);
        assert_eq!(refresh_interval(&list("1 hour")), MIN_REFRESH);
        assert_eq!(refresh_interval(&list("10 days")), MAX_REFRESH, "above the cap");
        assert_eq!(refresh_interval("||ads.example^\n"), DEFAULT_REFRESH, "no header");
        assert_eq!(refresh_interval(&list("soon")), DEFAULT_REFRESH, "unreadable header");
        assert_eq!(refresh_interval(&list("0 hours")), DEFAULT_REFRESH, "zero is not a valid interval");
    }

    #[test]
    fn due_when_never_fetched_or_past_the_refresh() {
        assert!(FetchState::default().is_due(0));
        let s = FetchState::fetched(&list("12 hours"), None, None, 1_000);
        assert!(!s.is_due(1_000));
        assert!(!s.is_due(1_000 + 12 * 3_600_000 - 1));
        assert!(s.is_due(1_000 + 12 * 3_600_000));
        assert!(!s.is_due(0), "a clock that went back is not a reason to refetch");
    }

    #[test]
    fn conditional_headers_carry_what_the_server_sent() {
        assert!(FetchState::default().conditional_headers().is_empty());
        let s = FetchState::fetched("", Some("\"abc\"".into()), Some("Sat, 17 Oct 2026 10:00:00 GMT".into()), 0);
        assert_eq!(
            s.conditional_headers(),
            [("If-None-Match", "\"abc\"".to_string()), ("If-Modified-Since", "Sat, 17 Oct 2026 10:00:00 GMT".to_string())]
        );
    }

    #[test]
    fn a_good_response_replaces_the_copy_and_a_304_renews_the_time() {
        let mut s = FetchState::default();
        let body = list("1 day");
        assert_eq!(s.apply(ok(&body), 10), Applied::Replaced(body.clone()));
        assert_eq!((s.etag.as_deref(), s.fetched_at_ms, s.refresh), (Some("\"v1\""), Some(10), HOUR * 24));
        let etag = s.etag.clone();
        assert_eq!(s.apply(FetchResponse { status: 304, ..FetchResponse::default() }, 20), Applied::NotModified);
        assert_eq!((s.etag, s.fetched_at_ms, s.refresh), (etag, Some(20), HOUR * 24));
    }

    #[test]
    fn a_304_with_no_copy_is_a_failure() {
        let mut s = FetchState::default();
        assert_eq!(s.apply(FetchResponse { status: 304, ..FetchResponse::default() }, 5), Applied::Refused);
        assert!(s.last_error.is_some() && s.fetched_at_ms.is_none());
    }

    #[test]
    fn every_bad_response_keeps_the_state_of_the_good_copy_and_says_why() {
        let good = FetchState::fetched(&list("1 day"), Some("\"v1\"".into()), None, 1);
        let bad = [
            (FetchResponse { status: 500, ..FetchResponse::default() }, "HTTP 500"),
            (FetchResponse { status: 302, ..FetchResponse::default() }, "HTTP 302"),
            (ok("<!DOCTYPE html><html>portal</html>"), "HTML"),
            (ok("  \n<html>portal</html>"), "HTML"),
            // Shorter than the longest start, or a character across where it ends.
            (ok("<html>é中<body>sign in</body></html>"), "HTML"),
            (ok("<html>"), "HTML"),
            (ok("<html>\n"), "HTML"),
            (ok("<HTML"), "HTML"),
            (FetchResponse { content_type: Some("Text/HTML; charset=utf-8".into()), ..ok("||ads.example^\n") }, "HTML"),
            (ok(""), "no rule"),
            (ok("! comments only\n"), "no rule"),
            (FetchResponse { status: 200, body: vec![0xff, 0xfe, 0x00], ..FetchResponse::default() }, "UTF-8"),
            (FetchResponse { status: 200, body: vec![b'a'; MAX_LIST_BYTES + 1], ..FetchResponse::default() }, "limit"),
        ];
        for (response, why) in bad {
            let mut s = good.clone();
            assert_eq!(s.apply(response, 2), Applied::Refused, "{why}");
            assert!(s.last_error.as_deref().unwrap().contains(why), "{:?}", s.last_error);
            assert_eq!((s.etag.as_deref(), s.fetched_at_ms, s.failed_at_ms), (Some("\"v1\""), Some(1), Some(2)), "{why}");
        }
    }

    #[test]
    fn a_utf8_bom_is_not_part_of_the_list() {
        let mut s = FetchState::default();
        let body = format!("\u{feff}{}", list("1 day"));
        assert_eq!(s.apply(ok(&body), 0), Applied::Replaced(list("1 day")));
    }

    #[test]
    fn no_copy_retries_sooner_than_a_failed_refresh() {
        let mut none = FetchState::default();
        none.failed("timeout".into(), 1_000);
        assert_eq!(none.due_at_ms(), 1_000 + millis(NO_COPY_RETRY));
        assert!(!none.is_due(1_000 + millis(NO_COPY_RETRY) - 1));

        let mut stale = FetchState::fetched(&list("1 day"), None, None, 0);
        stale.failed("timeout".into(), DAY_MS);
        assert_eq!(stale.due_at_ms(), DAY_MS + millis(MIN_REFRESH));
        assert!(NO_COPY_RETRY < MIN_REFRESH);

        stale.apply(ok(&list("1 day")), DAY_MS + 1);
        assert_eq!((stale.last_error.as_deref(), stale.failed_at_ms), (None, None));
    }

    #[test]
    fn a_saved_state_is_joined_with_its_copy_and_refresh_is_never_stored() {
        let s = FetchState { failed_at_ms: Some(3), ..FetchState::fetched(&list("1 day"), Some("\"v\"".into()), None, 9) };
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("refresh"), "{json}");
        let read: FetchState = serde_json::from_str(&json).unwrap();
        assert_eq!(read.clone().restored(Some(&list("1 day"))), s);
        assert_eq!(read.restored(None), FetchState::default(), "no copy: an ETag would earn a 304 and no list");
    }
}
