//! Download metadata of one list (plan 5.4). The refresh interval is read
//! from the list's own `! Expires:` header and clamped, so it is derived from
//! the data, not a per-list table (S49). Requests are conditional; the last
//! good copy is kept by the caller when a download fails.

use std::time::Duration;

use adblock::lists::{ExpiresInterval, read_list_metadata};

const HOUR: Duration = Duration::from_secs(3_600);
/// Never refresh more often than this, whatever the list says.
pub const MIN_REFRESH: Duration = HOUR;
/// Never wait longer than this, whatever the list says.
pub const MAX_REFRESH: Duration = Duration::from_secs(4 * 24 * 3_600);
/// A list without a readable `Expires` header refreshes at the slowest rate.
pub const DEFAULT_REFRESH: Duration = MAX_REFRESH;

/// How long a downloaded copy of `text` stays fresh.
pub fn refresh_interval(text: &str) -> Duration {
    let declared = match read_list_metadata(text).expires {
        Some(ExpiresInterval::Hours(h)) => HOUR * u32::from(h),
        Some(ExpiresInterval::Days(d)) => HOUR * 24 * u32::from(d),
        None => DEFAULT_REFRESH,
    };
    declared.clamp(MIN_REFRESH, MAX_REFRESH)
}

/// What the engine remembers about its last good download of a list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchState {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// Milliseconds since the Unix epoch of the last good download.
    pub fetched_at_ms: Option<u64>,
    /// The refresh interval read from that copy.
    pub refresh: Duration,
}

impl FetchState {
    /// The state after a good download of `text` at `now_ms`.
    pub fn fetched(text: &str, etag: Option<String>, last_modified: Option<String>, now_ms: u64) -> Self {
        Self { etag, last_modified, fetched_at_ms: Some(now_ms), refresh: refresh_interval(text) }
    }

    /// True when the list was never fetched or its copy is past its refresh.
    pub fn is_due(&self, now_ms: u64) -> bool {
        let refresh_ms = u64::try_from(self.refresh.as_millis()).unwrap_or(u64::MAX);
        self.fetched_at_ms.is_none_or(|t| now_ms.saturating_sub(t) >= refresh_ms)
    }

    /// The headers that make the next request conditional.
    pub fn conditional_headers(&self) -> Vec<(&'static str, String)> {
        let etag = self.etag.clone().map(|v| ("If-None-Match", v));
        let modified = self.last_modified.clone().map(|v| ("If-Modified-Since", v));
        etag.into_iter().chain(modified).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(expires: &str) -> String {
        format!("[Adblock Plus 2.0]\n! Title: Test\n! Expires: {expires}\n||ads.example^\n")
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
}
