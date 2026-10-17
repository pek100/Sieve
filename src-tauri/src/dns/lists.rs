//! List source: the filter list is downloaded at runtime into the app data
//! dir (never vendored), cached with the time it was fetched, refreshed when
//! older than `MAX_AGE_MS`, and the cached copy is used while offline. The
//! user's own rules (`user-rules.txt`, same syntax) are merged on top.
//!
//! Time and the network are injected (`now`, `Fetcher`) so every decision
//! here is testable without a clock or a socket.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::DnsError;
use super::rules::RuleSet;

/// AdGuard DNS filter, the default list.
pub const DEFAULT_LIST_URL: &str =
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt";
/// A cached list older than this is re-downloaded (24 h).
pub const MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000;
/// Timeout for one list download.
pub const DOWNLOAD_TIMEOUT_SECS: u64 = 60;

const LIST_FILE: &str = "filter.txt";
const META_FILE: &str = "filter.meta.json";
pub const USER_RULES_FILE: &str = "user-rules.txt";

/// Downloads a URL as text. Injected so tests never touch the network.
pub type Fetcher = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> + Send + Sync,
>;

/// The real fetcher (HTTPS through the OS TLS stack).
pub fn http_fetcher() -> Fetcher {
    Arc::new(|url: String| Box::pin(fetch_http(url)))
}

async fn fetch_http(url: String) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let response = client.get(&url).send().await.map_err(|e| format!("download failed: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("download failed: HTTP {status}"));
    }
    response.text().await.map_err(|e| format!("download failed: {e}"))
}

#[derive(Debug, Serialize, Deserialize)]
struct Meta {
    url: String,
    fetched_at: u64,
}

/// A list text and when it was fetched (ms since the Unix epoch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cached {
    pub text: String,
    pub fetched_at: u64,
}

/// The outcome of `load`: the text to use (if any) and what went wrong on
/// the way (if anything). A failed refresh with a usable cache is a list
/// AND an error; the error is reported, the cache still filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListLoad {
    pub list: Option<Cached>,
    /// True when `list` came from the network on this call.
    pub downloaded: bool,
    pub error: Option<String>,
}

/// True when a list fetched at `fetched_at` must be refreshed at `now`. A
/// timestamp in the future (clock moved back) counts as stale, so a skewed
/// clock can never pin an old list forever.
pub fn is_stale(fetched_at: u64, now: u64) -> bool {
    fetched_at > now || now - fetched_at >= MAX_AGE_MS
}

/// The cached list for `url`, or None when there is none or it was fetched
/// from a different URL.
pub fn read_cache(dir: &Path, url: &str) -> Result<Option<Cached>, DnsError> {
    let meta_path = dir.join(META_FILE);
    let meta_text = match std::fs::read_to_string(&meta_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(DnsError::io(&meta_path, e)),
    };
    let Ok(meta) = serde_json::from_str::<Meta>(&meta_text) else {
        return Ok(None);
    };
    if meta.url != url {
        return Ok(None);
    }
    let list_path = dir.join(LIST_FILE);
    match std::fs::read_to_string(&list_path) {
        Ok(text) => Ok(Some(Cached { text, fetched_at: meta.fetched_at })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(DnsError::io(&list_path, e)),
    }
}

/// Writes the list then its meta, each through a temp file and a rename,
/// so a crash never leaves a list paired with the wrong timestamp.
pub fn write_cache(dir: &Path, url: &str, text: &str, now: u64) -> Result<(), DnsError> {
    std::fs::create_dir_all(dir).map_err(|e| DnsError::io(dir, e))?;
    write_atomic(&dir.join(LIST_FILE), text)?;
    let meta = serde_json::to_string(&Meta { url: url.to_owned(), fetched_at: now })
        .map_err(|e| DnsError::Cache(e.to_string()))?;
    write_atomic(&dir.join(META_FILE), &meta)
}

fn write_atomic(path: &Path, text: &str) -> Result<(), DnsError> {
    let tmp: PathBuf = path.with_extension("tmp");
    std::fs::write(&tmp, text).map_err(|e| DnsError::io(&tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| DnsError::io(path, e))
}

/// The user's rules, or empty text when the file does not exist.
pub fn read_user_rules(dir: &Path) -> Result<String, DnsError> {
    let path = dir.join(USER_RULES_FILE);
    match std::fs::read_to_string(&path) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(DnsError::io(&path, e)),
    }
}

/// The list to filter with at `now`: a fresh cache as is; otherwise a
/// download, kept only if it holds at least one block rule (a captive
/// portal page or an empty body never replaces a good cache); otherwise
/// the stale cache, with the reason; otherwise nothing, with the reason.
pub async fn load(dir: &Path, url: &str, now: u64, fetch: &Fetcher) -> ListLoad {
    let (cached, mut error) = match read_cache(dir, url) {
        Ok(c) => (c, None),
        Err(e) => (None, Some(e.to_string())),
    };
    if let Some(c) = &cached
        && !is_stale(c.fetched_at, now)
    {
        return ListLoad { list: cached, downloaded: false, error };
    }
    match fetch(url.to_owned()).await {
        Ok(text) if has_block_rules(&text) => {
            let write_error = write_cache(dir, url, &text, now).err().map(|e| e.to_string());
            ListLoad {
                list: Some(Cached { text, fetched_at: now }),
                downloaded: true,
                error: write_error,
            }
        }
        Ok(_) => {
            error = Some("download held no block rules; not used".to_owned());
            ListLoad { list: cached, downloaded: false, error }
        }
        Err(e) => ListLoad { list: cached, downloaded: false, error: Some(e) },
    }
}

fn has_block_rules(text: &str) -> bool {
    let mut r = RuleSet::new();
    r.add_text(text);
    r.counts().block > 0
}

/// The one way list and user rules become a RuleSet: the list, then the
/// user's rules on top (an allow rule wins wherever it comes from).
pub fn build_rules(list: Option<&str>, user: &str) -> RuleSet {
    let mut rules = RuleSet::new();
    if let Some(text) = list {
        rules.add_text(text);
    }
    rules.add_text(user);
    rules
}

#[cfg(test)]
mod tests {
    use super::super::rules::Verdict;
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const URL: &str = "https://lists.example.invalid/filter.txt";
    const FIXTURE: &str = "! fixture\n||ads.sieve-test.invalid^\n||doubleclick.net^\n";
    const T0: u64 = 1_800_000_000_000;

    /// A fetcher that returns `reply` and counts its calls.
    fn fake(reply: Result<&'static str, &'static str>) -> (Fetcher, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let f: Fetcher = Arc::new(move |_url| {
            c.fetch_add(1, Ordering::SeqCst);
            let r = reply.map(str::to_owned).map_err(str::to_owned);
            Box::pin(async move { r })
        });
        (f, calls)
    }

    #[test]
    fn staleness_is_24_hours_and_future_timestamps_are_stale() {
        assert!(!is_stale(T0, T0));
        assert!(!is_stale(T0, T0 + MAX_AGE_MS - 1));
        assert!(is_stale(T0, T0 + MAX_AGE_MS));
        assert!(is_stale(T0 + 1, T0));
    }

    #[tokio::test]
    async fn first_load_downloads_and_caches_with_timestamp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (f, calls) = fake(Ok(FIXTURE));
        let got = load(dir.path(), URL, T0, &f).await;
        assert!(got.downloaded);
        assert_eq!(got.error, None);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let cached = read_cache(dir.path(), URL).expect("read").expect("cached");
        assert_eq!(cached, Cached { text: FIXTURE.to_owned(), fetched_at: T0 });
    }

    #[tokio::test]
    async fn fresh_cache_is_used_without_the_network() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_cache(dir.path(), URL, FIXTURE, T0).expect("write");
        let (f, calls) = fake(Ok("||other.example^"));
        let got = load(dir.path(), URL, T0 + MAX_AGE_MS - 1, &f).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!got.downloaded);
        assert_eq!(got.list.map(|c| c.text).as_deref(), Some(FIXTURE));
    }

    #[tokio::test]
    async fn stale_cache_is_refreshed() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_cache(dir.path(), URL, FIXTURE, T0).expect("write");
        let (f, calls) = fake(Ok("||new.example.com^"));
        let now = T0 + MAX_AGE_MS;
        let got = load(dir.path(), URL, now, &f).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(got.downloaded);
        let cached = read_cache(dir.path(), URL).expect("read").expect("cached");
        assert_eq!(cached.fetched_at, now);
        assert_eq!(cached.text, "||new.example.com^");
    }

    #[tokio::test]
    async fn offline_with_stale_cache_uses_the_cache_and_reports_why() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_cache(dir.path(), URL, FIXTURE, T0).expect("write");
        let (f, _) = fake(Err("download failed: offline"));
        let got = load(dir.path(), URL, T0 + 3 * MAX_AGE_MS, &f).await;
        assert!(!got.downloaded);
        assert_eq!(got.list.map(|c| c.fetched_at), Some(T0));
        assert_eq!(got.error.as_deref(), Some("download failed: offline"));
    }

    #[tokio::test]
    async fn offline_without_cache_has_no_list_and_says_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (f, _) = fake(Err("download failed: offline"));
        let got = load(dir.path(), URL, T0, &f).await;
        assert_eq!(got.list, None);
        assert!(got.error.is_some());
    }

    #[tokio::test]
    async fn a_download_without_block_rules_never_replaces_the_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_cache(dir.path(), URL, FIXTURE, T0).expect("write");
        let (f, _) = fake(Ok("<html><body>Sign in to the hotel wifi</body></html>"));
        let got = load(dir.path(), URL, T0 + MAX_AGE_MS, &f).await;
        assert_eq!(got.list.map(|c| c.text).as_deref(), Some(FIXTURE));
        assert!(got.error.is_some());
        let cached = read_cache(dir.path(), URL).expect("read").expect("cached");
        assert_eq!(cached.fetched_at, T0);
    }

    #[tokio::test]
    async fn a_cache_from_another_url_is_not_used() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_cache(dir.path(), "https://other.invalid/list.txt", FIXTURE, T0).expect("write");
        assert_eq!(read_cache(dir.path(), URL).expect("read"), None);
        let (f, calls) = fake(Ok(FIXTURE));
        load(dir.path(), URL, T0, &f).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn user_rules_merge_on_top_and_their_allow_wins() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_user_rules(dir.path()).expect("missing is empty"), "");
        std::fs::write(
            dir.path().join(USER_RULES_FILE),
            "@@||doubleclick.net^\n||mine.example.org^\n",
        )
        .expect("write");
        let user = read_user_rules(dir.path()).expect("read");
        let rules = build_rules(Some(FIXTURE), &user);
        assert_eq!(rules.verdict("doubleclick.net"), Verdict::Allow);
        assert_eq!(rules.verdict("mine.example.org"), Verdict::Block);
        assert_eq!(rules.verdict("ads.sieve-test.invalid"), Verdict::Block);
        let counts = rules.counts();
        assert_eq!((counts.block, counts.allow), (3, 1));
    }

    #[test]
    fn no_list_still_applies_user_rules() {
        let rules = build_rules(None, "||only.user.example^");
        assert_eq!(rules.verdict("a.only.user.example"), Verdict::Block);
    }
}
