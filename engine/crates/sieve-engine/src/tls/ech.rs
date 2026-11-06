//! The engine's own upstream hello uses ECH when the name's HTTPS record carries
//! a config (plan 2.9, task D9, D10). An active lookup behind a cache: one lookup
//! per host in flight, on its own task, so a flow that stops waiting still fills
//! the cache. Every failure ends as a plain handshake, so no site breaks over ECH.
//!
//! Retry configs are not used: on a rejection the server shown is the public
//! name's and the capturing verifier asserts everything, so they would be
//! unauthenticated (task F10). The cost: an active attacker can force the real
//! SNI onto the wire. The hello it forces is the one the browser would have sent
//! with ECH stripped, and a pass-through would show it too.
//!
//! No GREASE without a config: plan 2.9 asks only for use, and it would change
//! the fingerprint with nothing gained. No tap on the browser's own HTTPS
//! queries: an optimisation with no measurement behind it (task U5).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::EchConfig;
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls::pki_types::EchConfigListBytes;
use tokio::sync::watch;

use crate::dns::service::Service;
use crate::dns::{BoxFuture, HttpsRecord, best_ech};
use crate::lru::Lru;

/// How long a flow waits for a lookup, then goes on without ECH.
pub const ECH_LOOKUP_WAIT: Duration = Duration::from_millis(300);
/// How long a handshake that offers ECH may take before the plain one.
pub const ECH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// Hosts remembered: one entry per host in use, as the leaf cache.
const CAPACITY: usize = crate::ca::LEAF_CACHE_SIZE;
/// A found config lives for its TTL, within these.
const MIN_TTL_S: u32 = 60;
const MAX_TTL_S: u32 = 3_600;
/// No config, or one that failed on the wire.
const NEGATIVE_TTL_MS: u64 = 5 * 60_000;
/// A lookup that failed says nothing about the host, so it is soon asked again.
const FAILED_TTL_MS: u64 = 30_000;
/// Another port's record lives under `_port._https`, which is not built (S35).
const HTTPS_PORT: u16 = 443;

/// Where HTTPS records come from: the engine's `Service` in production.
pub trait EchLookup: Send + Sync + 'static {
    fn https<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<HttpsRecord>, String>>;
}

impl EchLookup for Service {
    fn https<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<HttpsRecord>, String>> {
        Box::pin(self.https_records(host))
    }
}

type ConfigList = Arc<Vec<u8>>;

#[derive(Clone)]
struct Entry {
    config: Option<ConfigList>,
    expires_ms: u64,
}

pub struct EchCache {
    lookup: Arc<dyn EchLookup>,
    entries: Mutex<Lru<String, Entry>>,
    in_flight: Mutex<HashMap<String, watch::Receiver<()>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn entry_of(answer: Result<Vec<HttpsRecord>, String>, now_ms: u64) -> Entry {
    let records = match answer {
        Ok(records) => records,
        Err(_) => return Entry { config: None, expires_ms: now_ms.saturating_add(FAILED_TTL_MS) },
    };
    match best_ech(&records).and_then(|r| r.ech.clone().map(|ech| (ech, r.ttl))) {
        Some((ech, ttl)) => Entry { config: Some(Arc::new(ech)), expires_ms: now_ms.saturating_add(u64::from(ttl.clamp(MIN_TTL_S, MAX_TTL_S)) * 1_000) },
        None => Entry { config: None, expires_ms: now_ms.saturating_add(NEGATIVE_TTL_MS) },
    }
}

impl EchCache {
    pub fn new(lookup: Arc<dyn EchLookup>) -> Self {
        Self { lookup, entries: Mutex::new(Lru::new(CAPACITY)), in_flight: Mutex::default() }
    }

    fn cached(&self, host: &str, now_ms: u64) -> Option<Option<ConfigList>> {
        lock(&self.entries).get(host, |e| now_ms < e.expires_ms).map(|e| e.config)
    }

    /// A host never asked for again would hold its config until the count pushed it
    /// out, so what is out of date goes with each store: at most once per lookup.
    fn store(&self, host: String, entry: Entry, now_ms: u64) {
        let mut entries = lock(&self.entries);
        entries.retain(|e| now_ms < e.expires_ms);
        entries.insert(host, entry);
    }

    fn start(self: &Arc<Self>, host: &str, now_ms: u64) -> watch::Receiver<()> {
        let (done, waiting) = watch::channel(());
        let (cache, host) = (self.clone(), host.to_string());
        tokio::spawn(async move {
            let answer = cache.lookup.https(&host).await;
            cache.store(host.clone(), entry_of(answer, now_ms), now_ms);
            lock(&cache.in_flight).remove(&host);
            let _ = done.send(());
        });
        waiting
    }

    /// The ECHConfigList for `host`, waiting at most [`ECH_LOOKUP_WAIT`].
    pub async fn config_for(self: &Arc<Self>, host: &str, port: u16, now_ms: u64) -> Option<ConfigList> {
        if port != HTTPS_PORT {
            return None;
        }
        let mut finished = {
            let mut flying = lock(&self.in_flight);
            if let Some(known) = self.cached(host, now_ms) {
                return known;
            }
            match flying.get(host) {
                Some(waiting) => waiting.clone(),
                None => {
                    let waiting = self.start(host, now_ms);
                    flying.insert(host.to_string(), waiting.clone());
                    waiting
                }
            }
        };
        let _ = tokio::time::timeout(ECH_LOOKUP_WAIT, finished.changed()).await;
        self.cached(host, now_ms).flatten()
    }

    /// This host's config failed on the wire: no ECH for a while.
    pub fn mark_negative(&self, host: &str, now_ms: u64) {
        self.store(host.to_string(), Entry { config: None, expires_ms: now_ms.saturating_add(NEGATIVE_TTL_MS) }, now_ms);
    }
}

/// The config rustls can use; one it cannot counts as no config (task D10).
pub fn usable_config(list: &[u8]) -> Option<EchConfig> {
    EchConfig::new(EchConfigListBytes::from(list), ALL_SUPPORTED_SUITES).ok()
}

#[cfg(test)]
pub(crate) mod testing {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Lookups answered from a script, and counted.
    pub(crate) struct FakeLookup {
        pub(crate) answer: Mutex<Result<Vec<HttpsRecord>, String>>,
        pub(crate) calls: AtomicUsize,
        pub(crate) takes: Duration,
    }

    impl FakeLookup {
        pub(crate) fn says(answer: Result<Vec<HttpsRecord>, String>, takes: Duration) -> Arc<Self> {
            Arc::new(Self { answer: Mutex::new(answer), calls: AtomicUsize::new(0), takes })
        }

        /// One service record holding `ech`.
        pub(crate) fn with_config(ech: Vec<u8>) -> Arc<Self> {
            Self::says(Ok(vec![HttpsRecord { priority: 1, ech: Some(ech), ttl: 300 }]), Duration::ZERO)
        }

        pub(crate) fn none() -> Arc<Self> {
            Self::says(Ok(Vec::new()), Duration::ZERO)
        }

        pub(crate) fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl EchLookup for FakeLookup {
        fn https<'a>(&'a self, _host: &'a str) -> BoxFuture<'a, Result<Vec<HttpsRecord>, String>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                tokio::time::sleep(self.takes).await;
                self.answer.lock().unwrap().clone()
            })
        }
    }

    /// An ECHConfigList: one V18 config for `public_name`, a real X25519 key,
    /// HKDF-SHA256 with AES-128-GCM. The list decoders refuse a bad key only at
    /// use, so the key is a real one (draft-ietf-tls-esni section 4).
    pub(crate) fn config_list(public_name: &str) -> Vec<u8> {
        const VERSION: u16 = 0xfe0d;
        const KEM_X25519: u16 = 0x0020;
        const KDF_HKDF_SHA256: u16 = 0x0001;
        const AEAD_AES_128_GCM: u16 = 0x0001;
        const CONFIG_ID: u8 = 7;
        const MAX_NAME_LENGTH: u8 = 0;
        let key = aws_lc_rs::agreement::PrivateKey::generate(&aws_lc_rs::agreement::X25519).unwrap();
        let public = key.compute_public_key().unwrap();
        let mut contents = vec![CONFIG_ID];
        contents.extend_from_slice(&KEM_X25519.to_be_bytes());
        contents.extend_from_slice(&u16::try_from(public.as_ref().len()).unwrap().to_be_bytes());
        contents.extend_from_slice(public.as_ref());
        contents.extend_from_slice(&4u16.to_be_bytes());
        contents.extend_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
        contents.extend_from_slice(&AEAD_AES_128_GCM.to_be_bytes());
        contents.push(MAX_NAME_LENGTH);
        contents.push(u8::try_from(public_name.len()).unwrap());
        contents.extend_from_slice(public_name.as_bytes());
        contents.extend_from_slice(&0u16.to_be_bytes());
        let mut config = VERSION.to_be_bytes().to_vec();
        config.extend_from_slice(&u16::try_from(contents.len()).unwrap().to_be_bytes());
        config.extend_from_slice(&contents);
        let mut list = u16::try_from(config.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&config);
        list
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::dns::MAX_ECH_CONFIG_BYTES;

    const HOST: &str = "site.example";
    const NOW: u64 = 1_800_000_000_000;

    fn cache(lookup: Arc<FakeLookup>) -> Arc<EchCache> {
        Arc::new(EchCache::new(lookup))
    }

    fn with_ttl(ttl: u32) -> Arc<FakeLookup> {
        FakeLookup::says(Ok(vec![HttpsRecord { priority: 1, ech: Some(vec![1, 2]), ttl }]), Duration::ZERO)
    }

    #[tokio::test]
    async fn cache_holds_for_the_clamped_ttl() {
        for (ttl, lives_s) in [(1, u64::from(MIN_TTL_S)), (300, 300), (999_999, u64::from(MAX_TTL_S))] {
            let lookup = with_ttl(ttl);
            let cache = cache(lookup.clone());
            assert_eq!(cache.config_for(HOST, 443, NOW).await.as_deref(), Some(&vec![1, 2]));
            assert_eq!(cache.config_for(HOST, 443, NOW + lives_s * 1_000 - 1).await.as_deref(), Some(&vec![1, 2]));
            assert_eq!(lookup.calls(), 1, "ttl {ttl}: held");
            cache.config_for(HOST, 443, NOW + lives_s * 1_000).await;
            assert_eq!(lookup.calls(), 2, "ttl {ttl}: out of date");
        }
    }

    #[tokio::test]
    async fn no_config_is_remembered_negative() {
        let lookup = FakeLookup::none();
        let cache = cache(lookup.clone());
        assert!(cache.config_for(HOST, 443, NOW).await.is_none());
        assert!(cache.config_for(HOST, 443, NOW + NEGATIVE_TTL_MS - 1).await.is_none());
        assert_eq!(lookup.calls(), 1);
        cache.config_for(HOST, 443, NOW + NEGATIVE_TTL_MS).await;
        assert_eq!(lookup.calls(), 2);
    }

    #[tokio::test]
    async fn failed_lookup_is_remembered_briefly() {
        let lookup = FakeLookup::says(Err("no upstream".into()), Duration::ZERO);
        let cache = cache(lookup.clone());
        assert!(cache.config_for(HOST, 443, NOW).await.is_none());
        assert!(cache.config_for(HOST, 443, NOW + FAILED_TTL_MS - 1).await.is_none());
        assert_eq!(lookup.calls(), 1);
        cache.config_for(HOST, 443, NOW + FAILED_TTL_MS).await;
        assert_eq!(lookup.calls(), 2);
    }

    #[tokio::test]
    async fn one_lookup_per_host_in_flight() {
        let lookup = FakeLookup::says(Ok(vec![HttpsRecord { priority: 1, ech: Some(vec![9]), ttl: 300 }]), Duration::from_millis(50));
        let cache = cache(lookup.clone());
        let waits: Vec<_> = (0..8)
            .map(|_| {
                let cache = cache.clone();
                tokio::spawn(async move { cache.config_for(HOST, 443, NOW).await })
            })
            .collect();
        for wait in waits {
            assert_eq!(wait.await.unwrap().as_deref(), Some(&vec![9]));
        }
        assert_eq!(lookup.calls(), 1);
        cache.config_for("other.example", 443, NOW).await;
        assert_eq!(lookup.calls(), 2, "per host");
    }

    #[tokio::test]
    async fn a_slow_lookup_lets_the_flow_go_and_still_fills_the_cache() {
        let lookup = FakeLookup::says(Ok(vec![HttpsRecord { priority: 1, ech: Some(vec![9]), ttl: 300 }]), ECH_LOOKUP_WAIT * 2);
        let cache = cache(lookup.clone());
        let start = std::time::Instant::now();
        assert!(cache.config_for(HOST, 443, NOW).await.is_none(), "went on without ECH");
        assert!(start.elapsed() < ECH_LOOKUP_WAIT * 2, "{:?}", start.elapsed());
        tokio::time::sleep(ECH_LOOKUP_WAIT * 2).await;
        assert_eq!(cache.config_for(HOST, 443, NOW).await.as_deref(), Some(&vec![9]));
        assert_eq!(lookup.calls(), 1);
    }

    #[tokio::test]
    async fn an_oversized_config_is_not_retained() {
        let lookup = FakeLookup::with_config(vec![1; MAX_ECH_CONFIG_BYTES + 1]);
        let oversized = cache(lookup.clone());
        assert!(oversized.config_for(HOST, 443, NOW).await.is_none());
        assert!(matches!(oversized.cached(HOST, NOW), Some(None)), "held as no config");
        assert!(oversized.config_for(HOST, 443, NOW + NEGATIVE_TTL_MS - 1).await.is_none());
        assert_eq!(lookup.calls(), 1, "and not asked again meanwhile");
        // The control: one at the bound is a config.
        let longest = cache(FakeLookup::with_config(vec![1; MAX_ECH_CONFIG_BYTES]));
        assert_eq!(longest.config_for(HOST, 443, NOW).await.map(|c| c.len()), Some(MAX_ECH_CONFIG_BYTES));
    }

    #[tokio::test]
    async fn an_expired_entry_gives_its_bytes_back_at_the_next_store() {
        const LIVES_MS: u64 = 300_000;
        let cache = cache(with_ttl(300));
        cache.config_for(HOST, 443, NOW).await;
        // The control: still in date, so it stays.
        cache.config_for("live.example", 443, NOW + LIVES_MS - 1).await;
        assert_eq!(lock(&cache.entries).len(), 2);
        cache.config_for("later.example", 443, NOW + LIVES_MS).await;
        let entries = lock(&cache.entries);
        assert_eq!((entries.len(), entries.index_len()), (2, 2), "the first went, from both sides of the index");
        drop(entries);
        assert!(cache.cached(HOST, NOW).is_none());
    }

    #[tokio::test]
    async fn port_other_than_443_does_not_look_up() {
        let lookup = with_ttl(300);
        assert!(cache(lookup.clone()).config_for(HOST, 8443, NOW).await.is_none());
        assert_eq!(lookup.calls(), 0);
    }

    #[test]
    fn a_config_rustls_cannot_use_is_no_config() {
        assert!(usable_config(&config_list("public.example")).is_some(), "the positive");
        assert!(usable_config(&[]).is_none());
        assert!(usable_config(&[0, 3, 1, 2, 3]).is_none(), "not a config");
        // A version this build does not know.
        let mut unknown = config_list("public.example");
        unknown[2] = 0xfd;
        assert!(usable_config(&unknown).is_none());
    }
}
