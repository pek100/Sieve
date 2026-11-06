//! What upstream validation said about (host, port), so the second connect costs
//! nothing (plan 2.6, task D5). A rejection skips the upstream handshake. An
//! `Eligible` with the same leaf skips only the trust call: the handshake and
//! eligibility always run, since each client connection has its own upstream.
//! `Unavailable` is never cached, and a late `Eligible` never replaces a
//! revocation in date. EV and client-certificate facts live in the exclusion
//! store (one owner per fact, S29), not here.

use std::sync::Mutex;

use sieve_filter::exclusions::UpstreamVerdict;

use crate::lru::Lru;

/// Plan 2.6: capped at 24 h.
pub const MAX_AGE_MS: u64 = 24 * 3_600_000;
/// Hosts remembered. The same size as the leaf cache: one entry per host in use.
pub const CAPACITY: usize = crate::ca::LEAF_CACHE_SIZE;

pub type LeafHash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cached {
    pub verdict: UpstreamVerdict,
    /// None when the upstream never showed a certificate.
    pub leaf: Option<LeafHash>,
    pub expires_ms: u64,
}

pub struct VerdictCache(Mutex<Lru<(String, u16), Cached>>);

impl Default for VerdictCache {
    fn default() -> Self {
        Self(Mutex::new(Lru::new(CAPACITY)))
    }
}

impl VerdictCache {
    fn lock(&self) -> std::sync::MutexGuard<'_, Lru<(String, u16), Cached>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The verdict still in date.
    pub fn get(&self, host: &str, port: u16, now_ms: u64) -> Option<Cached> {
        let key = (host.to_string(), port);
        let mut cache = self.lock();
        let hit = cache.get(&key, |c| now_ms < c.expires_ms);
        if hit.is_none() {
            cache.remove(&key);
        }
        hit
    }

    /// Holds a verdict until the earlier of the certificate's end and 24 h. An
    /// `Eligible` never replaces a revocation still in date, for any leaf: it
    /// can only come from a flow that was asking when the revocation landed, and
    /// its trust call may simply have soft-failed. Checked here, under the lock,
    /// because a flow's own closed signal can still be unset at this instant.
    pub fn put(&self, host: &str, port: u16, verdict: UpstreamVerdict, leaf: Option<LeafHash>, not_after_ms: Option<u64>, now_ms: u64) {
        if verdict == UpstreamVerdict::Unavailable {
            return;
        }
        let cap = now_ms.saturating_add(MAX_AGE_MS);
        let expires_ms = not_after_ms.map_or(cap, |end| end.min(cap));
        let key = (host.to_string(), port);
        let mut cache = self.lock();
        if verdict == UpstreamVerdict::Eligible && cache.get(&key, |c| c.verdict == UpstreamVerdict::Revoked && now_ms < c.expires_ms).is_some() {
            return;
        }
        cache.insert(key, Cached { verdict, leaf, expires_ms });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_793_000_000_000;
    const HOST: &str = "a.example";

    #[test]
    fn verdict_cache_expires_at_cert_end_or_24h() {
        let cache = VerdictCache::default();
        cache.put(HOST, 443, UpstreamVerdict::Invalid, None, Some(NOW + 1_000), NOW);
        assert!(cache.get(HOST, 443, NOW + 999).is_some());
        assert!(cache.get(HOST, 443, NOW + 1_000).is_none(), "the certificate's end");
        cache.put(HOST, 443, UpstreamVerdict::Invalid, None, Some(NOW + 10 * MAX_AGE_MS), NOW);
        assert!(cache.get(HOST, 443, NOW + MAX_AGE_MS - 1).is_some());
        assert!(cache.get(HOST, 443, NOW + MAX_AGE_MS).is_none(), "24 h");
        cache.put(HOST, 443, UpstreamVerdict::Protocol, None, None, NOW);
        assert_eq!(cache.get(HOST, 443, NOW + 1).unwrap().expires_ms, NOW + MAX_AGE_MS, "no certificate at all");
    }

    #[test]
    fn an_in_date_revocation_is_not_replaced_by_eligible() {
        const LEAF: Option<LeafHash> = Some([7; 32]);
        const OTHER_LEAF: Option<LeafHash> = Some([8; 32]);
        let cache = VerdictCache::default();
        cache.put(HOST, 443, UpstreamVerdict::Revoked, LEAF, None, NOW);
        for leaf in [LEAF, OTHER_LEAF] {
            cache.put(HOST, 443, UpstreamVerdict::Eligible, leaf, None, NOW + 1);
            assert_eq!(cache.get(HOST, 443, NOW + 1).unwrap(), Cached { verdict: UpstreamVerdict::Revoked, leaf: LEAF, expires_ms: NOW + MAX_AGE_MS });
        }
        cache.put(HOST, 443, UpstreamVerdict::Invalid, LEAF, None, NOW + 1);
        assert_eq!(cache.get(HOST, 443, NOW + 1).unwrap().verdict, UpstreamVerdict::Invalid, "a rejection may replace it");
        // Out of date, the OS may be asked again and may answer otherwise.
        cache.put(HOST, 443, UpstreamVerdict::Revoked, LEAF, None, NOW);
        cache.put(HOST, 443, UpstreamVerdict::Eligible, LEAF, None, NOW + MAX_AGE_MS);
        assert_eq!(cache.get(HOST, 443, NOW + MAX_AGE_MS).unwrap().verdict, UpstreamVerdict::Eligible);
    }

    #[test]
    fn unavailable_is_never_cached_and_the_key_is_host_and_port() {
        let cache = VerdictCache::default();
        cache.put(HOST, 443, UpstreamVerdict::Unavailable, None, None, NOW);
        assert!(cache.get(HOST, 443, NOW).is_none());
        cache.put(HOST, 443, UpstreamVerdict::Eligible, Some([7; 32]), None, NOW);
        assert_eq!(cache.get(HOST, 443, NOW).unwrap().leaf, Some([7; 32]));
        assert!(cache.get(HOST, 8443, NOW).is_none());
    }
}
