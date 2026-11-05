//! Leaf certificates (plan 2.5), the API slice 6 calls. One [`Minter`] per
//! root, holding the cache, so a rotation replaces the cache with no
//! invalidation logic. `rustls` stays out until slice 6: these are bytes.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use rcgen::{
    CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls_pki_types::CertificateDer;

use super::key::RootKey;
use super::root::{random_serial, time_of};
use super::{CLOCK_SKEW_MS, CaError, LEAF_CACHE_SIZE, LEAF_MAX_LIFETIME_MS};

/// RFC 1035's limits on a name and a label.
const HOST_MAX: usize = 253;
const LABEL_MAX: usize = 63;
const MS_PER_S: u64 = 1_000;

pub struct LeafRequest<'a> {
    /// The client's SNI.
    pub host: &'a str,
    pub upstream_not_after_ms: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Leaf {
    pub der: Vec<u8>,
    pub not_after_ms: u64,
}

/// A host as a certificate may name it: lowercase, a valid DNS name. An IP,
/// a wildcard or an empty name is an error, which slice 6 treats as
/// pass-through.
fn leaf_host(host: &str) -> Result<String, CaError> {
    let refuse = |why: &str| Err(CaError::Host(format!("{host:?}: {why}")));
    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if name.is_empty() {
        return refuse("empty");
    }
    if name.len() > HOST_MAX {
        return refuse("too long");
    }
    if name.parse::<IpAddr>().is_ok() || name.rsplit('.').next().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit())) {
        return refuse("an address, not a name");
    }
    let valid_label = |label: &str| {
        let bytes = label.as_bytes();
        !label.is_empty()
            && label.len() <= LABEL_MAX
            && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            && bytes.first() != Some(&b'-')
            && bytes.last() != Some(&b'-')
    };
    if !name.split('.').all(valid_label) {
        return refuse("not a DNS name");
    }
    Ok(name)
}

/// Least recently used: `used` orders the hosts by the tick of their last
/// use, so the oldest is its first entry.
struct Lru {
    capacity: usize,
    tick: u64,
    leaves: HashMap<String, (Arc<Leaf>, u64)>,
    used: BTreeMap<u64, String>,
}

impl Lru {
    fn new(capacity: usize) -> Self {
        Self { capacity, tick: 0, leaves: HashMap::new(), used: BTreeMap::new() }
    }

    fn touch(&mut self, host: &str, old_tick: u64) -> u64 {
        self.used.remove(&old_tick);
        self.tick += 1;
        self.used.insert(self.tick, host.to_string());
        self.tick
    }

    /// The leaf for `host` that `accept` takes, marked as just used.
    fn get(&mut self, host: &str, accept: impl Fn(&Leaf) -> bool) -> Option<Arc<Leaf>> {
        let (leaf, old_tick) = self.leaves.get(host).map(|(l, t)| (l.clone(), *t))?;
        if !accept(&leaf) {
            return None;
        }
        let tick = self.touch(host, old_tick);
        self.leaves.insert(host.to_string(), (leaf.clone(), tick));
        Some(leaf)
    }

    fn insert(&mut self, host: &str, leaf: Arc<Leaf>) {
        let old_tick = self.leaves.get(host).map_or(0, |(_, t)| *t);
        let tick = self.touch(host, old_tick);
        self.leaves.insert(host.to_string(), (leaf, tick));
        while self.leaves.len() > self.capacity {
            let Some((_, oldest)) = self.used.pop_first() else { return };
            self.leaves.remove(&oldest);
        }
    }
}

/// Mints leaves under one root. `None` from `Ca::minter` means no installed,
/// in-date root: slice 6 passes through.
pub struct Minter {
    root_der: Vec<u8>,
    thumbprint: String,
    root_not_after_ms: u64,
    issuer: Issuer<'static, RootKey>,
    leaf_key: Arc<KeyPair>,
    cache: Mutex<Lru>,
}

impl Minter {
    pub(super) fn new(
        root_der: Vec<u8>,
        thumbprint: String,
        root_not_after_ms: u64,
        key: RootKey,
        leaf_key: Arc<KeyPair>,
    ) -> Result<Self, CaError> {
        Self::with_capacity(root_der, thumbprint, root_not_after_ms, key, leaf_key, LEAF_CACHE_SIZE)
    }

    fn with_capacity(
        root_der: Vec<u8>,
        thumbprint: String,
        root_not_after_ms: u64,
        key: RootKey,
        leaf_key: Arc<KeyPair>,
        capacity: usize,
    ) -> Result<Self, CaError> {
        // Rebuilt from the root's own DER, so no parameters are stored twice.
        let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(root_der.as_slice()), key)
            .map_err(|e| CaError::Cert(format!("issuer from the root: {e}")))?;
        Ok(Self { root_der, thumbprint, root_not_after_ms, issuer, leaf_key, cache: Mutex::new(Lru::new(capacity)) })
    }

    pub(super) fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// The chain's root, for the handshake.
    pub fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    /// The leaf key of this engine run, memory only. All leaves share it.
    pub fn leaf_key_pkcs8(&self) -> &[u8] {
        self.leaf_key.serialized_der()
    }

    /// A leaf for the host, from the cache when one is still good.
    ///
    /// notAfter is the earliest of upstream, now + 7 d and the root's. A
    /// cached leaf is reused only when it is in date and not later than that
    /// same cap, so a renewed upstream with an earlier expiry never gets an
    /// older, longer leaf.
    pub fn leaf(&self, req: LeafRequest<'_>, now_ms: u64) -> Result<Arc<Leaf>, CaError> {
        let host = leaf_host(req.host)?;
        let cap = req.upstream_not_after_ms.min(now_ms.saturating_add(LEAF_MAX_LIFETIME_MS)).min(self.root_not_after_ms);
        // X.509 keeps whole seconds; what the certificate says is what counts.
        let not_after_ms = cap - cap % MS_PER_S;
        if not_after_ms <= now_ms {
            return Err(CaError::Expired(format!("{host}: no validity left")));
        }
        let cached = |l: &Leaf| l.not_after_ms > now_ms && l.not_after_ms <= cap;
        if let Some(leaf) = self.lock_cache().get(&host, cached) {
            return Ok(leaf);
        }
        let leaf = Arc::new(Leaf { der: self.mint(&host, now_ms, not_after_ms)?, not_after_ms });
        // Signed outside the lock; two racing mints of a host are harmless.
        self.lock_cache().insert(&host, leaf.clone());
        Ok(leaf)
    }

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, Lru> {
        self.cache.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Subject empty with a critical SAN: one rule, and no 64-character CN
    /// limit to special-case for long hosts. `ExplicitNoCa` writes the SKI
    /// and CA:false that plan 2.5 asks for.
    fn mint(&self, host: &str, now_ms: u64, not_after_ms: u64) -> Result<Vec<u8>, CaError> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        let name = host.to_string().try_into().map_err(|e| CaError::Host(format!("{host:?}: {e}")))?;
        params.subject_alt_names = vec![SanType::DnsName(name)];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(random_serial()?);
        params.not_before = time_of(now_ms.saturating_sub(CLOCK_SKEW_MS))?;
        params.not_after = time_of(not_after_ms)?;
        let cert = params.signed_by(self.leaf_key.as_ref(), &self.issuer).map_err(|e| {
            let why = self.issuer.key().take_sign_error();
            CaError::Cert(why.map_or_else(|| format!("leaf: {e}"), |why| format!("leaf: signing: {why}")))
        })?;
        Ok(cert.der().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
    use rcgen::PKCS_ECDSA_P256_SHA256;
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::super::key::memory_signer;
    use super::super::root::{self, build};
    use super::super::ROOT_LIFETIME_MS;
    use super::*;

    const NOW: u64 = 1_793_000_000_000;
    const WEEK: u64 = LEAF_MAX_LIFETIME_MS;
    const FAR: u64 = NOW + 100 * WEEK;

    fn minter_with(capacity: usize) -> Minter {
        let key = Arc::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap());
        let der = build(&memory_signer(key.clone()), "BOX", NOW).unwrap();
        let facts = root::facts(&der).unwrap();
        let leaf_key = Arc::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap());
        Minter::with_capacity(der, facts.thumbprint, facts.not_after_ms, memory_signer(key), leaf_key, capacity).unwrap()
    }

    fn minter() -> Minter {
        minter_with(LEAF_CACHE_SIZE)
    }

    fn req(host: &str) -> LeafRequest<'_> {
        LeafRequest { host, upstream_not_after_ms: FAR }
    }

    fn parsed(der: &[u8]) -> X509Certificate<'_> {
        X509Certificate::from_der(der).unwrap().1
    }

    #[test]
    fn leaf_san_is_the_host_only() {
        let leaf = minter().leaf(req("WWW.Example.test."), NOW).unwrap();
        let cert = parsed(&leaf.der);
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert!(san.critical, "the subject is empty, so the SAN is critical");
        assert_eq!(san.value.general_names, [GeneralName::DNSName("www.example.test")]);
        assert_eq!(cert.subject().iter().count(), 0, "no subject");
    }

    #[test]
    fn leaf_has_ski_aki_digital_signature_and_server_auth_only() {
        let m = minter();
        let leaf = m.leaf(req("a.example"), NOW).unwrap();
        let cert = parsed(&leaf.der);
        let root = parsed(m.root_der());
        let root_ski = root
            .extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
                _ => None,
            })
            .unwrap();
        let (mut ski, mut aki, mut basic, mut usage, mut eku) = (false, false, false, false, false);
        for ext in cert.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(_) => ski = true,
                ParsedExtension::AuthorityKeyIdentifier(a) => {
                    assert_eq!(a.key_identifier.as_ref().map(|k| k.0.to_vec()), Some(root_ski.clone()));
                    aki = true;
                }
                ParsedExtension::BasicConstraints(b) => {
                    assert!(!b.ca);
                    basic = true;
                }
                ParsedExtension::KeyUsage(u) => {
                    assert!(u.digital_signature() && !u.key_cert_sign() && !u.crl_sign() && !u.key_encipherment());
                    usage = true;
                }
                ParsedExtension::ExtendedKeyUsage(e) => {
                    assert!(e.server_auth && !e.client_auth && !e.code_signing && !e.any && e.other.is_empty());
                    eku = true;
                }
                ParsedExtension::SubjectAlternativeName(_) => {}
                other => panic!("no AIA, no CRL DP, nothing else: {other:?}"),
            }
        }
        assert!(ski && aki && basic && usage && eku);
    }

    #[test]
    fn leaf_not_after_is_the_earliest_of_upstream_week_and_root() {
        let m = minter();
        let at = |host: &str, upstream: u64, now: u64| m.leaf(LeafRequest { host, upstream_not_after_ms: upstream }, now).unwrap();
        let not_after = |leaf: &Leaf| parsed(&leaf.der).validity().not_after.timestamp() as u64 * MS_PER_S;
        // Upstream first.
        let leaf = at("a.example", NOW + 3_600_000, NOW);
        assert_eq!((leaf.not_after_ms, not_after(&leaf)), (NOW + 3_600_000, NOW + 3_600_000));
        // The week.
        let leaf = at("b.example", FAR, NOW);
        assert_eq!((leaf.not_after_ms, not_after(&leaf)), (NOW + WEEK, NOW + WEEK));
        // The root.
        let late = NOW + ROOT_LIFETIME_MS - 3_600_000;
        let leaf = at("c.example", u64::MAX, late);
        assert_eq!((leaf.not_after_ms, not_after(&leaf)), (NOW + ROOT_LIFETIME_MS, NOW + ROOT_LIFETIME_MS));
        // Nothing left is an error.
        assert!(matches!(m.leaf(LeafRequest { host: "d.example", upstream_not_after_ms: NOW }, NOW), Err(CaError::Expired(_))));
        assert!(matches!(m.leaf(req("e.example"), NOW + ROOT_LIFETIME_MS), Err(CaError::Expired(_))));
    }

    #[test]
    fn leaf_not_before_is_an_hour_back() {
        let leaf = minter().leaf(req("a.example"), NOW).unwrap();
        assert_eq!(parsed(&leaf.der).validity().not_before.timestamp() as u64 * MS_PER_S, NOW - 3_600_000);
        assert_eq!(CLOCK_SKEW_MS, 3_600_000);
    }

    #[test]
    fn leaf_serials_differ() {
        let m = minter();
        let (a, b) = (m.leaf(req("a.example"), NOW).unwrap(), m.leaf(req("b.example"), NOW).unwrap());
        let serial = |l: &Leaf| parsed(&l.der).raw_serial_as_string();
        assert_ne!(serial(&a), serial(&b));
        assert!(parsed(&a.der).tbs_certificate.raw_serial().len() <= 20);
    }

    #[test]
    fn leaf_verifies_against_the_root() {
        let m = minter();
        let leaf = m.leaf(req("a.example"), NOW).unwrap();
        let (cert, root) = (parsed(&leaf.der), parsed(m.root_der()));
        let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, root.public_key().subject_public_key.data.as_ref());
        verifier.verify(cert.tbs_certificate.as_ref(), cert.signature_value.data.as_ref()).unwrap();
        assert_eq!(cert.issuer().to_string(), root.subject().to_string());
    }

    #[test]
    fn all_leaves_share_one_key() {
        let m = minter();
        let public = |host: &str| {
            let leaf = m.leaf(req(host), NOW).unwrap();
            parsed(&leaf.der).public_key().subject_public_key.data.to_vec()
        };
        assert_eq!(public("a.example"), public("b.example"));
        assert_eq!(public("a.example"), m.leaf_key.public_key_raw());
        assert!(!m.leaf_key_pkcs8().is_empty());
    }

    #[test]
    fn cache_hits_return_the_same_leaf() {
        let m = minter();
        let first = m.leaf(req("a.example"), NOW).unwrap();
        assert!(Arc::ptr_eq(&first, &m.leaf(req("A.EXAMPLE"), NOW + 1_000).unwrap()), "same host, any case");
        let expired = m.leaf(req("a.example"), first.not_after_ms).unwrap();
        assert!(!Arc::ptr_eq(&first, &expired), "an expired leaf is minted again");
    }

    #[test]
    fn cache_evicts_least_recently_used_at_capacity() {
        let m = minter_with(2);
        let a = m.leaf(req("a.example"), NOW).unwrap();
        let b = m.leaf(req("b.example"), NOW).unwrap();
        assert!(Arc::ptr_eq(&a, &m.leaf(req("a.example"), NOW).unwrap()), "a is now the newer");
        m.leaf(req("c.example"), NOW).unwrap();
        assert!(Arc::ptr_eq(&a, &m.leaf(req("a.example"), NOW).unwrap()), "a stayed");
        assert!(!Arc::ptr_eq(&b, &m.leaf(req("b.example"), NOW).unwrap()), "b, the oldest, went");
        let cache = m.lock_cache();
        assert_eq!((cache.leaves.len(), cache.used.len()), (2, 2));
    }

    #[test]
    fn an_earlier_upstream_expiry_is_not_served_a_longer_cached_leaf() {
        let m = minter();
        let long = m.leaf(req("a.example"), NOW).unwrap();
        let earlier = NOW + 3_600_000;
        let short = m.leaf(LeafRequest { host: "a.example", upstream_not_after_ms: earlier }, NOW).unwrap();
        assert!(!Arc::ptr_eq(&long, &short));
        assert_eq!(short.not_after_ms, earlier);
    }

    #[test]
    fn bad_hosts_are_errors() {
        let long = format!("{}.example", "a".repeat(64));
        let very_long = "a.".repeat(127) + "example";
        for bad in [
            "", ".", "1.2.3.4", "::1", "[::1]", "*.example.test", "*", "a b.example", "-a.example", "a-.example", "a..example",
            "1.2.3.999", long.as_str(), very_long.as_str(), "exa\u{0}mple.test", "bücher.example",
        ] {
            assert!(matches!(minter().leaf(req(bad), NOW), Err(CaError::Host(_))), "{bad:?}");
        }
    }
}
