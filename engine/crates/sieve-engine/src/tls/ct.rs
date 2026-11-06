//! Certificate Transparency under Chrome's policy (plan 2.6, task D2 to D4):
//! pure, no clock and no I/O. A chain that fails ends as a pass-through, so the
//! client judges the real server; nothing here can break a site.
//!
//! The log list arrives as an envelope at `update::data_path`: `u32 LE signature
//! length, signature, JSON`. The update cycle checked its minisign signature;
//! Google's own is checked here against the compiled-in key, so the timestamp
//! that decides staleness is Chrome's word and a leak of Sieve's update key
//! cannot add a log.
//!
//! rustls never asks for TLS-delivered SCTs (task F4), so a site whose SCTs come
//! only that way fails CT and passes through, which is safe.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey, VerificationAlgorithm};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use x509_parser::extensions::{ParsedExtension, SignedCertificateTimestamp, parse_ct_signed_certificate_timestamp_list};
use x509_parser::prelude::X509Certificate;

/// Chrome's log list key, SPKI DER.
pub const LOG_LIST_KEY: &[u8] = include_bytes!("../../data/ct-log-list-pubkey.der");

const DAY_MS: u64 = 86_400_000;
/// Chrome stops enforcing CT when its list is older than this (task F5).
pub const MAX_LIST_AGE_MS: u64 = 70 * DAY_MS;
/// Chrome's line between the two lifetimes of an embedded set.
pub const SHORT_LIFETIME_DAYS: u64 = 180;
/// SCTs an embedded set needs at or below that lifetime.
pub const SCTS_SHORT: usize = 2;
/// And above it.
pub const SCTS_LONG: usize = 3;
/// SCTs a set that is not embedded needs, at any lifetime.
pub const SCTS_STAPLED: usize = 2;
/// Distinct log operators every set needs.
pub const MIN_OPERATORS: usize = 2;
/// Signatures checked per set, listed logs only: twice the most any set needs.
/// A server chooses its staple, up to what a handshake message holds, and this
/// runs inline on a worker that also carries the relay, so a flood must not buy
/// signature checks. One per log would not bound it: the recorded list has 89
/// logs. An SCT past the bound does not count, so whoever floods fails CT and
/// passes through.
pub const MAX_SCTS_CHECKED: usize = 2 * SCTS_LONG;

const SIG_LEN_BYTES: usize = 4;
const LOG_ID_BYTES: usize = 32;
/// RFC 6962 3.2: `sct_version` v1.
const SCT_VERSION_V1: u8 = 0;
const SIGNATURE_TYPE_CERTIFICATE: u8 = 0;
const ENTRY_X509: u16 = 0;
const ENTRY_PRECERT: u16 = 1;
/// RFC 5246 7.4.1.4.1: sha256, rsa, ecdsa.
const HASH_SHA256: u8 = 4;
const SIG_RSA: u8 = 1;
const SIG_ECDSA: u8 = 3;

const DER_SEQUENCE: u8 = 0x30;
const DER_OCTET_STRING: u8 = 0x04;
const DER_TBS_EXTENSIONS: u8 = 0xa3;
const DER_RESPONSE_BYTES: u8 = 0xa0;
const DER_SINGLE_EXTENSIONS: u8 = 0xa1;
/// RFC 6960 SingleResponse: `certID` and `certStatus` come first, and `revoked [1]`
/// has the tag of `singleExtensions`, so the search starts after them.
const SINGLE_FIELDS_BEFORE_OPTIONALS: usize = 2;
/// 1.3.6.1.4.1.11129.2.4.2, the embedded list, as its whole DER element.
const OID_EMBEDDED_SCTS: [u8; 12] = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];
/// 1.3.6.1.4.1.11129.2.4.5, the list in an OCSP single response.
const OID_STAPLED_SCTS: [u8; 12] = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x05];

pub type LogId = [u8; LOG_ID_BYTES];
pub type SpkiHash = [u8; 32];

// ---- The DER walk: bounded by the input, no panic on hostile bytes.

/// One DER element. Multi-byte tags and indefinite lengths do not occur where
/// this looks, so they are refused rather than guessed.
#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    whole: &'a [u8],
    body: &'a [u8],
    rest: &'a [u8],
}

fn tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let (&tag, after_tag) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, after_first) = after_tag.split_first()?;
    let (length, head) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > size_of::<u32>() {
            return None;
        }
        let bytes = after_first.get(..count)?;
        (bytes.iter().fold(0usize, |n, b| (n << 8) | usize::from(*b)), 2 + count)
    };
    let end = head.checked_add(length)?;
    Some(Tlv { tag, whole: input.get(..end)?, body: input.get(head..end)?, rest: input.get(end..)? })
}

fn expect(input: &[u8], tag: u8) -> Option<Tlv<'_>> {
    tlv(input).filter(|t| t.tag == tag)
}

/// The elements of a constructed value, or None if any of them is malformed.
fn children(mut body: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    while !body.is_empty() {
        let next = tlv(body)?;
        body = next.rest;
        out.push(next);
    }
    Some(out)
}

/// One DER element around `body`.
pub(crate) fn der_wrap(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match u8::try_from(body.len()).ok().filter(|n| *n < 0x80) {
        Some(short) => out.push(short),
        None => {
            let be = body.len().to_be_bytes();
            let skip = be.iter().take_while(|b| **b == 0).count();
            let count = u8::try_from(be.len() - skip).unwrap_or(0);
            out.push(0x80 | count);
            out.extend_from_slice(&be[skip..]);
        }
    }
    out.extend_from_slice(body);
    out
}

/// The hash CT and CRLite use, over a full SPKI (task F12).
pub fn spki_hash(spki_der: &[u8]) -> SpkiHash {
    let mut out = [0u8; 32];
    out.copy_from_slice(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, spki_der).as_ref());
    out
}

/// A trust anchor's SPKI lacks its outer SEQUENCE (task F12): its hash, rewrapped.
pub fn anchor_spki_hash(spki_contents: &[u8]) -> SpkiHash {
    spki_hash(&der_wrap(DER_SEQUENCE, spki_contents))
}

/// The TBSCertificate a log signed for an embedded SCT: the leaf's, with the SCT
/// extension removed and every enclosing length rewritten, order kept. None when
/// the DER does not parse or has no such extension.
pub fn precert_tbs(leaf_der: &[u8]) -> Option<Vec<u8>> {
    let certificate = expect(leaf_der, DER_SEQUENCE)?;
    let tbs = expect(certificate.body, DER_SEQUENCE)?;
    let mut out = Vec::with_capacity(tbs.body.len());
    let mut found = false;
    for field in children(tbs.body)? {
        if field.tag != DER_TBS_EXTENSIONS {
            out.extend_from_slice(field.whole);
            continue;
        }
        let list = expect(field.body, DER_SEQUENCE)?;
        let mut kept = Vec::with_capacity(list.body.len());
        for extension in children(list.body)? {
            if tlv(expect(extension.whole, DER_SEQUENCE)?.body)?.whole == OID_EMBEDDED_SCTS {
                found = true;
            } else {
                kept.extend_from_slice(extension.whole);
            }
        }
        if !kept.is_empty() {
            out.extend_from_slice(&der_wrap(DER_TBS_EXTENSIONS, &der_wrap(DER_SEQUENCE, &kept)));
        }
    }
    found.then(|| der_wrap(DER_SEQUENCE, &out))
}

/// What an SCT's signature covers.
#[derive(Debug, Clone, Copy)]
pub enum SignedEntry<'a> {
    /// An embedded SCT: the issuer's key hash and [`precert_tbs`].
    Precert { issuer: &'a SpkiHash, tbs: &'a [u8] },
    /// A stapled one: the certificate as sent.
    X509 { leaf: &'a [u8] },
}

fn u24(n: usize) -> Option<[u8; 3]> {
    let be = u32::try_from(n).ok()?.to_be_bytes();
    (be[0] == 0).then_some([be[1], be[2], be[3]])
}

/// The bytes an SCT's signature covers (RFC 6962 3.2). None for an entry too
/// long for its length field.
pub fn sct_message(timestamp_ms: u64, entry: SignedEntry<'_>, extensions: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![SCT_VERSION_V1, SIGNATURE_TYPE_CERTIFICATE];
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    match entry {
        SignedEntry::Precert { issuer, tbs } => {
            out.extend_from_slice(&ENTRY_PRECERT.to_be_bytes());
            out.extend_from_slice(issuer);
            out.extend_from_slice(&u24(tbs.len())?);
            out.extend_from_slice(tbs);
        }
        SignedEntry::X509 { leaf } => {
            out.extend_from_slice(&ENTRY_X509.to_be_bytes());
            out.extend_from_slice(&u24(leaf.len())?);
            out.extend_from_slice(leaf);
        }
    }
    out.extend_from_slice(&u16::try_from(extensions.len()).ok()?.to_be_bytes());
    out.extend_from_slice(extensions);
    Some(out)
}

/// The SCTs a leaf carries.
pub fn scts_of<'a>(cert: &'a X509Certificate<'_>) -> Vec<&'a SignedCertificateTimestamp<'a>> {
    cert.extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::SCT(list) => Some(list.iter().collect()),
            _ => None,
        })
        .unwrap_or_default()
}

/// The SCTs of an OCSP staple's single responses; none when it does not parse.
/// The staple's own signature is not checked, because each SCT signs the
/// certificate itself. x509-parser has no OCSP reader, and one extension does
/// not justify a new crate.
pub fn stapled_scts(ocsp: &[u8]) -> Vec<SignedCertificateTimestamp<'_>> {
    stapled_lists(ocsp).unwrap_or_default().into_iter().filter_map(|list| parse_ct_signed_certificate_timestamp_list(list).ok()).flat_map(|(_, scts)| scts).collect()
}

/// Walks OCSPResponse, responseBytes, BasicOCSPResponse, tbsResponseData,
/// responses, and each single response's extensions, to the list's OCTET STRINGs.
fn stapled_lists(ocsp: &[u8]) -> Option<Vec<&[u8]>> {
    let response = expect(ocsp, DER_SEQUENCE)?;
    let wrapper = children(response.body)?.into_iter().find(|t| t.tag == DER_RESPONSE_BYTES)?;
    let bytes = expect(wrapper.body, DER_SEQUENCE)?;
    let basic = children(bytes.body)?.into_iter().find(|t| t.tag == DER_OCTET_STRING)?;
    let basic = expect(basic.body, DER_SEQUENCE)?;
    let data = expect(basic.body, DER_SEQUENCE)?;
    let responses = children(data.body)?.into_iter().find(|t| t.tag == DER_SEQUENCE)?;
    let mut lists = Vec::new();
    for single in children(responses.body)? {
        let Some(extensions) = children(single.body)?.into_iter().skip(SINGLE_FIELDS_BEFORE_OPTIONALS).find(|t| t.tag == DER_SINGLE_EXTENSIONS) else { continue };
        for extension in children(expect(extensions.body, DER_SEQUENCE)?.body)? {
            let parts = children(extension.body)?;
            if parts.first().is_some_and(|oid| oid.whole == OID_STAPLED_SCTS)
                && let Some(value) = parts.iter().find(|t| t.tag == DER_OCTET_STRING)
            {
                lists.push(value.body);
            }
        }
    }
    Some(lists)
}

// ---- The list.

/// A log as the policy reads its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogState {
    /// `qualified`, `usable` or `readonly`.
    Live,
    /// Counts only in an embedded set, for an SCT of its own from before this.
    Retired { at_ms: u64 },
    /// `rejected`, `pending`, or a state this build does not know.
    Dead,
}

#[derive(Debug, Clone)]
struct Log {
    operator: usize,
    key: Vec<u8>,
    state: LogState,
    /// An SCT from before this was issued under an earlier operator of the log.
    operator_since_ms: u64,
}

#[derive(Debug, Clone)]
pub struct LogList {
    pub timestamp_ms: u64,
    logs: HashMap<LogId, Log>,
}

#[derive(Deserialize)]
struct ListJson {
    log_list_timestamp: String,
    operators: Vec<OperatorJson>,
}

#[derive(Deserialize)]
struct OperatorJson {
    #[serde(default)]
    logs: Vec<LogJson>,
    #[serde(default)]
    tiled_logs: Vec<LogJson>,
}

#[derive(Deserialize)]
struct LogJson {
    log_id: String,
    key: String,
    state: Option<serde_json::Value>,
    previous_operators: Option<serde_json::Value>,
}

fn rfc3339_ms(text: &str) -> Option<u64> {
    let at = OffsetDateTime::parse(text, &Rfc3339).ok()?;
    u64::try_from(at.unix_timestamp_nanos() / 1_000_000).ok()
}

fn state_of(state: Option<&serde_json::Value>) -> LogState {
    let Some((name, body)) = state.and_then(serde_json::Value::as_object).and_then(|o| o.iter().next()) else { return LogState::Dead };
    match name.as_str() {
        "qualified" | "usable" | "readonly" => LogState::Live,
        "retired" => body.get("timestamp").and_then(serde_json::Value::as_str).and_then(rfc3339_ms).map_or(LogState::Dead, |at_ms| LogState::Retired { at_ms }),
        _ => LogState::Dead,
    }
}

/// When a log's present operator took it over: its latest `previous_operators`
/// `end_time`, or the epoch with none. A shape this build cannot read proves nothing
/// about any SCT, so it gives the latest time there is, not the earliest, and the
/// list itself stays good.
fn operator_since_ms(previous: Option<&serde_json::Value>) -> u64 {
    let Some(previous) = previous else { return 0 };
    let Some(entries) = previous.as_array() else { return u64::MAX };
    entries.iter().map(|entry| entry.get("end_time").and_then(serde_json::Value::as_str).and_then(rfc3339_ms).unwrap_or(u64::MAX)).max().unwrap_or(0)
}

impl LogList {
    /// The list inside an envelope, once its signature holds under `key`.
    /// Anything refused means no list.
    pub fn from_envelope(bytes: &[u8], key: &[u8]) -> Result<Self, String> {
        let (length, rest) = bytes.split_first_chunk::<SIG_LEN_BYTES>().ok_or("the envelope has no signature length")?;
        let length = usize::try_from(u32::from_le_bytes(*length)).map_err(|_| "the signature length does not fit")?;
        let signature = rest.get(..length).ok_or("the envelope is shorter than its signature")?;
        let json = &rest[length..];
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key).verify(json, signature).map_err(|_| "the log list's signature does not hold")?;
        Self::parse(json)
    }

    /// A map from log id to operator, key and state, over `logs` and
    /// `tiled_logs`. Unknown fields are ignored, since Google adds them.
    pub fn parse(json: &[u8]) -> Result<Self, String> {
        let list: ListJson = serde_json::from_slice(json).map_err(|e| format!("the log list: {e}"))?;
        let timestamp_ms = rfc3339_ms(&list.log_list_timestamp).ok_or("the log list's timestamp")?;
        let mut logs = HashMap::new();
        for (operator, entry) in list.operators.iter().enumerate() {
            for log in entry.logs.iter().chain(&entry.tiled_logs) {
                let id: LogId = STANDARD.decode(&log.log_id).ok().and_then(|id| id.try_into().ok()).ok_or("a log id")?;
                let key = STANDARD.decode(&log.key).map_err(|_| "a log key")?;
                logs.insert(id, Log { operator, key, state: state_of(log.state.as_ref()), operator_since_ms: operator_since_ms(log.previous_operators.as_ref()) });
            }
        }
        if !logs.values().any(|l| l.state == LogState::Live) {
            return Err("the log list has no usable log".into());
        }
        Ok(Self { timestamp_ms, logs })
    }

    /// True past Chrome's limit. A list dated in the future is fresh: it is
    /// signed, and a wrong local clock already fails in the safe direction.
    pub fn is_stale(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.timestamp_ms) > MAX_LIST_AGE_MS
    }
}

/// The envelope [`LogList::from_envelope`] reads.
pub fn encode_envelope(signature: &[u8], json: &[u8]) -> Result<Vec<u8>, String> {
    let length = u32::try_from(signature.len()).map_err(|_| "the signature is too long")?;
    let mut out = length.to_le_bytes().to_vec();
    out.extend_from_slice(signature);
    out.extend_from_slice(json);
    Ok(out)
}

// ---- Verification.

/// How an SCT reached us. The two sets are judged apart (task F5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Embedded,
    Stapled,
}

/// An SCT whose signature held under a log in the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedSct {
    pub log: LogId,
    pub timestamp_ms: u64,
    pub delivery: Delivery,
}

fn algorithm_of(sct: &SignedCertificateTimestamp<'_>) -> Option<&'static dyn VerificationAlgorithm> {
    match (sct.signature.hash_alg_id, sct.signature.sign_alg_id) {
        (HASH_SHA256, SIG_ECDSA) => Some(&ECDSA_P256_SHA256_ASN1),
        (HASH_SHA256, SIG_RSA) => Some(&RSA_PKCS1_2048_8192_SHA256),
        _ => None,
    }
}

/// The key and algorithm to check an SCT with: none for an unknown log, a wrong
/// version or an algorithm this build does not take, all without a signature check.
fn signable<'l>(sct: &SignedCertificateTimestamp<'_>, list: &'l LogList) -> Option<(&'l Log, &'static dyn VerificationAlgorithm)> {
    if sct.version.0 != SCT_VERSION_V1 {
        return None;
    }
    Some((list.logs.get(sct.id.key_id)?, algorithm_of(sct)?))
}

/// One SCT, if it counts: one that is not [`signable`] or has a bad signature does
/// not, and nothing else follows from that.
fn verify_sct(sct: &SignedCertificateTimestamp<'_>, entry: SignedEntry<'_>, delivery: Delivery, list: &LogList) -> Option<VerifiedSct> {
    let (log, algorithm) = signable(sct, list)?;
    let message = sct_message(sct.timestamp, entry, sct.extensions.0)?;
    UnparsedPublicKey::new(algorithm, &log.key).verify(&message, sct.signature.data).ok()?;
    Some(VerifiedSct { log: *sct.id.key_id, timestamp_ms: sct.timestamp, delivery })
}

/// The SCTs of one set that count, at most [`MAX_SCTS_CHECKED`] signatures' worth.
fn verified_set<'a, 'b: 'a>(scts: impl Iterator<Item = &'a SignedCertificateTimestamp<'b>>, entry: SignedEntry<'_>, delivery: Delivery, list: &LogList) -> Vec<VerifiedSct> {
    scts.filter(|sct| signable(sct, list).is_some()).take(MAX_SCTS_CHECKED).filter_map(|sct| verify_sct(sct, entry, delivery, list)).collect()
}

/// The SCTs of this leaf and its staple that count. Each set has its own bound, so
/// a flooded staple cannot crowd out what the certificate carries.
pub fn verified_scts(cert: &X509Certificate<'_>, leaf_der: &[u8], issuer: &SpkiHash, ocsp: &[u8], list: &LogList) -> Vec<VerifiedSct> {
    let mut out = Vec::new();
    let embedded = scts_of(cert);
    if !embedded.is_empty()
        && let Some(tbs) = precert_tbs(leaf_der)
    {
        out = verified_set(embedded.iter().copied(), SignedEntry::Precert { issuer, tbs: &tbs }, Delivery::Embedded, list);
    }
    out.extend(verified_set(stapled_scts(ocsp).iter(), SignedEntry::X509 { leaf: leaf_der }, Delivery::Stapled, list));
    out
}

// ---- The policy.

/// Why CT said nothing about a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtSkip {
    NoList,
    StaleList,
    /// No issuer to check against: x509-parser refused a leaf webpki accepted, so
    /// `intercept` has no facts and passes it through, or no path was built here.
    /// No verdict follows from this: the trust call still runs.
    NoIssuer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtAnswer {
    Compliant,
    Violates,
    Skipped(CtSkip),
}

/// One set under Chrome's rules: enough distinct logs, from enough operators,
/// at least one still live. A retired log counts only in an embedded set, and only
/// for its own SCT from before the retirement. A log whose operator changed after
/// its SCT counts for nothing: this list says who runs it now, and the policy asks
/// who ran it then, so what its SCT adds to the operators is not proven (task D3). A
/// future timestamp counts for nothing.
fn set_complies(verified: &[VerifiedSct], delivery: Delivery, required: usize, list: &LogList, now_ms: u64) -> bool {
    let mut earliest_by_log: BTreeMap<LogId, u64> = BTreeMap::new();
    for sct in verified.iter().filter(|s| s.delivery == delivery && s.timestamp_ms <= now_ms) {
        let entry = earliest_by_log.entry(sct.log).or_insert(sct.timestamp_ms);
        *entry = (*entry).min(sct.timestamp_ms);
    }
    let counted: Vec<&Log> = earliest_by_log
        .iter()
        .filter_map(|(id, at)| list.logs.get(id).filter(|log| *at >= log.operator_since_ms).map(|log| (log, *at)))
        .filter(|(log, at)| match log.state {
            LogState::Live => true,
            LogState::Retired { at_ms } => delivery == Delivery::Embedded && *at < at_ms,
            LogState::Dead => false,
        })
        .map(|(log, _)| log)
        .collect();
    let operators: BTreeSet<usize> = counted.iter().map(|l| l.operator).collect();
    counted.len() >= required && operators.len() >= MIN_OPERATORS && counted.iter().any(|l| l.state == LogState::Live)
}

/// Chrome's policy (task F5): the embedded set or the stapled one must comply
/// alone. No threshold for "predates CT": no certificate that old is still in
/// date. `temporal_interval` is not asked for by the published policy.
///
/// TENSION: the published policy takes OCSP SCTs only before Chrome 148, and stapled
/// is the only non-embedded set here (task F4). So 2 live stapled SCTs pass here where
/// a current Chrome refuses the real certificate. Dropping the arm reverses task F5 and
/// is the user's call (F5 says so).
pub fn policy(verified: &[VerifiedSct], lifetime_ms: u64, list: &LogList, now_ms: u64) -> CtAnswer {
    let embedded_needs = if lifetime_ms > SHORT_LIFETIME_DAYS * DAY_MS { SCTS_LONG } else { SCTS_SHORT };
    let compliant = set_complies(verified, Delivery::Embedded, embedded_needs, list, now_ms) || set_complies(verified, Delivery::Stapled, SCTS_STAPLED, list, now_ms);
    if compliant { CtAnswer::Compliant } else { CtAnswer::Violates }
}

/// A leaf's lifetime in ms.
pub fn lifetime_ms(cert: &X509Certificate<'_>) -> u64 {
    let validity = cert.validity();
    u64::try_from(validity.not_after.timestamp().saturating_sub(validity.not_before.timestamp())).unwrap_or(0).saturating_mul(1_000)
}

#[cfg(test)]
pub(crate) mod testing {
    use rcgen::{KeyPair, PublicKeyData, SigningKey};

    use super::*;

    /// A log in memory: its key, id and the JSON entry for it.
    pub(crate) struct MemoryLog {
        pub(crate) key: KeyPair,
        pub(crate) id: LogId,
    }

    impl MemoryLog {
        pub(crate) fn new() -> Self {
            let key = KeyPair::generate().unwrap();
            let id = spki_hash(&key.subject_public_key_info());
            Self { key, id }
        }

        /// One SCT over `entry`, as TLS encodes it, with its length.
        pub(crate) fn sct(&self, timestamp_ms: u64, entry: SignedEntry<'_>) -> Vec<u8> {
            let signature = self.key.sign(&sct_message(timestamp_ms, entry, &[]).unwrap()).unwrap();
            let mut body = vec![SCT_VERSION_V1];
            body.extend_from_slice(&self.id);
            body.extend_from_slice(&timestamp_ms.to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes());
            body.extend_from_slice(&[HASH_SHA256, SIG_ECDSA]);
            body.extend_from_slice(&u16::try_from(signature.len()).unwrap().to_be_bytes());
            body.extend_from_slice(&signature);
            let mut out = u16::try_from(body.len()).unwrap().to_be_bytes().to_vec();
            out.extend_from_slice(&body);
            out
        }

        pub(crate) fn json(&self, state: &str) -> String {
            log_json(&self.id, &self.key.subject_public_key_info(), state)
        }
    }

    pub(crate) fn log_json(id: &[u8], key: &[u8], state: &str) -> String {
        format!(r#"{{"log_id":"{}","key":"{}","state":{state}}}"#, STANDARD.encode(id), STANDARD.encode(key))
    }

    pub(crate) const USABLE: &str = r#"{"usable":{"timestamp":"2024-01-01T00:00:00Z"}}"#;

    /// The list text, one operator per entry, each with these log entries.
    pub(crate) fn list_json(timestamp: &str, operators: &[Vec<String>]) -> String {
        let operators: Vec<String> = operators.iter().enumerate().map(|(i, logs)| format!(r#"{{"name":"op{i}","logs":[{}],"tiled_logs":[]}}"#, logs.join(","))).collect();
        format!(r#"{{"version":"1","log_list_timestamp":"{timestamp}","operators":[{}]}}"#, operators.join(","))
    }

    /// The value of the SCT extension: an OCTET STRING around the TLS list.
    pub(crate) fn sct_list_value(scts: &[Vec<u8>]) -> Vec<u8> {
        let inner: Vec<u8> = scts.concat();
        let mut list = u16::try_from(inner.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&inner);
        der_wrap(DER_OCTET_STRING, &list)
    }

    const GENERALIZED: [u8; 17] = [0x18, 0x0f, b'2', b'0', b'2', b'6', b'1', b'1', b'0', b'5', b'0', b'0', b'0', b'0', b'0', b'0', b'Z'];
    /// RFC 6960 `good [0] IMPLICIT NULL`.
    pub(crate) const STATUS_GOOD: [u8; 2] = [0x80, 0x00];
    /// RFC 6960 `unknown [2] IMPLICIT UnknownInfo`.
    pub(crate) const STATUS_UNKNOWN: [u8; 2] = [0x82, 0x00];

    /// RFC 6960 `revoked [1] IMPLICIT RevokedInfo`, with a reason: constructed, so
    /// it carries the tag of `singleExtensions`.
    pub(crate) fn status_revoked() -> Vec<u8> {
        const KEY_COMPROMISE: [u8; 3] = [0x0a, 0x01, 0x01];
        der_wrap(DER_SINGLE_EXTENSIONS, &[&GENERALIZED[..], &der_wrap(0xa0, &KEY_COMPROMISE)].concat())
    }

    /// An OCSPResponse with one good single response carrying this extension value.
    pub(crate) fn ocsp_with(value: &[u8]) -> Vec<u8> {
        ocsp_with_status(&STATUS_GOOD, false, value)
    }

    /// The same under this `certStatus`, with or without a `nextUpdate`.
    pub(crate) fn ocsp_with_status(status: &[u8], next_update: bool, value: &[u8]) -> Vec<u8> {
        const ENUMERATED_SUCCESS: [u8; 3] = [0x0a, 0x01, 0x00];
        const OID_BASIC: [u8; 11] = [0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
        let extension = der_wrap(DER_SEQUENCE, &[&OID_STAPLED_SCTS[..], &der_wrap(DER_OCTET_STRING, value)].concat());
        let extensions = der_wrap(DER_SINGLE_EXTENSIONS, &der_wrap(DER_SEQUENCE, &extension));
        let cert_id = der_wrap(DER_SEQUENCE, &[]);
        let next = if next_update { der_wrap(0xa0, &GENERALIZED) } else { Vec::new() };
        let single = der_wrap(DER_SEQUENCE, &[&cert_id[..], status, &GENERALIZED, &next, &extensions].concat());
        let responses = der_wrap(DER_SEQUENCE, &single);
        let responder = der_wrap(0xa2, &der_wrap(DER_OCTET_STRING, &[7u8; 20]));
        let data = der_wrap(DER_SEQUENCE, &[&responder[..], &GENERALIZED, &responses].concat());
        let basic = der_wrap(DER_SEQUENCE, &data);
        let bytes = der_wrap(DER_SEQUENCE, &[&OID_BASIC[..], &der_wrap(DER_OCTET_STRING, &basic)].concat());
        der_wrap(DER_SEQUENCE, &[&ENUMERATED_SUCCESS[..], &der_wrap(DER_RESPONSE_BYTES, &bytes)].concat())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use x509_parser::prelude::FromDer;

    use super::testing::*;
    use super::*;

    const LIST: &[u8] = include_bytes!("../../fixtures/validation/log_list.json");
    const SIG: &[u8] = include_bytes!("../../fixtures/validation/log_list.sig");
    const LEAF: &[u8] = include_bytes!("../../fixtures/validation/leaf.der");
    const ISSUER: &[u8] = include_bytes!("../../fixtures/validation/issuer.der");
    /// `log_list_timestamp` of the recorded list, 2026-11-05T13:36:08Z.
    const LIST_AT_MS: u64 = 1_793_885_768_000;
    const NOW: u64 = LIST_AT_MS + DAY_MS;

    fn recorded() -> LogList {
        LogList::from_envelope(&encode_envelope(SIG, LIST).unwrap(), LOG_LIST_KEY).unwrap()
    }

    fn issuer_hash() -> SpkiHash {
        let (_, issuer) = X509Certificate::from_der(ISSUER).unwrap();
        spki_hash(issuer.public_key().raw)
    }

    fn leaf() -> X509Certificate<'static> {
        X509Certificate::from_der(LEAF).unwrap().1
    }

    /// Both SCTs of a leaf under `list`.
    fn counted(der: &[u8], list: &LogList) -> usize {
        match X509Certificate::from_der(der) {
            Ok((_, cert)) => verified_scts(&cert, der, &issuer_hash(), &[], list).len(),
            Err(_) => 0,
        }
    }

    #[test]
    fn recorded_list_signature_verifies() {
        let list = recorded();
        assert_eq!(list.timestamp_ms, LIST_AT_MS);
        assert!(list.logs.len() > 10);
        assert!(list.logs.values().any(|l| l.state == LogState::Live));
        assert!(list.logs.values().any(|l| matches!(l.state, LogState::Retired { .. })));
    }

    #[test]
    fn a_tampered_list_is_refused() {
        let mut json = LIST.to_vec();
        json[100] ^= 1;
        assert!(LogList::from_envelope(&encode_envelope(SIG, &json).unwrap(), LOG_LIST_KEY).unwrap_err().contains("signature"));
        let mut sig = SIG.to_vec();
        sig[0] ^= 1;
        assert!(LogList::from_envelope(&encode_envelope(&sig, LIST).unwrap(), LOG_LIST_KEY).is_err());
        assert!(LogList::from_envelope(&[1, 0, 0], LOG_LIST_KEY).is_err(), "too short");
        assert!(LogList::from_envelope(&[255, 255, 255, 255, 1], LOG_LIST_KEY).is_err(), "a length past the end");
    }

    #[test]
    fn a_wrong_key_is_refused() {
        let other = rcgen::PublicKeyData::subject_public_key_info(&rcgen::KeyPair::generate().unwrap());
        assert!(LogList::from_envelope(&encode_envelope(SIG, LIST).unwrap(), &other).is_err());
    }

    #[test]
    fn recorded_leaf_scts_verify_against_recorded_list() {
        let list = recorded();
        let cert = leaf();
        assert_eq!(scts_of(&cert).len(), 2);
        let verified = verified_scts(&cert, LEAF, &issuer_hash(), &[], &list);
        assert_eq!(verified.len(), 2, "both SCTs counted");
        assert!(verified.iter().all(|s| s.delivery == Delivery::Embedded));
    }

    #[test]
    fn recorded_leaf_is_compliant() {
        let list = recorded();
        let cert = leaf();
        let verified = verified_scts(&cert, LEAF, &issuer_hash(), &[], &list);
        assert_eq!(policy(&verified, lifetime_ms(&cert), &list, NOW), CtAnswer::Compliant);
    }

    #[test]
    fn precert_tbs_of_the_recorded_leaf_is_704_bytes_and_lacks_the_extension() {
        let tbs = precert_tbs(LEAF).unwrap();
        assert_eq!(tbs.len(), 704);
        assert_eq!(leaf().tbs_certificate.as_ref().len(), 968, "the full one");
        assert!(!tbs.windows(OID_EMBEDDED_SCTS.len()).any(|w| w == OID_EMBEDDED_SCTS));
        assert!(LEAF.windows(OID_EMBEDDED_SCTS.len()).any(|w| w == OID_EMBEDDED_SCTS));
        // No such extension, no answer.
        assert!(precert_tbs(ISSUER).is_none());
    }

    proptest! {
        #[test]
        fn precert_tbs_refuses_hostile_der(bytes in proptest::collection::vec(any::<u8>(), 0..2048), flip in 0..LEAF.len()) {
            let _ = precert_tbs(&bytes);
            let mut changed = LEAF.to_vec();
            changed[flip] ^= 0xff;
            let _ = precert_tbs(&changed);
        }

        #[test]
        fn stapled_walk_refuses_hostile_der(bytes in proptest::collection::vec(any::<u8>(), 0..2048), at in 0usize..400, flip in any::<u8>()) {
            let _ = stapled_scts(&bytes);
            let mut built = ocsp_with(&sct_list_value(&[vec![0, 1, 2]]));
            let at = at % built.len();
            built[at] ^= flip;
            let _ = stapled_scts(&built);
        }
    }

    #[test]
    fn every_truncation_of_the_leaf_is_refused() {
        for end in 0..LEAF.len() {
            assert!(precert_tbs(&LEAF[..end]).is_none(), "cut at {end}");
        }
    }

    #[test]
    fn a_changed_byte_in_the_leaf_stops_its_scts_counting() {
        let list = recorded();
        assert_eq!(counted(LEAF, &list), 2, "the positive");
        // A byte of the subject's key, well inside the TBS and outside any length.
        let spki = leaf().tbs_certificate.subject_pki.raw.to_vec();
        let at = LEAF.windows(spki.len()).position(|w| w == spki).unwrap() + spki.len() - 8;
        let mut changed = LEAF.to_vec();
        changed[at] ^= 1;
        assert_eq!(counted(&changed, &list), 0, "the control");
    }

    #[test]
    fn recorded_list_at_exactly_70_days_is_used_and_one_ms_later_is_skipped() {
        let list = recorded();
        assert!(!list.is_stale(LIST_AT_MS + MAX_LIST_AGE_MS));
        assert!(list.is_stale(LIST_AT_MS + MAX_LIST_AGE_MS + 1));
        assert!(!list.is_stale(LIST_AT_MS - DAY_MS), "dated in the future is fresh");
    }

    // ---- The policy table.

    const T0: u64 = 1_700_000_000_000;
    const TODAY: u64 = T0 + 10 * DAY_MS;

    fn id(n: u8) -> LogId {
        [n; 32]
    }

    fn entry(n: u8, state: &str) -> String {
        log_json(&id(n), b"not a key", state)
    }

    const QUALIFIED: &str = r#"{"qualified":{"timestamp":"2024-01-01T00:00:00Z"}}"#;
    const READONLY: &str = r#"{"readonly":{"timestamp":"2024-01-01T00:00:00Z"}}"#;
    /// T0 + 1 day, as RFC 3339.
    const RETIRED: &str = r#"{"retired":{"timestamp":"2023-11-15T22:13:20Z"}}"#;
    const RETIRED_AT: u64 = T0 + DAY_MS;
    const REJECTED: &str = r#"{"rejected":{"timestamp":"2024-01-01T00:00:00Z"}}"#;
    const PENDING: &str = r#"{"pending":{"timestamp":"2024-01-01T00:00:00Z"}}"#;
    const STRANGE: &str = r#"{"a_state_of_next_year":{}}"#;

    /// Ops: 0 holds logs 1, 2, 3; 1 holds 4, 5; 2 holds 6, 7, 8, 9, 10; each in
    /// the state its row needs.
    fn table_list() -> LogList {
        let ops = vec![
            vec![entry(1, USABLE), entry(2, QUALIFIED), entry(3, READONLY)],
            vec![entry(4, USABLE), entry(5, RETIRED)],
            vec![entry(6, RETIRED), entry(7, REJECTED), entry(8, PENDING), entry(9, STRANGE)],
        ];
        let tiled = format!(r#"{{"name":"tiled","logs":[],"tiled_logs":[{}]}}"#, entry(10, USABLE));
        let text = list_json("2023-11-20T00:00:00Z", &ops).replace(r#"],"tiled_logs":[]}]}"#, &format!(r#"],"tiled_logs":[]}},{tiled}]}}"#));
        LogList::parse(text.as_bytes()).unwrap()
    }

    fn e(log: u8, at: u64) -> VerifiedSct {
        VerifiedSct { log: id(log), timestamp_ms: at, delivery: Delivery::Embedded }
    }

    fn s(log: u8, at: u64) -> VerifiedSct {
        VerifiedSct { log: id(log), timestamp_ms: at, delivery: Delivery::Stapled }
    }

    #[test]
    fn policy_table() {
        const D180: u64 = 180 * DAY_MS;
        const D181: u64 = 181 * DAY_MS;
        use CtAnswer::{Compliant as OK, Violates as NO};
        let at = T0;
        let late = RETIRED_AT + 1;
        let rows: Vec<(&str, Vec<VerifiedSct>, u64, CtAnswer)> = vec![
            ("2 embedded from 2 operators, 180 days", vec![e(1, at), e(4, at)], D180, OK),
            ("2 at 181 days", vec![e(1, at), e(4, at)], D181, NO),
            ("3 at 181 days", vec![e(1, at), e(2, at), e(4, at)], D181, OK),
            ("2 from one operator", vec![e(1, at), e(2, at)], D180, NO),
            ("3 from one operator at 181 days", vec![e(1, at), e(2, at), e(3, at)], D181, NO),
            ("the same log twice counts once", vec![e(1, at), e(1, at + 1)], D180, NO),
            ("the same log twice, and a second log, is 2 not 3", vec![e(1, at), e(1, at + 1), e(4, at)], D181, NO),
            ("1 usable plus 1 retired, earliest before retirement", vec![e(1, at), e(5, at)], D180, OK),
            ("1 usable plus 1 retired, earliest after it", vec![e(1, late), e(5, late)], D180, NO),
            ("the retired log's own SCT is after it, whatever the set's earliest", vec![e(1, at), e(5, late)], D180, NO),
            ("the retired log's own SCT is before it, the live one's after", vec![e(1, late), e(5, at)], D180, OK),
            ("a retired log counts for nothing in a stapled set", vec![s(1, at), s(5, at)], D180, NO),
            ("2 retired only", vec![e(5, at), e(6, at)], D180, NO),
            ("rejected counts for nothing", vec![e(1, at), e(7, at)], D180, NO),
            ("pending counts for nothing", vec![e(1, at), e(8, at)], D180, NO),
            ("an unknown state counts for nothing", vec![e(1, at), e(9, at)], D180, NO),
            ("a timestamp in the future counts for nothing", vec![e(1, at), e(4, TODAY + 1)], D180, NO),
            ("tiled logs count as logs", vec![e(1, at), e(10, at)], D180, OK),
            ("2 stapled, short", vec![s(1, at), s(4, at)], D180, OK),
            ("2 stapled at any lifetime", vec![s(1, at), s(4, at)], 10 * D181, OK),
            ("1 stapled plus 1 embedded, neither set alone suffices", vec![s(1, at), e(4, at)], D180, NO),
            ("nothing at all", vec![], D180, NO),
        ];
        let list = table_list();
        for (name, verified, lifetime, want) in rows {
            assert_eq!(policy(&verified, lifetime, &list, TODAY), want, "{name}");
        }
    }

    /// Logs 1 and 2 are both A's at T0. Log 2 moved to B at T0 + 1 day, so the list
    /// reads them as two operators.
    #[test]
    fn a_log_moved_to_another_operator_does_not_prove_diversity_from_before_the_move() {
        const MOVED_AT: u64 = RETIRED_AT;
        let moved = |previous: &str| format!(r#"{{"log_id":"{}","key":"AA==","state":{USABLE},"previous_operators":{previous}}}"#, STANDARD.encode(id(2)));
        let list_with = |previous: &str| LogList::parse(list_json("2023-11-20T00:00:00Z", &[vec![entry(1, USABLE)], vec![moved(previous)]]).as_bytes()).unwrap();
        let list = list_with(r#"[{"name":"A","end_time":"2023-11-15T22:13:20Z"}]"#);
        let answer = |list: &LogList, at| policy(&[e(1, T0), e(2, at)], DAY_MS, list, TODAY);
        assert_eq!(answer(&list, T0), CtAnswer::Violates, "one operator at issuance");
        assert_eq!(answer(&list, MOVED_AT), CtAnswer::Compliant, "issued under its present operator");
        let two_moves = list_with(r#"[{"name":"Z","end_time":"2023-11-14T00:00:00Z"},{"name":"A","end_time":"2023-11-15T22:13:20Z"}]"#);
        assert_eq!(answer(&two_moves, MOVED_AT - 1), CtAnswer::Violates, "the latest move is the one that says");
        assert_eq!(answer(&list_with("[]"), T0), CtAnswer::Compliant, "no move, no question");
        for unreadable in [r#""soon""#, r#"[{"name":"A"}]"#, r#"[{"end_time":"yesterday"}]"#] {
            assert_eq!(answer(&list_with(unreadable), TODAY), CtAnswer::Violates, "{unreadable}: unproven, and the list stays good");
        }
        assert_eq!(policy(&[e(1, T0), e(2, T0)], DAY_MS, &table_of_two(), TODAY), CtAnswer::Compliant, "the control: never moved");
    }

    fn table_of_two() -> LogList {
        LogList::parse(list_json("2023-11-20T00:00:00Z", &[vec![entry(1, USABLE)], vec![entry(2, USABLE)]]).as_bytes()).unwrap()
    }

    #[test]
    fn unknown_log_and_bad_signature_do_not_count() {
        let (known, unknown) = (MemoryLog::new(), MemoryLog::new());
        let list = LogList::parse(list_json("2023-11-20T00:00:00Z", &[vec![known.json(USABLE)]]).as_bytes()).unwrap();
        let (issuer, tbs) = ([9u8; 32], [1u8, 2, 3]);
        let entry = SignedEntry::Precert { issuer: &issuer, tbs: &tbs };
        let parse = |bytes: &[u8]| {
            let (_, sct) = x509_parser::extensions::parse_ct_signed_certificate_timestamp(bytes).map(|(r, s)| (r.to_vec(), verify_sct(&s, entry, Delivery::Embedded, &list))).unwrap();
            sct
        };
        assert!(parse(&known.sct(T0, entry)).is_some(), "the positive");
        assert!(parse(&unknown.sct(T0, entry)).is_none(), "an unknown log");
        let mut bad = known.sct(T0, entry);
        *bad.last_mut().unwrap() ^= 1;
        assert!(parse(&bad).is_none(), "a bad signature");
        let other = [8u8; 32];
        assert!(parse(&known.sct(T0, SignedEntry::Precert { issuer: &other, tbs: &tbs })).is_none(), "another issuer's");
        let mut wrong_version = known.sct(T0, entry);
        wrong_version[2] = 1;
        assert!(parse(&wrong_version).is_none(), "a wrong version");
    }

    #[test]
    fn unknown_state_and_unknown_fields_do_not_refuse_the_list() {
        let extra = r#"{"from_next_year":[1],"version":"9","log_list_timestamp":"2023-11-20T00:00:00Z","operators":[{"name":"a","email":["x"],"logs":[{"log_id":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","key":"AA==","mmd":86400,"new":true,"state":{"usable":{"timestamp":"2024-01-01T00:00:00Z","new":1}}},{"log_id":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","key":"AA==","state":{"strange":{}}},{"log_id":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=","key":"AA=="}]}]}"#;
        let list = LogList::parse(extra.as_bytes()).unwrap();
        assert_eq!(list.logs[&id(1)].state, LogState::Live);
        assert_eq!(list.logs[&id(2)].state, LogState::Dead);
        assert_eq!(list.logs[&id(3)].state, LogState::Dead, "no state at all");
    }

    #[test]
    fn a_list_with_no_usable_log_is_refused() {
        let text = list_json("2023-11-20T00:00:00Z", &[vec![entry(1, RETIRED), entry(2, REJECTED), entry(3, STRANGE)]]);
        assert!(LogList::parse(text.as_bytes()).unwrap_err().contains("no usable log"));
        assert!(LogList::parse(b"not json").is_err());
        assert!(LogList::parse(list_json("yesterday", &[vec![entry(1, USABLE)]]).as_bytes()).is_err(), "a timestamp that does not parse");
    }

    #[test]
    fn stapled_scts_are_read_from_a_built_ocsp_response() {
        let log = MemoryLog::new();
        let leaf = [5u8; 40];
        let entry = SignedEntry::X509 { leaf: &leaf };
        let value = sct_list_value(&[log.sct(T0, entry), log.sct(T0 + 1, entry)]);
        let ocsp = ocsp_with(&value);
        let read = stapled_scts(&ocsp);
        assert_eq!(read.len(), 2);
        assert_eq!((read[0].timestamp, read[1].timestamp), (T0, T0 + 1));
        assert_eq!(read[0].id.key_id, &log.id);
        let list = LogList::parse(list_json("2023-11-20T00:00:00Z", &[vec![log.json(USABLE)]]).as_bytes()).unwrap();
        assert!(verify_sct(&read[0], entry, Delivery::Stapled, &list).is_some(), "a stapled SCT signs the full certificate");
        assert!(verify_sct(&read[0], SignedEntry::X509 { leaf: &[6u8; 40] }, Delivery::Stapled, &list).is_none(), "the control");
        assert!(stapled_scts(&[]).is_empty());
    }

    #[test]
    fn stapled_scts_are_read_under_every_cert_status() {
        let log = MemoryLog::new();
        let leaf = [5u8; 40];
        let entry = SignedEntry::X509 { leaf: &leaf };
        let value = sct_list_value(&[log.sct(T0, entry), log.sct(T0 + 1, entry)]);
        let revoked = status_revoked();
        let rows: [(&str, &[u8], bool); 6] = [
            ("good", &STATUS_GOOD, false),
            ("good, with nextUpdate", &STATUS_GOOD, true),
            ("revoked, whose tag is that of singleExtensions", &revoked, false),
            ("revoked, with nextUpdate", &revoked, true),
            ("unknown", &STATUS_UNKNOWN, false),
            ("unknown, with nextUpdate", &STATUS_UNKNOWN, true),
        ];
        for (name, status, next_update) in rows {
            assert_eq!(stapled_scts(&ocsp_with_status(status, next_update, &value)).len(), 2, "{name}");
        }
    }

    /// What fills the 64 KiB a handshake message may hold.
    const FLOOD: usize = 539;

    #[test]
    fn a_flooded_staple_buys_a_bounded_number_of_signature_checks() {
        let log = MemoryLog::new();
        let list = LogList::parse(list_json("2023-11-20T00:00:00Z", &[vec![log.json(USABLE)]]).as_bytes()).unwrap();
        let cert = leaf();
        let one = log.sct(T0, SignedEntry::X509 { leaf: LEAF });
        // Every one of them verifies, so what counts is what was checked.
        let flood = ocsp_with(&sct_list_value(&vec![one.clone(); FLOOD]));
        assert_eq!(stapled_scts(&flood).len(), FLOOD, "the flood was read");
        assert_eq!(verified_scts(&cert, LEAF, &issuer_hash(), &flood, &list).len(), MAX_SCTS_CHECKED);
        // SCTs that cost no signature do not use the bound up.
        let stranger = MemoryLog::new().sct(T0, SignedEntry::X509 { leaf: LEAF });
        let mut scts = vec![stranger; FLOOD];
        scts.push(one);
        assert_eq!(verified_scts(&cert, LEAF, &issuer_hash(), &ocsp_with(&sct_list_value(&scts)), &list).len(), 1);
    }

    #[test]
    fn a_flooded_staple_does_not_crowd_out_the_embedded_set() {
        let (list, cert) = (recorded(), leaf());
        // A listed log's id on a signature that fails only at the last step.
        let forger = MemoryLog { key: rcgen::KeyPair::generate().unwrap(), id: *scts_of(&cert)[0].id.key_id };
        let flood = ocsp_with(&sct_list_value(&vec![forger.sct(LIST_AT_MS, SignedEntry::X509 { leaf: LEAF }); FLOOD]));
        let verified = verified_scts(&cert, LEAF, &issuer_hash(), &flood, &list);
        assert_eq!(verified.len(), 2, "the embedded two, and none of the flood");
        assert_eq!(policy(&verified, lifetime_ms(&cert), &list, NOW), CtAnswer::Compliant);
    }
}
