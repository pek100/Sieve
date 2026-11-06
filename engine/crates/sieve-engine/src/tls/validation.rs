//! The data of the two local chain checks, and the checks themselves (plan 2.6,
//! task D1, D8), in the form of `FilterSlot`: the log list and the CRLite bundle,
//! both from `update::data_path`, swapped behind one snapshot.
//!
//! The top rule of this stream: **validation can only move a flow from intercept
//! to pass-through**, and a pass-through is the client's own connection to the
//! real server. No data, broken data or a parse failure all reach the trust call
//! as slice 6 does. A refused new file keeps what was loaded: signed data that
//! was good stays good, and the refusal is counted. A missing file means no data,
//! so removing it is how a bad artefact is taken back.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use sieve_filter::exclusions::UpstreamVerdict;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::crlite::{Crlite, MAX_BUNDLE_BYTES};
use super::ct::{self, CtAnswer, CtSkip, LOG_LIST_KEY, LogList, SpkiHash};
use super::upstream::Chain;
use crate::stack::Meters;
use crate::update::{Kind, data_path};

/// The kinds at `update::data_path` (task D2, D7). Published by hand (task Q2).
pub const KIND_LOG_LIST: &str = "ct-logs";
pub const KIND_CRLITE: &str = "crlite";

/// One file's parsed value and the modified time that value came from.
struct Loaded<T> {
    value: Option<Arc<T>>,
    modified: Option<SystemTime>,
}

impl<T> Default for Loaded<T> {
    fn default() -> Self {
        Self { value: None, modified: None }
    }
}

impl<T> Clone for Loaded<T> {
    fn clone(&self) -> Self {
        Self { value: self.value.clone(), modified: self.modified }
    }
}

#[derive(Default, Clone)]
struct ValidationData {
    list: Loaded<LogList>,
    crlite: Loaded<Crlite>,
}

/// What the local checks said about one chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checked {
    /// A verdict that ends the stack; None means it carries on to trust.
    pub verdict: Option<UpstreamVerdict>,
    pub ct: CtAnswer,
}

#[derive(Default)]
pub struct ValidationSlot {
    data: RwLock<Arc<ValidationData>>,
    /// One reload at a time: `control::routing` can run two (`load_validation` and a
    /// wake of `refresh_exclusions`), and each reads what the last one kept.
    reloading: Mutex<()>,
    meters: Arc<Meters>,
}

impl ValidationSlot {
    pub fn new(meters: Arc<Meters>) -> Self {
        Self { data: RwLock::default(), reloading: Mutex::default(), meters }
    }

    fn snapshot(&self) -> Arc<ValidationData> {
        self.data.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// CRLite, then CT, both local and inline, on one snapshot, holding no lock.
    /// `issuer` names the chain's issuer: asked only when there is data to use
    /// it on, so with none nothing costs more than slice 6.
    pub fn check(&self, chain: &Chain, now_ms: u64, issuer: impl FnOnce() -> Option<SpkiHash>) -> Checked {
        let data = self.snapshot();
        let checked = local_checks(&data, chain, now_ms, issuer);
        let meters = &self.meters.https;
        if checked.verdict == Some(UpstreamVerdict::Revoked) {
            Meters::bump(&meters.crlite_revoked);
        }
        match checked.ct {
            CtAnswer::Compliant => Meters::bump(&meters.ct_compliant),
            CtAnswer::Violates => Meters::bump(&meters.ct_violating),
            CtAnswer::Skipped(CtSkip::NoList) => Meters::bump(&meters.ct_skipped_no_list),
            CtAnswer::Skipped(CtSkip::StaleList) => Meters::bump(&meters.ct_skipped_stale),
            CtAnswer::Skipped(CtSkip::NoIssuer) => {}
        }
        checked
    }

    /// Rereads what changed, off the runtime.
    pub async fn reload(self: &Arc<Self>, engine_dir: &Path) {
        let (slot, dir) = (self.clone(), engine_dir.to_path_buf());
        let _ = tokio::task::spawn_blocking(move || slot.reload_now(&dir)).await;
    }

    /// Reads a file only when its time changed. A refused file's time is kept,
    /// so it is refused and counted once. Readers never wait on this: `check` takes
    /// a snapshot, and the swap at the end is the only write.
    fn reload_now(&self, dir: &Path) {
        let _one_at_a_time = self.reloading.lock().unwrap_or_else(|p| p.into_inner());
        let before = self.snapshot();
        let list = self.refreshed(data_path(dir, &Kind::List(KIND_LOG_LIST.into())), &before.list, |bytes| LogList::from_envelope(bytes, LOG_LIST_KEY));
        let crlite = self.refreshed(data_path(dir, &Kind::List(KIND_CRLITE.into())), &before.crlite, Crlite::from_bundle);
        *self.data.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(ValidationData { list, crlite });
    }

    fn refreshed<T>(&self, path: Option<PathBuf>, was: &Loaded<T>, parse: impl Fn(&[u8]) -> Result<T, String>) -> Loaded<T> {
        let Some(path) = path else { return Loaded::default() };
        let Some(modified) = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok()) else { return Loaded::default() };
        if was.modified == Some(modified) {
            return was.clone();
        }
        match read_capped(&path).and_then(|bytes| parse(&bytes)) {
            Ok(value) => Loaded { value: Some(Arc::new(value)), modified: Some(modified) },
            Err(_) => {
                Meters::bump(&self.meters.https.validation_refused);
                Loaded { value: was.value.clone(), modified: Some(modified) }
            }
        }
    }

    /// The `status.json.https` additions (task D11): the list's date and how
    /// many filters are held. No host.
    pub fn report(&self, into: &mut serde_json::Value) {
        let data = self.snapshot();
        into["ct_list_timestamp"] = data.list.value.as_ref().map_or(serde_json::Value::Null, |l| l.timestamp_ms.into());
        into["crlite_filters"] = data.crlite.value.as_ref().map_or(0, |c| c.filters()).into();
    }

    /// Data as a test built it, for lists no real key signed.
    #[cfg(test)]
    pub(crate) fn install(&self, list: Option<LogList>, crlite: Option<Crlite>) {
        let data = ValidationData { list: Loaded { value: list.map(Arc::new), modified: None }, crlite: Loaded { value: crlite.map(Arc::new), modified: None } };
        *self.data.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(data);
    }
}

fn read_capped(path: &Path) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_BUNDLE_BYTES + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_BUNDLE_BYTES {
        return Err("past the size cap".into());
    }
    Ok(bytes)
}

fn local_checks(data: &ValidationData, chain: &Chain, now_ms: u64, issuer: impl FnOnce() -> Option<SpkiHash>) -> Checked {
    let list = match data.list.value.as_deref() {
        None => Err(CtSkip::NoList),
        Some(list) if list.is_stale(now_ms) => Err(CtSkip::StaleList),
        Some(list) => Ok(list),
    };
    let crlite = data.crlite.value.as_deref();
    let skipped = |no_list: CtSkip| Checked { verdict: None, ct: CtAnswer::Skipped(list.err().unwrap_or(no_list)) };
    if crlite.is_none() && list.is_err() {
        return skipped(CtSkip::NoList);
    }
    // A leaf x509-parser cannot read has no facts, so `intercept` passes it
    // through whatever this says. The path comes second: it costs more.
    let Ok((_, cert)) = X509Certificate::from_der(&chain.end_entity) else { return skipped(CtSkip::NoIssuer) };
    let Some(issuer) = issuer() else { return skipped(CtSkip::NoIssuer) };
    let revoked = crlite.is_some_and(|c| {
        let embedded: Vec<([u8; 32], u64)> = ct::scts_of(&cert).iter().map(|s| (*s.id.key_id, s.timestamp)).collect();
        c.is_revoked(&issuer, cert.raw_serial(), &embedded)
    });
    let ct = match list {
        Err(skip) => CtAnswer::Skipped(skip),
        Ok(list) => {
            let verified = ct::verified_scts(&cert, &chain.end_entity, &issuer, &chain.ocsp, list);
            ct::policy(&verified, ct::lifetime_ms(&cert), list, now_ms)
        }
    };
    // Revoked comes first, so a revoked and non-compliant chain still closes open flows.
    let verdict = if revoked {
        Some(UpstreamVerdict::Revoked)
    } else if ct == CtAnswer::Violates {
        Some(UpstreamVerdict::NoTransparency)
    } else {
        None
    };
    Checked { verdict, ct }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::Ordering;

    use clubcard_crlite::Encoding;
    use rustls::pki_types::CertificateDer;

    use super::*;
    use crate::tls::crlite::{encode_bundle, testing::filter};
    use crate::tls::ct::encode_envelope;

    const LIST: &[u8] = include_bytes!("../../fixtures/validation/log_list.json");
    const SIG: &[u8] = include_bytes!("../../fixtures/validation/log_list.sig");
    const LEAF: &[u8] = include_bytes!("../../fixtures/validation/leaf.der");
    const ISSUER: &[u8] = include_bytes!("../../fixtures/validation/issuer.der");
    /// `log_list_timestamp` of the recorded list.
    const LIST_AT_MS: u64 = 1_793_885_768_000;
    pub(crate) const NOW: u64 = LIST_AT_MS + 86_400_000;

    pub(crate) fn envelope() -> Vec<u8> {
        encode_envelope(SIG, LIST).unwrap()
    }

    pub(crate) fn issuer() -> SpkiHash {
        ct::spki_hash(X509Certificate::from_der(ISSUER).unwrap().1.public_key().raw)
    }

    pub(crate) fn chain() -> Chain {
        Chain { end_entity: CertificateDer::from(LEAF.to_vec()), intermediates: Vec::new(), ocsp: Vec::new() }
    }

    /// A real builder-made filter over the recorded leaf's first SCT.
    pub(crate) fn recorded_filter(revoked: bool) -> Vec<u8> {
        let (_, cert) = X509Certificate::from_der(LEAF).unwrap();
        let scts = ct::scts_of(&cert);
        let (log, at) = (scts[0].id.key_id, scts[0].timestamp);
        let serial = cert.raw_serial();
        let other: &[u8] = &[0x7f, 0x01];
        let (bad, good): (&[&[u8]], &[&[u8]]) = if revoked { (&[serial], &[other]) } else { (&[other], &[serial]) };
        filter(&issuer(), bad, good, log, at - 1_000, at + 1_000, Encoding::V3)
    }

    fn put(dir: &Path, kind: &str, bytes: &[u8]) -> PathBuf {
        let path = data_path(dir, &Kind::List(kind.into())).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn slot() -> ValidationSlot {
        ValidationSlot::default()
    }

    #[test]
    fn reload_reads_through_data_path() {
        let dir = tempfile::tempdir().unwrap();
        put(dir.path(), KIND_LOG_LIST, &envelope());
        put(dir.path(), KIND_CRLITE, &encode_bundle(&[recorded_filter(false)]).unwrap());
        let slot = slot();
        slot.reload_now(dir.path());
        let mut status = serde_json::json!({});
        slot.report(&mut status);
        assert_eq!(status["ct_list_timestamp"], LIST_AT_MS);
        assert_eq!(status["crlite_filters"], 1);
        assert_eq!(slot.check(&chain(), NOW, || Some(issuer())), Checked { verdict: None, ct: CtAnswer::Compliant });
        assert_eq!(slot.meters.https.ct_compliant.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_refused_new_file_keeps_what_was_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let list_path = put(dir.path(), KIND_LOG_LIST, &envelope());
        let crlite_path = put(dir.path(), KIND_CRLITE, &encode_bundle(&[recorded_filter(true)]).unwrap());
        let slot = slot();
        slot.reload_now(dir.path());
        assert_eq!(slot.check(&chain(), NOW, || Some(issuer())).verdict, Some(UpstreamVerdict::Revoked));
        let later = SystemTime::now() + std::time::Duration::from_secs(60);
        for (path, bytes) in [(&list_path, b"tampered".as_slice()), (&crlite_path, &[2, 0, 0, 0, 2, 0])] {
            std::fs::write(path, bytes).unwrap();
            std::fs::File::options().write(true).open(path).unwrap().set_modified(later).unwrap();
        }
        slot.reload_now(dir.path());
        assert_eq!(slot.meters.https.validation_refused.load(Ordering::Relaxed), 2);
        let held = slot.check(&chain(), NOW, || Some(issuer()));
        assert_eq!((held.verdict, held.ct), (Some(UpstreamVerdict::Revoked), CtAnswer::Compliant), "both still held");
        slot.reload_now(dir.path());
        assert_eq!(slot.meters.https.validation_refused.load(Ordering::Relaxed), 2, "counted once");
    }

    #[test]
    fn an_unchanged_file_is_not_parsed_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = put(dir.path(), KIND_LOG_LIST, &envelope());
        let slot = slot();
        slot.reload_now(dir.path());
        // Garbage under the same time: a parse would count a refusal.
        let time = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::fs::write(&path, b"garbage").unwrap();
        std::fs::File::options().write(true).open(&path).unwrap().set_modified(time).unwrap();
        slot.reload_now(dir.path());
        assert_eq!(slot.meters.https.validation_refused.load(Ordering::Relaxed), 0);
        assert_eq!(slot.check(&chain(), NOW, || Some(issuer())).ct, CtAnswer::Compliant);
    }

    #[test]
    fn missing_files_mean_no_data_and_no_error() {
        let dir = tempfile::tempdir().unwrap();
        let slot = slot();
        slot.reload_now(dir.path());
        assert_eq!(slot.meters.https.validation_refused.load(Ordering::Relaxed), 0);
        let asked = std::cell::Cell::new(false);
        let checked = slot.check(&chain(), NOW, || {
            asked.set(true);
            None
        });
        assert_eq!(checked, Checked { verdict: None, ct: CtAnswer::Skipped(CtSkip::NoList) });
        assert!(!asked.get(), "no data, no path built");
        assert_eq!(slot.meters.https.ct_skipped_no_list.load(Ordering::Relaxed), 1);
        // And a file that goes away takes its data with it.
        let path = put(dir.path(), KIND_LOG_LIST, &envelope());
        slot.reload_now(dir.path());
        assert_eq!(slot.check(&chain(), NOW, || Some(issuer())).ct, CtAnswer::Compliant);
        std::fs::remove_file(path).unwrap();
        slot.reload_now(dir.path());
        assert_eq!(slot.check(&chain(), NOW, || Some(issuer())).ct, CtAnswer::Skipped(CtSkip::NoList));
    }

    #[test]
    fn the_status_says_what_is_held_and_names_no_host() {
        let slot = slot();
        let mut status = slot.meters.https.report();
        slot.report(&mut status);
        assert_eq!(status["ct_list_timestamp"], serde_json::Value::Null);
        assert_eq!(status["crlite_filters"], 0);
        for count in ["ct_compliant", "ct_violating", "ct_skipped_no_list", "ct_skipped_stale", "crlite_revoked", "validation_refused", "ech_offered", "ech_accepted", "ech_failed"] {
            assert_eq!(status[count], 0, "{count}");
        }
    }

    #[test]
    fn concurrent_reloads_refuse_a_file_version_once() {
        const RELOADS: usize = 8;
        const VERSIONS: u64 = 20;
        let dir = tempfile::tempdir().unwrap();
        let mut tampered = envelope();
        *tampered.last_mut().unwrap() ^= 1;
        let path = put(dir.path(), KIND_LOG_LIST, &tampered);
        let (slot, start) = (slot(), SystemTime::now());
        for version in 1..=VERSIONS {
            std::fs::File::options().write(true).open(&path).unwrap().set_modified(start + std::time::Duration::from_secs(version)).unwrap();
            let gate = std::sync::Barrier::new(RELOADS);
            std::thread::scope(|scope| {
                for _ in 0..RELOADS {
                    scope.spawn(|| {
                        gate.wait();
                        slot.reload_now(dir.path());
                    });
                }
            });
            assert_eq!(slot.meters.https.validation_refused.load(Ordering::Relaxed), version);
        }
    }

    #[test]
    fn a_leaf_x509_parser_refuses_is_no_issuer_and_no_verdict() {
        let slot = slot();
        slot.install(Some(LogList::from_envelope(&envelope(), LOG_LIST_KEY).unwrap()), None);
        let refused = Chain { end_entity: CertificateDer::from(vec![0x30, 0x00]), intermediates: Vec::new(), ocsp: Vec::new() };
        let asked = std::cell::Cell::new(false);
        let checked = slot.check(&refused, NOW, || {
            asked.set(true);
            Some(issuer())
        });
        assert_eq!(checked, Checked { verdict: None, ct: CtAnswer::Skipped(CtSkip::NoIssuer) });
        assert!(!asked.get(), "no path is built for it");
        assert!(crate::tls::upstream::leaf_facts(&refused.end_entity).is_none(), "and with no facts `intercept` passes it through");
    }

    #[test]
    fn an_oversized_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = put(dir.path(), KIND_CRLITE, &[]);
        std::fs::File::options().write(true).open(&path).unwrap().set_len(MAX_BUNDLE_BYTES + 1).unwrap();
        let slot = slot();
        slot.reload_now(dir.path());
        assert_eq!(slot.meters.https.validation_refused.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn the_tool_output_loads() {
        let (list_bytes, bundle) = (envelope(), encode_bundle(&[recorded_filter(true), recorded_filter(false)]).unwrap());
        assert_eq!(LogList::from_envelope(&list_bytes, LOG_LIST_KEY).unwrap().timestamp_ms, LIST_AT_MS);
        assert_eq!(Crlite::from_bundle(&bundle).unwrap().filters(), 2);
    }

    #[test]
    fn no_list_is_skipped() {
        let slot = slot();
        assert_eq!(slot.check(&chain(), NOW, || Some(issuer())), Checked { verdict: None, ct: CtAnswer::Skipped(CtSkip::NoList) });
        // A filter with no list still answers for revocation, and CT stays skipped.
        slot.install(None, Some(Crlite::from_bundle(&encode_bundle(&[recorded_filter(true)]).unwrap()).unwrap()));
        assert_eq!(slot.check(&chain(), NOW, || Some(issuer())), Checked { verdict: Some(UpstreamVerdict::Revoked), ct: CtAnswer::Skipped(CtSkip::NoList) });
    }

    #[test]
    fn stale_list_is_skipped_and_counted() {
        let slot = slot();
        slot.install(Some(LogList::from_envelope(&envelope(), LOG_LIST_KEY).unwrap()), None);
        let at_limit = LIST_AT_MS + ct::MAX_LIST_AGE_MS;
        assert_eq!(slot.check(&chain(), at_limit, || Some(issuer())).ct, CtAnswer::Compliant);
        assert_eq!(slot.check(&chain(), at_limit + 1, || Some(issuer())).ct, CtAnswer::Skipped(CtSkip::StaleList));
        assert_eq!(slot.meters.https.ct_skipped_stale.load(Ordering::Relaxed), 1);
    }

}
