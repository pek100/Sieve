//! CRLite as a hard-fail revocation source (plan 2.6, task D6, D7), over Mozilla's
//! `clubcard-crlite`: Mozilla no longer publishes filter cascades, so
//! `rust_cascade` cannot read the published data (task F1).
//!
//! The bundle at `update::data_path` is repeated `u32 LE length, clubcard bytes`,
//! the full filter first, then its deltas in order. One broken filter refuses the
//! whole bundle: one normalizer per boundary.
//!
//! No age limit: CRLite here only ever adds "revoked". A certificate issued after
//! a filter was built has SCT timestamps outside its coverage, so the answer is
//! `NotCovered`, not a guess, and the OS is still asked (S52).

use clubcard_crlite::{CRLiteClubcard, CRLiteKey, CRLiteStatus, IssuerSpkiHash, LogId, Timestamp};

/// What a bundle file may be when read. The signed index's `size` already caps
/// the download; the published data is 16 MB (task F2).
pub const MAX_BUNDLE_BYTES: u64 = 64 << 20;
const LENGTH_BYTES: usize = 4;

/// The filters of one bundle.
pub struct Crlite(Vec<CRLiteClubcard>);

impl std::fmt::Debug for Crlite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Crlite({} filters)", self.0.len())
    }
}

impl Crlite {
    pub fn from_bundle(mut bytes: &[u8]) -> Result<Self, String> {
        let mut filters = Vec::new();
        while !bytes.is_empty() {
            let (length, rest) = bytes.split_first_chunk::<LENGTH_BYTES>().ok_or("a bundle cut inside a length")?;
            let length = usize::try_from(u32::from_le_bytes(*length)).map_err(|_| "a length that does not fit")?;
            let filter = rest.get(..length).ok_or("a filter longer than its bundle")?;
            filters.push(CRLiteClubcard::from_bytes(filter).map_err(|e| format!("filter {}: {e}", filters.len()))?);
            bytes = &rest[length..];
        }
        Ok(Self(filters))
    }

    pub fn filters(&self) -> usize {
        self.0.len()
    }

    /// True when any filter says revoked, the rule for a full filter plus deltas,
    /// since a revocation stays revoked. `Good`, `NotCovered` and `NotEnrolled`
    /// all mean false: the stack carries on to the OS. Embedded SCTs only, as
    /// Firefox and the crate's example do.
    pub fn is_revoked(&self, issuer: &[u8; 32], raw_serial: &[u8], embedded: &[([u8; 32], u64)]) -> bool {
        let issuer = IssuerSpkiHash(*issuer);
        let key = CRLiteKey::new(&issuer, raw_serial);
        self.0.iter().any(|filter| filter.contains(&key, embedded.iter().map(|(log, at)| (LogId(*log), Timestamp(*at)))) == CRLiteStatus::Revoked)
    }
}

/// The bundle [`Crlite::from_bundle`] reads, within the size a reader takes.
pub fn encode_bundle(filters: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let size: usize = filters.iter().map(|filter| LENGTH_BYTES + filter.len()).sum();
    if size as u64 > MAX_BUNDLE_BYTES {
        return Err(format!("{size} bytes: the engine reads a bundle of at most {MAX_BUNDLE_BYTES}"));
    }
    let mut out = Vec::with_capacity(size);
    for filter in filters {
        out.extend_from_slice(&u32::try_from(filter.len()).map_err(|_| "a filter too long")?.to_le_bytes());
        out.extend_from_slice(filter);
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod testing {
    // The filter is made as the crate's own tests make theirs (clubcard-crlite,
    // src/builder.rs, MPL-2.0: http://mozilla.org/MPL/2.0/).
    use clubcard::builder::{ApproximateRibbon, ClubcardBuilder, ExactRibbon};
    use clubcard_crlite::builder::CRLiteBuilderItem;
    use clubcard_crlite::{CRLiteClubcard, CRLiteCoverage, CRLiteQuery, Encoding, IssuerSpkiHash};

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    /// A filter over one issuer: these serials revoked, those good, covering one
    /// log for `low..=high`.
    pub(crate) fn filter(issuer: &[u8; 32], revoked: &[&[u8]], good: &[&[u8]], log: &[u8; 32], low: u64, high: u64, encoding: Encoding) -> Vec<u8> {
        let hash = || IssuerSpkiHash(*issuer);
        let mut builder = ClubcardBuilder::new();
        let mut approx = builder.new_approx_builder(issuer);
        approx.set_universe_size(revoked.len() + good.len());
        for serial in revoked {
            approx.insert(CRLiteBuilderItem::revoked(hash(), serial.to_vec()));
        }
        builder.collect_approx_ribbons(vec![ApproximateRibbon::from(approx)]);
        let mut exact = builder.new_exact_builder(issuer);
        for serial in revoked {
            exact.insert(CRLiteBuilderItem::revoked(hash(), serial.to_vec()));
        }
        for serial in good {
            exact.insert(CRLiteBuilderItem::not_revoked(hash(), serial.to_vec()));
        }
        builder.collect_exact_ribbons(vec![ExactRibbon::from(exact)]);
        let logs = format!(r#"[{{"LogID":"{}","MaxTimestamp":{high},"MinTimestamp":{low},"MMD":0,"MinEntry":0}}]"#, STANDARD.encode(log));
        let coverage = CRLiteCoverage::from_mozilla_ct_logs_json(logs.as_bytes());
        CRLiteClubcard::from(builder.build::<CRLiteQuery>(coverage, ())).to_bytes(encoding).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use clubcard_crlite::Encoding;

    use super::testing::filter;
    use super::*;

    const ISSUER: [u8; 32] = [3; 32];
    const OTHER_ISSUER: [u8; 32] = [4; 32];
    const LOG: [u8; 32] = [5; 32];
    const OTHER_LOG: [u8; 32] = [6; 32];
    const LOW: u64 = 1_000;
    const HIGH: u64 = 2_000;
    const AT: u64 = 1_500;
    const BAD: &[u8] = &[0x01, 0xba, 0xd0];
    const FINE: &[u8] = &[0x02, 0xf1, 0x4e];
    const NEWLY_BAD: &[u8] = &[0x03, 0x77];

    fn scts(at: u64) -> [([u8; 32], u64); 1] {
        [(LOG, at)]
    }

    fn full(encoding: Encoding) -> Vec<u8> {
        filter(&ISSUER, &[BAD], &[FINE, NEWLY_BAD], &LOG, LOW, HIGH, encoding)
    }

    fn bundle_of(filters: &[Vec<u8>]) -> Crlite {
        Crlite::from_bundle(&encode_bundle(filters).unwrap()).unwrap()
    }

    #[test]
    fn a_revoked_serial_is_revoked_and_a_good_one_is_not() {
        let crlite = bundle_of(&[full(Encoding::V3)]);
        assert!(crlite.is_revoked(&ISSUER, BAD, &scts(AT)));
        assert!(!crlite.is_revoked(&ISSUER, FINE, &scts(AT)));
    }

    #[test]
    fn not_covered_and_not_enrolled_are_no_answer() {
        let crlite = bundle_of(&[full(Encoding::V3)]);
        assert!(!crlite.is_revoked(&ISSUER, BAD, &scts(HIGH + 1)), "a timestamp outside coverage");
        assert!(!crlite.is_revoked(&ISSUER, BAD, &[(OTHER_LOG, AT)]), "a log outside coverage");
        assert!(!crlite.is_revoked(&OTHER_ISSUER, BAD, &scts(AT)), "an issuer not in the filter");
    }

    #[test]
    fn a_bundle_the_engine_would_refuse_is_not_made() {
        let cap = usize::try_from(MAX_BUNDLE_BYTES).unwrap();
        let exactly = vec![vec![0u8; cap - LENGTH_BYTES]];
        assert_eq!(encode_bundle(&exactly).unwrap().len(), cap, "the cap itself is read");
        let over = vec![vec![0u8; cap - 2 * LENGTH_BYTES], vec![0u8; 1]];
        assert!(encode_bundle(&over).unwrap_err().contains(&MAX_BUNDLE_BYTES.to_string()));
    }

    #[test]
    fn no_embedded_scts_is_no_answer() {
        assert!(!bundle_of(&[full(Encoding::V3)]).is_revoked(&ISSUER, BAD, &[]));
    }

    #[test]
    fn a_delta_can_revoke_what_the_full_filter_calls_good() {
        let delta = filter(&ISSUER, &[NEWLY_BAD], &[FINE, BAD], &LOG, LOW, HIGH, Encoding::V3);
        assert!(!bundle_of(&[full(Encoding::V3)]).is_revoked(&ISSUER, NEWLY_BAD, &scts(AT)), "the control");
        let crlite = bundle_of(&[full(Encoding::V3), delta]);
        assert!(crlite.is_revoked(&ISSUER, NEWLY_BAD, &scts(AT)));
        assert!(crlite.is_revoked(&ISSUER, BAD, &scts(AT)), "a revocation stays revoked though the delta calls it good");
        assert!(!crlite.is_revoked(&ISSUER, FINE, &scts(AT)));
    }

    #[test]
    fn the_bundle_round_trips_v3() {
        let crlite = bundle_of(&[full(Encoding::V3), full(Encoding::V4)]);
        assert_eq!(crlite.filters(), 2);
        assert!(crlite.is_revoked(&ISSUER, BAD, &scts(AT)));
        let v4 = bundle_of(&[full(Encoding::V4)]);
        assert!(v4.is_revoked(&ISSUER, BAD, &scts(AT)), "the crate reads both (task U9)");
    }

    #[test]
    fn one_broken_filter_refuses_the_bundle() {
        let mut broken = full(Encoding::V3);
        broken.truncate(broken.len() / 2);
        let bytes = encode_bundle(&[full(Encoding::V3), broken]).unwrap();
        assert!(Crlite::from_bundle(&bytes).unwrap_err().contains("filter 1"));
        let whole = encode_bundle(&[full(Encoding::V3)]).unwrap();
        assert!(Crlite::from_bundle(&whole[..whole.len() - 1]).is_err(), "cut short");
        assert!(Crlite::from_bundle(&[1, 0]).is_err(), "cut inside a length");
    }

    #[test]
    fn an_oversized_length_refuses_the_bundle() {
        let mut bytes = u32::MAX.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[3, 0, 1, 2]);
        assert!(Crlite::from_bundle(&bytes).unwrap_err().contains("longer than its bundle"));
    }

    #[test]
    fn an_empty_bundle_is_no_filter() {
        let crlite = Crlite::from_bundle(&[]).unwrap();
        assert_eq!(crlite.filters(), 0);
        assert!(!crlite.is_revoked(&ISSUER, BAD, &scts(AT)));
    }

    #[test]
    fn a_cascade_file_is_refused_not_misread() {
        // Cascades use versions 0 to 2 (task F1).
        let cascade = [2u8, 0, 1, 2, 3, 4, 5, 6, 7];
        let bytes = encode_bundle(&[cascade.to_vec()]).unwrap();
        assert!(Crlite::from_bundle(&bytes).unwrap_err().contains("unsupported clubcard version (2)"));
    }
}
