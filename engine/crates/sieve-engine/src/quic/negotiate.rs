//! The Version Negotiation packet a blocked QUIC flow is answered with (RFC 9000
//! section 17.2.1), written back through the app's UDP stream so it reaches the
//! browser's socket as a datagram from the server. It offers one reserved greasing
//! version, so no client can continue, and it fails the connection attempt at once
//! where silence makes the browser wait out QUIC's idle timeout.

use crate::flow::quic::initial_cids;

/// RFC 9000 section 15's reserved pattern (0x?a?a?a?a), so never a client's version.
pub const GREASE_VERSION: u32 = 0x1a2a_3a4a;
/// RFC 9000 section 17.2.1: the top bit set, the rest arbitrary, and 0x40 set so it
/// looks like any other QUIC packet.
const FIRST_BYTE: u8 = 0xc0;
const NEGOTIATION_VERSION: u32 = 0;

/// The answer to `datagram`, or None when it is no client Initial. The client's
/// SCID becomes the destination and its DCID the source. Both lengths come from
/// [`initial_cids`], bounded and read inside the datagram, so the answer is always
/// smaller than the datagram it answers.
pub fn version_negotiation(datagram: &[u8]) -> Option<Vec<u8>> {
    let (dcid, scid) = initial_cids(datagram)?;
    let mut out = Vec::with_capacity(1 + 4 + 1 + scid.len() + 1 + dcid.len() + 4);
    out.push(FIRST_BYTE);
    out.extend_from_slice(&NEGOTIATION_VERSION.to_be_bytes());
    out.push(u8::try_from(scid.len()).ok()?);
    out.extend_from_slice(scid);
    out.push(u8::try_from(dcid.len()).ok()?);
    out.extend_from_slice(dcid);
    out.extend_from_slice(&GREASE_VERSION.to_be_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::quic::{MAX_CID_LEN, MIN_INITIAL_DATAGRAM, VERSION_1, VERSION_2, crypto_frame, is_supported_version, seal_client_initial};
    use proptest::prelude::*;

    const DCID: [u8; 8] = [0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7];
    const SCID: [u8; 5] = [0x50, 0x51, 0x52, 0x53, 0x54];
    const FULL_SIZE: usize = MIN_INITIAL_DATAGRAM + 40;
    /// Where the version ends and the first CID length begins.
    const CID_LENGTH_AT: usize = 5;

    fn initial(version: u32, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut frames = crypto_frame(0, &[1, 0, 0, 0]);
        frames.resize(MIN_INITIAL_DATAGRAM, 0);
        seal_client_initial(version, dcid, scid, 0, 1, &frames)
    }

    /// A header written by hand, so a broken one can be spelled out, then padded.
    fn raw(first: u8, version: u32, cids: &[u8]) -> Vec<u8> {
        let mut out = vec![first];
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(cids);
        out.resize(out.len().max(FULL_SIZE), 0);
        out
    }

    #[test]
    fn the_exact_bytes() {
        #[rustfmt::skip]
        let expected = [
            0xc0,
            0, 0, 0, 0,
            5, 0x50, 0x51, 0x52, 0x53, 0x54,
            8, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
            0x1a, 0x2a, 0x3a, 0x4a,
        ];
        for version in [VERSION_1, VERSION_2] {
            assert_eq!(version_negotiation(&initial(version, &DCID, &SCID)).unwrap(), expected, "{version:#x}");
        }
    }

    #[test]
    fn zero_length_ids_are_answered() {
        let (no_ids, no_scid, no_dcid) = (initial(VERSION_1, &[], &[]), initial(VERSION_1, &DCID, &[]), initial(VERSION_1, &[], &SCID));
        assert_eq!(version_negotiation(&no_ids).unwrap(), [0xc0, 0, 0, 0, 0, 0, 0, 0x1a, 0x2a, 0x3a, 0x4a]);
        assert_eq!(version_negotiation(&no_scid).unwrap(), [&[0xc0, 0, 0, 0, 0, 0, 8][..], &DCID, &[0x1a, 0x2a, 0x3a, 0x4a]].concat());
        assert_eq!(version_negotiation(&no_dcid).unwrap(), [&[0xc0, 0, 0, 0, 0, 5][..], &SCID, &[0], &[0x1a, 0x2a, 0x3a, 0x4a]].concat());
    }

    #[test]
    fn the_longest_ids_are_answered() {
        let (dcid, scid) = ([1u8; MAX_CID_LEN], [2u8; MAX_CID_LEN]);
        let answer = version_negotiation(&initial(VERSION_2, &dcid, &scid)).unwrap();
        assert_eq!(answer.len(), 1 + 4 + 1 + MAX_CID_LEN + 1 + MAX_CID_LEN + 4);
        assert_eq!(&answer[6..6 + MAX_CID_LEN], scid);
    }

    /// The control for every row below is `the_exact_bytes`: only the named byte differs.
    #[test]
    fn what_is_no_client_initial_gets_no_answer() {
        let long_cid = [&[(MAX_CID_LEN + 1) as u8][..], &[0; MAX_CID_LEN + 1], &[0]].concat();
        let long_scid = [&[0][..], &[(MAX_CID_LEN + 1) as u8], &[0; MAX_CID_LEN + 1]].concat();
        let past_the_end = vec![0xc0, 0, 0, 0, 1, 20, 0, 0, 0];
        let rows: [(&str, Vec<u8>); 12] = [
            ("empty", Vec::new()),
            ("one byte", vec![0xc0]),
            ("short of the version", vec![0xc0, 0, 0]),
            ("no CIDs in a short packet", vec![0xc0, 0, 0, 0, 1]),
            ("a CID past the end", past_the_end),
            ("under 1200 bytes", initial(VERSION_1, &DCID, &SCID)[..MIN_INITIAL_DATAGRAM - 1].to_vec()),
            ("a short header", raw(0x40, VERSION_1, &[0, 0])),
            ("the fixed bit clear", raw(0x80, VERSION_1, &[0, 0])),
            ("an unknown version", raw(0xc0, 0x5a5a_5a5a, &[0, 0])),
            ("a Version Negotiation itself", raw(0xc0, 0, &[0, 0])),
            ("a DCID over 20", raw(0xc0, VERSION_1, &long_cid)),
            ("an SCID over 20", raw(0xc0, VERSION_1, &long_scid)),
        ];
        for (name, datagram) in rows {
            assert_eq!(version_negotiation(&datagram), None, "{name}");
        }
        assert_eq!(version_negotiation(&raw(0xc0, VERSION_1, &[0, 0])).unwrap().len(), 11, "the control: this header is answered");
    }

    #[test]
    fn only_the_initial_type_is_answered() {
        // Bits 5..4: v1 Initial 00, 0-RTT 01, Handshake 10, Retry 11; v2 Retry 00, Initial 01.
        for (first, version, answered) in [(0xc0, VERSION_1, true), (0xd0, VERSION_1, false), (0xe0, VERSION_1, false), (0xf0, VERSION_1, false), (0xd0, VERSION_2, true), (0xc0, VERSION_2, false), (0xe0, VERSION_2, false), (0xf0, VERSION_2, false)] {
            assert_eq!(version_negotiation(&raw(first, version, &[0, 0])).is_some(), answered, "{first:#x} {version:#x}");
        }
    }

    #[test]
    fn the_offered_version_is_no_version_a_client_uses() {
        assert!(!is_supported_version(GREASE_VERSION));
        assert_eq!(GREASE_VERSION & 0x0f0f_0f0f, 0x0a0a_0a0a, "the reserved pattern");
    }

    proptest! {
        #[test]
        fn any_bytes_never_panic_and_an_answer_is_always_well_formed(
            mut datagram in prop_oneof![prop::collection::vec(any::<u8>(), 0..MIN_INITIAL_DATAGRAM), prop::collection::vec(any::<u8>(), MIN_INITIAL_DATAGRAM..1400)],
            first in prop::sample::select(vec![0xc0u8, 0xd0]),
            version in prop::sample::select(vec![VERSION_1, VERSION_2]),
            dcid_len in 0usize..=MAX_CID_LEN,
            scid_len in 0u8..=20,
        ) {
            let _ = version_negotiation(&datagram);
            // The same bytes with a header that gets past the first checks, so the
            // lines below are reached (half the versions pair with the right type).
            if datagram.len() >= MIN_INITIAL_DATAGRAM {
                datagram[0] = first;
                datagram[1..CID_LENGTH_AT].copy_from_slice(&version.to_be_bytes());
                datagram[CID_LENGTH_AT] = dcid_len as u8;
                datagram[CID_LENGTH_AT + 1 + dcid_len] = scid_len;
            }
            if let Some(answer) = version_negotiation(&datagram) {
                prop_assert!(answer.len() < datagram.len(), "no amplification");
                prop_assert_eq!(&answer[..5], &[0xc0, 0, 0, 0, 0]);
                prop_assert_eq!(&answer[answer.len() - 4..], &GREASE_VERSION.to_be_bytes());
                prop_assert_eq!(answer.len(), 1 + 4 + 1 + usize::from(answer[5]) + 1 + usize::from(answer[6 + usize::from(answer[5])]) + 4);
            }
        }
    }
}
