//! The two byte formats where CNG and X.509 disagree (plan 2.2). Pure, so
//! the format risk is tested without touching a key store.

/// `BCRYPT_ECDSA_PUBLIC_P256_MAGIC` ("ECS1" little-endian).
const ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345;
/// Bytes of one P-256 coordinate.
const P256_COORDINATE: usize = 32;
/// `BCRYPT_ECCKEY_BLOB`: the magic and the coordinate length, u32 each.
const BLOB_HEADER: usize = 8;
const ASN1_SEQUENCE: u8 = 0x30;
const ASN1_INTEGER: u8 = 0x02;
/// The longest DER length with a one-byte form.
const SHORT_FORM_MAX: usize = 0x7f;
/// The SEC1 tag of an uncompressed point.
const UNCOMPRESSED: u8 = 0x04;

/// `r` or `s` as a DER INTEGER: no leading zeros, and one zero byte when the
/// high bit is set (the value is positive).
fn der_integer(value: &[u8], out: &mut Vec<u8>) {
    let first = value.iter().position(|b| *b != 0).unwrap_or(value.len().saturating_sub(1));
    let digits = &value[first..];
    let pad = digits.first().is_some_and(|b| b & 0x80 != 0);
    out.push(ASN1_INTEGER);
    out.push((digits.len() + usize::from(pad)) as u8);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(digits);
}

/// `NCryptSignHash` returns P1363 `r||s`; X.509 carries a DER SEQUENCE.
pub fn p1363_to_der(signature: &[u8]) -> Result<Vec<u8>, String> {
    let half = signature.len() / 2;
    if half == 0 || !signature.len().is_multiple_of(2) || half > P256_COORDINATE {
        return Err(format!("not a P-256 signature: {} bytes", signature.len()));
    }
    let (r, s) = signature.split_at(half);
    let mut body = Vec::with_capacity(signature.len() + 6);
    der_integer(r, &mut body);
    der_integer(s, &mut body);
    debug_assert!(body.len() <= SHORT_FORM_MAX);
    let mut der = vec![ASN1_SEQUENCE, body.len() as u8];
    der.append(&mut body);
    Ok(der)
}

/// A `BCRYPT_ECCPUBLIC_BLOB` as the SEC1 point rcgen takes: `0x04||X||Y`.
pub fn ecc_public_blob_to_point(blob: &[u8]) -> Result<Vec<u8>, String> {
    let (Some(magic), Some(length)) = (blob.get(..4), blob.get(4..BLOB_HEADER)) else {
        return Err(format!("public key blob of {} bytes has no header", blob.len()));
    };
    let magic = u32::from_le_bytes(magic.try_into().map_err(|_| "blob magic")?);
    if magic != ECDSA_PUBLIC_P256_MAGIC {
        return Err(format!("public key blob magic {magic:#x} is not P-256"));
    }
    let length = u32::from_le_bytes(length.try_into().map_err(|_| "blob length")?) as usize;
    if length != P256_COORDINATE || blob.len() != BLOB_HEADER + 2 * P256_COORDINATE {
        return Err(format!("public key blob of {} bytes, coordinate {length}", blob.len()));
    }
    let mut point = Vec::with_capacity(1 + 2 * P256_COORDINATE);
    point.push(UNCOMPRESSED);
    point.extend_from_slice(&blob[BLOB_HEADER..]);
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, UnparsedPublicKey};

    /// Half of all P-256 signature halves have the high bit set, and one in
    /// 256 starts with a zero, so 256 signatures cross both cases.
    #[test]
    fn p1363_to_der_verifies_with_the_asn1_verifier() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key.public_key().as_ref());
        let mut high_bit = false;
        for i in 0..256u32 {
            let message = i.to_le_bytes();
            let fixed = key.sign(&rng, &message).unwrap();
            high_bit |= fixed.as_ref()[0] & 0x80 != 0;
            verifier.verify(&message, &p1363_to_der(fixed.as_ref()).unwrap()).unwrap();
        }
        assert!(high_bit, "the run crossed a high bit");
    }

    #[test]
    fn integers_lose_leading_zeros_and_gain_a_sign_byte() {
        let mut signature = [0u8; 64];
        signature[1] = 0x7f; // r: one leading zero, then a clear high bit
        signature[32] = 0x80; // s: high bit set
        let der = p1363_to_der(&signature).unwrap();
        assert_eq!(&der[..2], &[ASN1_SEQUENCE, (der.len() - 2) as u8]);
        assert_eq!(&der[2..4], &[ASN1_INTEGER, 31]);
        assert_eq!(der[4], 0x7f);
        assert_eq!(&der[35..38], &[ASN1_INTEGER, 33, 0]);
        assert_eq!(der[38], 0x80);
    }

    #[test]
    fn a_zero_value_stays_one_byte_and_bad_lengths_are_refused() {
        assert_eq!(p1363_to_der(&[0; 64]).unwrap(), [ASN1_SEQUENCE, 6, ASN1_INTEGER, 1, 0, ASN1_INTEGER, 1, 0]);
        for bad in [&[][..], &[0; 63], &[0; 66]] {
            assert!(p1363_to_der(bad).is_err(), "{}", bad.len());
        }
    }

    fn blob(magic: u32, coordinate: u32, body: usize) -> Vec<u8> {
        let mut b = magic.to_le_bytes().to_vec();
        b.extend_from_slice(&coordinate.to_le_bytes());
        b.extend((0..body).map(|i| i as u8));
        b
    }

    #[test]
    fn ecc_public_blob_gives_the_uncompressed_point() {
        let point = ecc_public_blob_to_point(&blob(ECDSA_PUBLIC_P256_MAGIC, 32, 64)).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], UNCOMPRESSED);
        assert_eq!(&point[1..], (0..64u8).collect::<Vec<_>>());
    }

    #[test]
    fn ecc_public_blob_refuses_wrong_magic_and_length() {
        assert_eq!(ECDSA_PUBLIC_P256_MAGIC.to_le_bytes(), *b"ECS1");
        for bad in [
            blob(0x3153_4B45, 32, 64),               // ECK1, an ECDH key
            blob(ECDSA_PUBLIC_P256_MAGIC, 48, 96),   // P-384 sized
            blob(ECDSA_PUBLIC_P256_MAGIC, 32, 63),   // short
            blob(ECDSA_PUBLIC_P256_MAGIC, 32, 65),   // long
            vec![1, 2, 3],                           // no header
        ] {
            assert!(ecc_public_blob_to_point(&bad).is_err(), "{bad:?}");
        }
    }
}
