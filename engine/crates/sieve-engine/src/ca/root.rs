//! The root certificate (plan 2.1): built here, then read back from the store
//! by thumbprint (`ca.json` holds no certificate, S51).

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
    SerialNumber,
};
use sha1::{Digest, Sha1};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::key::RootKey;
use super::{CLOCK_SKEW_MS, CaError, ROOT_LIFETIME_MS};

/// 128 bits (plan 2.5, and the same for the root).
const SERIAL_BYTES: usize = 16;
const MS_PER_S: u64 = 1_000;
const SUBJECT_PREFIX: &str = "Sieve local filtering CA (";
/// `ub-common-name` (RFC 5280, characters): a long machine name is cut, the
/// date stays.
const COMMON_NAME_MAX: usize = 64;

/// What the DER says, the one source of these facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootFacts {
    pub thumbprint: String,
    pub not_after_ms: u64,
}

/// The store's identity for a certificate: SHA-1 of the DER, lowercase hex,
/// as `certutil -store Root <hash>` takes it.
pub fn thumbprint(der: &[u8]) -> String {
    Sha1::digest(der).iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn time_of(ms: u64) -> Result<OffsetDateTime, CaError> {
    let seconds = i64::try_from(ms / MS_PER_S).map_err(|_| CaError::Cert(format!("time out of range: {ms}")))?;
    OffsetDateTime::from_unix_timestamp(seconds).map_err(|e| CaError::Cert(format!("time out of range: {e}")))
}

pub(super) fn random_serial() -> Result<SerialNumber, CaError> {
    let mut bytes = [0u8; SERIAL_BYTES];
    SystemRandom::new().fill(&mut bytes).map_err(|_| CaError::Cert("no random bytes for a serial".into()))?;
    Ok(SerialNumber::from_slice(&bytes))
}

/// "Sieve local filtering CA (<machine>, <date>)": the date is this root's
/// own, so a rotated root never shares a subject with its predecessor.
pub fn subject(machine: &str, now_ms: u64) -> Result<String, CaError> {
    let date = time_of(now_ms)?.date();
    let tail = format!(", {:04}-{:02}-{:02})", date.year(), u8::from(date.month()), date.day());
    let room = COMMON_NAME_MAX - SUBJECT_PREFIX.len() - tail.len();
    Ok(format!("{SUBJECT_PREFIX}{}{tail}", machine.chars().take(room).collect::<String>()))
}

/// Builds and signs the root with the limits of plan 2.1. Name constraints
/// are not used: the CA signs for any public host.
pub fn build(key: &RootKey, machine: &str, now_ms: u64) -> Result<Vec<u8>, CaError> {
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, subject(machine, now_ms)?);
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.serial_number = Some(random_serial()?);
    params.not_before = time_of(now_ms.saturating_sub(CLOCK_SKEW_MS))?;
    params.not_after = time_of(now_ms.saturating_add(ROOT_LIFETIME_MS))?;
    let cert = params.self_signed(key).map_err(|e| {
        CaError::Cert(key.take_sign_error().map_or_else(|| format!("root: {e}"), |why| format!("root: signing: {why}")))
    })?;
    Ok(cert.der().to_vec())
}

/// The facts of a certificate the store holds.
pub fn facts(der: &[u8]) -> Result<RootFacts, CaError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| CaError::Cert(format!("stored root: {e}")))?;
    let not_after = cert.validity().not_after.timestamp();
    let not_after_ms = u64::try_from(not_after).map_err(|_| CaError::Cert(format!("stored root: notAfter {not_after}")))?;
    Ok(RootFacts { thumbprint: thumbprint(der), not_after_ms: not_after_ms * MS_PER_S })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::oid_registry::{
        OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256, OID_X509_EXT_BASIC_CONSTRAINTS,
        OID_X509_EXT_EXTENDED_KEY_USAGE, OID_X509_EXT_KEY_USAGE, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
    };

    use super::super::key::memory_signer;
    use super::super::trust::SERVER_AUTH_EKU_DER;
    use super::*;

    const NOW: u64 = 1_793_000_000_000;

    fn key() -> RootKey {
        memory_signer(Arc::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()))
    }

    fn root() -> Vec<u8> {
        build(&key(), "BOX", NOW).unwrap()
    }

    fn parsed(der: &[u8]) -> X509Certificate<'_> {
        X509Certificate::from_der(der).unwrap().1
    }

    #[test]
    fn root_has_exactly_the_planned_extensions() {
        let der = root();
        let cert = parsed(&der);
        let oids: BTreeSet<String> = cert.extensions().iter().map(|e| e.oid.to_id_string()).collect();
        let want: BTreeSet<String> = [
            &OID_X509_EXT_KEY_USAGE,
            &OID_X509_EXT_EXTENDED_KEY_USAGE,
            &OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
            &OID_X509_EXT_BASIC_CONSTRAINTS,
        ]
        .iter()
        .map(|o| o.to_id_string())
        .collect();
        assert_eq!(oids, want, "exactly these, so no name constraints");
        for ext in cert.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::KeyUsage(u) => {
                    assert!(ext.critical && u.key_cert_sign() && u.crl_sign());
                    assert!(!u.digital_signature() && !u.non_repudiation() && !u.key_encipherment());
                    assert!(!u.data_encipherment() && !u.key_agreement() && !u.encipher_only() && !u.decipher_only());
                }
                ParsedExtension::BasicConstraints(b) => {
                    assert!(ext.critical && b.ca);
                    assert_eq!(b.path_len_constraint, Some(0));
                }
                ParsedExtension::ExtendedKeyUsage(_) | ParsedExtension::SubjectKeyIdentifier(_) => {}
                other => panic!("unexpected extension {other:?}"),
            }
        }
    }

    #[test]
    fn root_eku_is_server_auth_only() {
        let der = root();
        let cert = parsed(&der);
        let ext = cert.extensions().iter().find(|e| e.oid == OID_X509_EXT_EXTENDED_KEY_USAGE).unwrap();
        let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() else { panic!("not parsed") };
        assert!(eku.server_auth);
        assert!(!eku.any && !eku.client_auth && !eku.code_signing && !eku.email_protection && !eku.time_stamping && !eku.ocsp_signing);
        assert!(eku.other.is_empty());
        assert_eq!(ext.value, SERVER_AUTH_EKU_DER, "the store property carries the same bytes");
    }

    #[test]
    fn root_is_p256_sha256_and_self_signature_verifies() {
        let der = root();
        let cert = parsed(&der);
        assert_eq!(cert.signature_algorithm.algorithm, OID_SIG_ECDSA_WITH_SHA256);
        assert_eq!(cert.public_key().algorithm.algorithm, OID_KEY_TYPE_EC_PUBLIC_KEY);
        let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, cert.public_key().subject_public_key.data.as_ref());
        verifier.verify(cert.tbs_certificate.as_ref(), cert.signature_value.data.as_ref()).unwrap();
        assert_eq!(cert.subject().to_string(), cert.issuer().to_string());
    }

    #[test]
    fn root_lives_one_year_from_the_given_clock() {
        let der = root();
        let validity = parsed(&der).validity().clone();
        assert_eq!(validity.not_after.timestamp() as u64 * MS_PER_S, NOW + ROOT_LIFETIME_MS);
        assert_eq!(validity.not_before.timestamp() as u64 * MS_PER_S, NOW - CLOCK_SKEW_MS);
        assert_eq!(ROOT_LIFETIME_MS, 365 * 24 * 3_600_000);
        assert_eq!(facts(&der).unwrap(), RootFacts { thumbprint: thumbprint(&der), not_after_ms: NOW + ROOT_LIFETIME_MS });
    }

    #[test]
    fn root_subject_names_machine_and_date() {
        // 1_793_000_000_000 ms is 2026-10-26 UTC.
        let der = build(&key(), "BOX", NOW).unwrap();
        let common = |der: &[u8]| {
            parsed(der).subject().iter_common_name().next().unwrap().as_str().unwrap().to_string()
        };
        assert_eq!(common(&der), "Sieve local filtering CA (BOX, 2026-10-26)");
        let der = build(&key(), "Pc-מיכאל-日本", NOW).unwrap();
        assert_eq!(common(&der), "Sieve local filtering CA (Pc-מיכאל-日本, 2026-10-26)");
        let long = "x".repeat(200);
        let der = build(&key(), &long, NOW).unwrap();
        let name = common(&der);
        assert_eq!(name.chars().count(), COMMON_NAME_MAX);
        assert!(name.ends_with(", 2026-10-26)"), "the date stays: {name}");
    }

    #[test]
    fn root_serial_is_random_positive_and_within_20_octets() {
        let mut seen = BTreeSet::new();
        for _ in 0..32 {
            let der = root();
            let cert = parsed(&der);
            assert_eq!(cert.tbs_certificate.raw_serial().first().map(|b| b & 0x80), Some(0), "positive");
            assert!(cert.tbs_certificate.raw_serial().len() <= 20);
            assert!(cert.tbs_certificate.serial.bits() > 64, "about 128 random bits");
            seen.insert(cert.raw_serial_as_string());
        }
        assert_eq!(seen.len(), 32);
    }

    #[test]
    fn a_broken_signer_reports_its_reason() {
        struct Broken;
        impl super::super::key::RootSigner for Broken {
            fn public_point(&self) -> &[u8] {
                &[4; 65]
            }
            fn sign_der(&self, _: &[u8]) -> Result<Vec<u8>, String> {
                Err("NCryptSignHash: denied".into())
            }
        }
        let err = build(&RootKey::new(Box::new(Broken)), "BOX", NOW).unwrap_err();
        assert!(err.to_string().contains("NCryptSignHash: denied"), "{err}");
    }

    #[test]
    fn the_thumbprint_is_lowercase_sha1_hex() {
        assert_eq!(thumbprint(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }
}
