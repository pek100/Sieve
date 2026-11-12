//! One-time pairing codes.
//!
//! The hub's owner makes a code; it travels to the device by a channel the
//! owner trusts (typed, pasted over SSH, read aloud). It carries:
//!
//! - the hub's key fingerprint, so the device pins the hub from its first
//!   connection on (a man in the middle cannot present that key);
//! - a 128-bit random secret;
//! - an expiry (default 10 minutes) and, optionally, the hub's address
//!   (absent when the hub will dial the device instead);
//! - a 4-byte checksum against typos.
//!
//! The secret itself never crosses the network. The device proves it knows it
//! with an HMAC over the TLS session's exported keying material and both
//! keys' fingerprints, so the proof is useless on any other connection, for
//! any other device key or hub key. The hub deletes the code on first
//! successful use and when it expires: a later holder of a used or expired
//! code has nothing the hub will accept. Until some code is outstanding the
//! hub refuses every unknown key at the TLS handshake.

use aws_lc_rs::{digest, hmac};
use data_encoding::BASE32_NOPAD;

use crate::error::{LinkError, Result};
use crate::identity::Fingerprint;

const PREFIX: &str = "SL1-";
const VERSION: u8 = 1;
const PROOF_LABEL: &[u8] = b"sieve-link pair proof v1";
/// Default code lifetime.
pub const DEFAULT_TTL_SECS: u64 = 600;
const MAX_ADDR: usize = 200;

#[derive(Clone, PartialEq, Eq)]
pub struct PairingCode {
    pub hub: Fingerprint,
    pub secret: [u8; 16],
    /// Unix seconds.
    pub expires_at: u64,
    /// Where the device dials the hub; `None` when the hub dials the device.
    pub addr: Option<String>,
}

impl std::fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret.
        f.debug_struct("PairingCode")
            .field("hub", &self.hub)
            .field("expires_at", &self.expires_at)
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl PairingCode {
    pub fn new(hub: Fingerprint, ttl_secs: u64, addr: Option<String>) -> Result<Self> {
        if addr.as_ref().is_some_and(|a| a.is_empty() || a.len() > MAX_ADDR) {
            return Err(LinkError::Pairing("the address must be 1..=200 bytes".into()));
        }
        let mut secret = [0u8; 16];
        aws_lc_rs::rand::fill(&mut secret).map_err(|_| LinkError::Pairing("no randomness".into()))?;
        Ok(PairingCode { hub, secret, expires_at: crate::now_secs() + ttl_secs, addr })
    }

    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs >= self.expires_at
    }

    pub fn encode(&self) -> String {
        let mut b = Vec::with_capacity(64);
        b.push(VERSION);
        b.extend_from_slice(&self.hub.0);
        b.extend_from_slice(&self.secret);
        b.extend_from_slice(&self.expires_at.to_be_bytes());
        let addr = self.addr.as_deref().unwrap_or("");
        b.push(addr.len() as u8);
        b.extend_from_slice(addr.as_bytes());
        let sum = digest::digest(&digest::SHA256, &b);
        b.extend_from_slice(&sum.as_ref()[..4]);
        let text = BASE32_NOPAD.encode(&b);
        // Groups of 8 for reading aloud or copying by hand.
        let grouped: Vec<&str> = text.as_bytes().chunks(8).map(|c| std::str::from_utf8(c).unwrap()).collect();
        format!("{PREFIX}{}", grouped.join("-"))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bad = |why: &str| LinkError::Pairing(format!("not a valid pairing code ({why})"));
        let s = s.trim();
        let body = s
            .strip_prefix(PREFIX)
            .or_else(|| s.strip_prefix(&PREFIX.to_ascii_lowercase()))
            .ok_or_else(|| bad("prefix"))?;
        let clean: String = body
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if clean.len() > 600 {
            return Err(bad("length"));
        }
        let b = BASE32_NOPAD.decode(clean.as_bytes()).map_err(|_| bad("characters"))?;
        if b.len() < 1 + 32 + 16 + 8 + 1 + 4 {
            return Err(bad("length"));
        }
        let (data, sum) = b.split_at(b.len() - 4);
        if digest::digest(&digest::SHA256, data).as_ref()[..4] != *sum {
            return Err(bad("checksum: a character is wrong"));
        }
        if data[0] != VERSION {
            return Err(bad("version"));
        }
        let mut hub = [0u8; 32];
        hub.copy_from_slice(&data[1..33]);
        let mut secret = [0u8; 16];
        secret.copy_from_slice(&data[33..49]);
        let expires_at = u64::from_be_bytes(data[49..57].try_into().unwrap());
        let alen = data[57] as usize;
        if data.len() != 58 + alen {
            return Err(bad("length"));
        }
        let addr = if alen == 0 {
            None
        } else {
            Some(String::from_utf8(data[58..].to_vec()).map_err(|_| bad("address"))?)
        };
        Ok(PairingCode { hub: Fingerprint(hub), secret, expires_at, addr })
    }
}

fn proof_input(exporter: &[u8; 32], device: &Fingerprint, hub: &Fingerprint) -> Vec<u8> {
    let mut m = Vec::with_capacity(PROOF_LABEL.len() + 96);
    m.extend_from_slice(PROOF_LABEL);
    m.extend_from_slice(exporter);
    m.extend_from_slice(&device.0);
    m.extend_from_slice(&hub.0);
    m
}

/// The device's proof that it holds `secret`, bound to this TLS session and both keys.
pub fn proof(secret: &[u8; 16], exporter: &[u8; 32], device: &Fingerprint, hub: &Fingerprint) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, &proof_input(exporter, device, hub));
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Constant-time check of a proof.
pub fn verify_proof(secret: &[u8; 16], exporter: &[u8; 32], device: &Fingerprint, hub: &Fingerprint, proof: &[u8; 32]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    hmac::verify(&key, &proof_input(exporter, device, hub), proof).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn fp(b: u8) -> Fingerprint {
        Fingerprint([b; 32])
    }

    #[test]
    fn code_roundtrips_with_and_without_address() {
        for addr in [None, Some("vm.example.net:7443".to_string())] {
            let c = PairingCode::new(fp(1), 600, addr).unwrap();
            let s = c.encode();
            assert!(s.starts_with("SL1-"));
            assert_eq!(PairingCode::decode(&s).unwrap(), c);
            // Case and spacing do not matter.
            assert_eq!(PairingCode::decode(&format!("  {}  ", s.to_ascii_lowercase().replacen("sl1-", "SL1-", 1))).unwrap(), c);
        }
    }

    #[test]
    fn a_typo_is_caught() {
        let s = PairingCode::new(fp(2), 600, None).unwrap().encode();
        let mut chars: Vec<char> = s.chars().collect();
        let i = 10;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(PairingCode::decode(&typo).is_err());
    }

    #[test]
    fn secrets_differ_and_debug_hides_them() {
        let a = PairingCode::new(fp(3), 600, None).unwrap();
        let b = PairingCode::new(fp(3), 600, None).unwrap();
        assert_ne!(a.secret, b.secret);
        let dbg = format!("{a:?}");
        assert!(!dbg.contains("secret"));
    }

    #[test]
    fn proof_is_bound_to_session_and_keys() {
        let s = [9u8; 16];
        let ex = [1u8; 32];
        let p = proof(&s, &ex, &fp(4), &fp(5));
        assert!(verify_proof(&s, &ex, &fp(4), &fp(5), &p));
        assert!(!verify_proof(&s, &[2u8; 32], &fp(4), &fp(5), &p), "other session");
        assert!(!verify_proof(&s, &ex, &fp(6), &fp(5), &p), "other device key");
        assert!(!verify_proof(&s, &ex, &fp(4), &fp(6), &p), "other hub key");
        assert!(!verify_proof(&[8u8; 16], &ex, &fp(4), &fp(5), &p), "other secret");
    }

    proptest! {
        #[test]
        fn decode_never_panics(s in "\\PC{0,200}") {
            let _ = PairingCode::decode(&s);
        }

        #[test]
        fn decode_of_prefixed_base32_never_panics(s in "[A-Z2-7-]{0,200}") {
            let _ = PairingCode::decode(&format!("SL1-{s}"));
        }
    }
}
