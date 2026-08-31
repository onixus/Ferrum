//! Policy-bundle integrity (Ed25519) and mTLS PEM material (X.509).
//!
//! Bundle signatures and TLS identity are separate domains. Do not reuse
//! [`BUNDLE_SIGNATURE_CONTEXT`] Ed25519 seeds as TLS keys.
//!
//! Trust roots are caller-supplied. This crate does not fetch Rekor, CT logs,
//! or any other network source, and it does not issue CAs at runtime.
//!
//! Signatures are Ed25519 over `BUNDLE_SIGNATURE_CONTEXT || raw`, not raw
//! Ed25519 over `raw`. Admission, agent, and controller must call these
//! functions; they must not verify with a generic Ed25519 verifier.

#![deny(unsafe_code)]

mod mtls;

pub use mtls::{load_mtls_pem, verify_mtls_material, verify_mtls_peer, MtlsMaterial, PeerRole};

#[cfg(feature = "x509")]
pub mod x509;

use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use ferrum_common::{FerrumError, Result};
use ferrum_ids::Digest;
use sha2::{Digest as _, Sha256};

/// RFC 8032 Ed25519 public key size.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// RFC 8032 Ed25519 secret seed size.
pub const ED25519_SECRET_KEY_LEN: usize = 32;
/// RFC 8032 Ed25519 signature size.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Domain separator prepended to `raw` for Ed25519 only. Digest is still SHA-256(`raw`).
pub const BUNDLE_SIGNATURE_CONTEXT: &[u8] = b"FERRUM-POLICY-BUNDLE-v1";

/// Domain separator for a break-glass grant, prepended to the grant bytes for
/// Ed25519 only.
///
/// A third domain beside [`BUNDLE_SIGNATURE_CONTEXT`] and `KEY_BIND_MSG`, and
/// it is the one that most needed to be separate. A break-glass grant is the
/// one artefact in this product whose whole effect is to stop enforcement; if
/// it shared a domain with the policy bundle, the operator who can publish a
/// bundle could have one of their signatures replayed as a grant, and the
/// journal would record a suspension nobody issued. Signing keys are held by
/// different people for exactly that reason, and the domain is what makes
/// "different people" mean something when one of them is compromised.
pub const BREAK_GLASS_CONTEXT: &[u8] = b"FERRUM-BREAK-GLASS-GRANT-v1";

/// SHA-256 of `raw`, lowercase hex, no algorithm prefix.
pub fn bundle_digest(raw: &[u8]) -> Digest {
    Digest::new(hex_encode(Sha256::digest(raw).as_slice()))
}

/// Derive the 32-byte Ed25519 public key from a 32-byte secret seed.
pub fn public_key_from_secret(secret_key: &[u8]) -> Result<Vec<u8>> {
    Ok(parse_keypair(secret_key)?.pk.to_vec())
}

/// Sign raw bundle bytes with a 32-byte Ed25519 seed. Returns a 64-byte signature.
///
/// The signed message is [`BUNDLE_SIGNATURE_CONTEXT`] concatenated with `raw`.
pub fn sign_bundle(raw: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let keypair = parse_keypair(secret_key)?;
    Ok(keypair.sk.sign(signed_message(raw), None).to_vec())
}

/// Verify Ed25519 over `BUNDLE_SIGNATURE_CONTEXT || raw` with a caller-supplied
/// 32-byte public key. Function arguments are unchanged: `(raw, sig, public_key)`.
///
/// Empty or truncated signatures fail with [`FerrumError::Integrity`]. There is
/// no unsigned fallback. On success, returns [`bundle_digest`] of `raw`.
pub fn verify_bundle_signature(raw: &[u8], sig: &[u8], public_key: &[u8]) -> Result<Digest> {
    let verifying_key = parse_public_key(public_key)?;
    let signature = parse_signature(sig)?;
    verifying_key
        .verify(signed_message(raw), &signature)
        .map_err(|_| FerrumError::Integrity("Ed25519 signature verification failed".into()))?;
    Ok(bundle_digest(raw))
}

/// Compare SHA-256(`raw`) to `expected`. Empty expected digest is a failure.
pub fn verify_bundle_digest(raw: &[u8], expected: &Digest) -> Result<()> {
    if expected.as_str().is_empty() {
        return Err(FerrumError::Integrity(
            "expected bundle digest is empty".into(),
        ));
    }
    let actual = bundle_digest(raw);
    if actual.as_str() != expected.as_str() {
        return Err(FerrumError::Integrity(format!(
            "bundle digest mismatch: expected {}, got {}",
            expected.as_str(),
            actual.as_str()
        )));
    }
    Ok(())
}

/// Sign break-glass grant bytes with a 32-byte Ed25519 seed.
///
/// Present so the gate and `ferrumctl` can produce a grant the verifier
/// accepts; nothing on the request path signs anything.
pub fn sign_break_glass(raw: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let keypair = parse_keypair(secret_key)?;
    Ok(keypair
        .sk
        .sign(domain_message(BREAK_GLASS_CONTEXT, raw), None)
        .to_vec())
}

/// Verify Ed25519 over `BREAK_GLASS_CONTEXT || raw` with a caller-supplied
/// 32-byte public key.
///
/// No unsigned fallback and no shared domain: a signature made over the bundle
/// domain fails here, and one made here fails [`verify_bundle_signature`].
pub fn verify_break_glass_signature(raw: &[u8], sig: &[u8], public_key: &[u8]) -> Result<()> {
    let verifying_key = parse_public_key(public_key)?;
    let signature = parse_signature(sig)?;
    verifying_key
        .verify(domain_message(BREAK_GLASS_CONTEXT, raw), &signature)
        .map_err(|_| {
            FerrumError::Integrity("break-glass Ed25519 signature verification failed".into())
        })
}

fn domain_message(context: &[u8], raw: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(context.len() + raw.len());
    msg.extend_from_slice(context);
    msg.extend_from_slice(raw);
    msg
}

fn signed_message(raw: &[u8]) -> Vec<u8> {
    domain_message(BUNDLE_SIGNATURE_CONTEXT, raw)
}

pub(crate) fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, b| acc | b) == 0
}

fn parse_keypair(secret_key: &[u8]) -> Result<KeyPair> {
    if secret_key.len() != ED25519_SECRET_KEY_LEN {
        return Err(FerrumError::Integrity(format!(
            "Ed25519 secret key must be {} bytes, got {}",
            ED25519_SECRET_KEY_LEN,
            secret_key.len()
        )));
    }
    if is_all_zero(secret_key) {
        return Err(FerrumError::Integrity(
            "Ed25519 secret seed must not be all zeros".into(),
        ));
    }
    let seed = Seed::from_slice(secret_key)
        .map_err(|_| FerrumError::Integrity("invalid Ed25519 secret seed".into()))?;
    Ok(KeyPair::from_seed(seed))
}

fn parse_public_key(public_key: &[u8]) -> Result<PublicKey> {
    if public_key.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(FerrumError::Integrity(format!(
            "Ed25519 public key must be {} bytes, got {}",
            ED25519_PUBLIC_KEY_LEN,
            public_key.len()
        )));
    }
    if is_all_zero(public_key) {
        return Err(FerrumError::Integrity(
            "Ed25519 public key must not be all zeros".into(),
        ));
    }
    PublicKey::from_slice(public_key)
        .map_err(|_| FerrumError::Integrity("invalid Ed25519 public key".into()))
}

fn parse_signature(sig: &[u8]) -> Result<Signature> {
    if sig.is_empty() {
        return Err(FerrumError::Integrity(
            "bundle signature is empty; unsigned bundles are rejected".into(),
        ));
    }
    if sig.len() != ED25519_SIGNATURE_LEN {
        return Err(FerrumError::Integrity(format!(
            "Ed25519 signature must be {} bytes, got {}",
            ED25519_SIGNATURE_LEN,
            sig.len()
        )));
    }
    Signature::from_slice(sig)
        .map_err(|_| FerrumError::Integrity("invalid Ed25519 signature encoding".into()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &[u8] = b"ferrum-policy-bundle";
    const RAW_SHA256: &str = "8253ce6ea4260821d86f49a49487bd5f032c763a9d63499d8dea0a3f7e3fabd2";

    /// RFC 8032 §7.1 test 1 secret seed.
    const RFC8032_SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    /// RFC 8032 §7.1 test 1 public key.
    const RFC8032_PK: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    /// RFC 8032 §7.1 test 2 secret seed (wrong key for test 1).
    const RFC8032_SK2: [u8; 32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ];
    /// Ed25519 over `BUNDLE_SIGNATURE_CONTEXT || RAW` with RFC 8032 test-1 seed.
    const DOMAIN_SEPARATED_RAW_SIG: [u8; 64] = [
        0x47, 0xdb, 0x26, 0xe7, 0x9c, 0xcf, 0x93, 0x3f, 0x5f, 0x2b, 0xad, 0x95, 0x55, 0xee, 0xde,
        0x4d, 0xdb, 0x16, 0x83, 0xa3, 0x22, 0x97, 0xa5, 0x59, 0x46, 0x62, 0x1a, 0xf8, 0x81, 0x23,
        0xe7, 0x35, 0x6e, 0x5c, 0xa9, 0x22, 0x10, 0x5e, 0x58, 0xce, 0x3e, 0x67, 0x65, 0x49, 0x00,
        0xeb, 0x7c, 0x8f, 0x43, 0x13, 0xbb, 0xc8, 0xcf, 0x80, 0xe4, 0x2a, 0x87, 0xd6, 0xf3, 0x0b,
        0xb8, 0x90, 0x31, 0x09,
    ];

    fn assert_integrity<T: std::fmt::Debug>(result: Result<T>) {
        match result {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected FerrumError::Integrity, got {:?}", other),
        }
    }

    #[test]
    fn valid_signature_returns_sha256_digest() {
        let pk = public_key_from_secret(&RFC8032_SK).expect("public key");
        assert_eq!(pk.as_slice(), RFC8032_PK.as_slice());

        let sig = sign_bundle(RAW, &RFC8032_SK).expect("sign");
        let digest = verify_bundle_signature(RAW, &sig, &pk).expect("verify");
        assert_eq!(digest.as_str(), RAW_SHA256);
        assert_eq!(digest, bundle_digest(RAW));
    }

    #[test]
    fn truncated_payload_fails() {
        let sig = sign_bundle(RAW, &RFC8032_SK).expect("sign");
        let truncated = &RAW[..RAW.len() - 1];
        assert_integrity(verify_bundle_signature(truncated, &sig, &RFC8032_PK));
    }

    #[test]
    fn truncated_signature_fails() {
        let sig = sign_bundle(RAW, &RFC8032_SK).expect("sign");
        assert_integrity(verify_bundle_signature(
            RAW,
            &sig[..ED25519_SIGNATURE_LEN - 1],
            &RFC8032_PK,
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let sig = sign_bundle(RAW, &RFC8032_SK).expect("sign");
        let wrong_pk = public_key_from_secret(&RFC8032_SK2).expect("wrong public key");
        assert_integrity(verify_bundle_signature(RAW, &sig, &wrong_pk));
    }

    #[test]
    fn empty_signature_fails() {
        assert_integrity(verify_bundle_signature(RAW, &[], &RFC8032_PK));
    }

    #[test]
    fn mutated_payload_fails() {
        let sig = sign_bundle(RAW, &RFC8032_SK).expect("sign");
        let mut mutated = RAW.to_vec();
        mutated[0] ^= 0x01;
        assert_integrity(verify_bundle_signature(&mutated, &sig, &RFC8032_PK));
    }

    #[test]
    fn digest_mismatch_fails() {
        let expected = Digest::new("00".repeat(32));
        assert_integrity(verify_bundle_digest(RAW, &expected));
    }

    #[test]
    fn digest_match_succeeds() {
        let expected = Digest::new(RAW_SHA256);
        verify_bundle_digest(RAW, &expected).expect("matching digest");
    }

    #[test]
    fn empty_expected_digest_fails() {
        assert_integrity(verify_bundle_digest(RAW, &Digest::new("")));
    }

    #[test]
    fn all_zero_seed_sign_fails() {
        assert_integrity(sign_bundle(RAW, &[0u8; ED25519_SECRET_KEY_LEN]));
    }

    #[test]
    fn all_zero_seed_public_key_fails() {
        assert_integrity(public_key_from_secret(&[0u8; ED25519_SECRET_KEY_LEN]));
    }

    #[test]
    fn all_zero_public_key_verify_fails() {
        let sig = sign_bundle(RAW, &RFC8032_SK).expect("sign");
        assert_integrity(verify_bundle_signature(
            RAW,
            &sig,
            &[0u8; ED25519_PUBLIC_KEY_LEN],
        ));
    }

    #[test]
    fn domain_separated_round_trip() {
        let sig = sign_bundle(RAW, &RFC8032_SK).expect("sign");
        verify_bundle_signature(RAW, &sig, &RFC8032_PK).expect("domain-separated verify");
        let unsigned = RFC8032_PK;
        let kp = KeyPair::from_seed(Seed::from_slice(&RFC8032_SK).expect("seed"));
        let raw_ed25519 = kp.sk.sign(RAW, None).to_vec();
        assert_ne!(sig, raw_ed25519);
        assert_integrity(verify_bundle_signature(RAW, &raw_ed25519, &unsigned));
    }

    /// The bundle domain and the break-glass domain are not interchangeable in
    /// either direction.
    ///
    /// This is the same invariant `AGENTS.md` states for
    /// `BUNDLE_SIGNATURE_CONTEXT` and `KEY_BIND_MSG`, extended to the third
    /// domain — and it is the one with the sharpest consequence. A grant
    /// suspends enforcement. If the two shared a domain, anybody holding a
    /// signature the policy publisher made over some bundle could replay it as
    /// a grant over the same bytes, and the break-glass journal would record a
    /// suspension that its named subject never issued: the repudiation the
    /// journal exists to prevent, arrived at through the signature rather than
    /// through the log.
    #[test]
    fn a_bundle_signature_is_not_a_break_glass_grant_and_the_reverse() {
        let bundle_sig = sign_bundle(RAW, &RFC8032_SK).expect("sign bundle");
        let grant_sig = sign_break_glass(RAW, &RFC8032_SK).expect("sign grant");
        assert_ne!(
            bundle_sig, grant_sig,
            "the two domains produced the same signature over the same bytes"
        );

        verify_break_glass_signature(RAW, &grant_sig, &RFC8032_PK).expect("its own domain");
        assert_integrity(
            verify_break_glass_signature(RAW, &bundle_sig, &RFC8032_PK).map(|()| Digest::new("")),
        );
        assert_integrity(verify_bundle_signature(RAW, &grant_sig, &RFC8032_PK));

        // And no unsigned fallback on the new domain either.
        assert_integrity(
            verify_break_glass_signature(RAW, &[], &RFC8032_PK).map(|()| Digest::new("")),
        );
        assert_integrity(
            verify_break_glass_signature(RAW, &grant_sig, &[0u8; ED25519_PUBLIC_KEY_LEN])
                .map(|()| Digest::new("")),
        );
    }

    #[test]
    fn domain_separated_known_vector() {
        let sig = sign_bundle(RAW, &RFC8032_SK).expect("sign");
        assert_eq!(sig.as_slice(), DOMAIN_SEPARATED_RAW_SIG.as_slice());
        let digest = verify_bundle_signature(RAW, &DOMAIN_SEPARATED_RAW_SIG, &RFC8032_PK)
            .expect("known vector");
        assert_eq!(digest.as_str(), RAW_SHA256);
    }
}
