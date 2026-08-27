//! PEM mTLS material. Separate from [`crate::BUNDLE_SIGNATURE_CONTEXT`] Ed25519.

use std::fmt;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use ferrum_common::{FerrumError, Result};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING, RSA_PKCS1_SHA256,
};
use rustls_pki_types::{
    CertificateDer, DnsName, ServerName, SignatureVerificationAlgorithm, UnixTime,
};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};

use crate::is_all_zero;

/// Domain separator for binding a PKCS#8/SEC1/PKCS#1 key to the leaf SPKI.
/// Not [`crate::BUNDLE_SIGNATURE_CONTEXT`].
const KEY_BIND_MSG: &[u8] = b"FERRUM-MTLS-KEY-BIND-v1";

static SUPPORTED_SIG_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::ED25519,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
    webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];

/// DER-encoded chain, private key, and caller-supplied CA roots.
///
/// `certs[0]` is the leaf; `certs[1..]` are intermediates. `ca` are trust
/// anchors that travel with the material — they do not live only in the
/// control plane.
#[derive(Clone, PartialEq, Eq)]
pub struct MtlsMaterial {
    pub certs: Vec<Vec<u8>>,
    pub key: Vec<u8>,
    pub ca: Vec<Vec<u8>>,
}

impl fmt::Debug for MtlsMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MtlsMaterial")
            .field("certs", &self.certs.len())
            .field("key_len", &self.key.len())
            .field("ca", &self.ca.len())
            .finish()
    }
}

/// Expected extended key usage when verifying a peer or local material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    Client,
    Server,
}

/// Parse PEM certificate, key, and CA into DER. Does not check expiry or chain.
pub fn load_mtls_pem(cert_pem: &[u8], key_pem: &[u8], ca_pem: &[u8]) -> Result<MtlsMaterial> {
    let certs = parse_pem_certs(
        cert_pem,
        "mTLS certificate PEM is empty",
        "certificate PEM contains no certificates",
    )?;
    let key = parse_pem_key(key_pem)?;
    let ca = parse_pem_certs(
        ca_pem,
        "mTLS CA PEM is empty",
        "CA PEM contains no certificates",
    )?;
    Ok(MtlsMaterial { certs, key, ca })
}

/// Verify local material: non-empty inputs, key bound to leaf, chain, EKU, SAN.
pub fn verify_mtls_material(
    material: &MtlsMaterial,
    now: SystemTime,
    role: PeerRole,
    dns_name: Option<&str>,
) -> Result<()> {
    if material.certs.is_empty() {
        return Err(integrity("mTLS certificate chain is empty"));
    }
    if material.key.is_empty() || is_all_zero(&material.key) {
        return Err(integrity(
            "mTLS private key is empty or all zeros; unsigned TLS is rejected",
        ));
    }
    if material.ca.is_empty() {
        return Err(integrity("mTLS CA list is empty"));
    }
    verify_key_matches_leaf(&material.certs[0], &material.key)?;
    verify_mtls_peer(
        &material.certs[0],
        &material.certs[1..],
        &material.ca,
        now,
        role,
        dns_name,
    )
}

/// Verify a presented leaf against caller-supplied CAs. No private key.
pub fn verify_mtls_peer(
    leaf_der: &[u8],
    intermediates: &[Vec<u8>],
    ca_ders: &[Vec<u8>],
    now: SystemTime,
    role: PeerRole,
    dns_name: Option<&str>,
) -> Result<()> {
    if leaf_der.is_empty() {
        return Err(integrity("mTLS leaf certificate is empty"));
    }
    if ca_ders.is_empty() {
        return Err(integrity("mTLS CA list is empty"));
    }

    let leaf = CertificateDer::from(leaf_der);
    let ee = EndEntityCert::try_from(&leaf)
        .map_err(|e| integrity(format!("invalid mTLS leaf certificate: {e}")))?;

    let mut ca_certs = Vec::with_capacity(ca_ders.len());
    for der in ca_ders {
        if der.is_empty() {
            return Err(integrity("mTLS CA certificate is empty"));
        }
        ca_certs.push(CertificateDer::from(der.as_slice()));
    }
    let mut anchors = Vec::with_capacity(ca_certs.len());
    for cert in &ca_certs {
        let ta = anchor_from_trusted_cert(cert)
            .map_err(|e| integrity(format!("invalid mTLS CA certificate: {e}")))?;
        anchors.push(ta);
    }

    let inter: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let usage = match role {
        PeerRole::Server => KeyUsage::server_auth(),
        PeerRole::Client => KeyUsage::client_auth(),
    };
    ee.verify_for_usage(
        SUPPORTED_SIG_ALGS,
        &anchors,
        &inter,
        unix_time(now)?,
        usage,
        None,
        None,
    )
    .map_err(|e| integrity(format!("mTLS certificate verification failed: {e}")))?;

    if let Some(name) = dns_name {
        let dns = DnsName::try_from(name)
            .map_err(|_| integrity(format!("invalid DNS name for mTLS SAN check: {name}")))?;
        ee.verify_is_valid_for_subject_name(&ServerName::DnsName(dns))
            .map_err(|e| integrity(format!("mTLS SAN mismatch: {e}")))?;
    }
    Ok(())
}

fn verify_key_matches_leaf(leaf_der: &[u8], key_der: &[u8]) -> Result<()> {
    let leaf = CertificateDer::from(leaf_der);
    let cert = EndEntityCert::try_from(&leaf)
        .map_err(|e| integrity(format!("invalid mTLS leaf certificate: {e}")))?;
    let rng = SystemRandom::new();

    if let Ok(kp) = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key_der, &rng) {
        return ecdsa_bind(&cert, &kp, &rng, webpki::ring::ECDSA_P256_SHA256);
    }
    if let Ok(kp) = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, key_der, &rng) {
        return ecdsa_bind(&cert, &kp, &rng, webpki::ring::ECDSA_P384_SHA384);
    }
    if let Ok(kp) = Ed25519KeyPair::from_pkcs8(key_der) {
        let _ = kp.public_key();
        let sig = kp.sign(KEY_BIND_MSG);
        return cert
            .verify_signature(webpki::ring::ED25519, KEY_BIND_MSG, sig.as_ref())
            .map_err(|_| integrity("mTLS private key does not match leaf certificate"));
    }
    if let Ok(kp) = RsaKeyPair::from_pkcs8(key_der) {
        return rsa_bind(&cert, &kp, &rng);
    }
    if let Ok(kp) = RsaKeyPair::from_der(key_der) {
        return rsa_bind(&cert, &kp, &rng);
    }

    Err(integrity("unsupported or invalid mTLS private key"))
}

fn ecdsa_bind(
    cert: &EndEntityCert<'_>,
    kp: &EcdsaKeyPair,
    rng: &SystemRandom,
    alg: &'static dyn SignatureVerificationAlgorithm,
) -> Result<()> {
    let _ = kp.public_key();
    let sig = kp
        .sign(rng, KEY_BIND_MSG)
        .map_err(|_| integrity("failed to sign with mTLS ECDSA key"))?;
    cert.verify_signature(alg, KEY_BIND_MSG, sig.as_ref())
        .map_err(|_| integrity("mTLS private key does not match leaf certificate"))
}

fn rsa_bind(cert: &EndEntityCert<'_>, kp: &RsaKeyPair, rng: &dyn SecureRandom) -> Result<()> {
    let mut sig = vec![0u8; kp.public().modulus_len()];
    kp.sign(&RSA_PKCS1_SHA256, rng, KEY_BIND_MSG, &mut sig)
        .map_err(|_| integrity("failed to sign with mTLS RSA key"))?;
    cert.verify_signature(webpki::ring::RSA_PKCS1_2048_8192_SHA256, KEY_BIND_MSG, &sig)
        .map_err(|_| integrity("mTLS private key does not match leaf certificate"))
}

fn parse_pem_certs(pem: &[u8], empty: &str, missing: &str) -> Result<Vec<Vec<u8>>> {
    if pem.is_empty() {
        return Err(integrity(empty));
    }
    let mut reader = Cursor::new(pem);
    let mut certs = Vec::new();
    for item in rustls_pemfile::certs(&mut reader) {
        let der =
            item.map_err(|e| integrity(format!("truncated or invalid certificate PEM: {e}")))?;
        certs.push(der.to_vec());
    }
    if certs.is_empty() {
        return Err(integrity(missing));
    }
    Ok(certs)
}

fn parse_pem_key(pem: &[u8]) -> Result<Vec<u8>> {
    if pem.is_empty() {
        return Err(integrity("mTLS private key PEM is empty"));
    }
    let mut reader = Cursor::new(pem);
    let mut keys = Vec::new();
    for item in rustls_pemfile::read_all(&mut reader) {
        let item =
            item.map_err(|e| integrity(format!("truncated or invalid private key PEM: {e}")))?;
        match item {
            rustls_pemfile::Item::Pkcs8Key(der) => keys.push(der.secret_pkcs8_der().to_vec()),
            rustls_pemfile::Item::Pkcs1Key(der) => keys.push(der.secret_pkcs1_der().to_vec()),
            rustls_pemfile::Item::Sec1Key(der) => keys.push(der.secret_sec1_der().to_vec()),
            _ => {}
        }
    }
    if keys.is_empty() {
        return Err(integrity("private key PEM contains no private key"));
    }
    if keys.len() != 1 {
        return Err(integrity(
            "private key PEM must contain exactly one private key",
        ));
    }
    let key = keys.remove(0);
    if key.is_empty() || is_all_zero(&key) {
        return Err(integrity("mTLS private key must not be empty or all zeros"));
    }
    Ok(key)
}

fn unix_time(now: SystemTime) -> Result<UnixTime> {
    let since_epoch = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| integrity("mTLS verification time is before unix epoch"))?;
    Ok(UnixTime::since_unix_epoch(since_epoch))
}

fn integrity(msg: impl Into<String>) -> FerrumError {
    FerrumError::Integrity(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{public_key_from_secret, sign_bundle, verify_bundle_signature};
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair as RcgenKeyPair, KeyUsagePurpose,
    };

    const DNS: &str = "agent.ferrum.test";

    fn assert_integrity<T: std::fmt::Debug>(result: Result<T>) {
        match result {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected FerrumError::Integrity, got {:?}", other),
        }
    }

    struct TestCa {
        cert: Certificate,
        key: RcgenKeyPair,
    }

    impl TestCa {
        fn pem(&self) -> String {
            self.cert.pem()
        }
    }

    fn test_ca(cn: &str) -> TestCa {
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = RcgenKeyPair::generate().expect("ca key");
        let cert = params.self_signed(&key).expect("ca");
        TestCa { cert, key }
    }

    struct Issued {
        cert_pem: String,
        key_pem: String,
        ca_pem: String,
    }

    fn issue(
        ca: &TestCa,
        dns: &str,
        eku: Vec<ExtendedKeyUsagePurpose>,
        tweak: impl FnOnce(&mut CertificateParams),
    ) -> Issued {
        let mut params = CertificateParams::new(vec![dns.to_string()]).expect("leaf params");
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, dns);
        params.extended_key_usages = eku;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        tweak(&mut params);
        let key = RcgenKeyPair::generate().expect("leaf key");
        let cert = params
            .signed_by(&key, &ca.cert, &ca.key)
            .expect("sign leaf");
        Issued {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            ca_pem: ca.pem(),
        }
    }

    fn dual_eku() -> Vec<ExtendedKeyUsagePurpose> {
        vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ]
    }

    fn load_issued(issued: &Issued) -> MtlsMaterial {
        load_mtls_pem(
            issued.cert_pem.as_bytes(),
            issued.key_pem.as_bytes(),
            issued.ca_pem.as_bytes(),
        )
        .expect("load pem")
    }

    #[test]
    fn valid_chain_matching_key_ok() {
        let ca = test_ca("ferrum-test-ca");
        let issued = issue(&ca, DNS, dual_eku(), |_| {});
        let material = load_issued(&issued);
        let now = SystemTime::now();
        verify_mtls_material(&material, now, PeerRole::Server, Some(DNS)).expect("server");
        verify_mtls_material(&material, now, PeerRole::Client, Some(DNS)).expect("client");
        verify_mtls_peer(
            &material.certs[0],
            &material.certs[1..],
            &material.ca,
            now,
            PeerRole::Server,
            None,
        )
        .expect("peer without SAN");
    }

    #[test]
    fn empty_cert_key_ca_are_integrity() {
        let ca = test_ca("ferrum-test-ca");
        let issued = issue(&ca, DNS, dual_eku(), |_| {});
        assert_integrity(load_mtls_pem(
            b"",
            issued.key_pem.as_bytes(),
            issued.ca_pem.as_bytes(),
        ));
        assert_integrity(load_mtls_pem(
            issued.cert_pem.as_bytes(),
            b"",
            issued.ca_pem.as_bytes(),
        ));
        assert_integrity(load_mtls_pem(
            issued.cert_pem.as_bytes(),
            issued.key_pem.as_bytes(),
            b"",
        ));

        let mut material = load_issued(&issued);
        material.certs.clear();
        assert_integrity(verify_mtls_material(
            &material,
            SystemTime::now(),
            PeerRole::Server,
            None,
        ));
        let mut material = load_issued(&issued);
        material.key.clear();
        assert_integrity(verify_mtls_material(
            &material,
            SystemTime::now(),
            PeerRole::Server,
            None,
        ));
        let mut material = load_issued(&issued);
        material.ca.clear();
        assert_integrity(verify_mtls_material(
            &material,
            SystemTime::now(),
            PeerRole::Server,
            None,
        ));
    }

    #[test]
    fn all_zero_key_is_integrity() {
        let ca = test_ca("ferrum-test-ca");
        let issued = issue(&ca, DNS, dual_eku(), |_| {});
        let zeros_pem = "-----BEGIN PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----\n";
        assert_integrity(load_mtls_pem(
            issued.cert_pem.as_bytes(),
            zeros_pem.as_bytes(),
            issued.ca_pem.as_bytes(),
        ));

        let mut material = load_issued(&issued);
        material.key = vec![0u8; 32];
        assert_integrity(verify_mtls_material(
            &material,
            SystemTime::now(),
            PeerRole::Server,
            Some(DNS),
        ));
    }

    #[test]
    fn expired_and_not_yet_valid_leaf_are_integrity() {
        let ca = test_ca("ferrum-test-ca");
        let expired = issue(&ca, DNS, dual_eku(), |p| {
            p.not_before = rcgen::date_time_ymd(2019, 1, 1);
            p.not_after = rcgen::date_time_ymd(2020, 1, 1);
        });
        let material = load_issued(&expired);
        assert_integrity(verify_mtls_material(
            &material,
            SystemTime::now(),
            PeerRole::Server,
            Some(DNS),
        ));

        let nyv = issue(&ca, DNS, dual_eku(), |p| {
            p.not_before = rcgen::date_time_ymd(2090, 1, 1);
            p.not_after = rcgen::date_time_ymd(2091, 1, 1);
        });
        let material = load_issued(&nyv);
        assert_integrity(verify_mtls_material(
            &material,
            SystemTime::now(),
            PeerRole::Server,
            Some(DNS),
        ));
    }

    #[test]
    fn wrong_ca_is_integrity() {
        let ca = test_ca("ferrum-test-ca");
        let other = test_ca("ferrum-other-ca");
        let issued = issue(&ca, DNS, dual_eku(), |_| {});
        let mut material = load_issued(&issued);
        material.ca = load_mtls_pem(
            issued.cert_pem.as_bytes(),
            issued.key_pem.as_bytes(),
            other.pem().as_bytes(),
        )
        .expect("load")
        .ca;
        assert_integrity(verify_mtls_material(
            &material,
            SystemTime::now(),
            PeerRole::Server,
            Some(DNS),
        ));
    }

    #[test]
    fn san_mismatch_is_integrity() {
        let ca = test_ca("ferrum-test-ca");
        let issued = issue(&ca, DNS, dual_eku(), |_| {});
        let material = load_issued(&issued);
        assert_integrity(verify_mtls_material(
            &material,
            SystemTime::now(),
            PeerRole::Server,
            Some("other.example"),
        ));
    }

    #[test]
    fn truncated_pem_is_integrity() {
        let ca = test_ca("ferrum-test-ca");
        let issued = issue(&ca, DNS, dual_eku(), |_| {});
        let cut = issued.cert_pem.find("-----END").expect("end marker");
        assert_integrity(load_mtls_pem(
            &issued.cert_pem.as_bytes()[..cut],
            issued.key_pem.as_bytes(),
            issued.ca_pem.as_bytes(),
        ));
        let key_cut = issued.key_pem.find("-----END").expect("key end marker");
        assert_integrity(load_mtls_pem(
            issued.cert_pem.as_bytes(),
            &issued.key_pem.as_bytes()[..key_cut],
            issued.ca_pem.as_bytes(),
        ));
    }

    #[test]
    fn client_cert_as_server_is_integrity() {
        let ca = test_ca("ferrum-test-ca");
        let client = issue(&ca, DNS, vec![ExtendedKeyUsagePurpose::ClientAuth], |_| {});
        let material = load_issued(&client);
        verify_mtls_material(&material, SystemTime::now(), PeerRole::Client, Some(DNS))
            .expect("client role");
        assert_integrity(verify_mtls_material(
            &material,
            SystemTime::now(),
            PeerRole::Server,
            Some(DNS),
        ));

        let server = issue(&ca, DNS, vec![ExtendedKeyUsagePurpose::ServerAuth], |_| {});
        let material = load_issued(&server);
        verify_mtls_material(&material, SystemTime::now(), PeerRole::Server, Some(DNS))
            .expect("server role");
        assert_integrity(verify_mtls_material(
            &material,
            SystemTime::now(),
            PeerRole::Client,
            Some(DNS),
        ));
    }

    #[test]
    fn verify_bundle_signature_independent_of_tls() {
        let ca = test_ca("ferrum-test-ca");
        let issued = issue(&ca, DNS, dual_eku(), |_| {});
        let material = load_issued(&issued);
        verify_mtls_material(&material, SystemTime::now(), PeerRole::Server, Some(DNS))
            .expect("tls");

        let mut seed = [0u8; 32];
        seed[0] = 0x5a;
        let pk = public_key_from_secret(&seed).expect("bundle pk");
        let raw = b"ferrum-policy-bundle";
        let sig = sign_bundle(raw, &seed).expect("bundle sign");
        verify_bundle_signature(raw, &sig, &pk).expect("bundle verify");

        assert_integrity(sign_bundle(raw, &material.key));
        assert_integrity(verify_bundle_signature(raw, &material.key, &pk));
        assert_integrity(verify_mtls_peer(
            &pk,
            &[],
            &material.ca,
            SystemTime::now(),
            PeerRole::Server,
            None,
        ));
    }
}
