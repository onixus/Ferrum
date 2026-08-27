//! Offline PKI for the admission webhook: a self-signed CA and one serving
//! certificate whose SAN covers the four names the API server may use to reach
//! a Service.
//!
//! ECDSA P-256, not Ed25519: Ed25519 serving certificates are still refused by
//! parts of the field, and the webhook is the one component that cannot afford
//! a TLS handshake that works on some clusters and not others.
//!
//! No function here returns `Ok` without checking what it claims:
//! [`verify_chain`] verifies the signature with the CA's own key, and issuance
//! runs it before handing the material back.

use ferrum_common::{FerrumError, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
    PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest as _, Sha256};
use std::time::{Duration, SystemTime};
use x509_parser::prelude::*;

/// CA/Browser Forum ballot SC-22: a serving certificate may not be valid for
/// more than 398 days. Kubernetes does not enforce it; a webhook certificate
/// that outlives the rule is a certificate nobody rotates.
pub const MAX_SERVING_CERT_DAYS: u64 = 398;

const DAY_SECS: u64 = 86_400;

/// Self-signed issuer. `key_pem` is a PKCS#8 private key and is never written
/// anywhere by this module.
#[derive(Clone, Debug)]
pub struct CaMaterial {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Serving certificate for one Service. `dns_names` is the SAN this material
/// claims; [`verify_chain`] rejects material whose certificate says otherwise.
#[derive(Clone, Debug)]
pub struct ServingMaterial {
    pub cert_pem: String,
    pub key_pem: String,
    pub dns_names: Vec<String>,
}

/// The four names an API server may use to reach `service.namespace`.
pub fn service_dns_names(service: &str, namespace: &str) -> Vec<String> {
    vec![
        service.to_string(),
        format!("{service}.{namespace}"),
        format!("{service}.{namespace}.svc"),
        format!("{service}.{namespace}.svc.cluster.local"),
    ]
}

/// Issue a self-signed CA valid until `not_after`.
pub fn issue_ca(common_name: &str, not_after: SystemTime) -> Result<CaMaterial> {
    if common_name.trim().is_empty() {
        return Err(FerrumError::Validation("CA common name is empty".into()));
    }
    check_lifetime(not_after)?;

    let mut params = CertificateParams::default();
    params.alg = &PKCS_ECDSA_P256_SHA256;
    params.not_before = SystemTime::now().into();
    params.not_after = not_after.into();
    params.serial_number = Some(serial_for(common_name.as_bytes()));
    params.distinguished_name = ferrum_dn(common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let cert = Certificate::from_params(params)
        .map_err(|e| FerrumError::Integrity(format!("CA generation failed: {e}")))?;
    let material = CaMaterial {
        cert_pem: cert
            .serialize_pem()
            .map_err(|e| FerrumError::Integrity(format!("CA encoding failed: {e}")))?,
        key_pem: cert.serialize_private_key_pem(),
    };
    let der = single(pem_certificates(&material.cert_pem)?, "CA")?;
    let (_, parsed) = X509Certificate::from_der(&der)
        .map_err(|e| FerrumError::Integrity(format!("CA is not a valid certificate: {e}")))?;
    if !parsed.is_ca() {
        return Err(FerrumError::Integrity(
            "generated CA lacks basicConstraints CA:TRUE".into(),
        ));
    }
    Ok(material)
}

/// Issue a serving certificate for `service.namespace`, signed by `ca`.
pub fn issue_serving_cert(
    ca: &CaMaterial,
    service: &str,
    namespace: &str,
    not_after: SystemTime,
) -> Result<ServingMaterial> {
    if service.trim().is_empty() || namespace.trim().is_empty() {
        return Err(FerrumError::Validation(
            "serving certificate needs a non-empty service and namespace".into(),
        ));
    }
    let dns_names = service_dns_names(service, namespace);
    if dns_names.iter().any(|n| n.trim().is_empty()) {
        return Err(FerrumError::Validation(
            "serving certificate would carry an empty SAN entry".into(),
        ));
    }
    check_lifetime(not_after)?;

    let issuer = load_ca(ca)?;

    let mut params = CertificateParams::default();
    params.alg = &PKCS_ECDSA_P256_SHA256;
    params.not_before = SystemTime::now().into();
    params.not_after = not_after.into();
    params.serial_number = Some(serial_for(dns_names.join(",").as_bytes()));
    params.distinguished_name = ferrum_dn(&dns_names[2]);
    params.is_ca = IsCa::ExplicitNoCa;
    params.subject_alt_names = dns_names
        .iter()
        .map(|n| SanType::DnsName(n.clone()))
        .collect();
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let cert = Certificate::from_params(params)
        .map_err(|e| FerrumError::Integrity(format!("serving cert generation failed: {e}")))?;
    let cert_pem = cert
        .serialize_pem_with_signer(&issuer)
        .map_err(|e| FerrumError::Integrity(format!("serving cert signing failed: {e}")))?;

    let material = ServingMaterial {
        cert_pem,
        key_pem: cert.serialize_private_key_pem(),
        dns_names,
    };
    // Material that cannot be verified is not issued material.
    verify_chain(&material, ca)?;
    Ok(material)
}

/// Check `serving` against `ca`: signed by that CA's key, issued by that CA's
/// subject, CA:TRUE on the issuer and not on the leaf, and a DNS SAN that is
/// exactly what `serving` claims to carry.
pub fn verify_chain(serving: &ServingMaterial, ca: &CaMaterial) -> Result<()> {
    let ca_der = single(pem_certificates(&ca.cert_pem)?, "CA")?;
    let leaf_der = single(pem_certificates(&serving.cert_pem)?, "serving certificate")?;

    let (_, ca_cert) = X509Certificate::from_der(&ca_der)
        .map_err(|e| FerrumError::Integrity(format!("CA is not a valid certificate: {e}")))?;
    let (_, leaf) = X509Certificate::from_der(&leaf_der).map_err(|e| {
        FerrumError::Integrity(format!(
            "serving certificate is not a valid certificate: {e}"
        ))
    })?;

    if !ca_cert.is_ca() {
        return Err(FerrumError::Integrity(
            "issuer certificate has no basicConstraints CA:TRUE".into(),
        ));
    }
    if leaf.is_ca() {
        return Err(FerrumError::Integrity(
            "serving certificate carries basicConstraints CA:TRUE".into(),
        ));
    }
    if leaf.issuer() != ca_cert.subject() {
        return Err(FerrumError::Integrity(format!(
            "serving certificate issuer '{}' is not the CA subject '{}'",
            leaf.issuer(),
            ca_cert.subject()
        )));
    }

    let san = dns_san(&leaf)?;
    if san.is_empty() {
        return Err(FerrumError::Integrity(
            "serving certificate has an empty DNS SAN".into(),
        ));
    }
    if san != serving.dns_names {
        return Err(FerrumError::Integrity(format!(
            "serving certificate SAN {san:?} is not the material's {:?}",
            serving.dns_names
        )));
    }

    leaf.verify_signature(Some(ca_cert.public_key()))
        .map_err(|e| {
            FerrumError::Integrity(format!("serving certificate is not signed by this CA: {e}"))
        })
}

/// True when the certificate's notAfter has passed or falls inside `within`.
pub fn expires_within(cert_pem: &str, within: Duration) -> Result<bool> {
    let der = single(pem_certificates(cert_pem)?, "certificate")?;
    let (_, cert) = X509Certificate::from_der(&der)
        .map_err(|e| FerrumError::Integrity(format!("not a valid certificate: {e}")))?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| FerrumError::Integrity("system clock is before the epoch".into()))?
        .as_secs() as i64;
    Ok(cert.validity().not_after.timestamp() <= now.saturating_add(within.as_secs() as i64))
}

fn ferrum_dn(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        DnValue::Utf8String(common_name.to_string()),
    );
    dn.push(
        DnType::OrganizationName,
        DnValue::Utf8String("FERRUM".to_string()),
    );
    dn
}

/// 16-byte positive serial. Two certificates issued in the same second for
/// different names must not collide, so the name goes into the hash too.
fn serial_for(seed: &[u8]) -> SerialNumber {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = Sha256::new();
    h.update(seed);
    h.update(nanos.to_be_bytes());
    let mut bytes = h.finalize()[..16].to_vec();
    bytes[0] &= 0x7f;
    SerialNumber::from(bytes)
}

fn check_lifetime(not_after: SystemTime) -> Result<()> {
    let lifetime = not_after
        .duration_since(SystemTime::now())
        .map_err(|_| FerrumError::Validation("notAfter is in the past".into()))?;
    let days = lifetime.as_secs() / DAY_SECS;
    if days > MAX_SERVING_CERT_DAYS {
        return Err(FerrumError::Validation(format!(
            "requested lifetime of {days} days exceeds the {MAX_SERVING_CERT_DAYS}-day maximum"
        )));
    }
    Ok(())
}

/// rcgen 0.12 signs a child from the issuer's *params*, not from its DER, so
/// the issuer has to be rebuilt: its subject DN and its key are the only parts
/// that reach the child. Any mismatch is caught by the `verify_chain` call at
/// the end of issuance, which compares the emitted issuer against the CA.
fn load_ca(ca: &CaMaterial) -> Result<Certificate> {
    let key = KeyPair::from_pem(&ca.key_pem)
        .map_err(|e| FerrumError::Integrity(format!("CA key is unreadable: {e}")))?;
    let der = single(pem_certificates(&ca.cert_pem)?, "CA")?;
    let (_, parsed) = X509Certificate::from_der(&der)
        .map_err(|e| FerrumError::Integrity(format!("CA is not a valid certificate: {e}")))?;
    if !parsed.is_ca() {
        return Err(FerrumError::Integrity(
            "issuer certificate has no basicConstraints CA:TRUE".into(),
        ));
    }

    let mut params = CertificateParams::default();
    params.alg = &PKCS_ECDSA_P256_SHA256;
    params.key_pair = Some(key);
    params.distinguished_name = rebuild_dn(parsed.subject())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    Certificate::from_params(params)
        .map_err(|e| FerrumError::Integrity(format!("CA is unusable as an issuer: {e}")))
}

fn rebuild_dn(name: &X509Name<'_>) -> Result<DistinguishedName> {
    let mut dn = DistinguishedName::new();
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid: Vec<u64> = attr
                .attr_type()
                .iter()
                .ok_or_else(|| FerrumError::Integrity("unreadable DN attribute OID".into()))?
                .collect();
            let ty = match oid.as_slice() {
                [2, 5, 4, 3] => DnType::CommonName,
                [2, 5, 4, 6] => DnType::CountryName,
                [2, 5, 4, 7] => DnType::LocalityName,
                [2, 5, 4, 8] => DnType::StateOrProvinceName,
                [2, 5, 4, 10] => DnType::OrganizationName,
                [2, 5, 4, 11] => DnType::OrganizationalUnitName,
                other => DnType::CustomDnType(other.to_vec()),
            };
            let value = attr
                .as_str()
                .map_err(|e| FerrumError::Integrity(format!("unreadable DN attribute: {e}")))?;
            dn.push(ty, DnValue::Utf8String(value.to_string()));
        }
    }
    Ok(dn)
}

fn dns_san(cert: &X509Certificate<'_>) -> Result<Vec<String>> {
    let san = cert
        .subject_alternative_name()
        .map_err(|e| FerrumError::Integrity(format!("unreadable subjectAltName: {e}")))?;
    let Some(san) = san else {
        return Ok(Vec::new());
    };
    Ok(san
        .value
        .general_names
        .iter()
        .filter_map(|n| match n {
            GeneralName::DNSName(d) => Some((*d).to_string()),
            _ => None,
        })
        .collect())
}

/// PEM decode restricted to CERTIFICATE blocks. Anything else in the file is an
/// error and not skipped input: a caBundle that silently drops a block is a
/// caBundle nobody can debug.
pub fn pem_certificates(pem: &str) -> Result<Vec<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut body: Option<String> = None;
    for line in pem.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == BEGIN {
            if body.is_some() {
                return Err(FerrumError::Integrity(
                    "nested BEGIN CERTIFICATE in PEM".into(),
                ));
            }
            body = Some(String::new());
        } else if line == END {
            let Some(b64) = body.take() else {
                return Err(FerrumError::Integrity(
                    "END CERTIFICATE without BEGIN in PEM".into(),
                ));
            };
            let der = base64_decode(&b64)?;
            if der.is_empty() {
                return Err(FerrumError::Integrity("empty CERTIFICATE block".into()));
            }
            out.push(der);
        } else if let Some(b) = body.as_mut() {
            b.push_str(line);
        } else {
            return Err(FerrumError::Integrity(
                "PEM holds a block that is not a CERTIFICATE".into(),
            ));
        }
    }
    if body.is_some() {
        return Err(FerrumError::Integrity(
            "unterminated CERTIFICATE block in PEM".into(),
        ));
    }
    if out.is_empty() {
        return Err(FerrumError::Integrity(
            "PEM holds no CERTIFICATE block".into(),
        ));
    }
    Ok(out)
}

fn single(mut der: Vec<Vec<u8>>, what: &str) -> Result<Vec<u8>> {
    if der.len() != 1 {
        return Err(FerrumError::Integrity(format!(
            "{what} PEM holds {} certificates, expected exactly one",
            der.len()
        )));
    }
    Ok(der.remove(0))
}

/// Standard base64 with padding — the encoding `caBundle` and Secret data use.
pub fn base64_encode(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b1 = *chunk.first().unwrap_or(&0) as u32;
        let b2 = *chunk.get(1).unwrap_or(&0) as u32;
        let b3 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b1 << 16) | (b2 << 8) | b3;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Inverse of [`base64_encode`]. ASCII whitespace is skipped because YAML folds
/// long scalars; every other deviation is an error, including non-zero trailing
/// bits and data after padding.
pub fn base64_decode(data: &str) -> Result<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut pad = 0usize;
    let mut chars = 0usize;
    let mut out = Vec::new();
    for c in data.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        chars += 1;
        if c == '=' {
            pad += 1;
            if pad > 2 {
                return Err(FerrumError::Integrity("too much base64 padding".into()));
            }
            continue;
        }
        if pad > 0 {
            return Err(FerrumError::Integrity(
                "base64 padding is followed by more data".into(),
            ));
        }
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => {
                return Err(FerrumError::Integrity(format!(
                    "invalid base64 character {c:?}"
                )))
            }
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if chars % 4 != 0 {
        return Err(FerrumError::Integrity(
            "base64 length is not a multiple of 4".into(),
        ));
    }
    if acc & ((1u32 << bits) - 1) != 0 {
        return Err(FerrumError::Integrity(
            "base64 has non-zero trailing bits".into(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_days(days: u64) -> SystemTime {
        SystemTime::now() + Duration::from_secs(days * DAY_SECS)
    }

    fn ca() -> CaMaterial {
        issue_ca("ferrum-admission-ca", in_days(365)).expect("ca")
    }

    #[test]
    fn issued_chain_verifies() {
        let ca = ca();
        let serving = issue_serving_cert(&ca, "ferrum-admission", "ferrum", in_days(365))
            .expect("serving cert");
        verify_chain(&serving, &ca).expect("chain must verify");
        assert_eq!(
            serving.dns_names,
            [
                "ferrum-admission",
                "ferrum-admission.ferrum",
                "ferrum-admission.ferrum.svc",
                "ferrum-admission.ferrum.svc.cluster.local",
            ]
        );
    }

    #[test]
    fn a_foreign_ca_does_not_verify() {
        let mine = ca();
        let other = issue_ca("someone-else", in_days(365)).expect("ca");
        let serving = issue_serving_cert(&mine, "ferrum-admission", "ferrum", in_days(365))
            .expect("serving cert");
        let err = verify_chain(&serving, &other).expect_err("foreign CA must not verify");
        assert!(matches!(err, FerrumError::Integrity(_)), "{err}");
    }

    #[test]
    fn a_foreign_san_does_not_verify() {
        let ca = ca();
        let real = issue_serving_cert(&ca, "ferrum-admission", "ferrum", in_days(30)).unwrap();
        let other = issue_serving_cert(&ca, "attacker-svc", "ferrum", in_days(30)).unwrap();
        // Same CA, same key material shape: only the SAN differs, and the claim
        // the material makes about its own SAN is part of the contract.
        let forged = ServingMaterial {
            cert_pem: other.cert_pem,
            key_pem: other.key_pem,
            dns_names: real.dns_names.clone(),
        };
        let err = verify_chain(&forged, &ca).expect_err("SAN mismatch must not verify");
        assert!(err.to_string().contains("SAN"), "{err}");
    }

    #[test]
    fn a_truncated_certificate_does_not_verify() {
        let ca = ca();
        let serving = issue_serving_cert(&ca, "ferrum-admission", "ferrum", in_days(30)).unwrap();
        let mut der = single(pem_certificates(&serving.cert_pem).unwrap(), "leaf").unwrap();
        der.truncate(der.len() - 8);
        let broken = ServingMaterial {
            cert_pem: format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                base64_encode(&der)
            ),
            key_pem: serving.key_pem,
            dns_names: serving.dns_names,
        };
        assert!(verify_chain(&broken, &ca).is_err());
    }

    #[test]
    fn four_hundred_days_is_refused() {
        let err = issue_ca("ferrum-admission-ca", in_days(400)).expect_err("400 days must fail");
        assert!(matches!(err, FerrumError::Validation(_)), "{err}");
        let ca = ca();
        let err = issue_serving_cert(&ca, "ferrum-admission", "ferrum", in_days(400))
            .expect_err("400 days must fail");
        assert!(err.to_string().contains("398"), "{err}");
    }

    #[test]
    fn a_past_not_after_is_refused() {
        let past = SystemTime::now() - Duration::from_secs(60);
        assert!(issue_ca("ferrum-admission-ca", past).is_err());
    }

    #[test]
    fn an_empty_service_or_namespace_is_refused() {
        let ca = ca();
        assert!(issue_serving_cert(&ca, "", "ferrum", in_days(30)).is_err());
        assert!(issue_serving_cert(&ca, "ferrum-admission", "  ", in_days(30)).is_err());
    }

    #[test]
    fn basic_constraints_separate_the_ca_from_the_leaf() {
        let ca = ca();
        let serving = issue_serving_cert(&ca, "ferrum-admission", "ferrum", in_days(30)).unwrap();
        let ca_der = single(pem_certificates(&ca.cert_pem).unwrap(), "ca").unwrap();
        let leaf_der = single(pem_certificates(&serving.cert_pem).unwrap(), "leaf").unwrap();
        assert!(X509Certificate::from_der(&ca_der).unwrap().1.is_ca());
        assert!(!X509Certificate::from_der(&leaf_der).unwrap().1.is_ca());
    }

    #[test]
    fn a_leaf_is_not_accepted_as_its_own_issuer() {
        let ca = ca();
        let serving = issue_serving_cert(&ca, "ferrum-admission", "ferrum", in_days(30)).unwrap();
        let as_ca = CaMaterial {
            cert_pem: serving.cert_pem.clone(),
            key_pem: serving.key_pem.clone(),
        };
        let err = verify_chain(&serving, &as_ca).expect_err("a leaf is not a CA");
        assert!(err.to_string().contains("CA:TRUE"), "{err}");
    }

    #[test]
    fn expiry_window_is_read_from_the_certificate() {
        let ca = issue_ca("ferrum-admission-ca", in_days(30)).unwrap();
        assert!(!expires_within(&ca.cert_pem, Duration::from_secs(DAY_SECS)).unwrap());
        assert!(expires_within(&ca.cert_pem, Duration::from_secs(31 * DAY_SECS)).unwrap());
    }

    #[test]
    fn base64_round_trips_and_rejects_junk() {
        for len in 0..64usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let encoded = base64_encode(&data);
            assert_eq!(base64_decode(&encoded).unwrap(), data, "len {len}");
        }
        assert!(base64_decode("REPLACE_WITH_PEM_CA_BUNDLE_BASE64").is_err());
        assert!(base64_decode("AAAA=AAA").is_err());
        assert!(base64_decode("AAA").is_err());
    }

    #[test]
    fn pem_parsing_rejects_non_certificate_input() {
        let ca = ca();
        assert!(pem_certificates("").is_err());
        assert!(pem_certificates(&ca.key_pem).is_err());
        assert!(pem_certificates("-----BEGIN CERTIFICATE-----\nAAAA\n").is_err());
        assert_eq!(
            pem_certificates(&format!("{}{}", ca.cert_pem, ca.cert_pem))
                .unwrap()
                .len(),
            2
        );
    }
}
