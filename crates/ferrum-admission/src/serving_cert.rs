//! Serving material for the webhook: what is on disk now, when it expires, and
//! which names it covers.
//!
//! With `failurePolicy: Fail` an expired serving certificate stops Pod creation
//! cluster-wide, so the material is not read once at start: kubelet rewrites a
//! mounted Secret in place through the `..data` symlink, and this module
//! follows it the same way the bundle poll does.
//!
//! notAfter and the DNS SAN come from a small DER walk rather than from a
//! certificate library on purpose: `ferrum-crypto/x509` pulls rcgen and
//! x509-parser, and the Jenkins `Crate boundary` stage fails if either reaches
//! this binary.

use rustls::ServerConfig;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use crate::server::{stamp_one, FileStamp};

/// Days before notAfter at which the loaded certificate becomes loud. Same
/// threshold as `ferrum_crypto::x509::SERVING_CERT_WARN_DAYS`, restated here
/// because that module carries the issuer and the parser this binary must not
/// link.
pub const SERVING_CERT_WARN_DAYS: i64 = 30;

const DAY_SECS: i64 = 86_400;

/// subjectAltName, OID 2.5.29.17.
const SAN_OID: &[u8] = &[0x55, 0x1d, 0x11];

/// What the decision path needs from a serving certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertFacts {
    /// notAfter as a Unix timestamp.
    pub not_after: i64,
    /// DNS SAN entries, in certificate order.
    pub dns_names: Vec<String>,
}

impl CertFacts {
    pub fn expires_within_days(&self, now: i64, days: i64) -> bool {
        self.not_after <= now.saturating_add(days.saturating_mul(DAY_SECS))
    }

    fn covers(&self, names: &[String]) -> bool {
        names.iter().all(|n| self.dns_names.contains(n))
    }
}

struct Loaded {
    config: Arc<ServerConfig>,
    facts: CertFacts,
    /// One warning per material, not one per poll tick.
    warned: bool,
}

/// The serving certificate the listener hands to new connections. Replaced in
/// place on rotation; material that does not parse, has already expired, or
/// drops a name the current certificate covers never replaces it.
pub struct TlsSource {
    cert_path: PathBuf,
    key_path: PathBuf,
    loaded: RwLock<Loaded>,
    reload_failures: AtomicU64,
    expiry_warnings: AtomicU64,
}

impl TlsSource {
    /// Read PEM cert + PKCS8/RSA key. An already-expired certificate is an
    /// error: serving TLS the API server will reject is, under
    /// `failurePolicy: Fail`, worse than not starting.
    pub fn load(cert_path: &str, key_path: &str) -> Result<Arc<Self>, String> {
        let (config, facts) = read_material(Path::new(cert_path), Path::new(key_path))?;
        let source = Arc::new(Self {
            cert_path: PathBuf::from(cert_path),
            key_path: PathBuf::from(key_path),
            loaded: RwLock::new(Loaded {
                config,
                facts,
                warned: false,
            }),
            reload_failures: AtomicU64::new(0),
            expiry_warnings: AtomicU64::new(0),
        });
        source.check_expiry();
        Ok(source)
    }

    /// Config for one new connection. Handshakes already in flight keep theirs.
    pub fn config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.loaded.read().unwrap_or_else(|e| e.into_inner()).config)
    }

    pub fn facts(&self) -> CertFacts {
        self.loaded
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .facts
            .clone()
    }

    /// Material rejected since start; the previous certificate stayed in place.
    pub fn reload_failures(&self) -> u64 {
        self.reload_failures.load(Ordering::Relaxed)
    }

    /// How many loaded certificates entered the [`SERVING_CERT_WARN_DAYS`] window.
    pub fn expiry_warnings(&self) -> u64 {
        self.expiry_warnings.load(Ordering::Relaxed)
    }

    /// Re-read both files and swap on success. Errors leave the old material
    /// serving and are counted.
    pub fn reload(&self) -> Result<(), String> {
        let previous = self.facts();
        let (config, facts) = read_material(&self.cert_path, &self.key_path).map_err(|e| {
            self.reload_failures.fetch_add(1, Ordering::Relaxed);
            e
        })?;
        if !facts.covers(&previous.dns_names) {
            self.reload_failures.fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "new serving certificate covers {:?}, which drops names the current one serves {:?}",
                facts.dns_names, previous.dns_names
            ));
        }
        *self.loaded.write().unwrap_or_else(|e| e.into_inner()) = Loaded {
            config,
            facts,
            warned: false,
        };
        self.check_expiry();
        Ok(())
    }

    fn check_expiry(&self) {
        let mut loaded = self.loaded.write().unwrap_or_else(|e| e.into_inner());
        if loaded.warned
            || !loaded
                .facts
                .expires_within_days(now_unix(), SERVING_CERT_WARN_DAYS)
        {
            return;
        }
        loaded.warned = true;
        let total = self.expiry_warnings.fetch_add(1, Ordering::Relaxed) + 1;
        eprintln!(
            "ferrum-admission: serving certificate expires at unix {} (within {SERVING_CERT_WARN_DAYS} days) \
             (serving_cert_expiring_total={total}); with failurePolicy: Fail expiry stops Pod creation \
             cluster-wide — rotate it (see deploy/admission/README)",
            loaded.facts.not_after
        );
    }
}

/// Watch the serving Secret mount and swap the certificate in place. Same shape
/// as the bundle poll: mtime+len on the path as given, so kubelet `..data`
/// rotation is visible; a vanished or broken file keeps the last-known-good.
pub fn poll_serving_cert(source: Arc<TlsSource>, interval: Duration) {
    thread::spawn(move || poll_loop(source, interval));
}

fn poll_loop(source: Arc<TlsSource>, interval: Duration) {
    // No initial stamp: a rotation between the first load and this thread must
    // not be skipped.
    let mut stamp: Option<(FileStamp, FileStamp)> = None;
    loop {
        thread::sleep(interval);
        source.check_expiry();
        let (Some(cert), Some(key)) = (stamp_one(&source.cert_path), stamp_one(&source.key_path))
        else {
            continue;
        };
        if Some((cert, key)) == stamp {
            continue;
        }
        stamp = Some((cert, key));
        if let Err(err) = source.reload() {
            eprintln!(
                "ferrum-admission: serving certificate reload failed, keeping the current one \
                 (serving_cert_reload_failures_total={}): {err}",
                source.reload_failures()
            );
        } else {
            eprintln!("ferrum-admission: serving certificate reloaded");
        }
    }
}

fn read_material(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Arc<ServerConfig>, CertFacts), String> {
    let cert_file = std::fs::File::open(cert_path).map_err(|e| format!("tls cert: {e}"))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .map_err(|e| format!("tls cert parse: {e}"))?
        .into_iter()
        .map(rustls::Certificate)
        .collect::<Vec<_>>();
    let leaf = certs
        .first()
        .ok_or_else(|| "tls cert file contains no certificates".to_string())?;
    let facts = certificate_facts(&leaf.0)?;
    let now = now_unix();
    if facts.not_after <= now {
        return Err(format!(
            "serving certificate expired at unix {} (now {now}); it cannot serve an API server \
             handshake and with failurePolicy: Fail that stops Pod creation cluster-wide",
            facts.not_after
        ));
    }
    if facts.dns_names.is_empty() {
        return Err(
            "serving certificate carries no DNS SAN; the API server dials the webhook by \
                    Service name and would reject it"
                .to_string(),
        );
    }

    let key_file = std::fs::File::open(key_path).map_err(|e| format!("tls key: {e}"))?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .map_err(|e| format!("tls key parse: {e}"))?;
    if keys.is_empty() {
        let key_file = std::fs::File::open(key_path).map_err(|e| format!("tls key: {e}"))?;
        let mut key_reader = BufReader::new(key_file);
        keys = rustls_pemfile::rsa_private_keys(&mut key_reader)
            .map_err(|e| format!("tls key parse: {e}"))?;
    }
    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| "tls key file contains no private key".to_string())?;
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, rustls::PrivateKey(key))
        .map_err(|e| format!("tls config: {e}"))?;
    Ok((Arc::new(config), facts))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// notAfter and the DNS SAN of a DER-encoded certificate.
pub fn certificate_facts(der: &[u8]) -> Result<CertFacts, String> {
    let (cert, _) = take(der)?;
    expect(&cert, 0x30, "certificate")?;
    let (tbs, _) = take(cert.value)?;
    expect(&tbs, 0x30, "tbsCertificate")?;

    let mut rest = tbs.value;
    let (first, after_first) = take(rest)?;
    // [0] EXPLICIT version is optional; v1 starts at serialNumber.
    if first.tag == 0xa0 {
        rest = after_first;
    }
    // serialNumber, signature, issuer.
    for _ in 0..3 {
        rest = take(rest)?.1;
    }
    let (validity, after_validity) = take(rest)?;
    expect(&validity, 0x30, "validity")?;
    let (_not_before, after_not_before) = take(validity.value)?;
    let (not_after, _) = take(after_not_before)?;
    let not_after = parse_time(&not_after)?;

    // subject, subjectPublicKeyInfo; then the optional [1]/[2]/[3] tags.
    rest = after_validity;
    for _ in 0..2 {
        rest = take(rest)?.1;
    }
    let mut dns_names = Vec::new();
    while !rest.is_empty() {
        let (tlv, next) = take(rest)?;
        rest = next;
        if tlv.tag == 0xa3 {
            dns_names = san_dns_names(tlv.value)?;
            break;
        }
    }
    Ok(CertFacts {
        not_after,
        dns_names,
    })
}

fn san_dns_names(extensions: &[u8]) -> Result<Vec<String>, String> {
    let (seq, _) = take(extensions)?;
    expect(&seq, 0x30, "extensions")?;
    let mut rest = seq.value;
    while !rest.is_empty() {
        let (ext, next) = take(rest)?;
        rest = next;
        expect(&ext, 0x30, "extension")?;
        let (oid, after_oid) = take(ext.value)?;
        expect(&oid, 0x06, "extension OID")?;
        if oid.value != SAN_OID {
            continue;
        }
        let (mut payload, after) = take(after_oid)?;
        if payload.tag == 0x01 {
            payload = take(after)?.0;
        }
        expect(&payload, 0x04, "subjectAltName value")?;
        let (names, _) = take(payload.value)?;
        expect(&names, 0x30, "GeneralNames")?;
        let mut names_rest = names.value;
        let mut out = Vec::new();
        while !names_rest.is_empty() {
            let (name, next) = take(names_rest)?;
            names_rest = next;
            // [2] IMPLICIT IA5String dNSName; other name forms are not what the
            // API server dials the webhook by.
            if name.tag == 0x82 {
                out.push(
                    std::str::from_utf8(name.value)
                        .map_err(|_| "dNSName is not UTF-8".to_string())?
                        .to_string(),
                );
            }
        }
        return Ok(out);
    }
    Ok(Vec::new())
}

fn parse_time(tlv: &Tlv<'_>) -> Result<i64, String> {
    let raw = std::str::from_utf8(tlv.value).map_err(|_| "certificate time is not UTF-8")?;
    let format = match tlv.tag {
        0x17 => "%y%m%d%H%M%SZ",
        0x18 => "%Y%m%d%H%M%SZ",
        other => return Err(format!("unexpected certificate time tag {other:#04x}")),
    };
    chrono::NaiveDateTime::parse_from_str(raw, format)
        .map(|dt| dt.and_utc().timestamp())
        .map_err(|e| format!("unreadable certificate time {raw:?}: {e}"))
}

fn expect(tlv: &Tlv<'_>, tag: u8, what: &str) -> Result<(), String> {
    if tlv.tag != tag {
        return Err(format!(
            "{what}: expected DER tag {tag:#04x}, found {:#04x}",
            tlv.tag
        ));
    }
    Ok(())
}

/// One definite-length DER element and whatever follows it.
fn take(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), String> {
    let tag = *input.first().ok_or("truncated DER element")?;
    if tag & 0x1f == 0x1f {
        return Err("multi-byte DER tags are not used in a certificate".into());
    }
    let first = *input.get(1).ok_or("truncated DER length")? as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        // Indefinite length is BER, not DER; four bytes is more than any
        // certificate field needs.
        if count == 0 || count > 4 {
            return Err("unsupported DER length".into());
        }
        let bytes = input.get(2..2 + count).ok_or("truncated DER length")?;
        (
            bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize),
            2 + count,
        )
    };
    let end = header.checked_add(len).ok_or("DER length overflows")?;
    let value = input
        .get(header..end)
        .ok_or("DER length past end of input")?;
    Ok((Tlv { tag, value }, &input[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVING: &str = include_str!("../tests/fixtures/pki/serving.crt");
    const NARROW: &str = include_str!("../tests/fixtures/pki/narrow.crt");
    const EXPIRED: &str = include_str!("../tests/fixtures/pki/expired.crt");

    fn der(pem: &str) -> Vec<u8> {
        rustls_pemfile::certs(&mut pem.as_bytes())
            .expect("pem")
            .remove(0)
    }

    fn unix(text: &str) -> i64 {
        chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S")
            .unwrap()
            .and_utc()
            .timestamp()
    }

    #[test]
    fn facts_are_read_from_a_generalized_time_certificate() {
        let facts = certificate_facts(&der(SERVING)).expect("facts");
        assert_eq!(facts.not_after, unix("2099-12-31T23:59:59"));
        assert_eq!(
            facts.dns_names,
            [
                "ferrum-admission",
                "ferrum-admission.ferrum",
                "ferrum-admission.ferrum.svc",
                "ferrum-admission.ferrum.svc.cluster.local",
            ]
        );
    }

    /// notAfter before 2050 is UTCTime, after it GeneralizedTime; both reach
    /// this parser from real material.
    #[test]
    fn facts_are_read_from_a_utc_time_certificate() {
        let facts = certificate_facts(&der(EXPIRED)).expect("facts");
        assert_eq!(facts.not_after, unix("2020-01-01T00:00:00"));
        assert_eq!(facts.dns_names.len(), 4);
    }

    #[test]
    fn a_narrow_san_does_not_cover_the_service_names() {
        let wide = certificate_facts(&der(SERVING)).unwrap();
        let narrow = certificate_facts(&der(NARROW)).unwrap();
        assert_eq!(narrow.dns_names, ["ferrum-admission"]);
        assert!(!narrow.covers(&wide.dns_names));
        assert!(wide.covers(&narrow.dns_names));
    }

    #[test]
    fn truncated_and_junk_der_do_not_parse() {
        let der = der(SERVING);
        assert!(certificate_facts(&der[..der.len() / 2]).is_err());
        assert!(certificate_facts(b"not a certificate").is_err());
        assert!(certificate_facts(&[]).is_err());
    }

    #[test]
    fn the_warning_window_is_days_before_not_after() {
        let facts = CertFacts {
            not_after: 1_000 * DAY_SECS,
            dns_names: vec!["ferrum-admission".into()],
        };
        let now = 970 * DAY_SECS;
        assert!(!facts.expires_within_days(now, 29));
        assert!(facts.expires_within_days(now, 30));
        assert!(facts.expires_within_days(1_001 * DAY_SECS, 0));
    }
}
