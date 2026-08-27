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

/// Days before notAfter at which the loaded certificate becomes loud. Defined
/// in `ferrum-common` so the deploy lint and this binary cannot drift: the
/// lint reads it through `ferrum_crypto::x509`, which carries the parser this
/// binary must not link.
pub const SERVING_CERT_WARN_DAYS: i64 = ferrum_common::SERVING_CERT_WARN_DAYS as i64;

const DAY_SECS: i64 = 86_400;

/// subjectAltName, OID 2.5.29.17.
const SAN_OID: &[u8] = &[0x55, 0x1d, 0x11];
/// authorityKeyIdentifier, OID 2.5.29.35. Its keyIdentifier is a digest of the
/// issuer's public key, which is what makes two CAs of the same name tell apart.
const AKI_OID: &[u8] = &[0x55, 0x1d, 0x23];

/// Who signed the material: the issuer Name as it appears in the certificate,
/// plus the authorityKeyIdentifier when the issuer set one.
///
/// This is a pin, not a verification. Building a chain to the CA in the applied
/// `caBundle` needs a certificate library, and `ferrum-crypto/x509` — the one
/// this workspace has — is exactly what the `Crate boundary` stage keeps off
/// this binary. What is affordable here is refusing material that names a
/// different issuer than the certificate this process started with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Issuer {
    /// DER of the issuer `Name`, element header included.
    pub name_der: Vec<u8>,
    /// keyIdentifier from authorityKeyIdentifier, when present.
    pub key_id: Option<Vec<u8>>,
}

impl Issuer {
    /// Short, stable label for a log line; the DER itself is not readable.
    fn label(&self) -> String {
        match &self.key_id {
            Some(id) => format!("keyid {}", hex(id)),
            None => format!("issuer {}", hex(&fnv1a(&self.name_der).to_be_bytes())),
        }
    }
}

/// What the decision path needs from a serving certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertFacts {
    /// notAfter as a Unix timestamp.
    pub not_after: i64,
    /// DNS SAN entries, in certificate order.
    pub dns_names: Vec<String>,
    /// The CA the certificate names as its issuer.
    pub issuer: Issuer,
}

impl CertFacts {
    pub fn expires_within_days(&self, now: i64, days: i64) -> bool {
        self.not_after <= now.saturating_add(days.saturating_mul(DAY_SECS))
    }

    fn covers(&self, names: &[String]) -> bool {
        names.iter().all(|n| self.dns_names.contains(n))
    }
}

#[derive(Clone)]
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
    /// The issuer of the certificate this process started with. The applied
    /// caBundle names one CA and only material from it can be served, so a
    /// rotation that changes issuer is a mistake, not a rotation.
    pinned_issuer: Issuer,
    /// The material that was serving before the last successful swap. Kept so
    /// a swap can be undone: under `failurePolicy: Fail` there is no second
    /// chance to fetch the old Secret back.
    previous: RwLock<Option<Loaded>>,
    reload_failures: AtomicU64,
    expiry_warnings: AtomicU64,
    rollbacks: AtomicU64,
}

impl TlsSource {
    /// Read PEM cert + PKCS8/RSA key. An already-expired certificate is an
    /// error: serving TLS the API server will reject is, under
    /// `failurePolicy: Fail`, worse than not starting.
    pub fn load(cert_path: &str, key_path: &str) -> Result<Arc<Self>, String> {
        let (config, facts) = read_material(Path::new(cert_path), Path::new(key_path))?;
        let pinned_issuer = facts.issuer.clone();
        let source = Arc::new(Self {
            cert_path: PathBuf::from(cert_path),
            key_path: PathBuf::from(key_path),
            loaded: RwLock::new(Loaded {
                config,
                facts,
                warned: false,
            }),
            pinned_issuer,
            previous: RwLock::new(None),
            reload_failures: AtomicU64::new(0),
            expiry_warnings: AtomicU64::new(0),
            rollbacks: AtomicU64::new(0),
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

    /// How many swaps were undone by [`Self::roll_back`].
    pub fn rollbacks(&self) -> u64 {
        self.rollbacks.load(Ordering::Relaxed)
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
        // A leaf from another CA parses, has a SAN and has not expired, so
        // every other check here passes it — and the API server, which trusts
        // one caBundle, rejects every handshake it makes. Serving it means
        // throwing away working material for material that cannot work.
        if facts.issuer != self.pinned_issuer {
            self.reload_failures.fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "new serving certificate was issued by {}, not by {} which signed the certificate \
                 this process started with; the API server trusts one caBundle and would reject it",
                facts.issuer.label(),
                self.pinned_issuer.label()
            ));
        }
        let mut loaded = self.loaded.write().unwrap_or_else(|e| e.into_inner());
        let replaced = std::mem::replace(
            &mut *loaded,
            Loaded {
                config,
                facts,
                warned: false,
            },
        );
        drop(loaded);
        *self.previous.write().unwrap_or_else(|e| e.into_inner()) = Some(replaced);
        self.check_expiry();
        Ok(())
    }

    /// Put the material from before the last swap back. Only useful while that
    /// material is still usable, so an expired one is refused: a rollback that
    /// installs a dead certificate is the same outage as the swap it undoes.
    pub fn roll_back(&self) -> Result<(), String> {
        let mut slot = self.previous.write().unwrap_or_else(|e| e.into_inner());
        let Some(candidate) = slot.take() else {
            return Err("no previous serving material to roll back to".to_string());
        };
        if candidate.facts.not_after <= now_unix() {
            return Err(format!(
                "previous serving certificate expired at unix {}; there is nothing to roll back to",
                candidate.facts.not_after
            ));
        }
        *self.loaded.write().unwrap_or_else(|e| e.into_inner()) = candidate;
        drop(slot);
        self.rollbacks.fetch_add(1, Ordering::Relaxed);
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
        let before = source.facts();
        if let Err(err) = source.reload() {
            eprintln!(
                "ferrum-admission: serving certificate reload failed, keeping the current one \
                 (serving_cert_reload_failures_total={}): {err}",
                source.reload_failures()
            );
            continue;
        }
        let after = source.facts();
        if is_stale_rotation(&before, &after, now_unix()) {
            match source.roll_back() {
                Ok(()) => eprintln!(
                    "ferrum-admission: new serving certificate expires at unix {} (within \
                     {SERVING_CERT_WARN_DAYS} days) while the one it replaced does not; rolled \
                     back (serving_cert_rollbacks_total={})",
                    after.not_after,
                    source.rollbacks()
                ),
                Err(err) => eprintln!(
                    "ferrum-admission: new serving certificate is already expiring and the \
                     rollback failed, serving it anyway: {err}"
                ),
            }
            continue;
        }
        eprintln!("ferrum-admission: serving certificate reloaded");
    }
}

/// A swap onto material that is already inside the rotation window, replacing
/// material that was not: an old Secret re-applied, not a rotation. Shorter
/// alone is not enough — a 90-day leaf legitimately replaces one with more time
/// left than that.
fn is_stale_rotation(before: &CertFacts, after: &CertFacts, now: i64) -> bool {
    after.expires_within_days(now, SERVING_CERT_WARN_DAYS)
        && !before.expires_within_days(now, SERVING_CERT_WARN_DAYS)
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
    // serialNumber, signature.
    for _ in 0..2 {
        rest = take(rest)?.1;
    }
    let at_issuer = rest;
    let after_issuer = take(rest)?.1;
    // The Name as encoded, header included: a byte-for-byte pin, not a parse
    // of the RDN sequence.
    let issuer_name_der = at_issuer[..at_issuer.len() - after_issuer.len()].to_vec();
    rest = after_issuer;
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
    let mut key_id = None;
    while !rest.is_empty() {
        let (tlv, next) = take(rest)?;
        rest = next;
        if tlv.tag == 0xa3 {
            (dns_names, key_id) = extensions(tlv.value)?;
            break;
        }
    }
    Ok(CertFacts {
        not_after,
        dns_names,
        issuer: Issuer {
            name_der: issuer_name_der,
            key_id,
        },
    })
}

/// DNS SAN entries and the authorityKeyIdentifier keyIdentifier, from one walk
/// of the extension sequence.
type Extensions = (Vec<String>, Option<Vec<u8>>);

fn extensions(der: &[u8]) -> Result<Extensions, String> {
    let (seq, _) = take(der)?;
    expect(&seq, 0x30, "extensions")?;
    let mut rest = seq.value;
    let mut dns_names = Vec::new();
    let mut key_id = None;
    while !rest.is_empty() {
        let (ext, next) = take(rest)?;
        rest = next;
        expect(&ext, 0x30, "extension")?;
        let (oid, after_oid) = take(ext.value)?;
        expect(&oid, 0x06, "extension OID")?;
        let wanted = oid.value == SAN_OID || oid.value == AKI_OID;
        if !wanted {
            continue;
        }
        // The optional critical BOOLEAN sits between the OID and the value.
        let (mut payload, after) = take(after_oid)?;
        if payload.tag == 0x01 {
            payload = take(after)?.0;
        }
        expect(&payload, 0x04, "extension value")?;
        if oid.value == SAN_OID {
            dns_names = san_dns_names(payload.value)?;
        } else {
            key_id = authority_key_id(payload.value)?;
        }
    }
    Ok((dns_names, key_id))
}

fn san_dns_names(der: &[u8]) -> Result<Vec<String>, String> {
    let (names, _) = take(der)?;
    expect(&names, 0x30, "GeneralNames")?;
    let mut rest = names.value;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (name, next) = take(rest)?;
        rest = next;
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
    Ok(out)
}

fn authority_key_id(der: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let (seq, _) = take(der)?;
    expect(&seq, 0x30, "AuthorityKeyIdentifier")?;
    let mut rest = seq.value;
    while !rest.is_empty() {
        let (field, next) = take(rest)?;
        rest = next;
        // [0] IMPLICIT keyIdentifier; the issuer name and serial forms that may
        // follow it say nothing this pin can use.
        if field.tag == 0x80 {
            return Ok(Some(field.value.to_vec()));
        }
    }
    Ok(None)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// FNV-1a, only ever used to shorten a DER blob for a log line.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ b as u64).wrapping_mul(0x100_0000_01b3)
    })
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

    /// Two leaves of the same CA pin the same issuer; the fixture from a
    /// second CA carries the same issuer *name* and a different key id, which
    /// is the case a name comparison alone would wave through.
    #[test]
    fn the_issuer_pin_follows_the_signing_key_not_the_name() {
        const ROTATED: &str = include_str!("../tests/fixtures/pki/rotated.crt");
        const FOREIGN: &str = include_str!("../tests/fixtures/pki/foreign.crt");
        let serving = certificate_facts(&der(SERVING)).unwrap().issuer;
        let rotated = certificate_facts(&der(ROTATED)).unwrap().issuer;
        let foreign = certificate_facts(&der(FOREIGN)).unwrap().issuer;
        assert!(serving.key_id.is_some(), "the fixtures carry an AKI");
        assert_eq!(serving, rotated);
        assert_eq!(
            serving.name_der, foreign.name_der,
            "the fixture is meant to reuse the CA's name"
        );
        assert_ne!(serving, foreign);
        assert_ne!(serving.label(), foreign.label());
    }

    #[test]
    fn truncated_and_junk_der_do_not_parse() {
        let der = der(SERVING);
        assert!(certificate_facts(&der[..der.len() / 2]).is_err());
        assert!(certificate_facts(b"not a certificate").is_err());
        assert!(certificate_facts(&[]).is_err());
    }

    #[test]
    fn only_a_swap_into_the_rotation_window_is_stale() {
        let facts = |days: i64| CertFacts {
            not_after: (1_000 + days) * DAY_SECS,
            dns_names: vec!["ferrum-admission".into()],
            issuer: Issuer::default(),
        };
        let now = 1_000 * DAY_SECS;
        // The rotation the README describes: 90 days replacing 200.
        assert!(!is_stale_rotation(&facts(200), &facts(90), now));
        // The same Secret applied twice; nothing moved.
        assert!(!is_stale_rotation(&facts(90), &facts(90), now));
        // An old Secret re-applied over healthy material.
        assert!(is_stale_rotation(&facts(90), &facts(10), now));
        // Already inside the window before the swap: nothing better to keep.
        assert!(!is_stale_rotation(&facts(10), &facts(5), now));
    }

    #[test]
    fn the_warning_window_is_days_before_not_after() {
        let facts = CertFacts {
            not_after: 1_000 * DAY_SECS,
            dns_names: vec!["ferrum-admission".into()],
            issuer: Issuer::default(),
        };
        let now = 970 * DAY_SECS;
        assert!(!facts.expires_within_days(now, 29));
        assert!(facts.expires_within_days(now, 30));
        assert!(facts.expires_within_days(1_001 * DAY_SECS, 0));
    }
}
