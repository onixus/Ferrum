//! The webhook's half of break-glass: a mount, a window, and a journal.
//!
//! `ferrum-breakglass` owns the format, the signature and the chain. This
//! module owns what the *webhook* does about them, and the two decisions worth
//! stating here are both refusals.
//!
//! **A suspension is never a fail-open.** While a grant holds, this webhook
//! answers allow to everything in its scope — that is what break-glass is —
//! and it says so in the admission response message, on stderr, in the journal
//! and on `/metrics`. What it does not do is change what a *missing* or
//! *unverifiable bundle* means: that is still a deny, and it stays a deny when
//! no grant is in force. The two states are reached by different paths and only
//! one of them is signed.
//!
//! **A rejected grant is journalled once, not once per poll.** The poll runs
//! every second; a grant with a bad signature sitting in the mount would
//! otherwise write eighty-six thousand entries a day and bury the one that
//! matters. So the rejection is keyed on the bytes and the reason, and a
//! repeat of the same refusal is silent until either changes. That is a
//! deliberate loss of information — how many times a forged grant was retried —
//! traded for a journal an operator can still read. The count is not lost: it
//! is `ferrum_admission_break_glass_rejections_total`, which counts every poll.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use ferrum_breakglass::{verify_grant, Journal, JournalEvent, VerifiedGrant};
use ferrum_common::{FerrumError, Result};

/// The two keys of the break-glass Secret, as filenames in its mount.
///
/// Two files rather than one envelope: a Kubernetes Secret mounts each key as
/// a file, so this is the shape an operator already has, and the signed bytes
/// stay exactly the bytes on disk. Any re-wrapping would introduce a
/// canonicalisation step, and a signature over bytes that were re-encoded on
/// the way in is a signature over something the signer never saw.
pub const GRANT_FILE: &str = "grant.json";
pub const SIGNATURE_FILE: &str = "grant.sig";

/// Largest grant document this webhook will read. A grant is a dozen short
/// fields; anything larger is a mount pointed at the wrong thing.
const MAX_GRANT_BYTES: u64 = 16 * 1024;

/// Break-glass state of one webhook process.
#[derive(Debug)]
pub struct BreakGlass {
    dir: PathBuf,
    trust_root: Vec<u8>,
    journal: Mutex<Journal>,
    active: RwLock<Option<VerifiedGrant>>,
    /// The last refusal, as bytes-digest plus message, so an unchanged refusal
    /// is not re-journalled. See the module docs.
    last_rejection: Mutex<Option<String>>,
    activations: AtomicU64,
    rejections: AtomicU64,
    admits: AtomicU64,
    journal_entries: AtomicU64,
    journal_head: RwLock<String>,
    /// The journal stopped accepting entries after start-up. Enforcement
    /// resumes: a window this process can no longer record must not stay open.
    journal_broken: RwLock<Option<String>>,
}

impl BreakGlass {
    /// Arm break-glass, or fail.
    ///
    /// Both halves are checked here rather than at the first grant: the journal
    /// is opened, verified and probed for writability, and a trust root that is
    /// not a usable Ed25519 key is refused. `cmd_serve` turns either into a
    /// start-up error, so an install whose break-glass could never have worked
    /// fails `kubectl rollout status` instead of failing at 03:00.
    pub fn arm(
        dir: impl Into<PathBuf>,
        journal_path: impl AsRef<Path>,
        trust_root: Vec<u8>,
        component: impl Into<String>,
    ) -> Result<Self> {
        if trust_root.len() != ferrum_crypto::ED25519_PUBLIC_KEY_LEN {
            return Err(FerrumError::Integrity(format!(
                "break-glass trust root must be {} bytes, got {}",
                ferrum_crypto::ED25519_PUBLIC_KEY_LEN,
                trust_root.len()
            )));
        }
        let journal = Journal::open(journal_path.as_ref(), component)?;
        let head = journal.head().to_string();
        let entries = journal.len();
        Ok(BreakGlass {
            dir: dir.into(),
            trust_root,
            journal: Mutex::new(journal),
            active: RwLock::new(None),
            last_rejection: Mutex::new(None),
            activations: AtomicU64::new(0),
            rejections: AtomicU64::new(0),
            admits: AtomicU64::new(0),
            journal_entries: AtomicU64::new(entries),
            journal_head: RwLock::new(head),
            journal_broken: RwLock::new(None),
        })
    }

    /// The grant in force at `now`, if any.
    ///
    /// The window is re-checked on every call and not only at load: a window
    /// checked once is a window that ends when the process restarts.
    pub fn active(&self, now: DateTime<Utc>) -> Option<VerifiedGrant> {
        let held = self.active.read().unwrap_or_else(|e| e.into_inner());
        held.as_ref().filter(|g| g.covers(now)).cloned()
    }

    /// Count one review this grant allowed. Separate from the ordinary allow
    /// counter, which also moves: "how many Pods went in unchecked" is the
    /// number an incident review asks for, and it is not derivable from the
    /// allow total.
    pub fn note_admit(&self) {
        self.admits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn admits(&self) -> u64 {
        self.admits.load(Ordering::Relaxed)
    }

    pub fn activations(&self) -> u64 {
        self.activations.load(Ordering::Relaxed)
    }

    pub fn rejections(&self) -> u64 {
        self.rejections.load(Ordering::Relaxed)
    }

    pub fn journal_entries(&self) -> u64 {
        self.journal_entries.load(Ordering::Relaxed)
    }

    /// Head of the chain. Published as a metric label so a Prometheus holds a
    /// copy off the node — see `ferrum-breakglass` on anchors.
    pub fn journal_head(&self) -> String {
        self.journal_head
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Why the journal stopped working, if it did.
    pub fn journal_broken(&self) -> Option<String> {
        self.journal_broken
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Read the mount and reconcile the process state with it.
    ///
    /// Idempotent and called on a timer. Every state transition it makes is
    /// journalled before it takes effect for activations and after it stops
    /// taking effect for the rest, so there is no ordering in which enforcement
    /// is suspended and the record of it is not yet written.
    pub fn poll(&self, now: DateTime<Utc>) {
        // Every read of `active` here ends before the matching write begins,
        // and each one goes through `snapshot` for that reason. A read guard
        // still alive when `active.write()` runs on the same thread deadlocks
        // `std::sync::RwLock`, and the shape that produces one —
        // `if let Some(x) = self.active.read()...clone()` — keeps the temporary
        // guard alive for the whole block rather than for the expression.
        if let Some(stale) = self.snapshot() {
            if !stale.covers(now) {
                // The window closed while the mount still holds the grant.
                self.clear();
                self.record(JournalEvent::Expired, now, &stale, "window closed");
            }
        }

        let Some((raw, signature)) = self.read_material() else {
            if let Some(stale) = self.snapshot() {
                self.clear();
                self.record(
                    JournalEvent::Revoked,
                    now,
                    &stale,
                    "grant removed from the mount",
                );
            }
            *self
                .last_rejection
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
            return;
        };

        match verify_grant(&raw, &signature, &self.trust_root, now) {
            Ok(verified) => {
                *self
                    .last_rejection
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                let previous = self.snapshot();
                if previous.as_ref().map(|g| g.digest.as_str()) == Some(verified.digest.as_str()) {
                    return;
                }
                if let Some(previous) = previous {
                    self.clear();
                    self.record(
                        JournalEvent::Revoked,
                        now,
                        &previous,
                        "superseded by another grant",
                    );
                }
                let detail = format!(
                    "admission enforcement suspended for {} more seconds",
                    verified.remaining_seconds(now)
                );
                // Journal first. If the entry cannot be written the grant does
                // not come into force: an unrecordable suspension is the one
                // this mechanism exists to make impossible.
                if !self.record(JournalEvent::Activated, now, &verified, &detail) {
                    return;
                }
                self.activations.fetch_add(1, Ordering::Relaxed);
                *self.active.write().unwrap_or_else(|e| e.into_inner()) = Some(verified);
            }
            Err(err) => {
                self.rejections.fetch_add(1, Ordering::Relaxed);
                let key = format!("{}:{err}", ferrum_crypto::bundle_digest(&raw).as_str());
                let repeat = {
                    let mut last = self
                        .last_rejection
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let seen = last.as_deref() == Some(key.as_str());
                    if !seen {
                        *last = Some(key);
                    }
                    seen
                };
                if !repeat {
                    self.write_entry(JournalEvent::Rejected, now, None, "", &err.to_string());
                }
            }
        }
    }

    /// The grant this process holds, window unchecked, as an owned value: the
    /// guard is released before the caller does anything with it.
    fn snapshot(&self) -> Option<VerifiedGrant> {
        self.active
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn clear(&self) {
        *self.active.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Both files, or nothing. A mount with only one half of a signed pair is
    /// mid-update, not a grant.
    fn read_material(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let raw = read_bounded(&self.dir.join(GRANT_FILE))?;
        let sig_text = read_bounded(&self.dir.join(SIGNATURE_FILE))?;
        let hex = String::from_utf8(sig_text).ok()?;
        let signature = decode_hex(hex.trim())?;
        Some((raw, signature))
    }

    fn record(
        &self,
        event: JournalEvent,
        now: DateTime<Utc>,
        grant: &VerifiedGrant,
        detail: &str,
    ) -> bool {
        self.write_entry(event, now, Some(&grant.grant), &grant.digest, detail)
    }

    fn write_entry(
        &self,
        event: JournalEvent,
        now: DateTime<Utc>,
        grant: Option<&ferrum_breakglass::Grant>,
        digest: &str,
        detail: &str,
    ) -> bool {
        let mut journal = self.journal.lock().unwrap_or_else(|e| e.into_inner());
        match journal.append(event, now, grant, digest, detail) {
            Ok(line) => {
                // The second copy, off this filesystem. The chain makes an edit
                // visible; only a copy somewhere else makes a truncation
                // visible.
                eprintln!("ferrum-admission: break-glass {line}");
                *self.journal_head.write().unwrap_or_else(|e| e.into_inner()) =
                    journal.head().to_string();
                self.journal_entries.store(journal.len(), Ordering::Relaxed);
                *self
                    .journal_broken
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                true
            }
            Err(err) => {
                eprintln!(
                    "ferrum-admission: break-glass journal write failed, enforcement stays on: \
                     {err}"
                );
                *self
                    .journal_broken
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = Some(err.to_string());
                false
            }
        }
    }
}

/// Read a file, refusing one that is larger than a grant can be.
fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_GRANT_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.is_empty() {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Reconcile the mount on a timer, on a thread of its own.
pub fn poll_break_glass(state: Arc<BreakGlass>, every: Duration) {
    std::thread::spawn(move || loop {
        state.poll(Utc::now());
        std::thread::sleep(every);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_breakglass::{Grant, GRANT_SCHEMA, GRANT_SCHEMA_VERSION, SCOPE_ADMISSION};

    const SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("timestamp")
    }

    fn dir(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ferrum-admission-bg-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("dir");
        path
    }

    fn grant(id: &str) -> Grant {
        Grant {
            schema: GRANT_SCHEMA.into(),
            schema_version: GRANT_SCHEMA_VERSION.into(),
            id: id.into(),
            scope: SCOPE_ADMISSION.into(),
            subject: "sre-oncall@example.test".into(),
            issuer: "sec-arch@example.test".into(),
            ticket: "INC-4471".into(),
            reason: "every replica unschedulable".into(),
            issued_at: t(0),
            expires_at: t(3600),
        }
    }

    fn write_grant(mount: &Path, g: &Grant, seed: &[u8; 32]) {
        let raw = serde_json::to_vec(g).expect("serialize");
        let sig = ferrum_crypto::sign_break_glass(&raw, seed).expect("sign");
        std::fs::write(mount.join(GRANT_FILE), &raw).expect("grant");
        std::fs::write(mount.join(SIGNATURE_FILE), hex_of(&sig)).expect("sig");
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn armed(tag: &str) -> (BreakGlass, PathBuf, PathBuf) {
        let mount = dir(tag);
        let journal = mount.join("break-glass.jsonl");
        let pk = ferrum_crypto::public_key_from_secret(&SK).expect("pk");
        let bg = BreakGlass::arm(&mount, &journal, pk, "ferrum-admission/test").expect("arm");
        (bg, mount, journal)
    }

    /// The whole life of one break-glass, read back from the chain afterwards.
    #[test]
    fn a_grant_activates_expires_and_leaves_a_chain_that_verifies() {
        let (bg, mount, journal) = armed("lifecycle");
        assert!(bg.active(t(10)).is_none(), "armed is not active");
        assert_eq!(bg.journal_head(), ferrum_breakglass::GENESIS_HASH);

        write_grant(&mount, &grant("bg-1"), &SK);
        bg.poll(t(10));
        let held = bg.active(t(10)).expect("the grant is in force");
        assert_eq!(held.grant.id, "bg-1");
        assert_eq!(bg.activations(), 1);
        assert_ne!(bg.journal_head(), ferrum_breakglass::GENESIS_HASH);

        // A second poll inside the window is not a second activation.
        bg.poll(t(20));
        assert_eq!(bg.activations(), 1, "the same grant re-activated");
        assert_eq!(bg.journal_entries(), 1);

        // Past the window: not active, and the journal says why.
        assert!(bg.active(t(3600)).is_none());
        bg.poll(t(3601));
        bg.poll(t(3602));
        let entries = Journal::verify_path(&journal).expect("the chain verifies");
        assert_eq!(entries[0].event, "activated");
        assert_eq!(entries[0].subject, "sre-oncall@example.test");
        assert_eq!(entries[0].ticket, "INC-4471");
        assert_eq!(entries[1].event, "expired");
        // Third entry, and it is not noise: the operator left the grant in the
        // mount after its window, and the document sitting there is now one
        // this process refuses. Saying so once is the record that the cleanup
        // step of the runbook was not done. Once, not once per second — the
        // second poll adds nothing.
        assert_eq!(entries.len(), 3, "{entries:#?}");
        assert_eq!(entries[2].event, "rejected");
        assert!(entries[2].detail.contains("expired at"), "{:?}", entries[2]);
        assert!(bg.active(t(3602)).is_none());
        let _ = std::fs::remove_dir_all(&mount);
    }

    /// A grant nobody with the key issued does not suspend anything, and the
    /// attempt is on the record.
    #[test]
    fn a_forged_grant_is_refused_journalled_once_and_counted_every_time() {
        let (bg, mount, journal) = armed("forged");
        let mut wrong = SK;
        wrong[0] ^= 0xff;
        write_grant(&mount, &grant("bg-forged"), &wrong);

        for n in 0..5 {
            bg.poll(t(10 + n));
        }
        assert!(
            bg.active(t(12)).is_none(),
            "a forged grant suspended enforcement"
        );
        assert_eq!(bg.activations(), 0);
        assert_eq!(
            bg.rejections(),
            5,
            "every poll must count, or the retry rate is invisible"
        );
        let entries = Journal::verify_path(&journal).expect("verify");
        assert_eq!(
            entries.len(),
            1,
            "an unchanged refusal was journalled more than once: {entries:#?}"
        );
        assert_eq!(entries[0].event, "rejected");
        assert_eq!(
            entries[0].grant_id, "",
            "an unverified document must not have its fields quoted as though somebody asserted \
             them"
        );
        assert!(entries[0].detail.contains("signature"), "{:?}", entries[0]);
        let _ = std::fs::remove_dir_all(&mount);
    }

    /// Removing the grant from the mount ends the break-glass early, and that
    /// is a different journal event from the clock ending it.
    #[test]
    fn removing_the_grant_revokes_it_and_says_so() {
        let (bg, mount, journal) = armed("revoke");
        write_grant(&mount, &grant("bg-2"), &SK);
        bg.poll(t(10));
        assert!(bg.active(t(10)).is_some());

        std::fs::remove_file(mount.join(GRANT_FILE)).expect("rm");
        bg.poll(t(20));
        assert!(bg.active(t(20)).is_none());
        let entries = Journal::verify_path(&journal).expect("verify");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].event, "revoked");
        assert_eq!(entries[1].grant_id, "bg-2");
        let _ = std::fs::remove_dir_all(&mount);
    }

    /// Half a mount is not a grant: the signature file alone, or the document
    /// alone, must not reach the verifier as an empty other half.
    #[test]
    fn a_half_written_mount_is_not_a_grant_and_is_not_a_rejection() {
        let (bg, mount, journal) = armed("half");
        let g = grant("bg-3");
        let raw = serde_json::to_vec(&g).expect("serialize");
        std::fs::write(mount.join(GRANT_FILE), &raw).expect("grant");
        bg.poll(t(10));
        assert!(bg.active(t(10)).is_none());
        assert_eq!(
            bg.rejections(),
            0,
            "an incomplete mount was read as a forged grant"
        );
        assert_eq!(std::fs::metadata(&journal).expect("journal").len(), 0);
        let _ = std::fs::remove_dir_all(&mount);
    }

    /// Arming fails, loudly, when the journal cannot be written — before the
    /// process starts serving.
    #[test]
    fn arming_without_a_writable_journal_fails_at_startup() {
        let mount = dir("nojournal");
        let unwritable = mount.join("no-such-directory").join("break-glass.jsonl");
        let pk = ferrum_crypto::public_key_from_secret(&SK).expect("pk");
        let err = BreakGlass::arm(&mount, &unwritable, pk.clone(), "c")
            .expect_err("armed with a journal it cannot write");
        assert!(err.to_string().contains("break-glass journal"), "{err}");

        // And a trust root that is not a key is refused here rather than at
        // the first grant.
        let err = BreakGlass::arm(&mount, mount.join("j.jsonl"), vec![0u8; 4], "c")
            .expect_err("armed with a four-byte trust root");
        assert!(err.to_string().contains("trust root"), "{err}");
        let _ = std::fs::remove_dir_all(&mount);
    }
}
