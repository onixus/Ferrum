//! The record of every break-glass, as a hash chain.
//!
//! # Why a chain and not a log line
//!
//! The threat model does not trust root on the node, and a break-glass journal
//! is the first file that root would want to edit: the whole value of the
//! record is that it says enforcement was off between two timestamps and who
//! said so. A plain append-only file answers "was a line deleted?" with
//! nothing. This one answers it with a broken link.
//!
//! Each [`Entry`] carries `seq`, the `prev` hash of the entry before it, and
//! its own `hash` over everything else. [`Journal::verify_lines`] recomputes
//! the whole chain. Altering a field changes that entry's hash and orphans
//! every entry after it; deleting an entry breaks the link across the gap;
//! reordering breaks both. Truncating the *tail* is the one edit a chain alone
//! cannot see — which is what the anchors in the crate docs are for, and why
//! [`Journal::append`] hands the caller the line to print as well as writing it.
//!
//! # Why an unwritable journal refuses the break-glass
//!
//! [`Journal::open`] fails on a file it cannot read, cannot verify or cannot
//! extend, and every caller in this tree treats that failure as "do not break
//! glass". That is a deliberate trade in the direction that looks wrong: it
//! means a full disk can stand between an operator and the switch that ends a
//! cluster-wide outage. It is still the right way round. The switch is not the
//! only way out of that outage — the API server will always let somebody delete
//! a `ValidatingWebhookConfiguration`, and the runbook says so in the same
//! breath — whereas a suspension with no record is indistinguishable, forever
//! and to everybody, from the thing an attacker does after taking the
//! namespace. A journal that yields under pressure is a journal whose absence
//! nobody can ever explain, and an incident review that cannot rule out an
//! attacker has to assume one.
//!
//! The consequence is an install-time obligation, not an incident-time
//! surprise: the process refuses to start with break-glass configured and a
//! journal it cannot write, so the fault surfaces on `kubectl rollout status`
//! and not at 03:00.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ferrum_common::{FerrumError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::Grant;

/// Name of the journal record schema, carried in every entry for the same
/// reason `EventEnvelope` carries one: the file is read by somebody who has
/// only the file.
pub const JOURNAL_SCHEMA: &str = "ferrum.io/break-glass-journal";

/// Version of that schema.
pub const JOURNAL_SCHEMA_VERSION: &str = "1.0";

/// `prev` of the first entry: 64 zeros. A real SHA-256 of nothing would be a
/// value an attacker can also produce; a fixed sentinel makes "this file starts
/// at the beginning" a thing the verifier states rather than infers.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What happened. Four values, and the third is the one that is easy to leave
/// out and expensive to have left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalEvent {
    /// A verified grant came into force in this process.
    Activated,
    /// A grant that had been in force reached `expiresAt` and enforcement
    /// resumed. Written by the same process that wrote `Activated`, so a
    /// journal whose last entry is an activation is a process that died inside
    /// the window — which is a fact worth being able to read.
    Expired,
    /// A grant document was present and was **not** honoured: a bad signature,
    /// an expired window, a scope this build does not act on, a malformed
    /// field. Journalled because the record of attempts is half of what the
    /// repudiation row is about, and because a forged grant that leaves no
    /// trace is a probe an attacker can repeat.
    Rejected,
    /// The mount stopped offering a grant while one was in force: the operator
    /// ended the break-glass early. Distinct from `Expired`, which is the clock
    /// doing it.
    Revoked,
}

impl JournalEvent {
    pub fn name(self) -> &'static str {
        match self {
            JournalEvent::Activated => "activated",
            JournalEvent::Expired => "expired",
            JournalEvent::Rejected => "rejected",
            JournalEvent::Revoked => "revoked",
        }
    }
}

/// One line of the journal.
///
/// Field order is the serialisation order and the hashing order; `serde_json`
/// writes a struct's fields in declaration order, so the bytes hashed are the
/// bytes written minus the `hash` field itself. That is why `hash` is last and
/// why it is skipped when hashing: a self-referential field cannot be inside
/// its own digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub schema: String,
    pub schema_version: String,
    /// Position in the chain, from zero. Present as well as the hash link: a
    /// gap in the numbering names *how many* entries went missing, which the
    /// links alone cannot say.
    pub seq: u64,
    /// `hash` of the previous entry, or [`GENESIS_HASH`].
    pub prev: String,
    pub ts: DateTime<Utc>,
    /// Which process wrote this — `ferrum-admission`, and its pod name when it
    /// has one. Two replicas keep two chains, and an entry that does not say
    /// which is an entry a reader has to guess about.
    pub component: String,
    pub event: String,
    pub scope: String,
    pub grant_id: String,
    /// SHA-256 of the signed grant bytes, or empty when there were none to
    /// verify.
    pub grant_digest: String,
    pub subject: String,
    pub issuer: String,
    pub ticket: String,
    pub reason: String,
    pub issued_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    /// Free text belonging to the *event* rather than to the grant: the
    /// verification error on a rejection, empty otherwise.
    pub detail: String,
    /// SHA-256, lowercase hex, over the JSON of every field above.
    #[serde(default)]
    pub hash: String,
}

impl Entry {
    /// The digest this entry should carry, computed from everything but the
    /// digest.
    pub fn computed_hash(&self) -> Result<String> {
        let mut bare = self.clone();
        bare.hash = String::new();
        let bytes = serde_json::to_vec(&bare).map_err(|err| {
            FerrumError::Degraded(format!(
                "break-glass journal entry will not serialise: {err}"
            ))
        })?;
        // The `hash` key is present and empty in `bytes`; that is fine and
        // deliberate — it is a constant suffix of every entry, so it neither
        // hides a field nor lets two different entries collide.
        Ok(hex(Sha256::digest(&bytes).as_slice()))
    }

    fn one_line(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|err| {
            FerrumError::Degraded(format!(
                "break-glass journal entry will not serialise: {err}"
            ))
        })
    }
}

/// An append-only hash chain in a file.
#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    component: String,
    next_seq: u64,
    head: String,
}

impl Journal {
    /// Open, read and verify the existing chain, then hold the file for
    /// appends.
    ///
    /// Refuses rather than repairs. A chain that does not verify is either
    /// corruption or an edit, and this code cannot tell which; starting a fresh
    /// chain beside it would erase the evidence of whichever it was, and
    /// appending to it would sign the operator's name onto a file somebody else
    /// has already written in.
    pub fn open(path: impl Into<PathBuf>, component: impl Into<String>) -> Result<Self> {
        let path = path.into();
        let component = component.into();
        let (next_seq, head) = match File::open(&path) {
            Ok(file) => {
                let mut lines = Vec::new();
                for line in BufReader::new(file).lines() {
                    let line = line.map_err(|err| {
                        FerrumError::Degraded(format!(
                            "break-glass journal {} is unreadable: {err}",
                            path.display()
                        ))
                    })?;
                    if !line.trim().is_empty() {
                        lines.push(line);
                    }
                }
                let entries = Self::verify_lines(&lines)?;
                match entries.last() {
                    Some(last) => (last.seq + 1, last.hash.clone()),
                    None => (0, GENESIS_HASH.to_string()),
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (0, GENESIS_HASH.to_string()),
            Err(err) => {
                return Err(FerrumError::Degraded(format!(
                    "break-glass journal {} cannot be opened: {err}",
                    path.display()
                )))
            }
        };
        let journal = Journal {
            path,
            component,
            next_seq,
            head,
        };
        // Prove the append, at start-up, on the real file. Opening for append
        // and never writing would leave "can this process journal?" answered
        // for the first time during the incident.
        journal.probe_writable()?;
        Ok(journal)
    }

    /// Hash of the last entry, or [`GENESIS_HASH`]. This is the value an
    /// operator copies somewhere the node cannot reach; see the crate docs on
    /// anchors.
    pub fn head(&self) -> &str {
        &self.head
    }

    /// Number of entries written to this chain, ever.
    pub fn len(&self) -> u64 {
        self.next_seq
    }

    pub fn is_empty(&self) -> bool {
        self.next_seq == 0
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append an entry about `grant`, returning the exact line written.
    ///
    /// The caller is expected to also put that line somewhere off this
    /// filesystem — stderr is what the shipped components do. The chain makes
    /// an edit visible; only a second copy makes a truncation visible.
    pub fn append(
        &mut self,
        event: JournalEvent,
        now: DateTime<Utc>,
        grant: Option<&Grant>,
        grant_digest: &str,
        detail: &str,
    ) -> Result<String> {
        let mut entry = Entry {
            schema: JOURNAL_SCHEMA.into(),
            schema_version: JOURNAL_SCHEMA_VERSION.into(),
            seq: self.next_seq,
            prev: self.head.clone(),
            ts: now,
            component: self.component.clone(),
            event: event.name().into(),
            scope: grant.map(|g| g.scope.clone()).unwrap_or_default(),
            grant_id: grant.map(|g| g.id.clone()).unwrap_or_default(),
            grant_digest: grant_digest.to_string(),
            subject: grant.map(|g| g.subject.clone()).unwrap_or_default(),
            issuer: grant.map(|g| g.issuer.clone()).unwrap_or_default(),
            ticket: grant.map(|g| g.ticket.clone()).unwrap_or_default(),
            reason: grant.map(|g| g.reason.clone()).unwrap_or_default(),
            issued_at: grant.map(|g| g.issued_at),
            expires_at: grant.map(|g| g.expires_at),
            detail: sanitize(detail),
            hash: String::new(),
        };
        entry.hash = entry.computed_hash()?;
        let line = entry.one_line()?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|err| {
                FerrumError::Degraded(format!(
                    "break-glass journal {} cannot be appended to: {err}",
                    self.path.display()
                ))
            })?;
        writeln!(file, "{line}").map_err(|err| {
            FerrumError::Degraded(format!(
                "break-glass journal {}: write failed: {err}",
                self.path.display()
            ))
        })?;
        // Not best-effort. An entry that is in the page cache when the node
        // loses power is an entry that never existed, and the window it opens
        // is the window nobody can account for afterwards.
        file.sync_all().map_err(|err| {
            FerrumError::Degraded(format!(
                "break-glass journal {}: fsync failed: {err}",
                self.path.display()
            ))
        })?;
        self.head = entry.hash;
        self.next_seq += 1;
        Ok(line)
    }

    /// Decode and check a whole chain: numbering, links and digests.
    ///
    /// Public because verifying somebody else's journal is the operation an
    /// incident review performs, and it must be the same code that wrote it.
    pub fn verify_lines(lines: &[String]) -> Result<Vec<Entry>> {
        let mut out: Vec<Entry> = Vec::with_capacity(lines.len());
        let mut prev = GENESIS_HASH.to_string();
        for (index, line) in lines.iter().enumerate() {
            let entry: Entry = serde_json::from_str(line).map_err(|err| {
                FerrumError::Integrity(format!(
                    "break-glass journal line {}: not a journal entry: {err}",
                    index + 1
                ))
            })?;
            if entry.schema != JOURNAL_SCHEMA {
                return Err(FerrumError::Integrity(format!(
                    "break-glass journal line {}: schema {:?} is not {JOURNAL_SCHEMA}",
                    index + 1,
                    entry.schema
                )));
            }
            if entry.seq != index as u64 {
                return Err(FerrumError::Integrity(format!(
                    "break-glass journal line {}: seq {} where {} was expected; {} entr{} \
                     missing or reordered",
                    index + 1,
                    entry.seq,
                    index,
                    entry.seq.abs_diff(index as u64),
                    if entry.seq.abs_diff(index as u64) == 1 {
                        "y is"
                    } else {
                        "ies are"
                    }
                )));
            }
            if entry.prev != prev {
                return Err(FerrumError::Integrity(format!(
                    "break-glass journal line {}: prev {} does not link to the entry before it \
                     ({prev}); the chain has been edited",
                    index + 1,
                    entry.prev
                )));
            }
            let computed = entry.computed_hash()?;
            if computed != entry.hash {
                return Err(FerrumError::Integrity(format!(
                    "break-glass journal line {}: hash {} does not match its own contents \
                     ({computed}); this entry was altered after it was written",
                    index + 1,
                    entry.hash
                )));
            }
            prev = entry.hash.clone();
            out.push(entry);
        }
        Ok(out)
    }

    /// Read and verify a journal file without holding it open.
    pub fn verify_path(path: impl AsRef<Path>) -> Result<Vec<Entry>> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|err| {
            FerrumError::Degraded(format!(
                "break-glass journal {} is unreadable: {err}",
                path.display()
            ))
        })?;
        let lines: Vec<String> = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect();
        Journal::verify_lines(&lines)
    }

    /// Open the file for append and flush nothing, so a directory that is
    /// read-only, full or missing fails here rather than at the first entry.
    fn probe_writable(&self) -> Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|err| {
                FerrumError::Degraded(format!(
                    "break-glass journal {} is not writable: {err}. Break-glass stays off: a \
                     suspension this process cannot record is one nobody can account for later.",
                    self.path.display()
                ))
            })?;
        file.sync_all().map_err(|err| {
            FerrumError::Degraded(format!(
                "break-glass journal {}: the filesystem refused fsync: {err}",
                self.path.display()
            ))
        })
    }
}

/// Journal detail text is the only field that can carry an error message from
/// somewhere else, so it is the only one that has to be made safe here; every
/// field of a `Grant` was checked by `check_invariants` before it got this far.
fn sanitize(text: &str) -> String {
    let mut out: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if out.chars().count() > crate::MAX_FIELD_CHARS {
        out = out.chars().take(crate::MAX_FIELD_CHARS).collect();
        out.push_str("...");
    }
    out
}

fn hex(bytes: &[u8]) -> String {
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
    use crate::tests::{grant, t};

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrum-bg-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        dir.join("break-glass.jsonl")
    }

    #[test]
    fn a_fresh_journal_starts_at_genesis_and_links_every_entry() {
        let path = tmp("chain");
        let mut journal = Journal::open(&path, "ferrum-admission/test").expect("open");
        assert_eq!(journal.head(), GENESIS_HASH);
        assert!(journal.is_empty());

        let g = grant();
        journal
            .append(JournalEvent::Activated, t(1), Some(&g), "sha-1", "")
            .expect("activate");
        let head_after_first = journal.head().to_string();
        assert_ne!(head_after_first, GENESIS_HASH);
        journal
            .append(JournalEvent::Expired, t(3600), Some(&g), "sha-1", "")
            .expect("expire");
        assert_eq!(journal.len(), 2);

        let entries = Journal::verify_path(&path).expect("the chain verifies");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].prev, GENESIS_HASH);
        assert_eq!(entries[1].prev, head_after_first);
        assert_eq!(entries[0].event, "activated");
        assert_eq!(entries[1].event, "expired");
        assert_eq!(entries[0].subject, g.subject);
        assert_eq!(entries[0].ticket, g.ticket);
        assert_eq!(entries[0].expires_at, Some(g.expires_at));

        // A reopened journal continues the chain rather than starting one.
        let reopened = Journal::open(&path, "ferrum-admission/test").expect("reopen");
        assert_eq!(reopened.head(), entries[1].hash);
        assert_eq!(reopened.len(), 2);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// The three edits the chain exists to catch, each on a file that is
    /// otherwise perfectly well-formed JSON.
    #[test]
    fn an_altered_deleted_or_reordered_entry_breaks_the_chain() {
        let path = tmp("tamper");
        let mut journal = Journal::open(&path, "ferrum-admission/test").expect("open");
        let g = grant();
        for n in 0..3 {
            journal
                .append(
                    JournalEvent::Activated,
                    t(n),
                    Some(&g),
                    "sha-1",
                    &format!("entry {n}"),
                )
                .expect("append");
        }
        let text = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        assert_eq!(lines.len(), 3);
        Journal::verify_lines(&lines).expect("control: the intact chain verifies");

        // 1. A field rewritten in place: the entry's own hash stops matching.
        let mut altered = lines.clone();
        altered[1] = altered[1].replace(&g.subject, "somebody-else");
        assert_ne!(altered[1], lines[1], "the edit matched nothing");
        let err = Journal::verify_lines(&altered).expect_err("an edited entry verified");
        assert!(
            err.to_string().contains("altered after it was written"),
            "{err}"
        );

        // 2. A line removed: numbering and links both say so.
        let removed = vec![lines[0].clone(), lines[2].clone()];
        let err = Journal::verify_lines(&removed).expect_err("a deletion verified");
        assert!(err.to_string().contains("seq"), "{err}");

        // 3. Two lines swapped.
        let swapped = vec![lines[1].clone(), lines[0].clone(), lines[2].clone()];
        assert!(
            Journal::verify_lines(&swapped).is_err(),
            "a reorder verified"
        );

        // 4. And the honest control: a hash copied from another entry does not
        //    rescue an edit, because `prev` of the next entry still names the
        //    original.
        let mut relinked = lines.clone();
        relinked[1] = relinked[1].replace(&g.subject, "somebody-else");
        let recomputed: Entry = serde_json::from_str(&relinked[1]).expect("decode");
        let fixed = Entry {
            hash: recomputed.computed_hash().expect("hash"),
            ..recomputed
        };
        relinked[1] = serde_json::to_string(&fixed).expect("encode");
        let err = Journal::verify_lines(&relinked)
            .expect_err("re-hashing one entry rescued a forged chain");
        assert!(err.to_string().contains("does not link"), "{err}");
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// A journal that cannot be opened refuses at open time, which is what
    /// keeps the refusal out of the incident.
    #[test]
    fn a_journal_that_cannot_be_written_is_a_refusal_and_not_a_warning() {
        let missing = std::env::temp_dir()
            .join("ferrum-bg-no-such-dir-6f3a1c")
            .join("nested")
            .join("break-glass.jsonl");
        let _ = std::fs::remove_dir_all(missing.parent().expect("dir"));
        let err = Journal::open(&missing, "ferrum-admission/test")
            .expect_err("a journal in a directory that does not exist opened");
        assert!(
            err.to_string().contains("break-glass journal"),
            "the refusal must name what it is about: {err}"
        );

        // A file that exists and is not a chain is refused too, rather than
        // being appended to as though it were one.
        let path = tmp("garbage");
        std::fs::write(&path, "not json\n").expect("write");
        assert!(Journal::open(&path, "c").is_err());
        std::fs::write(&path, "{\"schema\":\"example.com/other\"}\n").expect("write");
        assert!(Journal::open(&path, "c").is_err());
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// A rejected grant is a journal entry. Without this the file records only
    /// what succeeded, and a repeated forgery attempt leaves nothing at all.
    #[test]
    fn a_rejected_grant_is_recorded_with_why() {
        let path = tmp("rejected");
        let mut journal = Journal::open(&path, "ferrum-admission/test").expect("open");
        journal
            .append(
                JournalEvent::Rejected,
                t(5),
                None,
                "",
                "break-glass Ed25519 signature verification failed",
            )
            .expect("append");
        let entries = Journal::verify_path(&path).expect("verify");
        assert_eq!(entries[0].event, "rejected");
        assert_eq!(entries[0].grant_id, "", "an unverified grant names nobody");
        assert!(entries[0].detail.contains("signature verification failed"));

        // A detail carrying a newline cannot become a second line.
        journal
            .append(
                JournalEvent::Rejected,
                t(6),
                None,
                "",
                "line one\nline two\r\n{\"seq\":9}",
            )
            .expect("append");
        let text = std::fs::read_to_string(&path).expect("read");
        assert_eq!(
            text.lines().filter(|l| !l.trim().is_empty()).count(),
            2,
            "a control character in `detail` forged a line:\n{text}"
        );
        Journal::verify_path(&path).expect("still verifies");
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
}
