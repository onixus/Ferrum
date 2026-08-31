//! Break-glass: suspending FERRUM's own enforcement, and the record of it.
//!
//! The threat model in `docs/rfc/FERRUM-RFC-02-architecture.md` §C has one row
//! for this, and it names the countermeasure rather than the attack:
//!
//! | Repudiation | «я не снимал enforce» | journal + IdP на break-glass |
//!
//! Two words, and only one of them is a thing this tree can be. What is here
//! and what is not is stated in [`README_BOUNDARY`], in one place, because a
//! break-glass whose limits live in a reviewer's head is a break-glass whose
//! limits are discovered during the incident.
//!
//! # What break-glass is for
//!
//! `failurePolicy: Fail` is the point of this product and its worst failure
//! mode at the same time. When the webhook cannot answer — every replica
//! unschedulable, a serving certificate that expired, a bundle mount that
//! stopped resolving — the API server refuses every Pod creation in scope, and
//! the cluster cannot even schedule the replacement webhook. The operator's
//! way out today is `kubectl delete validatingwebhookconfiguration`, which
//! works, takes seconds, and leaves nothing behind except a line in an API
//! server audit log that most clusters do not keep and that this product
//! neither writes nor reads. That is the repudiation row: enforcement was off
//! for forty minutes and nothing in the enforcement plane knows.
//!
//! So break-glass here is not a new capability. It is the *same* suspension,
//! moved inside the product so that taking it costs a signature and produces a
//! record.
//!
//! # Three properties, and none of them is optional
//!
//! 1. **Authenticated.** A [`Grant`] is bytes signed under
//!    [`ferrum_crypto::BREAK_GLASS_CONTEXT`], verified against a trust root the
//!    operator configured. Whoever can edit a Secret in the namespace cannot
//!    mint one; whoever holds the key can. The key is deliberately *not* the
//!    bundle-signing key — see that constant for why.
//! 2. **Bounded.** `expiresAt` is required and no more than
//!    [`MAX_GRANT_SECONDS`] after `issuedAt`. The policy invariants already say
//!    an `exception` must carry a TTL of at most 90 days; a break-glass is the
//!    same thing under more pressure and less review, so it gets the same rule
//!    with a much shorter ceiling. There is no way to express an open-ended
//!    grant: the field is not optional, the ceiling is not a warning, and a
//!    grant that has run out is refused by the same code that refuses a forged
//!    one.
//! 3. **Journalled, or refused.** Every activation, every expiry and every
//!    *rejected* grant is appended to a hash-chained [`Journal`]. A component
//!    that cannot write its journal does not break glass — see
//!    [`Journal::open`]. An emergency switch that leaves no trace is worse than
//!    no emergency switch, because the second at least cannot be used quietly.
//!
//! # What the journal proves, and what it does not
//!
//! The chain proves *self-consistency*: an entry cannot be altered, removed or
//! reordered without breaking a `prev`/`hash` link, and the break is visible to
//! anybody reading the file. What it cannot do on its own is prove that the
//! whole file was not replaced — a chain rewritten from genesis by somebody
//! with write access verifies perfectly. Tamper-evidence needs an *anchor*: one
//! copy of one head hash, held somewhere the person rewriting the file cannot
//! reach.
//!
//! This crate produces two anchors and assumes neither is sufficient alone:
//! every entry is also written to stderr as one line, which the cluster's log
//! pipeline collects off the node, and the head hash is published as a metric
//! label by whoever embeds the journal, which a Prometheus scrape stores off
//! the node too. Both are outside this crate's control, which is why they are
//! named here as a requirement rather than claimed as a feature.
//!
//! # The part that needs an IdP, stated plainly
//!
//! Verification answers exactly one question: *the holder of key K asserted
//! this*. `subject` is a string the signer chose. Nothing in this tree can tell
//! you that the string names a real person, that the person still works here,
//! that they authenticated today, or that the key was not copied off a laptop
//! in March. Those are the IdP's questions, and answering them requires a
//! system that is reachable, that this product does not ship, and that must not
//! be on the path — a break-glass that fails when the identity provider is
//! unreachable fails in precisely the outage it exists for.
//!
//! The boundary is therefore: **FERRUM proves key custody and bounds the
//! window; an external IdP or PKI is what binds a key to a human**, by issuing
//! break-glass keys to named people and revoking them when those people leave.
//! `subject`, `issuer` and `ticket` are the fields that join a journal entry to
//! that external record; they are mandatory and non-empty for that reason and
//! for no other.

#![deny(unsafe_code)]

mod journal;

pub use journal::{
    Entry, Journal, JournalEvent, GENESIS_HASH, JOURNAL_SCHEMA, JOURNAL_SCHEMA_VERSION,
};

use chrono::{DateTime, Duration, Utc};
use ferrum_common::{FerrumError, Result};
use serde::{Deserialize, Serialize};

/// The one-paragraph statement of what this mechanism does and does not do,
/// kept as a constant so the operator-facing documents can be checked against
/// it instead of paraphrasing it.
///
/// `break_glass_gate.rs` requires the runbook to carry these sentences. A
/// limitation that is written in a doc comment nobody reads during an incident
/// is not a stated limitation.
pub const README_BOUNDARY: &str = "\
FERRUM проверяет владение ключом и ограничивает окно; связь ключа с человеком \
даёт внешний IdP или PKI, и в этом дереве её нет.";

/// Name of the grant document, carried in the document itself.
pub const GRANT_SCHEMA: &str = "ferrum.io/break-glass-grant";

/// Version of the grant document, `major.minor`.
pub const GRANT_SCHEMA_VERSION: &str = "1.0";

/// The only scope this build honours.
///
/// One value and not an enum with a future in it. A scope this tree parses and
/// nothing acts on would be a switch an operator can throw during an incident
/// that changes nothing — the "заглушка Ok" of an operational surface. When the
/// runtime plane learns to suspend its own reactions, it adds a value here and
/// the code that honours it in the same change.
///
/// What is *not* covered by this scope, and has no other: the node agent's
/// `respond` role. Suspending it is still a DaemonSet operation
/// (`deploy/agent/optional-respond.yaml`), it is not journalled here, and
/// `docs/runbooks/README.md` says so where an operator will read it.
pub const SCOPE_ADMISSION: &str = "admission";

/// Longest window a grant may cover: four hours.
///
/// Not a round number picked for looking cautious. Two things in this tree
/// already have a clock on them and both were consulted. `expiresAt` on a
/// `PolicyException` may run 90 days because a waiver is reviewed, scoped to
/// one policy and one namespace, and demotes a single action. A break-glass is
/// none of those: it is unscoped within its plane, it is taken by one person
/// under pressure without review, and while it holds, this product admits
/// everything. The other clock is the agent's — "CP down ≤ 2ч → last-known-good"
/// — which is the length of outage this system is designed to survive without
/// changing its own behaviour. Four hours is that, doubled: long enough to
/// cover an incident that outlasts the design point plus a handover, short
/// enough that it cannot be forgotten. A longer suspension is a second signature
/// and a second journal entry, which is the intended cost.
pub const MAX_GRANT_SECONDS: i64 = 4 * 60 * 60;

/// Longest any free-text field of a grant may be. The values reach a journal
/// line and a metric label; unbounded ones reach a log pipeline as one record
/// per megabyte.
pub const MAX_FIELD_CHARS: usize = 256;

/// A signed authorisation to suspend one plane of enforcement for a bounded
/// window.
///
/// Every field is required and every field answers one of the three questions
/// the roadmap asks of this mechanism — *кто, когда, на какой срок* — plus the
/// two that make the answer joinable to something outside this product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    /// Always [`GRANT_SCHEMA`]. A document from somewhere else is refused
    /// rather than parsed, for the reason `ferrum-proto` gives at length.
    pub schema: String,
    /// Always [`GRANT_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Identity of this grant, unique to it. It is what the journal, the log
    /// line, the metric and the admission response all key on, so an operator
    /// reading any one of them can find the other three.
    pub id: String,
    /// Which plane is suspended. [`SCOPE_ADMISSION`] and nothing else.
    pub scope: String,
    /// **Кто.** The human this grant is issued to, as the signer named them.
    /// Meaningful only against the external directory that issued the key —
    /// see the module docs.
    pub subject: String,
    /// Who signed. A second name rather than a duplicate of `subject`: an
    /// on-call engineer breaking glass under a key issued by a security team
    /// is the ordinary case, and collapsing the two loses the approval half of
    /// the record.
    pub issuer: String,
    /// The incident or change record this belongs to. Mandatory for the same
    /// reason `PolicyException.ticket` is: it is the join to the system where
    /// the review actually lives, and it is what makes shipping the human names
    /// to a third-party store unnecessary.
    pub ticket: String,
    /// Why, in the operator's own words. Ends up in the journal and on stderr.
    pub reason: String,
    /// **Когда.** Not "when the file was written": a grant is refused before
    /// this instant, so a signature made in advance cannot sit in a repository
    /// waiting to be dropped into a mount.
    pub issued_at: DateTime<Utc>,
    /// **На какой срок.** Required, and at most [`MAX_GRANT_SECONDS`] after
    /// `issued_at`.
    pub expires_at: DateTime<Utc>,
}

/// A grant that verified, together with the bytes it verified over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGrant {
    pub grant: Grant,
    /// SHA-256 of the signed bytes, lowercase hex. The journal records it so a
    /// reader can tell two grants apart even if a signer reuses an `id`.
    pub digest: String,
}

impl VerifiedGrant {
    /// Whether the window covers `now`. Verification already checked this once;
    /// the request path asks again on every review, because a window that is
    /// only checked at load time is a window that ends when somebody restarts
    /// the process.
    pub fn covers(&self, now: DateTime<Utc>) -> bool {
        now >= self.grant.issued_at && now < self.grant.expires_at
    }

    /// Seconds left, floored at zero.
    pub fn remaining_seconds(&self, now: DateTime<Utc>) -> i64 {
        (self.grant.expires_at - now).num_seconds().max(0)
    }
}

/// Verify a grant document against a trust root and a clock.
///
/// Order matters and is not an accident: the signature is checked *first*, so
/// no field of an unverified document is ever parsed into a decision, printed,
/// or journalled as though somebody had asserted it. Everything after it is a
/// refusal of something the key holder really did sign, which is why those
/// refusals carry the grant's own words back to the operator.
pub fn verify_grant(
    raw: &[u8],
    signature: &[u8],
    trust_root: &[u8],
    now: DateTime<Utc>,
) -> Result<VerifiedGrant> {
    ferrum_crypto::verify_break_glass_signature(raw, signature, trust_root)?;
    let grant: Grant = serde_json::from_slice(raw)
        .map_err(|err| FerrumError::Integrity(format!("break-glass grant is not valid: {err}")))?;
    check_invariants(&grant)?;
    if now < grant.issued_at {
        return Err(FerrumError::Integrity(format!(
            "break-glass grant {} is not valid yet: issuedAt {} is in the future",
            grant.id, grant.issued_at
        )));
    }
    if now >= grant.expires_at {
        return Err(FerrumError::Integrity(format!(
            "break-glass grant {} expired at {}",
            grant.id, grant.expires_at
        )));
    }
    Ok(VerifiedGrant {
        digest: ferrum_crypto::bundle_digest(raw).as_str().to_string(),
        grant,
    })
}

/// Everything a grant must satisfy that does not depend on the clock reading.
///
/// Split out so it can be asserted on its own and so the messages say which
/// rule was broken. A grant failing here was signed by a key this deployment
/// trusts: the answer is to reissue it correctly, and the operator needs to
/// know which field.
pub fn check_invariants(grant: &Grant) -> Result<()> {
    if grant.schema != GRANT_SCHEMA {
        return Err(FerrumError::Integrity(format!(
            "not a {GRANT_SCHEMA} document: schema={:?}",
            grant.schema
        )));
    }
    if grant.schema_version != GRANT_SCHEMA_VERSION {
        return Err(FerrumError::Integrity(format!(
            "break-glass grant schemaVersion {:?}: this build speaks {GRANT_SCHEMA_VERSION}",
            grant.schema_version
        )));
    }
    if grant.scope != SCOPE_ADMISSION {
        return Err(FerrumError::Integrity(format!(
            "break-glass scope {:?} is not honoured by this build; the only scope that suspends \
             anything is {SCOPE_ADMISSION:?}",
            grant.scope
        )));
    }
    for (name, value) in [
        ("id", &grant.id),
        ("subject", &grant.subject),
        ("issuer", &grant.issuer),
        ("ticket", &grant.ticket),
        ("reason", &grant.reason),
    ] {
        if value.trim().is_empty() {
            return Err(FerrumError::Integrity(format!(
                "break-glass grant field {name:?} is empty; an unattributable suspension is the \
                 one this journal exists to make impossible"
            )));
        }
        if value.chars().count() > MAX_FIELD_CHARS {
            return Err(FerrumError::Integrity(format!(
                "break-glass grant field {name:?} is longer than {MAX_FIELD_CHARS} characters"
            )));
        }
        if value.chars().any(|c| c.is_control()) {
            return Err(FerrumError::Integrity(format!(
                "break-glass grant field {name:?} carries a control character; it would forge a \
                 second line in the journal it is about to be written to"
            )));
        }
    }
    if grant.expires_at <= grant.issued_at {
        return Err(FerrumError::Integrity(format!(
            "break-glass grant {}: expiresAt {} is not after issuedAt {}",
            grant.id, grant.expires_at, grant.issued_at
        )));
    }
    let window = grant.expires_at - grant.issued_at;
    if window > Duration::seconds(MAX_GRANT_SECONDS) {
        return Err(FerrumError::Integrity(format!(
            "break-glass grant {} covers {} seconds; the ceiling is {MAX_GRANT_SECONDS}. A longer \
             suspension is a second grant and a second journal entry, not a longer window.",
            grant.id,
            window.num_seconds()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 §7.1 test 1 seed; the tree already uses it in `ferrum-crypto`.
    const SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    pub(crate) fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("timestamp")
    }

    pub(crate) fn grant() -> Grant {
        Grant {
            schema: GRANT_SCHEMA.into(),
            schema_version: GRANT_SCHEMA_VERSION.into(),
            id: "bg-2026-08-31-01".into(),
            scope: SCOPE_ADMISSION.into(),
            subject: "sre-oncall@example.test".into(),
            issuer: "sec-arch@example.test".into(),
            ticket: "INC-4471".into(),
            reason: "webhook replicas unschedulable, cluster cannot create pods".into(),
            issued_at: t(0),
            expires_at: t(3600),
        }
    }

    fn signed(grant: &Grant) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let raw = serde_json::to_vec(grant).expect("serialize");
        let sig = ferrum_crypto::sign_break_glass(&raw, &SK).expect("sign");
        let pk = ferrum_crypto::public_key_from_secret(&SK).expect("pk");
        (raw, sig, pk)
    }

    #[test]
    fn a_signed_bounded_grant_verifies_and_carries_its_own_digest() {
        let (raw, sig, pk) = signed(&grant());
        let verified = verify_grant(&raw, &sig, &pk, t(10)).expect("verify");
        assert_eq!(verified.grant.subject, "sre-oncall@example.test");
        assert_eq!(
            verified.digest,
            ferrum_crypto::bundle_digest(&raw).as_str(),
            "the digest must be over the bytes that were signed"
        );
        assert!(verified.covers(t(10)));
        assert_eq!(verified.remaining_seconds(t(10)), 3590);
        assert!(!verified.covers(t(3600)), "the window is half-open");
        assert_eq!(verified.remaining_seconds(t(9999)), 0);
    }

    /// The signature is checked before anything is parsed, so a document that
    /// was not signed never reaches the fields that would be journalled.
    #[test]
    fn an_unsigned_or_tampered_or_foreign_grant_does_not_verify() {
        let (raw, sig, pk) = signed(&grant());
        verify_grant(&raw, &sig, &pk, t(10)).expect("control: the intact one verifies");

        assert!(verify_grant(&raw, &[], &pk, t(10)).is_err(), "unsigned");

        let mut tampered = raw.clone();
        let at = tampered
            .windows(4)
            .position(|w| w == b"3600")
            .or_else(|| {
                String::from_utf8_lossy(&tampered)
                    .find("expiresAt")
                    .map(|_| 0)
            })
            .unwrap_or(0);
        tampered[at] ^= 0x20;
        assert!(
            verify_grant(&tampered, &sig, &pk, t(10)).is_err(),
            "a mutated byte verified"
        );

        // Signed under the bundle domain instead: the same key, the same
        // bytes, and it must not open the glass.
        let bundle_sig = ferrum_crypto::sign_bundle(&raw, &SK).expect("sign");
        assert!(
            verify_grant(&raw, &bundle_sig, &pk, t(10)).is_err(),
            "a policy-bundle signature was accepted as a break-glass grant"
        );

        // Another key entirely.
        let mut other = SK;
        other[0] ^= 0xff;
        let other_pk = ferrum_crypto::public_key_from_secret(&other).expect("pk");
        assert!(verify_grant(&raw, &sig, &other_pk, t(10)).is_err());
    }

    /// The whole point of the TTL rule: there is no way to express a grant that
    /// does not end, and no way to express one that ends too late.
    #[test]
    fn no_grant_can_be_open_ended_or_outlive_the_ceiling() {
        // Absent expiresAt does not decode at all — it is not defaulted to
        // "forever" and not defaulted to anything else.
        let mut doc = serde_json::to_value(grant()).expect("value");
        doc.as_object_mut().expect("object").remove("expiresAt");
        let raw = serde_json::to_vec(&doc).expect("bytes");
        let sig = ferrum_crypto::sign_break_glass(&raw, &SK).expect("sign");
        let pk = ferrum_crypto::public_key_from_secret(&SK).expect("pk");
        let err = verify_grant(&raw, &sig, &pk, t(10)).expect_err("must refuse");
        assert!(
            err.to_string().contains("expiresAt"),
            "a grant with no expiry was refused for the wrong reason: {err}"
        );

        // One second over the ceiling.
        let mut over = grant();
        over.expires_at = over.issued_at + Duration::seconds(MAX_GRANT_SECONDS + 1);
        let err = check_invariants(&over).expect_err("must refuse");
        assert!(err.to_string().contains(&MAX_GRANT_SECONDS.to_string()));
        // Exactly the ceiling is allowed: a boundary the operator can aim at.
        let mut exact = grant();
        exact.expires_at = exact.issued_at + Duration::seconds(MAX_GRANT_SECONDS);
        check_invariants(&exact).expect("the ceiling itself is a legal window");

        // Backwards and zero-length windows.
        let mut backwards = grant();
        backwards.expires_at = backwards.issued_at;
        assert!(check_invariants(&backwards).is_err());
        backwards.expires_at = backwards.issued_at - Duration::seconds(1);
        assert!(check_invariants(&backwards).is_err());
    }

    /// A grant is refused outside its window by the same path that refuses a
    /// forged one, and a grant dated into the future cannot be pre-signed and
    /// parked in a repository.
    #[test]
    fn the_clock_is_checked_on_a_grant_that_is_otherwise_perfect() {
        let (raw, sig, pk) = signed(&grant());
        assert!(verify_grant(&raw, &sig, &pk, t(-1)).is_err(), "not yet");
        verify_grant(&raw, &sig, &pk, t(0)).expect("issuedAt itself is inside");
        verify_grant(&raw, &sig, &pk, t(3599)).expect("the last second is inside");
        assert!(
            verify_grant(&raw, &sig, &pk, t(3600)).is_err(),
            "expiresAt itself must be outside"
        );
    }

    /// Every field that names a person, an approval or a plane is mandatory,
    /// bounded and free of the bytes that would forge a journal line.
    #[test]
    fn an_unattributable_or_line_forging_grant_is_refused() {
        for blank in ["", "   "] {
            for field in ["id", "subject", "issuer", "ticket", "reason"] {
                let mut doc = serde_json::to_value(grant()).expect("value");
                doc[field] = serde_json::Value::String(blank.into());
                let g: Grant = serde_json::from_value(doc).expect("decode");
                let err = check_invariants(&g).expect_err("{field} was allowed to be blank");
                assert!(err.to_string().contains(field), "{field}: {err}");
            }
        }

        let mut forged = grant();
        forged.reason = "ok\n{\"seq\":0,\"event\":\"expired\"}".into();
        let err = check_invariants(&forged).expect_err("a newline was allowed through");
        assert!(err.to_string().contains("control character"), "{err}");

        let mut long = grant();
        long.reason = "x".repeat(MAX_FIELD_CHARS + 1);
        assert!(check_invariants(&long).is_err());

        let mut wrong_scope = grant();
        wrong_scope.scope = "respond".into();
        let err = check_invariants(&wrong_scope).expect_err("an unhonoured scope was accepted");
        assert!(
            err.to_string().contains(SCOPE_ADMISSION),
            "the refusal must name the scope that does work: {err}"
        );

        let mut foreign = grant();
        foreign.schema = "example.com/grant".into();
        assert!(check_invariants(&foreign).is_err());
        let mut future = grant();
        future.schema_version = "2.0".into();
        assert!(check_invariants(&future).is_err());
    }
}
