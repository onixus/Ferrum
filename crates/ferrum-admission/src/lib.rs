//! Admission evaluation of a compiled `FADM` program.
//!
//! Trust roots travel in the bundle. The admit hot path does not fetch Rekor,
//! OCI, or CT logs. Missing, truncated, unverifiable, or ABI-mismatched
//! programs deny — never allow-by-default.

#![deny(unsafe_code)]

mod break_glass;
mod bundle;
mod encoding;
mod eval;
mod labels;
mod metrics;
mod program;
mod review;
mod server;
mod serving_cert;
mod subject;

use chrono::{DateTime, Utc};
use ferrum_api::PolicyExceptionSpec;

/// The latency budget this product claims, in seconds: **p99 of one
/// AdmissionReview inside `WebhookState::handle` is at most 5 ms.**
///
/// What the number is about, exactly, because a budget whose subject is vague
/// is a budget nobody can hold anyone to. It covers the span
/// `ferrum_admission_review_seconds` measures and nothing else: JSON in,
/// subject built, image signature verified against the bundle trust roots,
/// program evaluated under the read lock, response encoded. The socket, the
/// TLS handshake and the API server's own queueing are outside it — they are
/// not this process's to promise, and `timeoutSeconds: 5` on the webhook
/// configuration is what covers them, three orders of magnitude away.
///
/// Why a bucket boundary and not a round number of the author's choosing: the
/// only measurement of this that exists in production is
/// `LATENCY_BUCKETS_SECONDS`, so a budget between two boundaries could only be
/// checked by interpolating inside a bucket — a claim finer than the instrument
/// that has to hold it. `latency_gate.rs::the_budget_is_a_boundary_the_shipped_histogram_can_decide`
/// refuses one that is not.
///
/// Why 5 ms and not the measurement: on the machine that measured it the p99
/// sits far below (see `docs/MVP-1-BOUNDARY.md` for the number, the hardware
/// and the build profile). The budget is deliberately not the measurement. It
/// has to hold on every machine the gate runs on — an aarch64 Jenkins
/// container, a shared two-core GitHub runner under an unknown neighbour, a
/// developer's laptop mid `cargo build` — and a threshold that only holds on
/// the fastest of those is a gate that gets switched off the first time it is
/// right. What it must never be is so loose that it cannot fail: the shipped
/// `timeoutSeconds` is 5 s, so this is a thousandth of the point where the API
/// server gives up, and a run that could not meet it would mean this process
/// grew work on the request path it does not admit to — a network call, a disk
/// read, a lock held across I/O. That is the change this number is here to
/// catch.
///
/// **This is the number for an optimized build**, because that is the only
/// build an operator ever runs: the images are built `--release`. See
/// [`REVIEW_LATENCY_BUDGET_DEBUG_SECONDS`] for the other one, and for why there
/// are two.
pub const REVIEW_LATENCY_BUDGET_SECONDS: f64 = 0.005;

/// The same budget for an unoptimized build, in seconds: 50 ms.
///
/// It exists because the gate that measures this runs inside `cargo test`, and
/// `cargo test` is a debug build unless somebody says otherwise. A debug build
/// of the request path is an order of magnitude slower than a release one and
/// almost all of the difference is one thing: the Ed25519 verification of the
/// image signature, which is real work the webhook really does and must not be
/// stubbed out to make a number look better. Holding a debug build to the
/// release budget would be asserting a number no operator will ever experience
/// against an artefact nobody ships, and on a shared two-core runner it would
/// be a coin flip — which is how a gate ends up with an `#[ignore]` on it.
///
/// So there are two declared numbers and the gate picks by
/// `cfg!(debug_assertions)`, which is a property of the artefact being measured
/// and not of the machine or the weather. That distinction is the whole reason
/// this is not the skip it might look like: every run still measures, still
/// asserts, and still fails on a regression — 50 ms is fifty times the debug
/// p99 measured on the machine in the boundary, so an order of magnitude of new
/// work on the request path is caught here too. And the release number, the one
/// this product actually claims, is not left to chance: the CI stage
/// `Security: admission latency` runs this gate `--release` in both CIs, so the
/// claim is exercised on every build rather than only on whoever remembers.
pub const REVIEW_LATENCY_BUDGET_DEBUG_SECONDS: f64 = 0.05;

/// The budget that applies to *this* build.
///
/// A function and not a `cfg!` at each call site: the gate, the messages it
/// prints and anything that reports the budget later must agree about which
/// number is in force, and three copies of the same `cfg!` is how they stop
/// agreeing.
pub const fn review_latency_budget_seconds() -> f64 {
    if cfg!(debug_assertions) {
        REVIEW_LATENCY_BUDGET_DEBUG_SECONDS
    } else {
        REVIEW_LATENCY_BUDGET_SECONDS
    }
}

pub use break_glass::{poll_break_glass, BreakGlass, GRANT_FILE, SIGNATURE_FILE};
pub use bundle::{
    encode_fsig, extract_fsig, load_bundle, load_digest, load_path, load_signed, load_source,
    load_source_with_expected, parse_trust_root, read_exceptions_path, read_source_path,
    verify_exceptions_fsig, ExtractedFsig, BUNDLE_DIGEST_KEY, BUNDLE_FSIG_KEY, EXCEPTIONS_FSIG_KEY,
    KUBELET_DATA_DIR, SIGNED_FORMAT, SIGNED_MAGIC,
};
pub use eval::{
    admit, cluster_scoped_kind, AdmissionDecision, AdmissionSubject, Patch, CLUSTER_SCOPED_KINDS,
    RULE_ADDED_CAPABILITIES, RULE_ALLOW_PRIVILEGE_ESCALATION, RULE_CLUSTER_ADMIN_BIND,
    RULE_HOST_IPC, RULE_HOST_NETWORK, RULE_HOST_PATH, RULE_HOST_PID, RULE_LATEST_TAG,
    RULE_PRIVILEGED, RULE_REGISTRY_ALLOW, RULE_REQUIRE_DIGEST, RULE_RUN_AS_ROOT, RULE_UNSIGNED,
    RULE_WILDCARDS_RBAC,
};
pub use ferrum_ids::Digest;
#[cfg(feature = "apiserver")]
pub use labels::WatchedLabels;
pub use labels::{
    ClusterLabels, ColdLabels, LabelSource, LabelWarmth, LabelWarmthCheck, StaticLabels,
};
pub use metrics::{exposition, metrics_text, spawn_metrics};
pub use program::{parse_program, AdmissionProgram, ADMISSION_ABI, ADMISSION_MAGIC};
pub use review::{
    break_glass_message, handle_review_bytes, BreakGlassGrant, ReviewConfig, ReviewReply,
};
pub use server::{poll_bundle_file, poll_exceptions_file, serve, serve_listener, WebhookState};
pub use serving_cert::{
    certificate_facts, poll_serving_cert, CertFacts, Issuer, TlsSource, SERVING_CERT_WARN_DAYS,
};
pub use subject::{subject_from_object, IMAGE_SIGNATURES_ANNOTATION, IMAGE_SIGNATURE_ANNOTATION};

/// Parse `fadm` and evaluate. Invalid or missing program → deny (fail closed).
pub fn admit_bytes(
    fadm: &[u8],
    subject: &AdmissionSubject,
    exceptions: &[PolicyExceptionSpec],
    now: DateTime<Utc>,
) -> AdmissionDecision {
    match parse_program(fadm) {
        Ok(program) => admit(&program, subject, exceptions, now),
        Err(err) => AdmissionDecision::fail_closed(err),
    }
}

/// Verify signature, then evaluate. Verify failure → deny (fail closed).
pub fn admit_signed(
    raw: &[u8],
    signature: &[u8],
    public_key: &[u8],
    subject: &AdmissionSubject,
    exceptions: &[PolicyExceptionSpec],
    now: DateTime<Utc>,
) -> AdmissionDecision {
    match load_signed(raw, signature, public_key) {
        Ok(program) => admit(&program, subject, exceptions, now),
        Err(err) => AdmissionDecision::fail_closed(err),
    }
}

/// Verify digest, then evaluate. Mismatch or empty expected → deny (fail closed).
pub fn admit_digest(
    raw: &[u8],
    expected: &Digest,
    subject: &AdmissionSubject,
    exceptions: &[PolicyExceptionSpec],
    now: DateTime<Utc>,
) -> AdmissionDecision {
    match load_digest(raw, expected) {
        Ok(program) => admit(&program, subject, exceptions, now),
        Err(err) => AdmissionDecision::fail_closed(err),
    }
}
