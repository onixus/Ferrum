//! Admission evaluation of a compiled `FADM` program.
//!
//! Trust roots travel in the bundle. The admit hot path does not fetch Rekor,
//! OCI, or CT logs. Missing, truncated, unverifiable, or ABI-mismatched
//! programs deny — never allow-by-default.

#![deny(unsafe_code)]

mod bundle;
mod encoding;
mod eval;
mod program;
mod review;
mod server;
mod subject;

use chrono::{DateTime, Utc};
use ferrum_api::PolicyExceptionSpec;

pub use bundle::{
    encode_fsig, load_bundle, load_digest, load_signed, parse_trust_root, SIGNED_FORMAT,
    SIGNED_MAGIC,
};
pub use eval::{
    admit, AdmissionDecision, AdmissionSubject, Patch, RULE_ADDED_CAPABILITIES,
    RULE_ALLOW_PRIVILEGE_ESCALATION, RULE_CLUSTER_ADMIN_BIND, RULE_HOST_IPC, RULE_HOST_NETWORK,
    RULE_HOST_PATH, RULE_HOST_PID, RULE_LATEST_TAG, RULE_PRIVILEGED, RULE_REGISTRY_ALLOW,
    RULE_REQUIRE_DIGEST, RULE_RUN_AS_ROOT, RULE_UNSIGNED, RULE_WILDCARDS_RBAC,
};
pub use ferrum_ids::Digest;
pub use program::{parse_program, AdmissionProgram, ADMISSION_ABI, ADMISSION_MAGIC};
pub use review::{handle_review_bytes, ReviewConfig, ReviewReply};
pub use server::{load_tls_config, serve, WebhookState};
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
