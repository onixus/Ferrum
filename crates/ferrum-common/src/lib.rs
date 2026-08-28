use thiserror::Error;

#[derive(Debug, Error)]
pub enum FerrumError {
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("policy compile error: {0}")]
    Compile(String),
    #[error("bundle integrity error: {0}")]
    Integrity(String),
    #[error("degraded: {0}")]
    Degraded(String),
}

pub type Result<T> = std::result::Result<T, FerrumError>;

/// Days before notAfter at which serving material counts as expiring: the
/// deploy lint fails on it, and the webhook logs it and rotates inside it.
///
/// It lives in this crate because the two places that enforce it cannot share
/// any other: `ferrum-crypto/x509` carries the certificate parser the Jenkins
/// `Crate boundary` stage keeps off the webhook's dependency graph, so
/// `ferrum-admission` restates the threshold from here instead of linking it.
pub const SERVING_CERT_WARN_DAYS: u32 = 30;

pub mod fields {
    pub const CLUSTER: &str = "ferrum.cluster";
    pub const POLICY: &str = "ferrum.policy";
    pub const RULE: &str = "ferrum.rule";
    pub const MODE: &str = "ferrum.mode";
}
