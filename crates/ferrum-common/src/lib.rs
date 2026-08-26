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

pub mod fields {
    pub const CLUSTER: &str = "ferrum.cluster";
    pub const POLICY: &str = "ferrum.policy";
    pub const RULE: &str = "ferrum.rule";
    pub const MODE: &str = "ferrum.mode";
}
