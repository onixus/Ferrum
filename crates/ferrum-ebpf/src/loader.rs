use crate::envelope::extract_febp;
use crate::eval::{decide, matched_action, Decision, SyscallEvent};
use crate::spec::{parse_febp_with, Action, DeadRules, EbpfSpec};
use ferrum_common::{FerrumError, Result};
use ferrum_ids::Digest;
use ferrum_k8smeta::WorkloadIdentity;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// LSM must protect this path. This process does not self-watch its own pins.
pub const PIN_PATH: &str = "/sys/fs/bpf/ferrum";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedBundle {
    pub digest: Digest,
    pub spec: EbpfSpec,
    /// Verified payload whose SHA-256 is `digest` (FEBP or FRMB), never a detached inner slice.
    pub raw: Vec<u8>,
}

/// Userspace FEBP loader. Last-known-good stays in memory.
/// Disk persist of the signed envelope is the agent's job; this loader never
/// writes unsigned FEBP. Kernel attach is not implied by a successful load.
pub struct Loader {
    last_good: Option<LoadedBundle>,
    lkg_dir: Option<PathBuf>,
    /// True when the latest load failed, or no bundle has ever loaded.
    degraded: bool,
    dropped: AtomicU64,
}

impl Default for Loader {
    fn default() -> Self {
        Self::new()
    }
}

impl Loader {
    pub fn new() -> Self {
        Self {
            last_good: None,
            lkg_dir: None,
            degraded: true,
            dropped: AtomicU64::new(0),
        }
    }

    /// Remember a persist directory. Does not read files: unsigned FEBP is not LKG.
    pub fn with_lkg_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            last_good: None,
            lkg_dir: Some(dir.into()),
            degraded: true,
            dropped: AtomicU64::new(0),
        }
    }

    pub fn lkg_dir(&self) -> Option<&PathBuf> {
        self.lkg_dir.as_ref()
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded || self.last_good.is_none()
    }

    /// Keep last-known-good, surface Degraded. Used when a new spec is rejected
    /// before `load_bundle` (ABI envelope mismatch, truncated FRMB).
    pub fn mark_degraded(&mut self) {
        self.degraded = true;
    }

    pub fn last_good(&self) -> Option<&LoadedBundle> {
        self.last_good.as_ref()
    }

    pub fn events_dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn record_drop(&self, n: u64) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
    }

    /// Install verified bytes as last-known-good. `digest` must be SHA-256(`bytes`).
    /// `bytes` is the signed payload (FRMB or FEBP), not a detached inner spec.
    ///
    /// Does not write disk. Does not attach kernel pins.
    pub fn load_bundle(&mut self, digest: &Digest, bytes: &[u8]) -> Result<()> {
        self.load_bundle_with(digest, bytes, DeadRules::Reject)
            .map(|_| ())
    }

    /// `load_bundle` with a say over rules no record can match. Only the
    /// last-known-good restore path passes `DeadRules::Drop`, and only because
    /// refusing the whole snapshot there leaves the node with no policy at
    /// all. Returns the reason for each dropped rule; the caller must surface
    /// them, since the node then enforces less than what was signed.
    pub fn load_bundle_with(
        &mut self,
        digest: &Digest,
        bytes: &[u8],
        dead: DeadRules,
    ) -> Result<Vec<String>> {
        if let Err(err) = ferrum_crypto::verify_bundle_digest(bytes, digest) {
            self.degraded = true;
            return Err(err);
        }
        let febp = match extract_febp(bytes) {
            Ok(slice) => slice,
            Err(err) => {
                self.degraded = true;
                return Err(err);
            }
        };
        match parse_febp_with(febp, dead) {
            Ok((parsed, dropped)) => {
                self.last_good = Some(LoadedBundle {
                    digest: digest.clone(),
                    spec: parsed,
                    raw: bytes.to_vec(),
                });
                self.degraded = false;
                Ok(dropped)
            }
            Err(err) => {
                self.degraded = true;
                Err(err)
            }
        }
    }

    /// Pins are not created. Program attach exists only behind the opt-in
    /// `attach` feature (`KernelHandle`), and even that does not pin at
    /// PIN_PATH yet, so this stays Degraded instead of pretending.
    pub fn attach_pins(&self) -> Result<()> {
        Err(FerrumError::Degraded(format!(
            "kernel eBPF attach not wired; pins not loaded at {PIN_PATH}"
        )))
    }

    pub fn matched_action(&self, event: &SyscallEvent<'_>) -> Decision {
        match &self.last_good {
            Some(loaded) => matched_action(&loaded.spec, event),
            None => Decision {
                action: Action::Deny,
                rule_id: None,
                labels_unknown: false,
                path_unknown: false,
            },
        }
    }

    pub fn decide(&self, event: &SyscallEvent<'_>, identity: &WorkloadIdentity) -> Decision {
        match &self.last_good {
            Some(loaded) => decide(&loaded.spec, event, identity),
            None => Decision {
                action: Action::Deny,
                rule_id: None,
                labels_unknown: false,
                path_unknown: false,
            },
        }
    }
}
