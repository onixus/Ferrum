//! Monotonic-floor wall clock.
//!
//! Waivers expire on wall-clock time, so moving the node clock back revives
//! expired exceptions. The floor never moves backwards: a reading below it is
//! counted as a rollback and the floor is returned instead.
//!
//! The floor is persisted next to the LKG bundle (`observed-time`), but a file
//! is only as trustworthy as root on the node. The stronger anchor is signed
//! data: policy caps an exception TTL at 90 days, so any live exception with
//! `expiresAt` implies the real time is no earlier than `expiresAt - 90d`.
//! Forging that lower bound requires the trust root, not root on the node.

use chrono::{DateTime, Days, Utc};
use ferrum_api::PolicyExceptionSpec;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Policy cap on exception TTL (`ferrum-policy`); the clock anchor is derived
/// from it, so the two must not drift apart.
pub const MAX_EXCEPTION_DAYS: u64 = 90;

const OBSERVED_TIME: &str = "observed-time";

/// Persist granularity. Writing on every event would put a file write on the
/// decision path; a coarse floor is still a floor.
const PERSIST_STEP_SECS: i64 = 60;

pub struct MonotonicFloor {
    dir: Option<PathBuf>,
    state: Mutex<FloorState>,
    rollbacks: AtomicU64,
}

struct FloorState {
    floor: DateTime<Utc>,
    persisted: DateTime<Utc>,
}

impl Default for MonotonicFloor {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicFloor {
    /// No persistence, no floor until something is observed.
    pub fn new() -> Self {
        Self {
            dir: None,
            state: Mutex::new(FloorState {
                floor: DateTime::<Utc>::MIN_UTC,
                persisted: DateTime::<Utc>::MIN_UTC,
            }),
            rollbacks: AtomicU64::new(0),
        }
    }

    /// Read `observed-time` from `dir` if present; an unreadable or malformed
    /// file leaves the floor at its minimum rather than failing the agent.
    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let stored = read_observed(&dir).unwrap_or(DateTime::<Utc>::MIN_UTC);
        Self {
            dir: Some(dir),
            state: Mutex::new(FloorState {
                floor: stored,
                persisted: stored,
            }),
            rollbacks: AtomicU64::new(0),
        }
    }

    pub fn clock_rollback_total(&self) -> u64 {
        self.rollbacks.load(Ordering::Relaxed)
    }

    pub fn floor(&self) -> DateTime<Utc> {
        self.lock().floor
    }

    /// Signed lower bound: a live exception cannot be more than 90 days from
    /// now, so its `expiresAt` minus 90 days is a time the node has passed.
    pub fn anchor_from_exceptions(&self, specs: &[PolicyExceptionSpec]) {
        let anchor = specs
            .iter()
            .filter_map(|spec| {
                spec.expires_at
                    .checked_sub_days(Days::new(MAX_EXCEPTION_DAYS))
            })
            .max();
        if let Some(anchor) = anchor {
            let mut state = self.lock();
            if anchor > state.floor {
                state.floor = anchor;
            }
        }
    }

    pub fn now(&self) -> DateTime<Utc> {
        self.now_from(Utc::now())
    }

    /// Same guard with an injected wall reading (tests, callers with their own
    /// clock). A reading below the floor counts as a rollback.
    pub fn now_from(&self, wall: DateTime<Utc>) -> DateTime<Utc> {
        let mut state = self.lock();
        if wall < state.floor {
            self.rollbacks.fetch_add(1, Ordering::Relaxed);
            return state.floor;
        }
        state.floor = wall;
        if (wall - state.persisted).num_seconds() >= PERSIST_STEP_SECS {
            state.persisted = wall;
            if let Some(dir) = &self.dir {
                let _ = write_observed(dir, wall);
            }
        }
        wall
    }

    /// Flush the current floor to disk regardless of the persist step.
    pub fn persist(&self) {
        let mut state = self.lock();
        let floor = state.floor;
        if floor == DateTime::<Utc>::MIN_UTC {
            return;
        }
        state.persisted = floor;
        if let Some(dir) = &self.dir {
            let _ = write_observed(dir, floor);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FloorState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn read_observed(dir: &Path) -> Option<DateTime<Utc>> {
    let raw = std::fs::read_to_string(dir.join(OBSERVED_TIME)).ok()?;
    DateTime::parse_from_rfc3339(raw.trim())
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

fn write_observed(dir: &Path, when: DateTime<Utc>) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("..{OBSERVED_TIME}-{}", std::process::id()));
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(when.to_rfc3339().as_bytes())?;
        file.flush()?;
    }
    std::fs::rename(&tmp, dir.join(OBSERVED_TIME))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrum-clock-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        dir
    }

    #[test]
    fn floor_only_moves_forward_and_counts_rollbacks() {
        let clock = MonotonicFloor::new();
        let t0 = Utc::now();
        assert_eq!(clock.now_from(t0), t0);
        let back = t0 - Days::new(30);
        assert_eq!(clock.now_from(back), t0);
        assert_eq!(clock.clock_rollback_total(), 1);
        let forward = t0 + chrono::Duration::try_seconds(5).expect("delta");
        assert_eq!(clock.now_from(forward), forward);
        assert_eq!(clock.clock_rollback_total(), 1);
    }

    #[test]
    fn floor_survives_restart_through_the_file() {
        let dir = temp_dir("persist");
        let t0 = Utc::now();
        {
            let clock = MonotonicFloor::with_dir(&dir);
            clock.now_from(t0);
            clock.persist();
        }
        let restored = MonotonicFloor::with_dir(&dir);
        assert_eq!(restored.floor().timestamp(), t0.timestamp());
        let back = t0 - Days::new(30);
        assert!(restored.now_from(back) > back);
        assert_eq!(restored.clock_rollback_total(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(OBSERVED_TIME))
                .expect("observed-time")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signed_exceptions_anchor_the_floor_without_the_file() {
        let clock = MonotonicFloor::new();
        let now = Utc::now();
        let spec = PolicyExceptionSpec {
            ticket: "JIRA-1".into(),
            requested_by: "sre".into(),
            approved_by: "sec".into(),
            reason: "documented".into(),
            expires_at: now + Days::new(10),
            mode: Default::default(),
            four_eyes: false,
            target: Default::default(),
        };
        clock.anchor_from_exceptions(std::slice::from_ref(&spec));
        // expiresAt - 90d is a time the node has provably passed.
        let anchor = clock.floor();
        assert!(anchor > now - Days::new(81), "{anchor}");
        assert!(anchor <= now);
        // A clock moved a year back cannot get under the signed anchor.
        assert_eq!(clock.now_from(now - Days::new(365)), anchor);
        assert_eq!(clock.clock_rollback_total(), 1);
    }
}
