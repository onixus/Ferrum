//! What the controller knows about itself after `run_watch` is entered, as
//! counters and as a file.
//!
//! Before this module the controller had no state at all. Every fault that
//! happens after startup — a reconcile that does not converge, a 403 on a
//! status PATCH, a watch error — was one `eprintln!` and the next turn of the
//! loop, so the only reader was a human tailing the pod's log at the moment it
//! scrolled past. Nothing was counted, nothing could be polled, and no census
//! in this tree could run over this binary because there was no list to run
//! over: a census over an empty list is vacuously complete, which is green for
//! the wrong reason.
//!
//! The shape is the agent's, deliberately: counters per class, a run of
//! consecutive failures per class, whether the class ever succeeded, a
//! `degraded_reasons()` list that `is_degraded()` is the emptiness of, and a
//! `status.json` published by atomic rename. Two subjects that report
//! differently are two things an operator has to learn.
//!
//! Two rules this surface keeps, both learned elsewhere in this tree:
//!
//! - **It is never a probe.** `deploy/controller/deployment.yaml` wires no
//!   liveness or readiness check to the status file, and none may be added.
//!   A restart on a recoverable degradation is a crash loop; a restart on a
//!   permanent one is an infinite loop that never lives long enough to say
//!   why. The file reports; the process decides.
//! - **A failed publish is its own reason, never a reason to stop.** A
//!   reporting surface that stalls the reconcile loop is worse than one that
//!   is missing, and a stale file is worse than no file: it asserts the state
//!   it had, which is the healthy one, exactly when it stopped being true. So
//!   a failed write removes the published file and raises
//!   `REASON_STATUS_UNWRITABLE` for the next reader that gets through.
//!
//! The one thing this module *does* decide is the terminal rule, and it is
//! deliberately narrow: see `TERMINAL_RUN`.

use ferrum_common::{FerrumError, Result};
use serde_json::{json, Value};
use std::fmt::Display;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Published into `--status-dir`.
pub const STATUS_NAME: &str = "status.json";
/// Written and fsynced in the same directory, then renamed over
/// `STATUS_NAME`: a reader never sees half an object, and a crash mid-write
/// leaves this behind instead of a truncated `status.json`.
pub const STATUS_TMP_NAME: &str = ".status.json.tmp";

/// The reason a node's own state is unreadable. Not terminal: the surface is
/// not the work.
pub const REASON_STATUS_UNWRITABLE: &str =
    "status file unwritable: this controller's counters have no reader on this pod";

/// Consecutive failures of one class, with no request of that class having
/// ever succeeded, that end the process.
///
/// Both halves matter and neither is sufficient.
///
/// *Never succeeded* is the whole of the protection. One 403 on one object is
/// a bad object, a conflict, a webhook in the way — the loop must survive it,
/// or the controller becomes the crash loop that `ferrum-agent`'s status
/// surface exists to avoid. But a class in which *nothing has ever worked* is
/// not an object-level fault: it is the deployment being wrong — a
/// mis-edited RBAC that 403s every status PATCH, a CRD that was never applied
/// — and a process that logs that forever while reporting nothing looks
/// healthy to Kubernetes and to every dashboard above it. Returning `Err` puts
/// it in `CrashLoopBackOff`, which is the one signal that reaches an operator
/// who is not reading logs.
///
/// The run is what keeps a single bad object from tripping it before anything
/// else has had a chance to succeed: ten in a row, with none of them ever
/// having worked, is a deployment fault and not an object.
///
/// The third half is `TERMINAL_WINDOW`: ten in a row *and nothing in between*
/// is a statement about a burst, and without a clock it was a statement about
/// the whole life of the process.
pub const TERMINAL_RUN: u64 = 10;

/// The longest gap between two failures of one class that still counts as the
/// same run.
///
/// Without it the run has no clock at all, and «ten in a row with nothing
/// succeeding in between» silently means «the tenth of them, whenever it
/// arrives». A class that has never had a success to reset it — `exception_
/// publish` on an installation with no bundle Secret yet is the shipped
/// example, since a pass over no Secret issues no request and receipts nothing
/// — then accumulates ten transient errors over an afternoon and ends a
/// controller that was working. That is the crash loop this module was written
/// to avoid, reached from the other side.
///
/// The value is the cadence a genuinely broken deployment cannot fall below,
/// not a round number. `kube::runtime::watcher` is driven by a watch whose
/// `timeoutSeconds` is 290 (`kube-core`'s `WatchParams`, sent on every watch
/// call this binary makes and capped at 295 by the API server): when the watch
/// ends, the watcher re-lists and every object is delivered again, so a fault
/// that is in the deployment rather than in one object re-fails at most 290
/// seconds after the last time it did — even on a cluster where nothing is
/// edited and one policy exists. Doubling that is the margin for the relist
/// itself: the list call takes time, can be retried, and a run must not be
/// broken by one slow one. Ten failures then still have to arrive inside about
/// ten minutes, rather than over a day.
pub const TERMINAL_WINDOW: Duration = Duration::from_secs(2 * 290);

/// A class of failure that can happen after `run_watch` has been entered.
///
/// The split is by the API call that failed, not by the text of the error: a
/// classifier that reads error strings is the defect this tree keeps closing.
/// `watch.rs` decides the class at the call site and this module never
/// inspects a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailureClass {
    /// A policy object did not converge: compile, the bundle Secret, or the
    /// status PATCH that ends a reconcile carrying one.
    Reconcile,
    /// A request that was nothing but a status PATCH — a PolicyException's
    /// status, or the status of a policy whose plan carries no Secret. This is
    /// the class a mis-edited RBAC lands in.
    StatusPatch,
    /// The watch stream itself handed up an error. `kube::runtime::watcher`
    /// re-lists and continues, so this never ends a loop on its own.
    Watch,
    /// The signed exception Secret could not be published. Exceptions that
    /// cannot be published are exceptions the agents do not have.
    ExceptionPublish,
}

impl FailureClass {
    pub const ALL: [FailureClass; 4] = [
        FailureClass::Reconcile,
        FailureClass::StatusPatch,
        FailureClass::Watch,
        FailureClass::ExceptionPublish,
    ];

    /// The class as an operator reads it in a reason and in the terminal
    /// error.
    pub fn name(self) -> &'static str {
        match self {
            FailureClass::Reconcile => "reconcile",
            FailureClass::StatusPatch => "status_patch",
            FailureClass::Watch => "watch",
            FailureClass::ExceptionPublish => "exception_publish",
        }
    }

    /// The counter's name, which is also its key in `status.json`, so a reader
    /// of the file and a reader of the code are looking at the same number.
    pub fn counter(self) -> &'static str {
        match self {
            FailureClass::Reconcile => "reconcile_failures",
            FailureClass::StatusPatch => "status_patch_failures",
            FailureClass::Watch => "watch_errors",
            FailureClass::ExceptionPublish => "exception_publish_failures",
        }
    }

    fn index(self) -> usize {
        match self {
            FailureClass::Reconcile => 0,
            FailureClass::StatusPatch => 1,
            FailureClass::Watch => 2,
            FailureClass::ExceptionPublish => 3,
        }
    }
}

/// The classes in which a call actually issued a request to the API server and
/// got an answer.
///
/// The only thing that can mark a class as having worked, and the reason
/// `note_success` does not take a bare `FailureClass`. A call site cannot know
/// what the call it just awaited decided to skip: `attach_exceptions` on a plan
/// that carries no Secret, `persist_exceptions` on an installation whose bundle
/// Secrets do not exist yet, a reconcile of an object that is already converged
/// — each of those returns `Ok(())` having asked the API server for nothing,
/// and each of them used to be counted as a success of its class. That is not a
/// counter being one out: `ever_ok` is what the terminal rule turns on, it can
/// never be turned back off, and one no-op success makes a deployment fault in
/// that class unreportable for the life of the process.
///
/// So the receipt travels out of the code that makes the request. A function
/// that issues nothing has nothing to return but `Requested::NONE`, and
/// `watch.rs` cannot invent one for it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Requested(u8);

impl Requested {
    /// Nothing was asked of the API server.
    pub const NONE: Requested = Requested(0);

    /// One request of `class` was issued and answered.
    pub fn of(class: FailureClass) -> Self {
        Requested(1 << class.index())
    }

    pub fn contains(self, class: FailureClass) -> bool {
        self.0 & Requested::of(class).0 != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Debug, Default)]
struct ClassState {
    total: AtomicU64,
    run: AtomicU64,
    ever_ok: AtomicBool,
    last: Mutex<Option<String>>,
    /// When the failure that ends the current run happened, so the next one
    /// can be told whether it belongs to the same burst. See
    /// `TERMINAL_WINDOW`.
    last_failure_at: Mutex<Option<Instant>>,
    /// Subjects of this class that are wrong in a way no API call can fix, as
    /// the last pass over them saw it. See `note_unactionable`.
    unactionable: Mutex<Vec<String>>,
}

/// Every counter the controller keeps, and the reasons they add up to.
///
/// Shared by the three watch loops and the publish loop of one `select!`, so
/// everything here takes `&self`.
#[derive(Debug, Default)]
pub struct ControllerHealth {
    classes: [ClassState; 4],
    status_write_failed: AtomicBool,
    status_write_failures: AtomicU64,
    /// Complain about an unwritable directory once, not once per tick.
    status_error_logged: AtomicBool,
    /// Same, for the case of no directory at all.
    no_status_dir_logged: AtomicBool,
    /// A counter moved since the last publish. What keeps a `Restarted` burst
    /// of a thousand objects from becoming a thousand fsyncs on the path the
    /// reconcile loops run on.
    changed: AtomicBool,
}

impl ControllerHealth {
    pub fn new() -> Self {
        Self::default()
    }

    fn class(&self, class: FailureClass) -> &ClassState {
        &self.classes[class.index()]
    }

    /// Every class in `requested` had a request go through: its run resets and
    /// the class is marked as having worked at least once, which is what can
    /// never be undone and what the terminal rule turns on.
    ///
    /// `Requested::NONE` records nothing, which is the point: a call that
    /// asked the API server for nothing did not succeed at anything.
    pub fn note_success(&self, requested: Requested) {
        for class in FailureClass::ALL {
            if requested.contains(class) {
                self.note_class_success(class);
            }
        }
    }

    fn note_class_success(&self, class: FailureClass) {
        let state = self.class(class);
        let first = !state.ever_ok.swap(true, Ordering::Relaxed);
        let recovered = state.run.swap(0, Ordering::Relaxed) != 0;
        *state.last.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *state
            .last_failure_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        if first || recovered {
            self.changed.store(true, Ordering::Relaxed);
        }
    }

    /// Everything of `class` that is wrong in a way no API call can mend, as
    /// this pass over it sees it. Replaces the previous list whole, and
    /// returns whether it changed.
    ///
    /// These are not failures and must never reach the terminal rule. A Secret
    /// carrying this controller's owner label and no policy label is one
    /// object being wrong: the controller can see it without asking the API
    /// server anything, no retry will change the answer, and so the run of it
    /// is unbounded by construction — every event forever. Charged to
    /// `note_failure` it was a guaranteed exit on the tenth event of a
    /// controller that was otherwise publishing correctly, dressed up as «this
    /// class has never worked».
    ///
    /// It is still a reason: `degraded_reasons` names every subject, so
    /// `is_degraded()` is true for exactly as long as the object is wrong, and
    /// false again on the first pass that no longer sees it. That last part is
    /// why the list is replaced rather than added to — a reason that outlives
    /// its cause teaches an operator to ignore reasons.
    pub fn note_unactionable(&self, class: FailureClass, subjects: Vec<String>) -> bool {
        let state = self.class(class);
        let mut held = state.unactionable.lock().unwrap_or_else(|e| e.into_inner());
        if *held == subjects {
            return false;
        }
        *held = subjects;
        self.changed.store(true, Ordering::Relaxed);
        true
    }

    pub fn unactionable(&self, class: FailureClass) -> Vec<String> {
        self.class(class)
            .unactionable
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// A request of `class` failed: count it, lengthen the run, keep the cause
    /// for the status file.
    ///
    /// `Err` is the terminal case and the only one — the caller propagates it
    /// out of `run_watch`, `main` prints `error: <cause>` and exits 1. `Ok` is
    /// «counted, keep going», which is what every ordinary failure gets.
    pub fn note_failure(&self, class: FailureClass, cause: impl Display) -> Result<()> {
        self.note_failure_at(class, cause, Instant::now())
    }

    /// `note_failure`, at an explicit instant, so the window the run is
    /// measured in can be asserted without waiting it out.
    pub fn note_failure_at(
        &self,
        class: FailureClass,
        cause: impl Display,
        now: Instant,
    ) -> Result<()> {
        let state = self.class(class);
        let cause = cause.to_string();
        state.total.fetch_add(1, Ordering::Relaxed);
        // The run is a burst, not a lifetime total: a failure that arrives
        // more than `TERMINAL_WINDOW` after the last one of its class starts a
        // new run rather than lengthening one that has been standing since the
        // process began.
        let run = {
            let mut at = state
                .last_failure_at
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let continues =
                at.is_none_or(|prev| now.saturating_duration_since(prev) <= TERMINAL_WINDOW);
            *at = Some(now);
            if continues {
                state.run.fetch_add(1, Ordering::Relaxed) + 1
            } else {
                state.run.store(1, Ordering::Relaxed);
                1
            }
        };
        self.changed.store(true, Ordering::Relaxed);
        *state.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(cause.clone());
        if run >= TERMINAL_RUN && !state.ever_ok.load(Ordering::Relaxed) {
            return Err(FerrumError::Degraded(terminal_reason(class, run, &cause)));
        }
        Ok(())
    }

    pub fn failures(&self, class: FailureClass) -> u64 {
        self.class(class).total.load(Ordering::Relaxed)
    }

    pub fn failure_run(&self, class: FailureClass) -> u64 {
        self.class(class).run.load(Ordering::Relaxed)
    }

    pub fn ever_succeeded(&self, class: FailureClass) -> bool {
        self.class(class).ever_ok.load(Ordering::Relaxed)
    }

    pub fn last_cause(&self, class: FailureClass) -> Option<String> {
        self.class(class)
            .last
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn reconcile_failures(&self) -> u64 {
        self.failures(FailureClass::Reconcile)
    }

    pub fn status_patch_failures(&self) -> u64 {
        self.failures(FailureClass::StatusPatch)
    }

    pub fn watch_errors(&self) -> u64 {
        self.failures(FailureClass::Watch)
    }

    pub fn exception_publish_failures(&self) -> u64 {
        self.failures(FailureClass::ExceptionPublish)
    }

    /// The last publish attempt failed, and stays true until one gets through.
    /// True in the first file written after a failure — that file is the
    /// carrier of the reason — and cleared once that write has landed.
    pub fn status_write_failed(&self) -> bool {
        self.status_write_failed.load(Ordering::Relaxed)
    }

    pub fn status_write_failures(&self) -> u64 {
        self.status_write_failures.load(Ordering::Relaxed)
    }

    /// Every reason this controller is degraded, in the words the operator
    /// reads in `status.json`. `is_degraded()` is this list being non-empty
    /// and nothing else: a signal that cannot be named here cannot degrade the
    /// process, so no reason can be raised silently.
    pub fn degraded_reasons(&self) -> Vec<String> {
        let mut out = Vec::new();
        for class in FailureClass::ALL {
            let run = self.failure_run(class);
            if run == 0 {
                continue;
            }
            let cause = self
                .last_cause(class)
                .unwrap_or_else(|| "<no cause recorded>".to_string());
            let ever = if self.ever_succeeded(class) {
                ""
            } else {
                ", and no request of this class has ever succeeded"
            };
            out.push(format!(
                "{}: {run} in a row{ever}; last: {cause}",
                class.name()
            ));
        }
        for class in FailureClass::ALL {
            let stuck = self.unactionable(class);
            if stuck.is_empty() {
                continue;
            }
            out.push(format!(
                "{}: {} object(s) this controller cannot act on and no retry will mend: {}",
                class.name(),
                stuck.len(),
                stuck.join(", ")
            ));
        }
        if self.status_write_failed() {
            out.push(REASON_STATUS_UNWRITABLE.to_string());
        }
        out
    }

    pub fn is_degraded(&self) -> bool {
        !self.degraded_reasons().is_empty()
    }

    /// Everything this controller knows about itself, as one JSON object.
    pub fn status_json(&self) -> Value {
        let reasons = self.degraded_reasons();
        let mut out = json!({
            "ts": unix_seconds(),
            "degraded": !reasons.is_empty(),
            "degradedReasons": reasons,
            "terminalRun": TERMINAL_RUN,
            "statusWriteFailed": self.status_write_failed(),
            "statusWriteFailuresTotal": self.status_write_failures(),
        });
        let map = out.as_object_mut().expect("object");
        for class in FailureClass::ALL {
            let counter = class.counter();
            map.insert(counter.to_string(), json!(self.failures(class)));
            map.insert(format!("{counter}_run"), json!(self.failure_run(class)));
            map.insert(
                format!("{counter}_ever_succeeded"),
                json!(self.ever_succeeded(class)),
            );
            map.insert(format!("{counter}_last"), json!(self.last_cause(class)));
            map.insert(
                format!("{counter}_unactionable"),
                json!(self.unactionable(class)),
            );
        }
        out
    }

    /// Write `status.json` into `dir` if a counter has moved since the last
    /// publish, whole or not at all.
    ///
    /// Called on the reconcile path, where the alternative is an `fsync` per
    /// watch event. The periodic publish is what keeps the timestamp moving
    /// when nothing changes.
    ///
    /// Returns nothing on purpose. A failed publish is already a counter, a
    /// reason and a line — see `publish` — and the loops that call this have
    /// no decision to make about it: a reporting surface that could divert the
    /// reconcile path would be the probe this module refuses to be. Its three
    /// callers dropped the `bool` it used to return, which is a value nobody
    /// reads and a question nobody may answer.
    pub fn publish_if_changed(&self, dir: Option<&Path>) {
        if !self.changed.swap(false, Ordering::Relaxed) {
            return;
        }
        self.publish(dir);
    }

    /// Write `status.json` into `dir`, whole or not at all.
    ///
    /// Returns whether the state is published. A failure is counted, raises
    /// `REASON_STATUS_UNWRITABLE` and removes the file that is now lying, and
    /// it never propagates: the caller has policy to reconcile.
    pub fn publish(&self, dir: Option<&Path>) -> bool {
        let Some(dir) = dir else {
            // Not a failure — an operator who asked for no status file did not
            // fail to get one — but not a silence either: without this line
            // «no file» is indistinguishable from a controller whose writes
            // are failing, and a `--status-dir` dropped between the manifest
            // and the process would look exactly like a controller that was
            // never given one. `ferrum-agent` says the same thing in the same
            // case.
            if !self.no_status_dir_logged.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "ferrum-controller: no --status-dir, so {STATUS_NAME} is not written: this \
                     controller's counters have no reader but the lines it prints on each failure"
                );
            }
            return true;
        };
        self.changed.store(false, Ordering::Relaxed);
        // Built before the flag is cleared, not after. Clearing it first made
        // `REASON_STATUS_UNWRITABLE` and `statusWriteFailed: true` unreachable
        // in every file that was ever published — the one state the module
        // promises to report is the one it deleted on its way to reporting it,
        // and the unit test behind it read the reasons in memory, where the
        // flag was still set. So the first file that gets through after a
        // failed publish is the one that says a publish failed, which is what
        // «raises it for the next reader that gets through» has to mean.
        let value = self.status_json();
        match write_status(dir, &value) {
            Ok(()) => {
                if self.status_write_failed.swap(false, Ordering::Relaxed) {
                    // The file just written says the surface was unwritable,
                    // and it no longer is. Republish so the reason does not
                    // stand on disk after it stopped being true.
                    self.changed.store(true, Ordering::Relaxed);
                }
                self.status_error_logged.store(false, Ordering::Relaxed);
                true
            }
            Err(err) => {
                self.status_write_failed.store(true, Ordering::Relaxed);
                self.status_write_failures.fetch_add(1, Ordering::Relaxed);
                let published = dir.join(STATUS_NAME);
                let removed = match fs::remove_file(&published) {
                    Ok(()) => true,
                    Err(rm) => rm.kind() == io::ErrorKind::NotFound,
                };
                if !self.status_error_logged.swap(true, Ordering::Relaxed) {
                    let tail = if removed {
                        "the last one was removed rather than left asserting the state it had"
                    } else {
                        "and the last one could not be removed either, so it is stale on disk: \
                         check its ts before believing it"
                    };
                    eprintln!(
                        "ferrum-controller: cannot write {}: {err}; this controller's state is \
                         not readable until it succeeds, {tail}",
                        published.display()
                    );
                }
                false
            }
        }
    }
}

/// The sentence a terminal run leaves on stderr and in the exit path. Names
/// the class, because «the controller failed» is what the log said before this
/// module existed.
fn terminal_reason(class: FailureClass, run: u64, cause: &str) -> String {
    format!(
        "{} failed {run} times in a row within {}s and no {} request has ever succeeded since \
         this process started: that is the deployment, not the object — check the RBAC and the \
         CRDs. Last cause: {cause}",
        class.name(),
        TERMINAL_WINDOW.as_secs(),
        class.name(),
    )
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Atomic publish: a temp file in the same directory, flushed and fsynced,
/// then renamed over the published name.
pub fn write_status(dir: &Path, value: &Value) -> io::Result<()> {
    let tmp = dir.join(STATUS_TMP_NAME);
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let write = || -> io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // The reasons quote API-server errors, which name objects and
            // namespaces; nothing in this pod but the controller reads them.
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()
    };
    if let Err(err) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    fs::rename(&tmp, dir.join(STATUS_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ferrum-controller-health-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    /// One failed event is a counted event, and nothing more.
    ///
    /// This is the half the controller did not have: before this module a
    /// failed reconcile was a line on stderr and the loop went round, so
    /// nothing an operator can poll moved at all. It is also the half the
    /// terminal rule must not break — a single 403 on a single object is a bad
    /// object, and a process that exits on it is the crash loop the agent's
    /// status surface was written to avoid.
    #[test]
    fn a_single_failed_event_is_counted_and_the_process_keeps_running() {
        let health = ControllerHealth::new();
        assert!(!health.is_degraded());
        assert!(health.degraded_reasons().is_empty());

        for class in FailureClass::ALL {
            health
                .note_failure(class, format!("403 on one object: {}", class.name()))
                .unwrap_or_else(|e| {
                    panic!("one failure of {} must not be terminal: {e}", class.name())
                });
            assert_eq!(health.failures(class), 1, "{}", class.name());
            assert_eq!(health.failure_run(class), 1, "{}", class.name());
            assert!(!health.ever_succeeded(class), "{}", class.name());
        }

        // Named counters, because the document names them.
        assert_eq!(health.reconcile_failures(), 1);
        assert_eq!(health.status_patch_failures(), 1);
        assert_eq!(health.watch_errors(), 1);
        assert_eq!(health.exception_publish_failures(), 1);

        // Every class it happened to is a reason, and every reason names its
        // class and its cause.
        let reasons = health.degraded_reasons();
        assert!(health.is_degraded());
        assert_eq!(reasons.len(), FailureClass::ALL.len(), "{reasons:?}");
        for class in FailureClass::ALL {
            assert!(
                reasons
                    .iter()
                    .any(|r| r.starts_with(class.name()) && r.contains("403 on one object")),
                "{} is degraded and no reason says so: {reasons:?}",
                class.name()
            );
        }

        // And a success takes the class back out of the list without erasing
        // the count: the counter is the history, the run is the state.
        health.note_success(Requested::of(FailureClass::Reconcile));
        assert_eq!(health.reconcile_failures(), 1);
        assert_eq!(health.failure_run(FailureClass::Reconcile), 0);
        assert!(health.ever_succeeded(FailureClass::Reconcile));
        assert_eq!(
            health.degraded_reasons().len(),
            FailureClass::ALL.len() - 1,
            "a class that just succeeded is not a reason"
        );
    }

    /// A run of one class in which nothing of that class ever worked ends the
    /// process, and says which class.
    ///
    /// This is the mis-edited RBAC: `policyexceptions/status` removed from the
    /// role and every status PATCH 403s forever. Before it, that deployment
    /// ran indefinitely, reconciling nothing, with `Deployment: 1/1 Ready`.
    #[test]
    fn a_run_of_status_patch_failures_with_no_success_is_terminal_and_names_the_class() {
        let health = ControllerHealth::new();
        for i in 1..TERMINAL_RUN {
            health
                .note_failure(FailureClass::StatusPatch, "status patch p: 403 Forbidden")
                .unwrap_or_else(|e| panic!("failure {i} of {TERMINAL_RUN} ended the process: {e}"));
        }
        let err = health
            .note_failure(FailureClass::StatusPatch, "status patch p: 403 Forbidden")
            .expect_err("a run with no success in the class is terminal");
        let text = err.to_string();
        assert!(
            text.contains(FailureClass::StatusPatch.name()),
            "the terminal error must name the class an operator has to fix: {text}"
        );
        assert!(
            text.contains("403 Forbidden"),
            "the terminal error must carry the cause: {text}"
        );
        assert!(
            text.contains(&TERMINAL_RUN.to_string()),
            "the terminal error must say how many: {text}"
        );

        // The classes are separate. The run that killed status_patch left the
        // other three where they were, so a controller cannot be ended by the
        // sum of unrelated faults.
        for class in FailureClass::ALL {
            if class == FailureClass::StatusPatch {
                continue;
            }
            assert_eq!(health.failures(class), 0, "{}", class.name());
            assert_eq!(health.failure_run(class), 0, "{}", class.name());
        }

        // And the same run in a class that is not the one failing is not
        // terminal either: nine of one and nine of another is eighteen
        // failures and no deployment fault.
        let mixed = ControllerHealth::new();
        for _ in 0..TERMINAL_RUN - 1 {
            mixed
                .note_failure(FailureClass::Reconcile, "compile")
                .expect("reconcile short of the run");
            mixed
                .note_failure(FailureClass::Watch, "connection reset")
                .expect("watch short of the run");
        }
        assert!(mixed.is_degraded());
    }

    /// A class that has ever worked cannot end the process, however long the
    /// burst — and «worked» means a request of that class was issued and
    /// answered, not that a function returned `Ok`.
    ///
    /// «Never once succeeded» is the whole of the protection: it is what tells
    /// a deployment that is wrong from a cluster that is busy. An API server
    /// rolling, a conflict storm on one object or a webhook in front of the
    /// PATCH all produce runs far longer than `TERMINAL_RUN`, and none of them
    /// is a reason to stop reconciling.
    ///
    /// The half added after the audit is the second one. This test used to
    /// take «a success» as given and ask only what a later burst did with it,
    /// which is exactly the assumption that made the defect invisible: three
    /// call sites in `watch.rs` marked a class as having worked after a call
    /// that had issued no request at all, and this test asserted the
    /// protection they thereby granted forever. `Requested::NONE` is what such
    /// a call returns now, and the assertions below are that it protects
    /// nothing.
    #[test]
    fn a_class_that_succeeded_once_does_not_go_terminal_on_a_later_burst() {
        // Nothing requested, nothing succeeded — and the class stays killable.
        let vacuous = ControllerHealth::new();
        vacuous.note_success(Requested::NONE);
        assert!(!vacuous.ever_succeeded(FailureClass::ExceptionPublish));
        let mut vacuous_err = None;
        for _ in 0..TERMINAL_RUN {
            vacuous_err = vacuous
                .note_failure(FailureClass::ExceptionPublish, "secret patch: 403")
                .err();
        }
        assert!(
            vacuous_err.is_some(),
            "a success that made no request disarmed the terminal rule for the class, which \
             nothing can re-arm for the life of the process"
        );

        // A receipt names its class and only its class: the same call that
        // issues a status PATCH and nothing else must not credit `reconcile`.
        let one = Requested::of(FailureClass::StatusPatch);
        assert!(one.contains(FailureClass::StatusPatch));
        for class in FailureClass::ALL {
            if class != FailureClass::StatusPatch {
                assert!(!one.contains(class), "{}", class.name());
            }
        }
        assert!(Requested::NONE.is_empty());
        assert!(!one.is_empty());

        let health = ControllerHealth::new();
        health.note_success(Requested::of(FailureClass::StatusPatch));
        for i in 0..TERMINAL_RUN * 10 {
            health
                .note_failure(FailureClass::StatusPatch, "status patch p: 409 Conflict")
                .unwrap_or_else(|e| {
                    panic!("failure {i} ended a process whose status patches have worked: {e}")
                });
        }
        assert_eq!(health.status_patch_failures(), TERMINAL_RUN * 10);
        assert!(health.failure_run(FailureClass::StatusPatch) >= TERMINAL_RUN);

        // Not terminal is not silent: the burst is still degradation, and the
        // reason says the class has worked before rather than never.
        let reasons = health.degraded_reasons();
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        assert!(reasons[0].starts_with("status_patch"), "{reasons:?}");
        assert!(
            !reasons[0].contains("never"),
            "a class that has succeeded must not claim it never has: {reasons:?}"
        );

        // The success has to be in the same class to protect it. The identical
        // burst in a class that has never worked is terminal, which is the
        // control on the sentence above.
        let other = ControllerHealth::new();
        other.note_success(Requested::of(FailureClass::StatusPatch));
        let mut err = None;
        for _ in 0..TERMINAL_RUN {
            err = other
                .note_failure(FailureClass::Reconcile, "secret create: 403")
                .err();
        }
        let err = err.expect("a success in another class protects nothing");
        assert!(
            err.to_string().contains(FailureClass::Reconcile.name()),
            "{err}"
        );
    }

    /// The file is published whole, and a publish that fails is its own reason
    /// rather than a silence.
    #[test]
    fn the_status_file_is_written_whole_and_a_failed_write_is_its_own_reason() {
        let dir = temp_dir("publish");
        let health = ControllerHealth::new();
        health.note_success(Requested::of(FailureClass::Watch));
        health
            .note_failure(FailureClass::Reconcile, "compile: rule 3 has no match")
            .expect("one failure is not terminal");

        assert!(health.publish(Some(&dir)), "publish into a writable dir");
        let published = dir.join(STATUS_NAME);
        let body = fs::read_to_string(published).expect("status.json");
        let value: Value = serde_json::from_str(&body).expect("status.json is whole JSON");
        assert_eq!(value["degraded"], json!(true));
        assert_eq!(value["reconcile_failures"], json!(1));
        assert_eq!(value["reconcile_failures_run"], json!(1));
        assert_eq!(value["reconcile_failures_ever_succeeded"], json!(false));
        assert_eq!(value["watch_errors"], json!(0));
        assert_eq!(value["watch_errors_ever_succeeded"], json!(true));
        assert_eq!(value["statusWriteFailed"], json!(false));
        for class in FailureClass::ALL {
            assert!(
                value.get(class.counter()).is_some(),
                "{} is a class this controller can fail in and the file does not carry it",
                class.counter()
            );
        }
        assert!(
            value["degradedReasons"]
                .as_array()
                .expect("reasons")
                .iter()
                .any(|r| r
                    .as_str()
                    .is_some_and(|r| r.contains("rule 3 has no match"))),
            "the file must carry the cause, not just the count: {body}"
        );
        // Whole means whole: the temp file is renamed, never left beside it.
        assert!(
            !dir.join(STATUS_TMP_NAME).exists(),
            "the temp file survived the publish, so a reader can find a half-written object"
        );

        // A publish that cannot happen is a reason of its own, and it takes
        // the stale file with it: that file says `degraded: false` for a
        // controller that is not, at exactly the moment somebody is reading
        // it.
        let gone = dir.join("removed");
        fs::create_dir_all(&gone).expect("dir");
        let health2 = ControllerHealth::new();
        assert!(health2.publish(Some(&gone)), "publish into a writable dir");
        assert!(gone.join(STATUS_NAME).exists());
        fs::remove_dir_all(&gone).expect("remove the directory under it");

        assert!(!health2.publish(Some(&gone)), "a vanished directory fails");
        assert!(health2.status_write_failed());
        assert_eq!(health2.status_write_failures(), 1);
        assert!(
            health2
                .degraded_reasons()
                .iter()
                .any(|r| r == REASON_STATUS_UNWRITABLE),
            "a failed publish must be a reason: {:?}",
            health2.degraded_reasons()
        );
        assert!(health2.is_degraded());
        assert!(
            !gone.join(STATUS_NAME).exists(),
            "the file that could not be updated must not be left asserting the state it had"
        );

        // No directory at all is not a failure: an operator who did not ask
        // for a status file did not fail to get one.
        let quiet = ControllerHealth::new();
        assert!(quiet.publish(None));
        assert!(!quiet.status_write_failed());
        assert!(!quiet.is_degraded());

        let _ = fs::remove_dir_all(&dir);
    }

    /// The reason a publish failed reaches the first file that gets written.
    ///
    /// The test above asserts `REASON_STATUS_UNWRITABLE` in the reasons *in
    /// memory*, and that is where it stayed: `publish` cleared the flag before
    /// building the object it was about to write, so `statusWriteFailed` was
    /// false and the reason absent in every file this controller ever
    /// published. A signal that runs the whole length of the module and
    /// arrives nowhere is the defect this tree keeps finding, one surface in.
    #[test]
    fn the_file_written_after_a_failed_publish_says_the_publish_failed() {
        let dir = temp_dir("unwritable");
        let health = ControllerHealth::new();

        // One publish that cannot happen: the directory is gone.
        let gone = dir.join("gone");
        fs::create_dir_all(&gone).expect("dir");
        assert!(health.publish(Some(&gone)));
        fs::remove_dir_all(&gone).expect("remove");
        assert!(!health.publish(Some(&gone)), "a vanished directory fails");
        assert!(health.status_write_failed());

        // And the next publish, into a directory that works. This is the file
        // «raises it for the next reader that gets through» is about.
        assert!(health.publish(Some(&dir)));
        let body = fs::read_to_string(dir.join(STATUS_NAME)).expect("status.json");
        let value: Value = serde_json::from_str(&body).expect("whole JSON");
        assert_eq!(
            value["statusWriteFailed"],
            json!(true),
            "the published file does not carry the failed publish it is the report of: {body}"
        );
        assert_eq!(value["statusWriteFailuresTotal"], json!(1));
        assert_eq!(value["degraded"], json!(true));
        assert!(
            value["degradedReasons"]
                .as_array()
                .expect("reasons")
                .iter()
                .any(|r| r.as_str() == Some(REASON_STATUS_UNWRITABLE)),
            "the reason is in memory and not in the file: {body}"
        );

        // The flag is cleared by the write that carried it, and the next
        // publish reports a surface that works — a reason that outlived its
        // cause is the other half of the same defect.
        assert!(!health.status_write_failed());
        assert!(health.publish(Some(&dir)));
        let body = fs::read_to_string(dir.join(STATUS_NAME)).expect("status.json");
        let value: Value = serde_json::from_str(&body).expect("whole JSON");
        assert_eq!(value["statusWriteFailed"], json!(false), "{body}");
        assert_eq!(value["degraded"], json!(false), "{body}");

        let _ = fs::remove_dir_all(&dir);
    }

    /// Ten failures spread over an afternoon are not a run.
    ///
    /// `TERMINAL_RUN` counted consecutive failures with no clock at all, so
    /// «ten in a row and nothing has ever succeeded» meant «the tenth of them,
    /// whenever it arrives». `exception_publish` on an installation whose
    /// bundle Secrets do not exist yet has no success to reset it — the pass
    /// issues no request and receipts nothing — so ten transient list errors,
    /// hours apart, ended a controller that was working. The run is a burst
    /// now, and the control below is that a burst still ends the process.
    #[test]
    fn a_failure_run_is_a_burst_and_not_a_lifetime() {
        let start = Instant::now();

        let slow = ControllerHealth::new();
        for i in 0..TERMINAL_RUN * 3 {
            // One gap longer than the window, repeatedly: no two of these
            // failures belong to the same run.
            let at = start + (TERMINAL_WINDOW + Duration::from_secs(1)) * (i as u32);
            slow.note_failure_at(FailureClass::ExceptionPublish, "secret list: timeout", at)
                .unwrap_or_else(|e| {
                    panic!(
                        "failure {i}, {}s after the one before it, ended the process: {e}",
                        (TERMINAL_WINDOW + Duration::from_secs(1)).as_secs()
                    )
                });
        }
        assert_eq!(slow.exception_publish_failures(), TERMINAL_RUN * 3);
        assert_eq!(
            slow.failure_run(FailureClass::ExceptionPublish),
            1,
            "a failure that arrives after the window starts a run, it does not lengthen one"
        );
        assert!(
            slow.is_degraded(),
            "not terminal is not silent: the last failure is still a reason"
        );

        // The control: the same ten failures at the cadence a deployment fault
        // actually produces them. `kube` re-lists when its watch times out, so
        // every object is delivered again and the fault re-fails — 290s apart
        // at the very slowest, which is inside the window by construction.
        let relist = Duration::from_secs(290);
        assert!(
            relist <= TERMINAL_WINDOW,
            "a window shorter than one relist cannot see a broken deployment at all"
        );
        let broken = ControllerHealth::new();
        let mut last = Ok(());
        for i in 0..TERMINAL_RUN {
            last = broken.note_failure_at(
                FailureClass::StatusPatch,
                "status patch: 403 Forbidden",
                start + relist * (i as u32),
            );
        }
        let err = last.expect_err("a deployment that never worked must still end the process");
        assert!(err.to_string().contains("status_patch"), "{err}");

        // And a success inside the window is what a healthy controller has:
        // it clears the run and the clock behind it.
        let ok = ControllerHealth::new();
        for i in 0..TERMINAL_RUN * 2 {
            ok.note_failure_at(
                FailureClass::Reconcile,
                "secret get: 500",
                start + relist * (i as u32),
            )
            .expect("a class that keeps working is never terminal");
            ok.note_success(Requested::of(FailureClass::Reconcile));
        }
    }

    /// An object nothing can mend is a reason, never a run.
    #[test]
    fn an_unactionable_object_degrades_without_ending_the_process() {
        let health = ControllerHealth::new();
        assert!(health.note_unactionable(
            FailureClass::ExceptionPublish,
            vec!["hand-made".to_string()]
        ));
        assert!(
            !health.note_unactionable(
                FailureClass::ExceptionPublish,
                vec!["hand-made".to_string()]
            ),
            "the same list twice is not a change, and a change is what publishes a file"
        );
        assert!(health.is_degraded());
        let reasons = health.degraded_reasons();
        assert!(
            reasons.iter().any(|r| r.contains("hand-made")),
            "{reasons:?}"
        );
        assert_eq!(
            health.failure_run(FailureClass::ExceptionPublish),
            0,
            "an object nothing can mend must not be able to reach the terminal rule: its run \
             is unbounded by construction"
        );
        assert_eq!(
            health.status_json()["exception_publish_failures_unactionable"],
            json!(["hand-made"])
        );

        // Self-healing: the pass that no longer sees it takes the reason with
        // it.
        assert!(health.note_unactionable(FailureClass::ExceptionPublish, Vec::new()));
        assert!(!health.is_degraded());
    }
}
