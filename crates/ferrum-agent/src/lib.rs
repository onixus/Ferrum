//! Node agent: signed FEBP, last-known-good, observe vs respond.
//! Kernel attach is not implied by a successful userspace load.

#![deny(unsafe_code)]

mod clock;
mod pump;
mod respond;
mod ring;
mod source;

use chrono::{DateTime, Utc};
use ferrum_api::PolicyExceptionSpec;
use ferrum_common::{FerrumError, Result};
use ferrum_ebpf::{extract_febp, Action, Decision, EventMeta, Loader, SyscallEvent};
use ferrum_export::EventSink;
use ferrum_ids::{Digest, PolicyId, RuleId};
use ferrum_k8smeta::{PodMetadataSource, PodRecord, SharedCgroupIndex, WorkloadIdentity};
use ferrum_proto::{EnforcementEvent, WaiverRef};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static LKG_SNAP_SEQ: AtomicU64 = AtomicU64::new(0);

/// How often the carrier re-scans the cgroup tree, re-joins it against the pod
/// snapshot and republishes the desired set to whoever owns `ferrum_cgroups`.
/// A container that starts between two ticks is a lookup miss, not a wrong
/// identity.
pub const CGROUP_REFRESH: Duration = Duration::from_secs(2);
/// A container map that has not been reaffirmed within this is not "quiet",
/// it is unproven: something on the publish path (pod watch, refresher, sync
/// thread) stopped, and the map now holds an arbitrarily old snapshot — dead
/// cgroup ids still flagged, every pod started since not flagged at all. Set
/// to 15 refresh rounds: long enough that a slow scan or a transient apiserver
/// error does not flap, far under the 2h last-known-good budget, which covers
/// a remote control plane rather than a thread in this process.
pub const CONTAINER_MAP_SYNC_BUDGET: Duration = Duration::from_secs(30);
/// A cgroup lands in the index one refresh before the carrier publishes it to
/// the kernel map, so every pod start has a window where its events arrive
/// without EVENT_FLAG_CONTAINER. That window is by construction, not a fault:
/// count it, and only call it a datapath fault once a sync that had the cgroup
/// available has since been accepted and it is still unflagged.
pub const CONTAINER_FLAG_GRACE: Duration = Duration::from_secs(6);
/// Degradation signals raised by observation (unresolved labels, a datapath
/// that keeps disagreeing) decay when the condition stops recurring. A latch
/// that only a restart clears stops carrying information.
pub const DEGRADED_RECOVERY: Duration = Duration::from_secs(30);
/// The thread that publishes the desired cgroup set is gone. Nothing will
/// update `ferrum_cgroups` again, so the map stops following the index.
pub const CGROUP_PUBLISHER_GONE: &str =
    "cgroup publisher gone: the container map can no longer follow the index";
/// The carrier that applies published sets is gone; publishing is pointless.
pub const CGROUP_CARRIER_GONE: &str = "cgroup carrier gone: nothing applies the published set";
/// Bound on the per-cgroup disagreement window map. Beyond this the oldest
/// windows are dropped; a cgroup that keeps disagreeing simply reopens one.
const CONTAINER_FLAG_TRACKED_MAX: usize = 4096;

fn mark_now(slot: &Mutex<Option<Instant>>, now: Instant) {
    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(now);
}

fn within(slot: &Mutex<Option<Instant>>, now: Instant, window: Duration) -> bool {
    match *slot.lock().unwrap_or_else(|e| e.into_inner()) {
        Some(at) => now.saturating_duration_since(at) < window,
        None => false,
    }
}

pub use clock::{MonotonicFloor, MAX_EXCEPTION_DAYS};
pub use pump::{pump_channel, pump_channel_host, pump_records, pump_records_host, PumpStats};
pub use respond::{
    host_pid_namespace, host_pid_namespace_at, NoopResponder, ProcCgroupCheck, Responder,
    SignalResponder, TargetCheck, HOST_PID_NS_INO, MAX_TGID, REFUSE_AGENT_SELF,
    REFUSE_DENY_NOT_ENFORCEABLE, REFUSE_ISOLATE, REFUSE_NOT_CONTAINER, REFUSE_NO_RESPONDER,
    REFUSE_ROLE, REFUSE_STALE_TARGET, REFUSE_TARGET_GONE, REFUSE_TGID_INIT, REFUSE_TGID_RANGE,
    REFUSE_TGID_SELF, REFUSE_TGID_ZERO, REFUSE_UNKNOWN_IDENTITY, RESPOND_NO_HOST_PIDNS,
};
pub use ring::{RingLoop, RingTick};
pub use source::{
    decode_fsig, encode_fsig, extract_fsig, load_exceptions_source, load_path, load_source,
    parse_trust_root, read_exceptions_path, read_source_path, ExtractedFsig, BUNDLE_DIGEST_KEY,
    BUNDLE_FSIG_KEY, EXCEPTIONS_FSIG_KEY, KUBELET_DATA_DIR, MAX_EXCEPTIONS_BYTES, SIGNED_FORMAT,
    SIGNED_MAGIC,
};

/// `EnforcementEvent.action` for a hit demoted by a live exception. Distinct
/// from plain "audit" so the waiver leaves an audit trail.
pub const WAIVED_ACTION: &str = "waived";

/// Cap on the number of specs in one `exceptions.fsig` payload.
pub const MAX_EXCEPTION_SPECS: usize = 4096;

/// Observe is default. Kill/Isolate execute only when Respond is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AgentRole {
    #[default]
    Observe,
    Respond,
}

impl AgentRole {
    pub fn respond_enabled(self) -> bool {
        matches!(self, Self::Respond)
    }

    pub fn parse_name(s: &str) -> Result<Self> {
        match s {
            "observe" => Ok(Self::Observe),
            "respond" => Ok(Self::Respond),
            other => Err(FerrumError::Validation(format!(
                "unknown role {other}; expected observe or respond"
            ))),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AgentConfig {
    pub role: AgentRole,
    pub lkg_dir: Option<PathBuf>,
    /// Pinned Ed25519 trust-root. Restore refuses unsigned FEBP without this.
    pub trust_root: Vec<u8>,
    /// kubelet Secret mount, `bundle.fsig` file, or raw FSIG.
    pub bundle_path: Option<PathBuf>,
    /// Live PolicyException list (`exceptions.json` from the bundle Secret).
    pub exceptions: Vec<PolicyExceptionSpec>,
    /// Exception scope matching needs the policy name; the FRMB does not carry
    /// it (mirrors `--policy-name` on admission). Empty = no waiver ever matches.
    pub policy_name: String,
}

pub struct Agent {
    role: AgentRole,
    loader: Loader,
    /// Shared with the refresher thread: the event path only reads it.
    cgroups: SharedCgroupIndex,
    cp_down: bool,
    lkg_dir: Option<PathBuf>,
    trust_root: Vec<u8>,
    bundle_path: Option<PathBuf>,
    exceptions: Vec<PolicyExceptionSpec>,
    policy_name: String,
    exceptions_reload_failed: AtomicU64,
    decode_failed: AtomicU64,
    unknown_syscalls: AtomicU64,
    /// Set when the decode table and the event source disagree (unknown nr):
    /// enforce rules can no longer be trusted to match, so the agent is
    /// Degraded even though the loaded bundle itself is fine.
    datapath_degraded: AtomicBool,
    /// True only after a real `KernelHandle::attach`; never inferred from a
    /// successful userspace bundle load.
    attached: AtomicBool,
    /// None until the carrier installs one. The library never signals by
    /// default: respond is opt-in and wired in `main`, not implied by a role.
    responder: Option<Box<dyn Responder>>,
    /// Re-reads the target's cgroup right before the signal. Defaults to the
    /// real `/proc`, so a caller that forgets to wire one refuses kills
    /// instead of signalling a pid that may have been reused.
    target_check: Box<dyn TargetCheck>,
    /// Set when respond was asked for and cannot be honoured (no host pid
    /// namespace): the agent runs in observe and stays Degraded.
    respond_disabled: Mutex<Option<String>>,
    clock: MonotonicFloor,
    respond_kill: AtomicU64,
    respond_refused: AtomicU64,
    respond_failed: AtomicU64,
    respond_stale_target: AtomicU64,
    /// Latched from the sink: export died, enforcement is no longer recorded.
    export_dead: AtomicBool,
    /// True once the carrier has pushed the cgroup index into `ferrum_cgroups`
    /// and the kernel accepted the whole plan.
    container_map_synced: AtomicBool,
    /// Entries the datapath map holds after the last successful sync.
    container_map_entries: AtomicU64,
    /// Last sync failure. Kept as a reason so the operator sees why the
    /// container flag cannot be trusted.
    container_map_error: Mutex<Option<String>>,
    /// Records where the index knew the pod but the datapath did not set
    /// EVENT_FLAG_CONTAINER. Every one of these is a `container_only` rule
    /// that did not match on a real container.
    container_flag_disagreement: AtomicU64,
    identity_unknown: AtomicU64,
    identity_unknown_at: Mutex<Option<Instant>>,
    /// When the last whole sync plan was accepted. Freshness, not just
    /// success: a publisher that stopped leaves `container_map_synced` true
    /// forever otherwise.
    container_map_synced_at: Mutex<Option<Instant>>,
    /// First unflagged event seen per cgroup, i.e. when its publish window
    /// opened. Bounded by `CONTAINER_FLAG_TRACKED_MAX`.
    container_flag_window: Mutex<HashMap<u64, Instant>>,
    /// Last disagreement that outlived its publish window. Recoverable.
    container_flag_fault_at: Mutex<Option<Instant>>,
    /// Decisions taken against a selector that could not be resolved because
    /// the label caches had nothing for that namespace / SA / cluster.
    labels_unknown: AtomicU64,
    labels_unknown_at: Mutex<Option<Instant>>,
    /// When the ring last dropped a record. Every verdict is taken in
    /// userspace, so a record that never arrived is an enforcement that never
    /// happened — indistinguishable, after the fact, from an event nobody had
    /// a rule for.
    ring_drop_at: Mutex<Option<Instant>>,
    /// Decisions where a `path_suffix` predicate was accepted on a path the
    /// datapath could not carry whole. Enforcement held, but on an assertion
    /// rather than on the argument, so the plane is not clean.
    path_truncated: AtomicU64,
    path_truncated_at: Mutex<Option<Instant>>,
}

impl Agent {
    pub fn new(config: AgentConfig) -> Self {
        let loader = match &config.lkg_dir {
            Some(dir) => Loader::with_lkg_dir(dir.clone()),
            None => Loader::new(),
        };
        let clock = match &config.lkg_dir {
            Some(dir) => MonotonicFloor::with_dir(dir.clone()),
            None => MonotonicFloor::new(),
        };
        clock.anchor_from_exceptions(&config.exceptions);
        let mut agent = Self {
            role: config.role,
            loader,
            cgroups: SharedCgroupIndex::new(),
            cp_down: false,
            lkg_dir: config.lkg_dir,
            trust_root: config.trust_root,
            bundle_path: config.bundle_path,
            exceptions: config.exceptions,
            policy_name: config.policy_name,
            exceptions_reload_failed: AtomicU64::new(0),
            decode_failed: AtomicU64::new(0),
            unknown_syscalls: AtomicU64::new(0),
            datapath_degraded: AtomicBool::new(false),
            attached: AtomicBool::new(false),
            responder: None,
            target_check: Box::new(ProcCgroupCheck::new()),
            respond_disabled: Mutex::new(None),
            clock,
            respond_kill: AtomicU64::new(0),
            respond_refused: AtomicU64::new(0),
            respond_failed: AtomicU64::new(0),
            respond_stale_target: AtomicU64::new(0),
            export_dead: AtomicBool::new(false),
            container_map_synced: AtomicBool::new(false),
            container_map_entries: AtomicU64::new(0),
            container_map_error: Mutex::new(None),
            container_flag_disagreement: AtomicU64::new(0),
            identity_unknown: AtomicU64::new(0),
            identity_unknown_at: Mutex::new(None),
            container_map_synced_at: Mutex::new(None),
            container_flag_window: Mutex::new(HashMap::new()),
            container_flag_fault_at: Mutex::new(None),
            labels_unknown: AtomicU64::new(0),
            labels_unknown_at: Mutex::new(None),
            ring_drop_at: Mutex::new(None),
            path_truncated: AtomicU64::new(0),
            path_truncated_at: Mutex::new(None),
        };
        let _ = agent.restore_last_known_good();
        agent
    }

    pub fn role(&self) -> AgentRole {
        self.role
    }

    pub fn set_role(&mut self, role: AgentRole) {
        self.role = role;
    }

    pub fn is_degraded(&self) -> bool {
        self.cp_down
            || self.loader.is_degraded()
            || !self.pins_attached()
            || self.datapath_degraded.load(Ordering::Relaxed)
            // An empty cgroup index is not "no pods": every lookup misses, so
            // every namespaced selector silently fails to match.
            || self.cgroups.is_empty()
            // The index alone proves nothing about the datapath: until those
            // cgroups are in `ferrum_cgroups`, EVENT_FLAG_CONTAINER is never
            // set and every container_only rule (shell, docker.sock) misses.
            || !self.container_map_ready()
            || self.export_dead.load(Ordering::Relaxed)
            // A selector the agent could not resolve is not a non-match: the
            // rules were applied fail-closed, and that is a Degraded plane
            // until the label caches catch up.
            || self.labels_unknown_recent()
            // An in-kernel drop under flood bounds the CPU cost, not the
            // policy: the dropped record carried an event no rule ever saw.
            // That is a missed enforcement, so it is Degraded while it lasts.
            || self.ring_drops_recent()
            // A path the datapath could not carry whole is a suffix rule
            // decided without the bytes it names. The rule still fired, but on
            // an assertion, and a node making those is Degraded.
            || self.path_truncated_recent()
            // A cgroup the index cannot name makes every namespaced selector
            // answer "no match" for a reason that has nothing to do with the
            // policy. That is a missed enforcement, not an allow.
            || self.identity_unknown_recent()
            || self.container_flag_degraded()
            || self.respond_disabled_reason().is_some()
    }

    /// The kernel container map is usable: last sync succeeded and it holds
    /// something. An empty map is not "no pods" — it is every container_only
    /// rule silently not matching.
    pub fn container_map_ready(&self) -> bool {
        self.container_map_synced.load(Ordering::Relaxed)
            && self.container_map_entries.load(Ordering::Relaxed) > 0
            && self.container_map_error().is_none()
            && !self.container_map_stale()
    }

    /// Nothing reaffirmed the map within `CONTAINER_MAP_SYNC_BUDGET`. The
    /// entries may be arbitrarily old, so they prove nothing about the pods
    /// running now.
    pub fn container_map_stale(&self) -> bool {
        self.container_map_stale_at(Instant::now())
    }

    pub fn container_map_stale_at(&self, now: Instant) -> bool {
        self.container_map_synced.load(Ordering::Relaxed)
            && !within(
                &self.container_map_synced_at,
                now,
                CONTAINER_MAP_SYNC_BUDGET,
            )
    }

    pub fn container_map_age(&self) -> Option<Duration> {
        (*self
            .container_map_synced_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()))
        .map(|at| Instant::now().saturating_duration_since(at))
    }

    pub fn container_map_synced(&self) -> bool {
        self.container_map_synced.load(Ordering::Relaxed)
    }

    pub fn container_map_entries(&self) -> u64 {
        self.container_map_entries.load(Ordering::Relaxed)
    }

    pub fn container_map_error(&self) -> Option<String> {
        self.container_map_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Called by the carrier after the kernel accepted a whole sync plan.
    pub fn set_container_map_synced(&self, entries: u64) {
        self.set_container_map_synced_at(entries, Instant::now())
    }

    /// The timestamp is the point the map was known to mirror a *freshly
    /// resolved* index. The carrier must not pass a fresh `Instant` for a plan
    /// computed from a set it could not re-resolve, or staleness never trips.
    pub fn set_container_map_synced_at(&self, entries: u64, at: Instant) {
        mark_now(&self.container_map_synced_at, at);
        self.container_map_entries.store(entries, Ordering::Relaxed);
        self.container_map_synced.store(true, Ordering::Relaxed);
        *self
            .container_map_error
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// A refused, partial or impossible sync. The map is no longer known to
    /// mirror the index, so the agent is Degraded until a sync succeeds.
    pub fn mark_container_map_error(&self, reason: impl Into<String>) {
        self.container_map_synced.store(false, Ordering::Relaxed);
        *self
            .container_map_error
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(reason.into());
    }

    /// Events whose cgroup is a known pod but which arrived without
    /// EVENT_FLAG_CONTAINER.
    pub fn container_flag_disagreement_total(&self) -> u64 {
        self.container_flag_disagreement.load(Ordering::Relaxed)
    }

    /// The datapath kept disagreeing past what the publish path can explain,
    /// recently enough to still mean something. Not a latch: it clears once
    /// the disagreements stop.
    pub fn container_flag_degraded(&self) -> bool {
        self.container_flag_degraded_at(Instant::now())
    }

    pub fn container_flag_degraded_at(&self, now: Instant) -> bool {
        within(&self.container_flag_fault_at, now, DEGRADED_RECOVERY)
    }

    /// Count one event whose cgroup the index knows but which the datapath did
    /// not flag as a container, and decide whether that is a fault. Returns
    /// true when it degraded the agent.
    pub fn note_container_flag_disagreement(&self, cgroup_id: u64, now: Instant) -> bool {
        self.container_flag_disagreement
            .fetch_add(1, Ordering::Relaxed);
        let synced_at = *self
            .container_map_synced_at
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut windows = self
            .container_flag_window
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if windows.len() >= CONTAINER_FLAG_TRACKED_MAX && !windows.contains_key(&cgroup_id) {
            windows
                .retain(|_, opened| now.saturating_duration_since(*opened) < CONTAINER_FLAG_GRACE);
        }
        let opened = *windows.entry(cgroup_id).or_insert(now);
        // A sync accepted after the window opened had this cgroup in the index
        // and still did not get it flagged: that is the datapath, not the
        // start-up race every pod goes through.
        let missed_a_sync = synced_at.is_some_and(|at| at > opened);
        if now.saturating_duration_since(opened) < CONTAINER_FLAG_GRACE || !missed_a_sync {
            return false;
        }
        windows.remove(&cgroup_id);
        drop(windows);
        mark_now(&self.container_flag_fault_at, now);
        true
    }

    /// Decisions taken against a selector whose labels were never observed.
    pub fn labels_unknown_total(&self) -> u64 {
        self.labels_unknown.load(Ordering::Relaxed)
    }

    /// Recoverable: an agent whose label caches filled in stops being Degraded
    /// on its own, without a restart.
    pub fn labels_unknown_recent(&self) -> bool {
        self.labels_unknown_recent_at(Instant::now())
    }

    pub fn labels_unknown_recent_at(&self, now: Instant) -> bool {
        within(&self.labels_unknown_at, now, DEGRADED_RECOVERY)
    }

    pub fn record_labels_unknown(&self, now: Instant) {
        self.labels_unknown.fetch_add(1, Ordering::Relaxed);
        mark_now(&self.labels_unknown_at, now);
    }

    pub fn identity_unknown_total(&self) -> u64 {
        self.identity_unknown.load(Ordering::Relaxed)
    }

    pub fn identity_unknown_recent(&self) -> bool {
        self.identity_unknown_recent_at(Instant::now())
    }

    pub fn identity_unknown_recent_at(&self, now: Instant) -> bool {
        within(&self.identity_unknown_at, now, DEGRADED_RECOVERY)
    }

    /// A cgroup the index cannot name. The counterpart of
    /// `note_container_flag_disagreement`, which covers the opposite direction
    /// (index knows the pod, kernel did not flag it).
    pub fn record_identity_unknown(&self, now: Instant) {
        self.identity_unknown.fetch_add(1, Ordering::Relaxed);
        mark_now(&self.identity_unknown_at, now);
    }

    /// True only while a `KernelHandle` attach is live. `Loader::attach_pins`
    /// stays Degraded: nothing is pinned at `PIN_PATH` yet, and that gap in
    /// the threat model is not covered by this flag.
    pub fn pins_attached(&self) -> bool {
        self.attached.load(Ordering::Relaxed)
    }

    /// Set by the carrier after `KernelHandle::attach` returns Ok, and cleared
    /// when the handle is dropped.
    pub fn set_attached(&self, attached: bool) {
        self.attached.store(attached, Ordering::Relaxed);
    }

    /// Install the reaction backend (`SignalResponder` in production, a fake
    /// in tests). Without one, a Kill decision is refused, not silently
    /// dropped.
    pub fn set_responder(&mut self, responder: Box<dyn Responder>) {
        self.responder = Some(responder);
    }

    /// Replace the pre-signal target check (tests, a non-standard `/proc`).
    pub fn set_target_check(&mut self, check: Box<dyn TargetCheck>) {
        self.target_check = check;
    }

    /// Respond was requested and cannot be delivered: drop to observe, keep
    /// the reason, and stay Degraded rather than signalling blind.
    pub fn disable_respond(&mut self, reason: impl Into<String>) {
        self.role = AgentRole::Observe;
        self.responder = None;
        *self
            .respond_disabled
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(reason.into());
    }

    pub fn respond_disabled_reason(&self) -> Option<String> {
        self.respond_disabled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn respond_kill_total(&self) -> u64 {
        self.respond_kill.load(Ordering::Relaxed)
    }

    pub fn respond_refused_total(&self) -> u64 {
        self.respond_refused.load(Ordering::Relaxed)
    }

    /// Reactions that passed every guard and still failed (the signal itself
    /// errored). Not a refusal: the agent meant to kill and could not.
    pub fn respond_failed_total(&self) -> u64 {
        self.respond_failed.load(Ordering::Relaxed)
    }

    /// Kills refused because the tgid no longer lives in the cgroup that
    /// raised the event, or the process is already gone. Each one is a signal
    /// that was NOT sent to a reused pid.
    pub fn respond_stale_target_total(&self) -> u64 {
        self.respond_stale_target.load(Ordering::Relaxed)
    }

    /// True once the export writer thread has died: enforcement still runs,
    /// but nothing is recorded, which is a Degraded agent.
    pub fn export_writer_dead(&self) -> bool {
        self.export_dead.load(Ordering::Relaxed)
    }

    pub fn clock_rollback_total(&self) -> u64 {
        self.clock.clock_rollback_total()
    }

    pub fn clock(&self) -> &MonotonicFloor {
        &self.clock
    }

    /// Wall clock guarded by the monotonic floor. A backwards jump marks the
    /// datapath Degraded: waiver expiry is decided on this reading.
    pub fn now(&self) -> DateTime<Utc> {
        self.now_from(Utc::now())
    }

    pub fn now_from(&self, wall: DateTime<Utc>) -> DateTime<Utc> {
        let before = self.clock.clock_rollback_total();
        let now = self.clock.now_from(wall);
        if self.clock.clock_rollback_total() != before {
            self.datapath_degraded.store(true, Ordering::Relaxed);
        }
        now
    }

    pub fn using_last_known_good(&self) -> bool {
        self.loader.last_good().is_some()
    }

    pub fn last_good_digest(&self) -> Option<&Digest> {
        self.loader.last_good().map(|b| &b.digest)
    }

    pub fn events_dropped_total(&self) -> u64 {
        self.loader.events_dropped_total()
    }

    /// In-kernel ring drops only (RFC-02 §C). Userspace decode failures go to
    /// `record_decode_failure` so a burst of malformed records cannot pose as
    /// ring-buffer pressure or vice versa.
    pub fn record_drop(&self, n: u64) {
        self.record_drop_at(n, Instant::now());
    }

    pub fn record_drop_at(&self, n: u64, now: Instant) {
        if n == 0 {
            return;
        }
        self.loader.record_drop(n);
        mark_now(&self.ring_drop_at, now);
    }

    /// Recoverable, like the other observation signals: a node that stops
    /// dropping stops being Degraded without a restart. A latch here would
    /// mark every agent that ever saw a burst as permanently blind.
    pub fn ring_drops_recent(&self) -> bool {
        self.ring_drops_recent_at(Instant::now())
    }

    pub fn ring_drops_recent_at(&self, now: Instant) -> bool {
        within(&self.ring_drop_at, now, DEGRADED_RECOVERY)
    }

    pub fn records_decode_failed_total(&self) -> u64 {
        self.decode_failed.load(Ordering::Relaxed)
    }

    pub fn record_decode_failure(&self, n: u64) {
        self.decode_failed.fetch_add(n, Ordering::Relaxed);
    }

    pub fn unknown_syscall_total(&self) -> u64 {
        self.unknown_syscalls.load(Ordering::Relaxed)
    }

    pub fn record_unknown_syscall(&self) {
        self.unknown_syscalls.fetch_add(1, Ordering::Relaxed);
        self.datapath_degraded.store(true, Ordering::Relaxed);
    }

    pub fn datapath_degraded(&self) -> bool {
        self.datapath_degraded.load(Ordering::Relaxed) || self.path_truncated_recent()
    }

    pub fn path_truncated_total(&self) -> u64 {
        self.path_truncated.load(Ordering::Relaxed)
    }

    /// Recoverable like the other observation signals: a node that stops
    /// seeing oversize paths stops being Degraded without a restart.
    pub fn record_path_truncated(&self, now: Instant) {
        self.path_truncated.fetch_add(1, Ordering::Relaxed);
        mark_now(&self.path_truncated_at, now);
    }

    pub fn path_truncated_recent(&self) -> bool {
        self.path_truncated_recent_at(Instant::now())
    }

    pub fn path_truncated_recent_at(&self, now: Instant) -> bool {
        within(&self.path_truncated_at, now, DEGRADED_RECOVERY)
    }

    /// CP down: keep LKG, never fail-open.
    pub fn mark_control_plane_down(&mut self) {
        self.cp_down = true;
    }

    pub fn mark_control_plane_up(&mut self) {
        self.cp_down = false;
    }

    pub fn control_plane_down(&self) -> bool {
        self.cp_down
    }

    pub fn bundle_path(&self) -> Option<&Path> {
        self.bundle_path.as_deref()
    }

    pub fn policy_name(&self) -> &str {
        &self.policy_name
    }

    pub fn exceptions(&self) -> &[PolicyExceptionSpec] {
        &self.exceptions
    }

    pub fn set_exceptions(&mut self, list: Vec<PolicyExceptionSpec>) {
        self.clock.anchor_from_exceptions(&list);
        self.exceptions = list;
    }

    pub fn exceptions_reload_failed_total(&self) -> u64 {
        self.exceptions_reload_failed.load(Ordering::Relaxed)
    }

    /// Verify an `exceptions.fsig` envelope against the pinned trust-root,
    /// then parse the signed JSON payload into the live table. Verification
    /// and parsing happen only here, never on the per-event path. Plain JSON,
    /// a foreign key, a tampered payload, garbage, or a spec-count overflow
    /// drops ALL waivers (fail-closed: never keep a stale list) and counts.
    pub fn try_reload_exceptions(&mut self, bytes: &[u8]) -> Result<usize> {
        match self.verify_and_parse_exceptions(bytes) {
            Ok(list) => {
                let n = list.len();
                self.clock.anchor_from_exceptions(&list);
                self.exceptions = list;
                Ok(n)
            }
            Err(err) => {
                self.exceptions.clear();
                self.exceptions_reload_failed
                    .fetch_add(1, Ordering::Relaxed);
                Err(err)
            }
        }
    }

    fn verify_and_parse_exceptions(&self, bytes: &[u8]) -> Result<Vec<PolicyExceptionSpec>> {
        let raw = load_exceptions_source(bytes, &self.trust_root)?;
        let list = serde_json::from_slice::<Vec<PolicyExceptionSpec>>(&raw)
            .map_err(|e| FerrumError::Validation(format!("exceptions.fsig payload: {e}")))?;
        if list.len() > MAX_EXCEPTION_SPECS {
            return Err(FerrumError::Validation(format!(
                "exceptions.fsig payload has {} specs, cap is {MAX_EXCEPTION_SPECS}",
                list.len()
            )));
        }
        Ok(list)
    }

    /// Reload `exceptions.fsig` from the same Secret mount as the bundle.
    /// Missing file = empty list; unreadable file drops waivers and counts.
    pub fn reload_exceptions_path(&mut self, path: &Path) -> Result<usize> {
        match read_exceptions_path(path) {
            Ok(Some(bytes)) => self.try_reload_exceptions(&bytes),
            Ok(None) => {
                self.exceptions.clear();
                Ok(0)
            }
            Err(err) => {
                self.exceptions.clear();
                self.exceptions_reload_failed
                    .fetch_add(1, Ordering::Relaxed);
                Err(err)
            }
        }
    }

    pub fn restore_last_known_good(&mut self) -> Result<()> {
        let dir = match &self.lkg_dir {
            Some(dir) => dir.clone(),
            None => return Ok(()),
        };
        if !lkg_present(&dir) {
            return Ok(());
        }
        if self.trust_root.is_empty() {
            self.loader.mark_degraded();
            return Err(FerrumError::Degraded(
                "LKG present but no pinned trust-root; unsigned FEBP is not applied".into(),
            ));
        }
        let (bytes, expected) = match read_source_path(&dir) {
            Ok(v) => v,
            Err(err) => {
                self.loader.mark_degraded();
                return Err(err);
            }
        };
        // Install only: do not persist back over the snapshot being restored.
        self.install_verified(&bytes, expected.as_ref()).map(|_| ())
    }

    pub fn insert_cgroup(&self, inode: u64, identity: WorkloadIdentity) {
        self.cgroups.insert(inode, identity);
    }

    /// Handle for the refresher thread (`CgroupResolver` writes through it).
    pub fn cgroup_index(&self) -> SharedCgroupIndex {
        self.cgroups.clone()
    }

    /// Number of resolved cgroups. Zero means every namespaced selector misses.
    pub fn cgroup_index_len(&self) -> usize {
        self.cgroups.len()
    }

    pub fn lookup_cgroup(&self, inode: u64) -> Result<WorkloadIdentity> {
        self.cgroups.lookup_cgroup(inode)
    }

    /// Verify FSIG with the pinned trust-root, then `load_bundle`. On failure the
    /// previous spec remains and the agent is Degraded. Empty signature is
    /// Integrity, never a fake Ok. Persists `bundle.fsig` + UTF-8 hex `digest`
    /// as one snapshot.
    pub fn apply_fsig(&mut self, bytes: &[u8], expected_digest: Option<&Digest>) -> Result<Digest> {
        let digest = self.install_verified(bytes, expected_digest)?;
        if let Err(err) = self.persist_fsig(bytes, &digest) {
            self.loader.mark_degraded();
            return Err(err);
        }
        Ok(digest)
    }

    /// Load a file or directory mount. Directory `digest` mismatch does not swap.
    pub fn apply_path(&mut self, path: &Path) -> Result<Digest> {
        let (bytes, expected) = match read_source_path(path) {
            Ok(v) => v,
            Err(err) => {
                self.loader.mark_degraded();
                return Err(err);
            }
        };
        self.apply_fsig(&bytes, expected.as_ref())
    }

    fn install_verified(
        &mut self,
        bytes: &[u8],
        expected_digest: Option<&Digest>,
    ) -> Result<Digest> {
        let (raw, digest) = match load_source(bytes, &self.trust_root, expected_digest) {
            Ok(v) => v,
            Err(err) => {
                self.loader.mark_degraded();
                return Err(err);
            }
        };
        if let Err(err) = extract_febp(&raw) {
            self.loader.mark_degraded();
            return Err(err);
        }
        self.loader.load_bundle(&digest, &raw)?;
        Ok(digest)
    }

    fn persist_fsig(&self, fsig: &[u8], digest: &Digest) -> Result<()> {
        let dir = match &self.lkg_dir {
            Some(dir) => dir,
            None => return Ok(()),
        };
        fs::create_dir_all(dir)
            .map_err(|e| FerrumError::Degraded(format!("create LKG dir: {e}")))?;
        if lkg_digest_on_disk(dir).as_deref() == Some(digest.as_str()) {
            return Ok(());
        }
        let snap_name = format!(
            "..snap-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            LKG_SNAP_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let snap = dir.join(&snap_name);
        if let Err(err) = write_snap(&snap, fsig, digest) {
            let _ = fs::remove_dir_all(&snap);
            return Err(err);
        }
        if let Err(err) = atomic_symlink(dir, KUBELET_DATA_DIR, &snap_name) {
            let _ = fs::remove_dir_all(&snap);
            return Err(err);
        }
        atomic_symlink(
            dir,
            BUNDLE_FSIG_KEY,
            &format!("{KUBELET_DATA_DIR}/{BUNDLE_FSIG_KEY}"),
        )?;
        atomic_symlink(
            dir,
            BUNDLE_DIGEST_KEY,
            &format!("{KUBELET_DATA_DIR}/{BUNDLE_DIGEST_KEY}"),
        )?;
        remove_stale_snaps(dir, &snap_name);
        Ok(())
    }

    pub fn matched_action(&self, event: &SyscallEvent<'_>) -> Decision {
        self.loader.matched_action(event)
    }

    /// `meta` carries the structural identity of the record (cgroup for the
    /// pod lookup, tgid for the reaction). A bare `u64` still works and means
    /// "cgroup only": it carries no tgid, so it can never cause a kill.
    pub fn handle_event<S: EventSink, M: Into<EventMeta>>(
        &self,
        meta: M,
        event: &SyscallEvent<'_>,
        sink: &S,
    ) -> Decision {
        self.handle_event_at(meta, event, sink, self.now())
    }

    pub fn handle_event_at<S: EventSink, M: Into<EventMeta>>(
        &self,
        meta: M,
        event: &SyscallEvent<'_>,
        sink: &S,
        now: DateTime<Utc>,
    ) -> Decision {
        let meta: EventMeta = meta.into();
        let identity = match self.cgroups.lookup_cgroup(meta.cgroup_id) {
            Ok(id) => {
                if !meta.in_container {
                    // The index says this cgroup is a pod container and the
                    // datapath did not flag it: `ferrum_cgroups` is behind the
                    // index, so container_only rules are missing on real
                    // containers. Always counted; Degraded only once it
                    // outlives the publish window (see
                    // `note_container_flag_disagreement`). Either way the
                    // decision is NOT upgraded from the flags we do have, and
                    // the kill guard in `react` still refuses: a wrong kill on
                    // the node is worse than a missed one.
                    self.note_container_flag_disagreement(meta.cgroup_id, Instant::now());
                }
                id
            }
            Err(_) => {
                // Only when the kernel says otherwise. Host processes (kubelet,
                // containerd, sshd) stream openat all day, their cgroups are
                // not pods and never will be, and the datapath already clears
                // EVENT_FLAG_CONTAINER for them: counting those would pin the
                // node to Degraded forever and drown every other signal. A miss
                // on a record the datapath *did* flag as a container is the
                // real gap: a namespaced selector cannot match an unknown
                // identity, so `decide` answers Allow and a container_only kill
                // rule silently does not fire.
                if meta.in_container {
                    self.record_identity_unknown(Instant::now());
                }
                WorkloadIdentity::unknown()
            }
        };
        let mut decision = self.loader.decide(event, &identity);
        if decision.labels_unknown {
            self.record_labels_unknown(Instant::now());
        }
        if decision.path_unknown {
            self.record_path_truncated(Instant::now());
        }
        let waiver = self
            .waiver_applies(&decision, &identity, now)
            .map(|spec| WaiverRef {
                ticket: spec.ticket.clone(),
                requested_by: spec.requested_by.clone(),
                approved_by: spec.approved_by.clone(),
                expires_at: spec.expires_at,
            });
        if waiver.is_some() {
            decision.action = Action::Audit;
        }
        decision.action = apply_role(self.role, decision.action);
        let (executed, respond_error) = self.react(&decision, &meta, &identity, event);
        let policy = match self.loader.last_good() {
            Some(loaded) => PolicyId::new(loaded.digest.as_str()),
            None => PolicyId::new("none"),
        };
        let rule = match &decision.rule_id {
            Some(id) => RuleId::new(id.clone()),
            None => RuleId::new("default"),
        };
        sink.emit(&EnforcementEvent {
            policy,
            rule,
            action: if waiver.is_some() {
                WAIVED_ACTION.into()
            } else {
                decision.action.as_str().into()
            },
            image_digest: None,
            pod: identity.pod,
            namespace: identity.namespace,
            comm: event.comm.into(),
            syscall: event.syscall.into(),
            pid: meta.pid,
            tgid: meta.tgid,
            executed,
            respond_error,
            waiver,
        });
        if sink.export_writer_dead() {
            self.export_dead.store(true, Ordering::Relaxed);
        }
        decision
    }

    /// Turn a decision into a reaction. Every path that does not signal
    /// returns a reason, which is exported with `executed=false`; nothing here
    /// fails silently, and nothing pretends an unimplemented reaction ran.
    fn react(
        &self,
        decision: &Decision,
        meta: &EventMeta,
        identity: &WorkloadIdentity,
        event: &SyscallEvent<'_>,
    ) -> (bool, Option<String>) {
        match decision.action {
            Action::Kill => {}
            Action::Isolate => {
                self.respond_refused.fetch_add(1, Ordering::Relaxed);
                return (false, Some(respond::REFUSE_ISOLATE.into()));
            }
            // Deny is a decision this layer cannot execute; saying so is the
            // difference between a policy nobody enforces and one whose gap
            // is on the record. Allow/Audit fall through with no reason
            // because there was nothing to execute in the first place.
            Action::Deny => {
                self.respond_refused.fetch_add(1, Ordering::Relaxed);
                return (false, Some(respond::REFUSE_DENY_NOT_ENFORCEABLE.into()));
            }
            Action::Allow | Action::Audit => return (false, None),
        }
        // The datapath flags are authoritative for the reaction: the string
        // view can be rebuilt by a caller, the record flags cannot.
        let agent_self = meta.agent_self || event.agent_self;
        let in_container = meta.in_container && event.in_container;
        if let Some(reason) = respond::refuse_reason(
            self.role.respond_enabled(),
            meta.tgid,
            agent_self,
            in_container,
            identity.is_unknown(),
        ) {
            self.respond_refused.fetch_add(1, Ordering::Relaxed);
            return (false, Some(reason.into()));
        }
        // The decision was made on an event that has been through a queue and
        // a poll interval; the pid space wraps in far less. Confirm the target
        // is still the workload that raised it before signalling anything.
        match self.target_check.cgroup_id(meta.tgid) {
            Some(current) if current == meta.cgroup_id => {}
            Some(_) => {
                self.respond_stale_target.fetch_add(1, Ordering::Relaxed);
                self.respond_refused.fetch_add(1, Ordering::Relaxed);
                return (false, Some(respond::REFUSE_STALE_TARGET.into()));
            }
            None => {
                self.respond_stale_target.fetch_add(1, Ordering::Relaxed);
                self.respond_refused.fetch_add(1, Ordering::Relaxed);
                return (false, Some(respond::REFUSE_TARGET_GONE.into()));
            }
        }
        let responder = match &self.responder {
            Some(responder) => responder,
            None => {
                self.respond_refused.fetch_add(1, Ordering::Relaxed);
                return (false, Some(respond::REFUSE_NO_RESPONDER.into()));
            }
        };
        match responder.kill(meta.tgid) {
            Ok(()) => {
                self.respond_kill.fetch_add(1, Ordering::Relaxed);
                (true, None)
            }
            Err(err) => {
                self.respond_failed.fetch_add(1, Ordering::Relaxed);
                (false, Some(err.to_string()))
            }
        }
    }

    /// A live in-scope exception demotes only enforcing actions on a named
    /// rule; the first match is the one recorded in the audit trail. Identity
    /// comes from the cgroup index, so `WorkloadIdentity::unknown()` (empty
    /// namespace) can never satisfy a namespaced exception.
    fn waiver_applies(
        &self,
        decision: &Decision,
        identity: &WorkloadIdentity,
        now: DateTime<Utc>,
    ) -> Option<&PolicyExceptionSpec> {
        if self.policy_name.is_empty() {
            return None;
        }
        if !matches!(
            decision.action,
            Action::Kill | Action::Isolate | Action::Deny
        ) {
            return None;
        }
        let rule = decision.rule_id.as_deref()?;
        self.exceptions.iter().find(|spec| {
            ferrum_policy::exception_applies(
                spec,
                &identity.namespace,
                &self.policy_name,
                rule,
                now,
            )
        })
    }

    /// Does not create pins. LSM on `PIN_PATH` is required in production.
    pub fn attach_pins(&self) -> Result<()> {
        self.loader.attach_pins()
    }
}

/// Pod metadata read from a cache someone else keeps current (the apiserver
/// watch thread). The refresher only reads it, so a stalled watch shows up as
/// an index that stops changing, never as a half-written snapshot.
pub struct SharedPodSource(std::sync::Arc<std::sync::RwLock<ferrum_k8smeta::PodCache>>);

impl SharedPodSource {
    pub fn new(cache: std::sync::Arc<std::sync::RwLock<ferrum_k8smeta::PodCache>>) -> Self {
        Self(cache)
    }
}

impl PodMetadataSource for SharedPodSource {
    fn snapshot(&self) -> Result<Vec<PodRecord>> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).snapshot()
    }
}

/// Drain every cgroup set the publisher has queued. A disconnected channel is
/// not an empty one: with the publisher gone the map is frozen on whatever it
/// held, so it is marked in error instead of quietly looking healthy. Returns
/// false once the publisher is gone.
pub fn drain_cgroup_updates<T, F>(
    rx: &std::sync::mpsc::Receiver<T>,
    agent: &Agent,
    mut apply: F,
) -> bool
where
    F: FnMut(&Agent, T),
{
    loop {
        match rx.try_recv() {
            Ok(update) => apply(agent, update),
            Err(std::sync::mpsc::TryRecvError::Empty) => return true,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                agent.mark_container_map_error(CGROUP_PUBLISHER_GONE);
                return false;
            }
        }
    }
}

/// Publish one desired cgroup set. A full channel drops this update on
/// purpose: each message is the whole set, so the next one carries current
/// truth. A disconnected channel is different in kind — nobody will ever apply
/// another set — and returns false so the publisher stops.
pub fn publish_cgroups<T>(tx: &std::sync::mpsc::SyncSender<T>, update: T) -> bool {
    !matches!(
        tx.try_send(update),
        Err(std::sync::mpsc::TrySendError::Disconnected(_))
    )
}

pub fn apply_role(role: AgentRole, action: Action) -> Action {
    match (role, action) {
        (AgentRole::Observe, Action::Kill | Action::Isolate) => Action::Audit,
        (_, action) => action,
    }
}

/// Watch `path` (file, or directory containing `bundle.fsig` + `digest`).
/// Uses mtime+len and follows kubelet `..data`; a vanished bundle keeps
/// last-good. The sibling `exceptions.fsig` rides the same interval; unlike
/// the bundle, a vanished exceptions file clears waivers (TTL'd data, no LKG).
/// `export`, when present, tracks the agent's digest/degraded state so every
/// exported envelope carries the state at emit time.
pub fn poll_bundle(
    agent: &mut Agent,
    path: &Path,
    interval: Duration,
    export: Option<&ferrum_export::SinkContext>,
) -> ! {
    // Stat the path as given so kubelet `..data` rotates are visible; do not canonicalize.
    // Start with no stamp so a rotation between first load and this thread is not skipped.
    let mut stamps = PollStamps::default();
    loop {
        std::thread::sleep(interval);
        poll_once(agent, path, &mut stamps, export);
    }
}

/// `poll_bundle` for a datapath that is pumping events concurrently: the write
/// lock is taken per tick, not held across the sleep, so reload never blocks
/// the decision path for longer than one reload.
pub fn poll_bundle_shared(
    agent: &std::sync::RwLock<Agent>,
    path: &Path,
    interval: Duration,
    export: Option<&ferrum_export::SinkContext>,
) -> ! {
    let mut stamps = PollStamps::default();
    loop {
        std::thread::sleep(interval);
        let mut guard = agent.write().unwrap_or_else(|e| e.into_inner());
        poll_once(&mut guard, path, &mut stamps, export);
    }
}

#[derive(Default)]
struct PollStamps {
    bundle: Option<source::SourceStamp>,
    exceptions: Option<source::FileStamp>,
}

fn poll_once(
    agent: &mut Agent,
    path: &Path,
    stamps: &mut PollStamps,
    export: Option<&ferrum_export::SinkContext>,
) {
    if let Some(next) = source::source_stamp(path) {
        if Some(next) != stamps.bundle {
            stamps.bundle = Some(next);
            if let Err(err) = agent.apply_path(path) {
                eprintln!("ferrum-agent: bundle reload failed, keeping last-known-good: {err}");
            }
        }
    }
    match source::exceptions_stamp(path) {
        None => {
            if stamps.exceptions.take().is_some() {
                agent.set_exceptions(Vec::new());
            }
        }
        Some(next) => {
            if Some(next) != stamps.exceptions {
                stamps.exceptions = Some(next);
                if let Err(err) = agent.reload_exceptions_path(path) {
                    eprintln!("ferrum-agent: exceptions reload failed, waivers dropped: {err}");
                }
            }
        }
    }
    agent.clock().persist();
    if let Some(ctx) = export {
        ctx.set_bundle_digest(agent.last_good_digest().cloned());
        ctx.set_degraded(agent.is_degraded());
    }
}

fn lkg_present(dir: &Path) -> bool {
    dir.join(BUNDLE_FSIG_KEY).exists()
        || dir.join(BUNDLE_DIGEST_KEY).exists()
        || dir.join(KUBELET_DATA_DIR).exists()
}

fn lkg_digest_on_disk(dir: &Path) -> Option<String> {
    let snap = source::source_snapshot_dir(dir)?;
    let bytes = fs::read(snap.join(BUNDLE_DIGEST_KEY)).ok()?;
    let hex = std::str::from_utf8(&bytes).ok()?.trim();
    if hex.is_empty() {
        None
    } else {
        Some(hex.to_string())
    }
}

fn remove_stale_snaps(dir: &Path, keep_name: &str) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for ent in rd.filter_map(|e| e.ok()) {
        let name = ent.file_name();
        let Some(n) = name.to_str() else {
            continue;
        };
        if n.starts_with("..snap-") && n != keep_name {
            let _ = fs::remove_dir_all(ent.path());
        }
    }
}

fn write_snap(snap: &Path, fsig: &[u8], digest: &Digest) -> Result<()> {
    fs::create_dir_all(snap).map_err(|e| FerrumError::Degraded(format!("create LKG snap: {e}")))?;
    fs::write(snap.join(BUNDLE_FSIG_KEY), fsig)
        .map_err(|e| FerrumError::Degraded(format!("write LKG fsig: {e}")))?;
    fs::write(snap.join(BUNDLE_DIGEST_KEY), digest.as_str().as_bytes())
        .map_err(|e| FerrumError::Degraded(format!("write LKG digest: {e}")))?;
    Ok(())
}

fn atomic_symlink(dir: &Path, link_name: &str, target: &str) -> Result<()> {
    let link = dir.join(link_name);
    let tmp = dir.join(format!("{link_name}.tmp"));
    let _ = fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp)
        .map_err(|e| FerrumError::Degraded(format!("symlink LKG {link_name}: {e}")))?;
    fs::rename(&tmp, link)
        .map_err(|e| FerrumError::Degraded(format!("rename LKG {link_name}: {e}")))?;
    Ok(())
}

#[cfg(test)]
impl Agent {
    fn apply_bundle(&mut self, raw: &[u8], sig: &[u8], public_key: &[u8]) -> Result<Digest> {
        let fsig = encode_fsig(raw, sig, public_key)?;
        self.apply_fsig(&fsig, None)
    }

    fn policy_degraded(&self) -> bool {
        self.loader.is_degraded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_common::FerrumError;
    use ferrum_ebpf::{parse_febp, Action, Mode, EBPF_MAGIC, PIN_PATH};
    use ferrum_export::MemorySink;
    use ferrum_ids::AGENT_ABI;
    use std::fs;
    use std::path::{Path, PathBuf};

    const SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const SK2: [u8; 32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ];

    struct Writer(Vec<u8>);

    impl Writer {
        fn new() -> Self {
            Self(Vec::new())
        }
        fn put_magic(&mut self, magic: &[u8; 4]) {
            self.0.extend_from_slice(magic);
        }
        fn put_u8(&mut self, v: u8) {
            self.0.push(v);
        }
        fn put_u16(&mut self, v: u16) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn put_u32(&mut self, v: u32) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn put_i32(&mut self, v: i32) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn put_bool(&mut self, v: bool) {
            self.put_u8(u8::from(v));
        }
        fn put_str(&mut self, s: &str) {
            self.put_u16(s.len() as u16);
            self.0.extend_from_slice(s.as_bytes());
        }
        fn put_str_list(&mut self, items: &[&str]) {
            self.put_u16(items.len() as u16);
            for item in items {
                self.put_str(item);
            }
        }
        fn finish(self) -> Vec<u8> {
            self.0
        }
    }

    fn put_empty_label_selector(w: &mut Writer) {
        w.put_u16(0);
        w.put_u16(0);
    }

    fn put_mvp_rules(w: &mut Writer) {
        w.put_u16(3);
        w.put_str("no-shell");
        w.put_str_list(&["execve", "execveat"]);
        w.put_u8(Action::Kill.as_u8());
        w.put_str_list(&["sh", "bash", "ash", "dash", "zsh"]);
        w.put_bool(true);
        w.put_str_list(&[]);
        w.put_str_list(&[]);
        w.put_bool(false);
        w.put_str("no-runtime-sock");
        w.put_str_list(&[]);
        w.put_u8(Action::Kill.as_u8());
        w.put_str_list(&[]);
        w.put_bool(false);
        w.put_str_list(&[]);
        w.put_str_list(&["docker.sock", "containerd.sock", "crio.sock"]);
        w.put_bool(false);
        w.put_str("no-module");
        w.put_str_list(&["init_module", "finit_module", "bpf"]);
        w.put_u8(Action::Deny.as_u8());
        w.put_str_list(&[]);
        w.put_bool(false);
        w.put_str_list(&[]);
        w.put_str_list(&[]);
        w.put_bool(true);
    }

    fn encode_mvp(abi: u32, mode: Mode) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_magic(&EBPF_MAGIC);
        w.put_u32(abi);
        w.put_u8(mode.as_u8());
        w.put_bool(false);
        w.put_i32(0);
        w.put_u8(Action::Audit.as_u8());
        for _ in 0..4 {
            put_empty_label_selector(&mut w);
        }
        w.put_str_list(&[]);
        w.put_bool(false);
        put_mvp_rules(&mut w);
        w.finish()
    }

    /// FEBP matching `policies/examples/prod-restricted.yaml` runtime + selector.
    fn encode_prod_restricted_ebpf(abi: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_magic(&EBPF_MAGIC);
        w.put_u32(abi);
        w.put_u8(Mode::Audit.as_u8());
        w.put_bool(false);
        w.put_i32(100);
        w.put_u8(Action::Audit.as_u8());
        put_empty_label_selector(&mut w);
        w.put_u16(0);
        w.put_u16(1);
        w.put_str("ferrum.io/zone");
        w.put_str("In");
        w.put_str_list(&["pci", "secrets"]);
        put_empty_label_selector(&mut w);
        put_empty_label_selector(&mut w);
        w.put_str_list(&["registry.internal.example"]);
        w.put_bool(true);
        put_mvp_rules(&mut w);
        w.finish()
    }

    fn pk() -> Vec<u8> {
        ferrum_crypto::public_key_from_secret(&SK).expect("pk")
    }

    fn sign(raw: &[u8]) -> Vec<u8> {
        ferrum_crypto::sign_bundle(raw, &SK).expect("sign")
    }

    fn cfg() -> AgentConfig {
        AgentConfig {
            trust_root: pk(),
            ..Default::default()
        }
    }

    fn cfg_respond() -> AgentConfig {
        AgentConfig {
            role: AgentRole::Respond,
            trust_root: pk(),
            ..Default::default()
        }
    }

    fn load_signed(agent: &mut Agent, raw: &[u8]) -> Digest {
        agent.apply_bundle(raw, &sign(raw), &pk()).expect("apply")
    }

    fn ev<'a>(
        syscall: &'a str,
        comm: &'a str,
        path: &'a str,
        in_container: bool,
        agent_self: bool,
    ) -> SyscallEvent<'a> {
        SyscallEvent {
            syscall,
            comm,
            path,
            in_container,
            agent_self,
            path_truncated: false,
        }
    }

    fn identity(pod: &str) -> WorkloadIdentity {
        WorkloadIdentity {
            namespace: "ns".into(),
            pod: pod.into(),
            container: "app".into(),
            service_account: "sa".into(),
            ..Default::default()
        }
    }

    fn pci_identity() -> WorkloadIdentity {
        let mut id = identity("web");
        id.namespace = "prod".into();
        id.namespace_labels
            .insert("ferrum.io/zone".into(), "pci".into());
        id.image = "registry.internal.example/app@sha256:abc".into();
        id.image_digest = "sha256:abc".into();
        id
    }

    fn temp_lkg() -> PathBuf {
        std::env::temp_dir().join(format!(
            "ferrum-agent-lkg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    fn snap_count(dir: &Path) -> usize {
        fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| {
                        e.file_name()
                            .to_str()
                            .map(|n| n.starts_with("..snap-"))
                            .unwrap_or(false)
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    fn assert_integrity<T: std::fmt::Debug>(result: Result<T>) {
        match result {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
    }

    fn assert_degraded<T: std::fmt::Debug>(result: Result<T>) {
        match result {
            Err(FerrumError::Degraded(_)) => {}
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    fn compile_prod_restricted() -> (Vec<u8>, Digest) {
        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        let obj: ferrum_api::ClusterSecurityPolicy =
            serde_yaml::from_str(yaml).expect("example yaml");
        let compiled = ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile");
        let material = ferrum_compiler::bundle_digest_material(
            AGENT_ABI,
            ferrum_ids::ADMISSION_ABI,
            &compiled.admission_program,
            &compiled.ebpf_spec,
            &compiled.wasm,
        )
        .expect("material");
        let digest = compiled.digest;
        (material, digest)
    }

    fn assert_mvp_actions(agent: &Agent) {
        assert_eq!(
            agent
                .matched_action(&ev("execve", "sh", "/bin/sh", true, false))
                .action,
            Action::Kill
        );
        assert_eq!(
            agent
                .matched_action(&ev("openat", "x", "/run/docker.sock", true, false))
                .action,
            Action::Kill
        );
        assert_eq!(
            agent
                .matched_action(&ev("bpf", "x", "", true, false))
                .action,
            Action::Deny
        );
    }

    #[test]
    fn default_role_is_observe() {
        let agent = Agent::new(AgentConfig::default());
        assert_eq!(agent.role(), AgentRole::Observe);
        assert!(!agent.role().respond_enabled());
        assert!(!agent.using_last_known_good());
        assert!(agent.is_degraded());
        assert_eq!(apply_role(AgentRole::Observe, Action::Kill), Action::Audit);
        assert_eq!(apply_role(AgentRole::Respond, Action::Kill), Action::Kill);
        assert_eq!(apply_role(AgentRole::Observe, Action::Deny), Action::Deny);
        assert_eq!(
            AgentRole::parse_name("observe").unwrap(),
            AgentRole::Observe
        );
        assert_eq!(
            AgentRole::parse_name("respond").unwrap(),
            AgentRole::Respond
        );
    }

    #[test]
    fn unsigned_bundle_is_integrity_and_keeps_lkg() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );

        assert_integrity(agent.apply_bundle(&good, &[], &pk()));
        assert_integrity(agent.apply_fsig(&good, None));
        assert!(agent.is_degraded());
        assert!(agent.policy_degraded());
        assert!(agent.using_last_known_good());
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );
        assert_eq!(
            agent
                .matched_action(&ev("execve", "sh", "/bin/sh", true, false))
                .action,
            Action::Kill
        );
    }

    #[test]
    fn unsigned_integrity_empty_is_deny() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        assert_integrity(agent.apply_fsig(&good, None));
        assert!(!agent.using_last_known_good());
        assert_eq!(
            agent
                .handle_event(
                    1,
                    &ev("execve", "sh", "/bin/sh", true, false),
                    &MemorySink::new()
                )
                .action,
            Action::Deny
        );
    }

    #[test]
    fn abi_mismatch_keeps_last_known_good() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);

        let bad = encode_mvp(AGENT_ABI.saturating_add(1), Mode::Enforce);
        assert_degraded(agent.apply_bundle(&bad, &sign(&bad), &pk()));
        assert!(agent.using_last_known_good());
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );
        assert_eq!(
            agent
                .matched_action(&ev("execve", "bash", "/bin/bash", true, false))
                .action,
            Action::Kill
        );
    }

    #[test]
    fn control_plane_down_keeps_lkg_not_allow() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        load_signed(&mut agent, &good);
        agent.set_role(AgentRole::Respond);
        agent.mark_control_plane_down();
        assert!(agent.control_plane_down());
        assert!(agent.is_degraded());
        assert!(agent.using_last_known_good());
        let sink = MemorySink::new();
        let d = agent.handle_event(1, &ev("execve", "sh", "/bin/sh", true, false), &sink);
        assert_eq!(d.action, Action::Kill);
        assert_ne!(d.action, Action::Allow);
    }

    #[test]
    fn mvp_execve_shell_kill_when_respond() {
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        let sink = MemorySink::new();
        let d = agent.handle_event(7, &ev("execve", "sh", "/bin/sh", true, false), &sink);
        assert_eq!(d.action, Action::Kill);
        assert_eq!(d.rule_id.as_deref(), Some("no-shell"));
        assert_eq!(sink.events()[0].action, "kill");
        assert_eq!(sink.events()[0].syscall, "execve");
    }

    #[test]
    fn mvp_docker_sock_kill_when_respond() {
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        let d = agent.handle_event(
            1,
            &ev("openat", "app", "/var/run/docker.sock", true, false),
            &MemorySink::new(),
        );
        assert_eq!(d.action, Action::Kill);
        assert_eq!(d.rule_id.as_deref(), Some("no-runtime-sock"));
    }

    #[test]
    fn mvp_bpf_not_agent_deny() {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        let d = agent.handle_event(
            1,
            &ev("bpf", "attacker", "", true, false),
            &MemorySink::new(),
        );
        assert_eq!(d.action, Action::Deny);
        let self_bpf = agent.handle_event(
            1,
            &ev("bpf", "ferrum-agent", "", false, true),
            &MemorySink::new(),
        );
        assert_eq!(self_bpf.action, Action::Audit);
    }

    #[test]
    fn observe_does_not_execute_kill() {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        let d = agent.handle_event(
            1,
            &ev("execve", "sh", "/bin/sh", true, false),
            &MemorySink::new(),
        );
        assert_eq!(d.action, Action::Audit);
        assert_eq!(
            agent
                .matched_action(&ev("execve", "sh", "/bin/sh", true, false))
                .action,
            Action::Kill
        );
    }

    #[test]
    fn cgroup_miss_does_not_spoof_pod() {
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(10, identity("pod-a"));
        let sink = MemorySink::new();
        agent.handle_event(99, &ev("execve", "sh", "/bin/sh", true, false), &sink);
        assert!(sink.events()[0].pod.is_empty());
        assert_ne!(sink.events()[0].pod, "pod-a");
        assert_eq!(agent.lookup_cgroup(10).expect("hit").pod, "pod-a");
        match agent.lookup_cgroup(99) {
            Err(FerrumError::Degraded(_)) => {}
            other => panic!("expected Degraded identity, got {other:?}"),
        }
    }

    #[test]
    fn attach_pins_does_not_pretend() {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        assert!(!agent.pins_attached());
        match agent.attach_pins() {
            Err(FerrumError::Degraded(msg)) => {
                assert!(msg.contains(PIN_PATH), "{msg}");
            }
            other => panic!("expected Degraded attach, got {other:?}"),
        }
        assert!(agent.using_last_known_good());
    }

    #[test]
    fn compiler_frmb_round_trip() {
        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        let obj: ferrum_api::ClusterSecurityPolicy =
            serde_yaml::from_str(yaml).expect("example yaml");
        let compiled = ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile");
        let ebpf = encode_prod_restricted_ebpf(AGENT_ABI);
        let parsed = parse_febp(&ebpf).expect("FEBP");
        assert_eq!(parsed.priority, obj.spec.priority);
        assert_eq!(
            parsed.selector.image.registries_allow,
            obj.spec.selector.image.registries_allow
        );
        assert_eq!(
            parsed.selector.image.require_digest,
            obj.spec.selector.image.require_digest
        );
        assert_eq!(
            parsed
                .selector
                .namespace_selector
                .match_expressions
                .first()
                .map(|e| e.key.as_str()),
            Some("ferrum.io/zone")
        );
        let material = ferrum_compiler::bundle_digest_material(
            AGENT_ABI,
            ferrum_ids::ADMISSION_ABI,
            &compiled.admission_program,
            &ebpf,
            &compiled.wasm,
        )
        .expect("material");
        let mut agent = Agent::new(cfg());
        let digest = load_signed(&mut agent, &material);
        assert_eq!(digest, ferrum_crypto::bundle_digest(&material));
        assert_mvp_actions(&agent);
    }

    #[test]
    fn compiler_fsig_of_prod_restricted() {
        let (material, compiled_digest) = compile_prod_restricted();
        let fsig = encode_fsig(&material, &sign(&material), &pk()).expect("fsig");
        let mut agent = Agent::new(cfg());
        let digest = agent
            .apply_fsig(&fsig, Some(&compiled_digest))
            .expect("apply");
        assert_eq!(digest, compiled_digest);
        assert_mvp_actions(&agent);
    }

    #[test]
    fn matching_dir_loads_mvp_actions() {
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let fsig = encode_fsig(&good, &sign(&good), &pk()).expect("fsig");
        let digest = ferrum_crypto::bundle_digest(&good);
        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        fs::write(dir.join(BUNDLE_FSIG_KEY), fsig).expect("bundle.fsig");
        fs::write(dir.join(BUNDLE_DIGEST_KEY), digest.as_str().as_bytes()).expect("digest");
        let mut agent = Agent::new(cfg());
        agent.apply_path(&dir).expect("dir load");
        assert_mvp_actions(&agent);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn digest_mismatch_keeps_lkg() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);
        let fsig = encode_fsig(&good, &sign(&good), &pk()).expect("fsig");
        assert_integrity(agent.apply_fsig(&fsig, Some(&Digest::new("00".repeat(32)))));
        assert!(agent.is_degraded());
        assert!(agent.policy_degraded());
        assert!(agent.using_last_known_good());
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );
        assert_mvp_actions(&agent);

        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        fs::write(dir.join(BUNDLE_FSIG_KEY), fsig).expect("bundle.fsig");
        fs::write(dir.join(BUNDLE_DIGEST_KEY), "00".repeat(32).as_bytes()).expect("digest");
        assert_integrity(agent.apply_path(&dir));
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_digest_is_integrity() {
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let fsig = encode_fsig(&good, &sign(&good), &pk()).expect("fsig");
        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        fs::write(dir.join(BUNDLE_FSIG_KEY), fsig).expect("bundle.fsig");
        let mut agent = Agent::new(cfg());
        assert_integrity(agent.apply_path(&dir));
        assert!(!agent.using_last_known_good());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_pin_is_integrity() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);
        let other_pk = ferrum_crypto::public_key_from_secret(&SK2).expect("pk2");
        let other_sig = ferrum_crypto::sign_bundle(&good, &SK2).expect("sig2");
        assert_integrity(agent.apply_bundle(&good, &other_sig, &other_pk));
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );

        let mut empty = Agent::new(AgentConfig {
            trust_root: other_pk,
            ..Default::default()
        });
        assert_integrity(empty.apply_bundle(&good, &sign(&good), &pk()));
        assert!(!empty.using_last_known_good());
        assert_eq!(
            empty
                .handle_event(
                    1,
                    &ev("execve", "sh", "/bin/sh", true, false),
                    &MemorySink::new()
                )
                .action,
            Action::Deny
        );
    }

    #[test]
    fn frmb_abi_mismatch_keeps_lkg() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);

        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        let obj: ferrum_api::ClusterSecurityPolicy =
            serde_yaml::from_str(yaml).expect("example yaml");
        let compiled = ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile");
        let mut material = ferrum_compiler::bundle_digest_material(
            AGENT_ABI.saturating_add(1),
            ferrum_ids::ADMISSION_ABI,
            &compiled.admission_program,
            &compiled.ebpf_spec,
            &compiled.wasm,
        )
        .expect("material");
        material[8..12].copy_from_slice(&AGENT_ABI.saturating_add(1).to_le_bytes());
        assert_degraded(agent.apply_bundle(&material, &sign(&material), &pk()));
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );
    }

    #[test]
    fn abi_too_new_is_degraded() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);
        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        let obj: ferrum_api::ClusterSecurityPolicy =
            serde_yaml::from_str(yaml).expect("example yaml");
        let compiled = ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile");
        let material = ferrum_compiler::bundle_digest_material(
            AGENT_ABI.saturating_add(1),
            ferrum_ids::ADMISSION_ABI,
            &compiled.admission_program,
            &compiled.ebpf_spec,
            &compiled.wasm,
        )
        .expect("material");
        let fsig = encode_fsig(&material, &sign(&material), &pk()).expect("fsig");
        assert_degraded(agent.apply_fsig(&fsig, None));
        assert!(agent.using_last_known_good());
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );
        assert_mvp_actions(&agent);
    }

    #[test]
    fn namespaced_selector_skips_unknown_cgroup() {
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_prod_restricted_ebpf(AGENT_ABI));
        let unknown = agent.handle_event(
            99,
            &ev("execve", "sh", "/bin/sh", true, false),
            &MemorySink::new(),
        );
        assert_eq!(unknown.action, Action::Allow);
        agent.insert_cgroup(1, pci_identity());
        let hit = agent.handle_event(
            1,
            &ev("execve", "sh", "/bin/sh", true, false),
            &MemorySink::new(),
        );
        assert_eq!(hit.action, Action::Audit);
        assert_eq!(hit.rule_id.as_deref(), Some("no-shell"));
    }

    #[test]
    fn signed_lkg_restore_from_dir() {
        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        let raw = encode_mvp(AGENT_ABI, Mode::Enforce);
        {
            let mut agent = Agent::new(AgentConfig {
                trust_root: pk(),
                lkg_dir: Some(dir.clone()),
                ..Default::default()
            });
            load_signed(&mut agent, &raw);
            load_signed(&mut agent, &raw);
            assert_eq!(snap_count(&dir), 1);
            assert!(agent.using_last_known_good());
            assert!(dir.join(KUBELET_DATA_DIR).exists());
            assert!(dir.join(BUNDLE_FSIG_KEY).exists());
            assert!(dir.join(BUNDLE_DIGEST_KEY).exists());
            assert!(!dir.join("lkg.raw").exists());
            assert!(!dir.join("lkg.sig").exists());
            assert!(!dir.join("lkg.pk").exists());
            assert!(!dir.join("lkg.febp").exists());
        }
        let snaps_before = snap_count(&dir);
        assert_eq!(snaps_before, 1);
        let restored = Agent::new(AgentConfig {
            trust_root: pk(),
            lkg_dir: Some(dir.clone()),
            role: AgentRole::Respond,
            ..Default::default()
        });
        assert_eq!(snap_count(&dir), snaps_before);
        assert!(restored.using_last_known_good());
        assert_eq!(
            restored
                .matched_action(&ev("execve", "sh", "/bin/sh", true, false))
                .action,
            Action::Kill
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_without_pin_and_files_is_degraded() {
        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        let raw = encode_mvp(AGENT_ABI, Mode::Enforce);
        {
            let mut agent = Agent::new(AgentConfig {
                trust_root: pk(),
                lkg_dir: Some(dir.clone()),
                ..Default::default()
            });
            load_signed(&mut agent, &raw);
        }
        let mut unsigned = Agent::new(AgentConfig {
            lkg_dir: Some(dir.clone()),
            ..Default::default()
        });
        assert!(!unsigned.using_last_known_good());
        assert_degraded(unsigned.restore_last_known_good());
        assert_eq!(
            unsigned
                .handle_event(
                    1,
                    &ev("execve", "sh", "/bin/sh", true, false),
                    &MemorySink::new()
                )
                .action,
            Action::Deny
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vanished_mount_keeps_lkg() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        load_signed(&mut agent, &good);
        let missing = temp_lkg().join("gone");
        assert_integrity(agent.apply_path(&missing));
        assert!(agent.using_last_known_good());
        assert_mvp_actions(&agent);
    }

    #[test]
    fn drops_surface() {
        let agent = Agent::new(AgentConfig::default());
        agent.record_drop(2);
        assert_eq!(agent.events_dropped_total(), 2);
    }

    /// A dropped ring record is a verdict that was never taken: every rule
    /// runs in userspace, so the kill for that event did not happen and
    /// nothing downstream can tell. It has to show up as Degraded.
    #[test]
    fn path_truncation_degrades_and_then_recovers() {
        let agent = Agent::new(AgentConfig::default());
        let now = Instant::now();
        assert!(!agent.path_truncated_recent_at(now));
        assert!(!agent.datapath_degraded());
        agent.record_path_truncated(now);
        assert_eq!(agent.path_truncated_total(), 1);
        assert!(agent.path_truncated_recent_at(now));
        assert!(agent.datapath_degraded());
        assert!(agent.is_degraded());
        // Recoverable: a node that stops seeing oversize paths recovers on its
        // own, but the count does not reset.
        assert!(!agent.path_truncated_recent_at(now + DEGRADED_RECOVERY));
        agent.record_path_truncated(now + DEGRADED_RECOVERY);
        assert!(agent.path_truncated_recent_at(now + DEGRADED_RECOVERY));
        assert_eq!(agent.path_truncated_total(), 2);
    }

    #[test]
    fn ring_drops_degrade_and_then_recover() {
        let agent = Agent::new(AgentConfig::default());
        let now = Instant::now();
        assert!(!agent.ring_drops_recent_at(now));

        agent.record_drop_at(1, now);
        assert_eq!(agent.events_dropped_total(), 1);
        assert!(agent.ring_drops_recent_at(now));
        assert!(agent.is_degraded());

        // Not a latch: an agent that stops dropping heals without a restart.
        assert!(!agent.ring_drops_recent_at(now + DEGRADED_RECOVERY));
        agent.record_drop_at(3, now + DEGRADED_RECOVERY);
        assert_eq!(agent.events_dropped_total(), 4);
        assert!(agent.ring_drops_recent_at(now + DEGRADED_RECOVERY));

        // Zero drops are not an event and must not re-arm the window.
        let quiet = Agent::new(AgentConfig::default());
        quiet.record_drop_at(0, now);
        assert!(!quiet.ring_drops_recent_at(now));
    }

    /// A tracepoint fires after the syscall ran, so runtime Deny cannot block
    /// anything. The event must carry the reason instead of looking like one
    /// nobody meant to act on.
    #[test]
    fn runtime_deny_is_refused_with_a_reason() {
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        let before = agent.respond_refused_total();
        let sink = MemorySink::new();
        let decision = agent.handle_event(7, &ev("bpf", "loader", "", true, false), &sink);
        assert_eq!(decision.action, Action::Deny);
        assert_eq!(decision.rule_id.as_deref(), Some("no-module"));

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert!(!events[0].executed);
        assert_eq!(
            events[0].respond_error.as_deref(),
            Some(REFUSE_DENY_NOT_ENFORCEABLE)
        );
        assert_eq!(agent.respond_refused_total(), before + 1);

        // Allow/Audit are the only actions that stay silent: there was never
        // anything to execute.
        let quiet = MemorySink::new();
        let audit = agent.handle_event(7, &ev("openat", "app", "/etc/passwd", true, false), &quiet);
        assert!(matches!(audit.action, Action::Allow | Action::Audit));
        assert!(!quiet.events()[0].executed);
        assert_eq!(quiet.events()[0].respond_error, None);
    }

    fn ring_record(syscall_nr: u32, comm: &str, path: &str, flags: u8, cgroup: u64) -> Vec<u8> {
        let mut event = ferrum_ebpf::Event::new();
        event.cgroup_id = cgroup;
        event.pid = 100;
        event.tgid = 100;
        event.syscall_nr = syscall_nr;
        event.flags = flags;
        event.comm[..comm.len()].copy_from_slice(comm.as_bytes());
        event.path[..path.len()].copy_from_slice(path.as_bytes());
        ferrum_ebpf::encode_event(&event)
    }

    #[test]
    fn pump_ring_records_round_trip() {
        use ferrum_ebpf::{SyscallArch, EVENT_FLAG_CONTAINER};
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        let sink = MemorySink::new();
        // x86_64 numbers: 59 execve, 257 openat.
        let records = vec![
            ring_record(59, "sh", "/bin/sh", EVENT_FLAG_CONTAINER, 7),
            ring_record(257, "app", "/var/run/docker.sock", EVENT_FLAG_CONTAINER, 7),
        ];
        let stats = pump_records(&agent, SyscallArch::X86_64, records, &sink);
        assert_eq!(
            stats,
            PumpStats {
                handled: 2,
                decode_failed: 0,
                unknown_syscall: 0
            }
        );
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].syscall, "execve");
        assert_eq!(events[0].comm, "sh");
        assert_eq!(events[0].action, "kill");
        assert_eq!(events[0].pod, "pod-a");
        assert_eq!(events[1].syscall, "openat");
        assert_eq!(events[1].action, "kill");
        assert_eq!(agent.events_dropped_total(), 0);
    }

    #[test]
    fn pump_unknown_syscall_and_garbage_do_not_panic() {
        use ferrum_ebpf::SyscallArch;
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        let sink = MemorySink::new();
        let records: Vec<Vec<u8>> = vec![
            ring_record(u32::MAX, "sh", "/bin/sh", 0, 1),
            vec![0u8; 5],
            Vec::new(),
        ];
        assert!(!agent.datapath_degraded());
        let stats = pump_records(&agent, SyscallArch::X86_64, records, &sink);
        assert_eq!(
            stats,
            PumpStats {
                handled: 0,
                decode_failed: 2,
                unknown_syscall: 1
            }
        );
        // The unknown nr is still exported for visibility, but the datapath is
        // no longer trusted: the agent is Degraded, not silently auditing.
        assert_eq!(sink.events().len(), 1);
        assert_eq!(sink.events()[0].syscall, ferrum_ebpf::SYSCALL_UNKNOWN);
        assert!(agent.datapath_degraded());
        assert!(agent.is_degraded());
        assert_eq!(agent.unknown_syscall_total(), 1);
        // Decode failures are not in-kernel ring drops.
        assert_eq!(agent.events_dropped_total(), 0);
        assert_eq!(agent.records_decode_failed_total(), 2);
    }

    /// The whole slice, end to end, on the execution layer: a real ring record
    /// with a 255-byte path and the truncation flag set. The workload opened
    /// `/var/run/` + `./` * 130 + `docker.sock`; the kernel resolved it, the
    /// buffer kept only the head, and `ends_with("docker.sock")` is false on
    /// what arrived. With the flag the kill rule still fires and the node is
    /// Degraded; without it the same bytes are indistinguishable from an
    /// honest short path and the rule silently does not fire. That second half
    /// is the regression anchor — it is the bypass this slice closes.
    #[test]
    fn a_truncated_docker_sock_path_still_kills_and_degrades() {
        use ferrum_ebpf::{SyscallArch, EVENT_FLAG_CONTAINER, EVENT_FLAG_PATH_TRUNCATED};
        let head = format!("/var/run/{}", "./".repeat(130));
        let head = &head[..255];

        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_container_map_synced(1);
        let sink = MemorySink::new();
        let record = ring_record(
            257,
            "app",
            head,
            EVENT_FLAG_CONTAINER | EVENT_FLAG_PATH_TRUNCATED,
            7,
        );
        let stats = pump_records(&agent, SyscallArch::X86_64, [record.clone()], &sink);
        assert_eq!(stats.handled, 1);
        assert_eq!(sink.events()[0].action, "kill");
        assert_eq!(agent.path_truncated_total(), 1);
        assert!(agent.path_truncated_recent());
        assert!(agent.datapath_degraded());
        assert!(agent.is_degraded());

        // Same bytes, flag cleared: the head is then the whole path, no suffix
        // matches, and the record is merely audited.
        let mut honest = record;
        honest[21] = EVENT_FLAG_CONTAINER;
        let mut clean = Agent::new(cfg_respond());
        load_signed(&mut clean, &encode_mvp(AGENT_ABI, Mode::Enforce));
        clean.insert_cgroup(7, identity("pod-a"));
        clean.set_container_map_synced(1);
        let quiet = MemorySink::new();
        pump_records(&clean, SyscallArch::X86_64, [honest], &quiet);
        assert_ne!(quiet.events()[0].action, "kill");
        assert_eq!(clean.path_truncated_total(), 0);
        assert!(!clean.path_truncated_recent());
    }

    #[test]
    fn pump_channel_drains_until_hangup() {
        use ferrum_ebpf::{SyscallArch, EVENT_FLAG_CONTAINER};
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        let sink = MemorySink::new();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(ring_record(
            59,
            "bash",
            "/bin/bash",
            EVENT_FLAG_CONTAINER,
            1,
        ))
        .expect("send");
        drop(tx);
        let stats = pump_channel(&agent, SyscallArch::X86_64, rx, &sink);
        assert_eq!(stats.handled, 1);
        assert_eq!(sink.events()[0].action, "kill");
    }

    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 8, 27, 12, 0, 0).unwrap()
    }

    fn waiver(ns: &str, policy: &str, rules: &[&str]) -> ferrum_api::PolicyExceptionSpec {
        ferrum_api::PolicyExceptionSpec {
            ticket: "JIRA-1".into(),
            requested_by: "sre".into(),
            approved_by: "sec-arch".into(),
            reason: "incident debug access".into(),
            expires_at: fixed_now() + chrono::Days::new(30),
            mode: Default::default(),
            four_eyes: false,
            target: ferrum_api::ExceptionTarget {
                namespace: ns.into(),
                policies: vec![policy.into()],
                rules: rules.iter().map(|r| (*r).into()).collect(),
            },
        }
    }

    fn cfg_respond_named(policy_name: &str) -> AgentConfig {
        AgentConfig {
            role: AgentRole::Respond,
            trust_root: pk(),
            policy_name: policy_name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn waiver_demotes_kill_to_audit_in_scope_only() {
        let mut agent = Agent::new(cfg_respond_named("p1"));
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_exceptions(vec![waiver("ns", "p1", &["no-runtime-sock"])]);
        let sink = MemorySink::new();
        let e = ev("openat", "app", "/var/run/docker.sock", true, false);
        let d = agent.handle_event_at(7, &e, &sink, fixed_now());
        assert_eq!(d.action, Action::Audit);
        assert_eq!(d.rule_id.as_deref(), Some("no-runtime-sock"));
        assert_eq!(sink.events()[0].action, WAIVED_ACTION);
        let waiver_ref = sink.events()[0].waiver.clone().expect("waiver audit trail");
        assert_eq!(waiver_ref.ticket, "JIRA-1");
        assert_eq!(waiver_ref.requested_by, "sre");
        assert_eq!(waiver_ref.approved_by, "sec-arch");

        // Other rule of the same policy still kills.
        let shell = agent.handle_event_at(
            7,
            &ev("execve", "sh", "/bin/sh", true, false),
            &sink,
            fixed_now(),
        );
        assert_eq!(shell.action, Action::Kill);
        assert_eq!(sink.events()[1].action, "kill");
        assert_eq!(sink.events()[1].waiver, None);
    }

    #[test]
    fn waiver_does_not_outlive_expiry_or_cross_namespace_or_policy() {
        let mut agent = Agent::new(cfg_respond_named("p1"));
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        let e = ev("openat", "app", "/var/run/docker.sock", true, false);

        let spec = waiver("ns", "p1", &["no-runtime-sock"]);
        let after_expiry = spec.expires_at + chrono::Days::new(1);
        agent.set_exceptions(vec![spec]);
        let d = agent.handle_event_at(7, &e, &MemorySink::new(), after_expiry);
        assert_eq!(d.action, Action::Kill);

        agent.set_exceptions(vec![waiver("other-ns", "p1", &["no-runtime-sock"])]);
        let d = agent.handle_event_at(7, &e, &MemorySink::new(), fixed_now());
        assert_eq!(d.action, Action::Kill);

        agent.set_exceptions(vec![waiver("ns", "other-policy", &["no-runtime-sock"])]);
        let d = agent.handle_event_at(7, &e, &MemorySink::new(), fixed_now());
        assert_eq!(d.action, Action::Kill);
    }

    #[test]
    fn empty_target_rules_is_no_waiver_not_global() {
        let mut agent = Agent::new(cfg_respond_named("p1"));
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_exceptions(vec![waiver("ns", "p1", &[])]);
        let d = agent.handle_event_at(
            7,
            &ev("openat", "app", "/var/run/docker.sock", true, false),
            &MemorySink::new(),
            fixed_now(),
        );
        assert_eq!(d.action, Action::Kill);
    }

    #[test]
    fn unknown_identity_never_matches_namespaced_waiver() {
        let mut agent = Agent::new(cfg_respond_named("p1"));
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.set_exceptions(vec![waiver("ns", "p1", &["no-runtime-sock"])]);
        // cgroup 99 misses the index → WorkloadIdentity::unknown().
        let sink = MemorySink::new();
        let d = agent.handle_event_at(
            99,
            &ev("openat", "app", "/var/run/docker.sock", true, false),
            &sink,
            fixed_now(),
        );
        assert_eq!(d.action, Action::Kill);
        assert_eq!(sink.events()[0].action, "kill");
    }

    fn exceptions_fsig(list: &[ferrum_api::PolicyExceptionSpec]) -> Vec<u8> {
        let json = serde_json::to_vec(list).expect("encode");
        encode_fsig(&json, &sign(&json), &pk()).expect("fsig")
    }

    #[test]
    fn garbage_exceptions_fsig_drops_all_waivers_and_counts() {
        let mut agent = Agent::new(cfg_respond_named("p1"));
        agent.set_exceptions(vec![waiver("ns", "p1", &["no-runtime-sock"])]);
        assert_eq!(agent.exceptions().len(), 1);
        assert!(agent.try_reload_exceptions(b"{not json").is_err());
        assert!(agent.exceptions().is_empty());
        assert_eq!(agent.exceptions_reload_failed_total(), 1);

        // Signed envelope over garbage JSON: signature is fine, payload is not.
        let garbage = encode_fsig(b"{not json", &sign(b"{not json"), &pk()).expect("fsig");
        agent.set_exceptions(vec![waiver("ns", "p1", &["no-runtime-sock"])]);
        assert!(agent.try_reload_exceptions(&garbage).is_err());
        assert!(agent.exceptions().is_empty());
        assert_eq!(agent.exceptions_reload_failed_total(), 2);

        let list = vec![waiver("ns", "p1", &["no-runtime-sock"])];
        let fsig = exceptions_fsig(&list);
        assert_eq!(agent.try_reload_exceptions(&fsig).expect("reload"), 1);
        assert_eq!(agent.exceptions(), list.as_slice());
    }

    #[test]
    fn unsigned_or_foreign_or_tampered_exceptions_drop_all_waivers() {
        let mut agent = Agent::new(cfg_respond_named("p1"));
        let list = vec![waiver("ns", "p1", &["no-runtime-sock"])];

        // Plain JSON array (the old exceptions.json contract) is rejected.
        agent.set_exceptions(list.clone());
        assert!(agent
            .try_reload_exceptions(&serde_json::to_vec(&list).expect("encode"))
            .is_err());
        assert!(agent.exceptions().is_empty());
        assert_eq!(agent.exceptions_reload_failed_total(), 1);

        // Envelope signed by a key other than the pinned trust-root.
        let json = serde_json::to_vec(&list).expect("encode");
        let pk2 = ferrum_crypto::public_key_from_secret(&SK2).expect("pk2");
        let sig2 = ferrum_crypto::sign_bundle(&json, &SK2).expect("sig2");
        let foreign = encode_fsig(&json, &sig2, &pk2).expect("fsig");
        agent.set_exceptions(list.clone());
        assert!(agent.try_reload_exceptions(&foreign).is_err());
        assert!(agent.exceptions().is_empty());
        assert_eq!(agent.exceptions_reload_failed_total(), 2);

        // Tampered payload under the pinned key.
        let mut tampered = exceptions_fsig(&list);
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        agent.set_exceptions(list);
        assert!(agent.try_reload_exceptions(&tampered).is_err());
        assert!(agent.exceptions().is_empty());
        assert_eq!(agent.exceptions_reload_failed_total(), 3);
    }

    #[test]
    fn exceptions_spec_count_over_cap_drops_all_waivers() {
        let mut agent = Agent::new(cfg_respond_named("p1"));
        let too_many: Vec<_> = (0..=MAX_EXCEPTION_SPECS)
            .map(|_| waiver("ns", "p1", &["no-runtime-sock"]))
            .collect();
        agent.set_exceptions(vec![waiver("ns", "p1", &["no-runtime-sock"])]);
        assert!(agent
            .try_reload_exceptions(&exceptions_fsig(&too_many))
            .is_err());
        assert!(agent.exceptions().is_empty());
        assert_eq!(agent.exceptions_reload_failed_total(), 1);
    }

    #[test]
    fn oversized_exceptions_file_drops_all_waivers() {
        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        fs::write(
            dir.join(EXCEPTIONS_FSIG_KEY),
            vec![0u8; (MAX_EXCEPTIONS_BYTES + 1) as usize],
        )
        .expect("write");
        let mut agent = Agent::new(cfg_respond_named("p1"));
        agent.set_exceptions(vec![waiver("ns", "p1", &["no-runtime-sock"])]);
        assert!(agent.reload_exceptions_path(&dir).is_err());
        assert!(agent.exceptions().is_empty());
        assert_eq!(agent.exceptions_reload_failed_total(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn exceptions_path_missing_is_empty_list_dir_is_snapshot_sibling() {
        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        let mut agent = Agent::new(cfg_respond_named("p1"));
        agent.set_exceptions(vec![waiver("ns", "p1", &["no-runtime-sock"])]);
        assert_eq!(agent.reload_exceptions_path(&dir).expect("missing"), 0);
        assert!(agent.exceptions().is_empty());
        assert_eq!(agent.exceptions_reload_failed_total(), 0);

        // kubelet layout: exceptions.fsig lives in the ..data snapshot.
        let snap = dir.join("..snap1");
        fs::create_dir_all(&snap).expect("snap");
        let list = vec![waiver("ns", "p1", &["no-runtime-sock"])];
        fs::write(snap.join(EXCEPTIONS_FSIG_KEY), exceptions_fsig(&list)).expect("write");
        std::os::unix::fs::symlink("..snap1", dir.join(KUBELET_DATA_DIR)).expect("..data");
        assert_eq!(agent.reload_exceptions_path(&dir).expect("reload"), 1);
        assert_eq!(agent.exceptions(), list.as_slice());

        fs::write(snap.join(EXCEPTIONS_FSIG_KEY), b"garbage").expect("overwrite");
        assert!(agent.reload_exceptions_path(&dir).is_err());
        assert!(agent.exceptions().is_empty());
        assert_eq!(agent.exceptions_reload_failed_total(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cargo_toml_forbids_hot_path_deps() {
        let toml = include_str!("../Cargo.toml");
        let deps = toml
            .split("[dev-dependencies]")
            .next()
            .expect("split dev")
            .split("[dependencies]")
            .nth(1)
            .expect("dependencies");
        for forbidden in [
            "kube",
            "tokio",
            "aya",
            "serde_yaml",
            "ferrum-compiler",
            "ferrum-admission",
            "ferrum-controller",
        ] {
            for line in deps.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                    continue;
                }
                let name = line.split([' ', '=', '\t']).next().unwrap_or("").trim();
                assert_ne!(
                    name, forbidden,
                    "{forbidden} must not appear in [dependencies]"
                );
            }
        }
    }

    /// Records what would have been signalled. No CAP, no victim process.
    #[derive(Default)]
    struct FakeResponder {
        killed: std::sync::Mutex<Vec<u32>>,
    }

    impl FakeResponder {
        fn killed(&self) -> Vec<u32> {
            self.killed.lock().expect("lock").clone()
        }
    }

    impl Responder for std::sync::Arc<FakeResponder> {
        fn kill(&self, tgid: u32) -> Result<()> {
            self.killed.lock().expect("lock").push(tgid);
            Ok(())
        }
    }

    /// Stands in for `/proc/<tgid>/cgroup`: the cgroup the target is in right
    /// now, or `None` for a process that is already gone.
    struct StaticCheck(Option<u64>);

    impl TargetCheck for StaticCheck {
        fn cgroup_id(&self, _tgid: u32) -> Option<u64> {
            self.0
        }
    }

    fn respond_agent_with_fake() -> (Agent, std::sync::Arc<FakeResponder>) {
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        // The target is still in the cgroup that raised the event.
        agent.set_target_check(Box::new(StaticCheck(Some(7))));
        let fake = std::sync::Arc::new(FakeResponder::default());
        agent.set_responder(Box::new(std::sync::Arc::clone(&fake)));
        (agent, fake)
    }

    /// A step short enough to stay inside any window under test.
    const MARGIN: Duration = Duration::from_secs(1);

    fn container_meta(tgid: u32) -> EventMeta {
        EventMeta {
            cgroup_id: 7,
            pid: tgid,
            tgid,
            in_container: true,
            agent_self: false,
            path_truncated: false,
        }
    }

    #[test]
    fn respond_kill_reaches_the_responder() {
        let (agent, fake) = respond_agent_with_fake();
        let meta = container_meta(4242);
        let decision = agent.handle_event(
            meta,
            &ev("execve", "sh", "/bin/sh", true, false),
            &MemorySink::new(),
        );
        assert_eq!(decision.action, Action::Kill);
        assert_eq!(fake.killed(), vec![4242]);
        assert_eq!(agent.respond_kill_total(), 1);
        assert_eq!(agent.respond_refused_total(), 0);
    }

    #[test]
    fn observe_never_calls_kill() {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        let fake = std::sync::Arc::new(FakeResponder::default());
        agent.set_responder(Box::new(std::sync::Arc::clone(&fake)));
        let sink = MemorySink::new();
        let decision = agent.handle_event(
            container_meta(4242),
            &ev("execve", "sh", "/bin/sh", true, false),
            &sink,
        );
        assert_eq!(decision.action, Action::Audit);
        assert!(fake.killed().is_empty());
        assert_eq!(agent.respond_kill_total(), 0);
        assert!(!sink.events()[0].executed);
    }

    #[test]
    fn agent_self_is_never_killed() {
        let (agent, fake) = respond_agent_with_fake();
        let mut meta = container_meta(4242);
        meta.agent_self = true;
        let sink = MemorySink::new();
        agent.handle_event(meta, &ev("execve", "sh", "/bin/sh", true, true), &sink);
        assert!(fake.killed().is_empty());
        assert_eq!(agent.respond_refused_total(), 1);
        assert!(!sink.events()[0].executed);
        assert_eq!(
            sink.events()[0].respond_error.as_deref(),
            Some(REFUSE_AGENT_SELF)
        );
    }

    #[test]
    fn host_process_is_never_killed() {
        let (agent, fake) = respond_agent_with_fake();
        let mut meta = container_meta(4242);
        meta.in_container = false;
        let sink = MemorySink::new();
        // The rule itself is not container-only, so the decision is still Kill.
        let decision = agent.handle_event(
            meta,
            &ev("openat", "app", "/var/run/docker.sock", true, false),
            &sink,
        );
        assert_eq!(decision.action, Action::Kill);
        assert!(fake.killed().is_empty());
        assert_eq!(agent.respond_refused_total(), 1);
        assert_eq!(
            sink.events()[0].respond_error.as_deref(),
            Some(REFUSE_NOT_CONTAINER)
        );
    }

    #[test]
    fn unknown_identity_is_never_killed() {
        let (agent, fake) = respond_agent_with_fake();
        let mut meta = container_meta(4242);
        // cgroup not in the index: identity is unknown, so there is no pod to
        // attribute the kill to.
        meta.cgroup_id = 999;
        let sink = MemorySink::new();
        agent.handle_event(
            meta,
            &ev("openat", "app", "/var/run/docker.sock", true, false),
            &sink,
        );
        assert!(fake.killed().is_empty());
        assert_eq!(agent.respond_refused_total(), 1);
        assert_eq!(
            sink.events()[0].respond_error.as_deref(),
            Some(REFUSE_UNKNOWN_IDENTITY)
        );
        assert!(!sink.events()[0].executed);
    }

    #[test]
    fn init_and_self_tgid_are_never_killed() {
        let (agent, fake) = respond_agent_with_fake();
        let sink = MemorySink::new();
        for tgid in [0, 1, std::process::id()] {
            agent.handle_event(
                container_meta(tgid),
                &ev("execve", "sh", "/bin/sh", true, false),
                &sink,
            );
        }
        assert!(fake.killed().is_empty());
        assert_eq!(agent.respond_refused_total(), 3);
        assert!(sink.events().iter().all(|e| !e.executed));
        assert!(sink
            .events()
            .iter()
            .all(|e| e.respond_error.is_some() && e.action == "kill"));
    }

    #[test]
    fn cgroup_only_call_site_carries_no_tgid() {
        let (agent, fake) = respond_agent_with_fake();
        let sink = MemorySink::new();
        // The back-compatible `u64` form has no pid/tgid, so it can only ever
        // observe: nothing structural to signal.
        agent.handle_event(7, &ev("execve", "sh", "/bin/sh", true, false), &sink);
        assert!(fake.killed().is_empty());
        assert_eq!(sink.events()[0].tgid, 0);
        assert!(!sink.events()[0].executed);
    }

    #[test]
    fn isolate_is_not_pretended_to_run() {
        let mut agent = Agent::new(cfg_respond());
        let spec = {
            let mut w = Writer::new();
            w.put_magic(&EBPF_MAGIC);
            w.put_u32(AGENT_ABI);
            w.put_u8(Mode::Enforce.as_u8());
            w.put_bool(false);
            w.put_i32(0);
            w.put_u8(Action::Audit.as_u8());
            for _ in 0..4 {
                put_empty_label_selector(&mut w);
            }
            w.put_str_list(&[]);
            w.put_bool(false);
            w.put_u16(1);
            w.put_str("isolate-shell");
            w.put_str_list(&["execve"]);
            w.put_u8(Action::Isolate.as_u8());
            w.put_str_list(&["sh"]);
            w.put_bool(true);
            w.put_str_list(&[]);
            w.put_str_list(&[]);
            w.put_bool(false);
            w.finish()
        };
        load_signed(&mut agent, &spec);
        agent.insert_cgroup(7, identity("pod-a"));
        let fake = std::sync::Arc::new(FakeResponder::default());
        agent.set_responder(Box::new(std::sync::Arc::clone(&fake)));
        let sink = MemorySink::new();
        let decision = agent.handle_event(
            container_meta(4242),
            &ev("execve", "sh", "/bin/sh", true, false),
            &sink,
        );
        assert_eq!(decision.action, Action::Isolate);
        assert!(fake.killed().is_empty());
        assert!(!sink.events()[0].executed);
        assert_eq!(
            sink.events()[0].respond_error.as_deref(),
            Some(REFUSE_ISOLATE)
        );
        assert_eq!(agent.respond_refused_total(), 1);
    }

    #[test]
    fn without_a_responder_kill_is_refused_not_silent() {
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_target_check(Box::new(StaticCheck(Some(7))));
        let sink = MemorySink::new();
        agent.handle_event(
            container_meta(4242),
            &ev("execve", "sh", "/bin/sh", true, false),
            &sink,
        );
        assert_eq!(agent.respond_kill_total(), 0);
        assert_eq!(agent.respond_refused_total(), 1);
        assert_eq!(
            sink.events()[0].respond_error.as_deref(),
            Some(REFUSE_NO_RESPONDER)
        );
    }

    /// The decision travelled through a queue and a poll interval; by the time
    /// it lands the pid may belong to somebody else. Signal only if the target
    /// is still in the cgroup that raised the event.
    #[test]
    fn a_reused_pid_is_refused_instead_of_killed() {
        let cases = [
            (Some(9_999u64), REFUSE_STALE_TARGET),
            (None, REFUSE_TARGET_GONE),
        ];
        for (current, reason) in cases {
            let (mut agent, fake) = respond_agent_with_fake();
            agent.set_target_check(Box::new(StaticCheck(current)));
            let sink = MemorySink::new();
            let decision = agent.handle_event(
                container_meta(4242),
                &ev("execve", "sh", "/bin/sh", true, false),
                &sink,
            );
            assert_eq!(decision.action, Action::Kill);
            assert!(fake.killed().is_empty(), "{reason}");
            assert!(!sink.events()[0].executed);
            assert_eq!(sink.events()[0].respond_error.as_deref(), Some(reason));
            assert_eq!(agent.respond_stale_target_total(), 1);
            assert_eq!(agent.respond_kill_total(), 0);
        }

        // Same event, target still in its own cgroup: the kill goes out.
        let (agent, fake) = respond_agent_with_fake();
        agent.handle_event(
            container_meta(4242),
            &ev("execve", "sh", "/bin/sh", true, false),
            &MemorySink::new(),
        );
        assert_eq!(fake.killed(), vec![4242]);
        assert_eq!(agent.respond_stale_target_total(), 0);
    }

    /// An empty index is not "this node runs no pods": it means every lookup
    /// misses and every namespaced selector silently fails to match.
    #[test]
    fn an_empty_cgroup_index_is_degraded() {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.set_attached(true);
        agent.set_container_map_synced(1);
        assert_eq!(agent.cgroup_index_len(), 0);
        assert!(agent.is_degraded(), "empty index must be Degraded");

        agent.insert_cgroup(7, identity("pod-a"));
        assert!(!agent.is_degraded());

        // The refresher writes through a shared handle, not through the agent.
        let index = agent.cgroup_index();
        index.replace_all(std::collections::HashMap::new());
        assert!(agent.is_degraded());
        index.insert(8, identity("pod-b"));
        assert_eq!(agent.lookup_cgroup(8).expect("hit").pod, "pod-b");
        assert!(!agent.is_degraded());
    }

    /// An index full of pods proves nothing about the datapath: until those
    /// cgroups are in `ferrum_cgroups`, EVENT_FLAG_CONTAINER is never set.
    #[test]
    fn an_unsynced_container_map_is_degraded() {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.set_attached(true);
        agent.insert_cgroup(7, identity("pod-a"));
        assert!(!agent.container_map_synced());
        assert!(
            agent.is_degraded(),
            "a non-empty index with an unsynced kernel map must be Degraded"
        );

        agent.set_container_map_synced(1);
        assert!(!agent.is_degraded());
        assert_eq!(agent.container_map_entries(), 1);

        // A map that synced to nothing is not "no pods" either.
        agent.set_container_map_synced(0);
        assert!(agent.is_degraded());

        agent.set_container_map_synced(1);
        agent.mark_container_map_error("partial sync");
        assert_eq!(agent.container_map_error().as_deref(), Some("partial sync"));
        assert!(agent.is_degraded());
        agent.set_container_map_synced(2);
        assert!(agent.container_map_error().is_none());
        assert!(!agent.is_degraded());
    }

    /// The index knows the pod, the record has no EVENT_FLAG_CONTAINER: the
    /// kernel map is behind. Count it, degrade — and still refuse the kill,
    /// because the flag is the last thing standing between a rule and a
    /// process on the node.
    #[test]
    fn a_missing_container_flag_is_counted_and_still_not_killed() {
        let (agent, fake) = respond_agent_with_fake();
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_attached(true);
        agent.set_container_map_synced(1);
        assert!(!agent.is_degraded());

        let sink = MemorySink::new();
        let meta = EventMeta {
            cgroup_id: 7,
            pid: 4242,
            tgid: 4242,
            in_container: false,
            agent_self: false,
            path_truncated: false,
        };
        let decision =
            agent.handle_event(meta, &ev("execve", "sh", "/bin/sh", false, false), &sink);

        assert!(agent.container_flag_disagreement_total() > 0);
        // Counted, but not Degraded: the index is filled one refresh before the
        // set reaches the kernel map, so every pod start opens this window.
        assert!(!agent.container_flag_degraded());
        assert!(!agent.is_degraded());
        // No flag, no container_only match, and no kill: the decision is not
        // upgraded from what the datapath actually reported.
        assert_ne!(decision.action, Action::Kill);
        assert!(fake.killed().is_empty());
        assert_eq!(agent.respond_kill_total(), 0);
    }

    /// Regression: even when the rule does match on the string view, a record
    /// without EVENT_FLAG_CONTAINER never reaches the responder.
    #[test]
    fn kill_is_refused_when_the_record_is_not_flagged_container() {
        let (agent, fake) = respond_agent_with_fake();
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_attached(true);
        agent.set_container_map_synced(1);

        let sink = MemorySink::new();
        let meta = EventMeta {
            cgroup_id: 7,
            pid: 4242,
            tgid: 4242,
            in_container: false,
            agent_self: false,
            path_truncated: false,
        };
        // The string view claims a container; the record flags do not. The
        // flags win.
        let decision = agent.handle_event(meta, &ev("execve", "sh", "/bin/sh", true, false), &sink);
        assert_eq!(decision.action, Action::Kill);
        assert!(fake.killed().is_empty());
        assert_eq!(agent.respond_kill_total(), 0);
        assert_eq!(
            sink.events()[0].respond_error.as_deref(),
            Some(REFUSE_NOT_CONTAINER)
        );
        assert!(agent.container_flag_disagreement_total() > 0);
    }

    /// The label caches are cold, relisting after a 410 or dead: the pod is
    /// known, its namespace labels are not. Empty labels are not a non-match -
    /// admission fails closed on exactly this — so the rule must still be
    /// applied, and the plane must say it is Degraded.
    #[test]
    fn unobserved_namespace_labels_do_not_skip_a_rule() {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_prod_restricted_ebpf(AGENT_ABI));
        agent.set_attached(true);
        let mut cold = pci_identity();
        cold.namespace_labels.clear();
        agent.insert_cgroup(1, cold);
        agent.set_container_map_synced(1);
        assert!(!agent.is_degraded());

        let sink = MemorySink::new();
        let meta = EventMeta {
            cgroup_id: 1,
            pid: 4242,
            tgid: 4242,
            in_container: true,
            agent_self: false,
            path_truncated: false,
        };
        let decision = agent.handle_event(meta, &ev("execve", "sh", "/bin/sh", true, false), &sink);
        assert_ne!(
            decision.action,
            Action::Allow,
            "a rule must not be skipped because its selector could not be resolved"
        );
        assert_eq!(decision.rule_id.as_deref(), Some("no-shell"));
        assert!(decision.labels_unknown);
        assert_eq!(agent.labels_unknown_total(), 1);
        assert!(
            agent.is_degraded(),
            "unresolved labels are not a clean pass"
        );

        // Recoverable: the caches fill in, the events stop, the signal decays.
        let now = Instant::now();
        assert!(agent.labels_unknown_recent_at(now));
        assert!(!agent.labels_unknown_recent_at(now + DEGRADED_RECOVERY));

        // The same selector against observed labels is unaffected.
        let mut observed = Agent::new(cfg());
        load_signed(&mut observed, &encode_prod_restricted_ebpf(AGENT_ABI));
        observed.insert_cgroup(1, pci_identity());
        let hit = observed.handle_event(meta, &ev("execve", "sh", "/bin/sh", true, false), &sink);
        assert_eq!(hit.rule_id.as_deref(), Some("no-shell"));
        assert!(!hit.labels_unknown);
        assert_eq!(observed.labels_unknown_total(), 0);
        assert!(!observed.labels_unknown_recent());
    }

    /// A sync that succeeded once is not a sync that is still happening. A
    /// publisher, pod watch or sync thread that froze leaves the map on an
    /// arbitrarily old snapshot: dead cgroup ids still flagged, every pod
    /// started since not flagged at all.
    #[test]
    fn a_container_map_nobody_reaffirms_goes_stale() {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.set_attached(true);
        agent.insert_cgroup(7, identity("pod-a"));

        let t0 = Instant::now();
        agent.set_container_map_synced_at(1, t0);
        assert!(!agent.container_map_stale_at(t0));
        assert!(!agent.container_map_stale_at(t0 + CONTAINER_MAP_SYNC_BUDGET - MARGIN));
        assert!(agent.container_map_stale_at(t0 + CONTAINER_MAP_SYNC_BUDGET));

        let Some(old) = t0.checked_sub(CONTAINER_MAP_SYNC_BUDGET * 2) else {
            return; // machine booted moments ago; the arithmetic below is moot
        };
        agent.set_container_map_synced_at(1, old);
        assert!(agent.container_map_stale());
        assert!(!agent.container_map_ready());
        assert!(
            agent.is_degraded(),
            "a map nothing has reaffirmed is not proof of anything"
        );
        // A sync that actually ran clears it; recovery does not need a restart.
        agent.set_container_map_synced(1);
        assert!(!agent.is_degraded());
    }

    /// `try_recv` cannot tell a dead publisher from an idle one unless the
    /// carrier looks: a disconnected channel means nothing will update
    /// `ferrum_cgroups` again.
    #[test]
    fn a_dead_cgroup_publisher_is_a_map_error() {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.set_attached(true);
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_container_map_synced(1);
        assert!(!agent.is_degraded());

        let (tx, rx) = std::sync::mpsc::sync_channel::<u64>(4);
        tx.send(7).expect("send");
        let mut seen = Vec::new();
        assert!(drain_cgroup_updates(&rx, &agent, |_, v| seen.push(v)));
        assert_eq!(seen, vec![7]);
        assert!(agent.container_map_error().is_none());

        drop(tx);
        assert!(!drain_cgroup_updates(&rx, &agent, |_, v| seen.push(v)));
        assert_eq!(
            agent.container_map_error().as_deref(),
            Some(CGROUP_PUBLISHER_GONE)
        );
        assert!(!agent.container_map_synced());
        assert!(agent.is_degraded());
    }

    /// A full channel drops one update on purpose (the next carries the whole
    /// set again); a disconnected one means nobody applies anything, ever.
    #[test]
    fn a_dead_carrier_stops_the_cgroup_publisher() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<u64>(1);
        assert!(publish_cgroups(&tx, 1));
        assert!(publish_cgroups(&tx, 2));
        drop(rx);
        assert!(!publish_cgroups(&tx, 3));
    }

    /// The refresher fills the index, then publishes, and the carrier applies
    /// the set a pass later: every pod start is unflagged for a moment. That
    /// window must not latch Degraded forever — but a cgroup a completed sync
    /// should have covered still must.
    #[test]
    fn the_pod_start_window_does_not_latch_degraded() {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.set_attached(true);
        agent.insert_cgroup(7, identity("pod-a"));

        let t0 = Instant::now();
        agent.set_container_map_synced_at(1, t0);
        // Pod just started: in the index, not yet in the kernel map.
        assert!(!agent.note_container_flag_disagreement(7, t0));
        assert!(!agent.note_container_flag_disagreement(7, t0 + MARGIN));
        assert!(!agent.container_flag_degraded_at(t0 + MARGIN));
        assert!(!agent.is_degraded());

        // A sync ran with this cgroup in the index and it is STILL unflagged
        // a whole window later: that is the datapath, not the race.
        agent.set_container_map_synced_at(1, t0 + MARGIN);
        let fault = t0 + CONTAINER_FLAG_GRACE + MARGIN;
        assert!(agent.note_container_flag_disagreement(7, fault));
        assert!(agent.container_flag_degraded_at(fault));
        assert!(agent.is_degraded());
        assert_eq!(agent.container_flag_disagreement_total(), 3);

        // Recoverable, not a one-way latch.
        assert!(!agent.container_flag_degraded_at(fault + DEGRADED_RECOVERY));
    }

    /// Without a sync since the window opened there is nothing to blame the
    /// datapath for: the stale map is its own signal.
    #[test]
    fn an_unsynced_map_does_not_blame_the_datapath() {
        let agent = Agent::new(cfg());
        let t0 = Instant::now();
        assert!(!agent.note_container_flag_disagreement(7, t0));
        assert!(!agent.note_container_flag_disagreement(7, t0 + CONTAINER_FLAG_GRACE * 2));
        assert!(!agent.container_flag_degraded_at(t0 + CONTAINER_FLAG_GRACE * 2));
        assert_eq!(agent.container_flag_disagreement_total(), 2);
    }

    /// Respond that cannot be delivered (no host pid namespace) drops to
    /// observe and says so, instead of signalling into the wrong namespace.
    #[test]
    fn respond_without_the_host_pid_namespace_falls_back_to_observe() {
        let (mut agent, fake) = respond_agent_with_fake();
        agent.disable_respond(RESPOND_NO_HOST_PIDNS);
        assert_eq!(agent.role(), AgentRole::Observe);
        assert_eq!(
            agent.respond_disabled_reason().as_deref(),
            Some(RESPOND_NO_HOST_PIDNS)
        );
        assert!(agent.is_degraded());
        let sink = MemorySink::new();
        let decision = agent.handle_event(
            container_meta(4242),
            &ev("execve", "sh", "/bin/sh", true, false),
            &sink,
        );
        assert_eq!(decision.action, Action::Audit);
        assert!(fake.killed().is_empty());
        assert_eq!(agent.respond_kill_total(), 0);
    }

    /// A dead export writer is not a telemetry hiccup: enforcement runs on
    /// unrecorded, which the agent must report.
    #[test]
    fn a_dead_export_writer_degrades_the_agent() {
        struct DeadSink;
        impl EventSink for DeadSink {
            fn emit(&self, _event: &EnforcementEvent) {}
            fn export_writer_dead(&self) -> bool {
                true
            }
        }
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.set_attached(true);
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_container_map_synced(1);
        assert!(!agent.is_degraded());
        agent.handle_event(
            container_meta(4242),
            &ev("execve", "sh", "/bin/sh", true, false),
            &DeadSink,
        );
        assert!(agent.export_writer_dead());
        assert!(agent.is_degraded());
    }

    #[test]
    fn attached_flag_is_not_implied_by_a_loaded_bundle() {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_container_map_synced(1);
        assert!(!agent.pins_attached());
        assert!(agent.is_degraded());
        agent.set_attached(true);
        assert!(agent.pins_attached());
        assert!(!agent.is_degraded());
        agent.set_attached(false);
        assert!(agent.is_degraded());
    }

    #[test]
    fn clock_rollback_keeps_an_expired_waiver_expired() {
        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        let mut agent = Agent::new(AgentConfig {
            lkg_dir: Some(dir.clone()),
            policy_name: "prod-restricted".into(),
            ..cfg_respond()
        });
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));

        let t0 = Utc::now();
        // A waiver that expired yesterday: only a clock moved backwards could
        // bring it back to life.
        let mut spec = waiver("ns", "prod-restricted", &["no-shell"]);
        spec.expires_at = t0 - chrono::Days::new(1);
        agent.set_exceptions(vec![spec]);

        assert_eq!(agent.now_from(t0), t0);
        assert!(!agent.datapath_degraded());

        let back = t0 - chrono::Days::new(30);
        let observed = agent.now_from(back);
        assert_eq!(observed, t0);
        assert_eq!(agent.clock_rollback_total(), 1);
        assert!(agent.datapath_degraded());
        assert!(agent.is_degraded());

        let sink = MemorySink::new();
        let decision = agent.handle_event_at(
            container_meta(4242),
            &ev("execve", "sh", "/bin/sh", true, false),
            &sink,
            observed,
        );
        assert_eq!(decision.action, Action::Kill);
        assert!(sink.events()[0].waiver.is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
