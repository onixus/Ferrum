//! Node agent: signed FEBP, last-known-good, observe vs respond.
//! Kernel attach is not implied by a successful userspace load.

#![deny(unsafe_code)]

mod clock;
mod pump;
mod respond;
mod ring;
mod source;
mod status;

use chrono::{DateTime, Utc};
use ferrum_api::PolicyExceptionSpec;
use ferrum_common::{FerrumError, Result};
use ferrum_ebpf::{extract_febp, Action, DeadRules, Decision, EventMeta, Loader, SyscallEvent};
use ferrum_export::EventSink;
use ferrum_ids::{Digest, PolicyId, RuleId};
use ferrum_k8smeta::{PodMetadataSource, PodRecord, SharedCgroupIndex, WorkloadIdentity};
use ferrum_proto::{EnforcementEvent, WaiverRef};
use std::collections::{BTreeSet, HashMap};
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
/// How long "a scan has been through and this cgroup is still not a pod" is
/// good for before it must be re-earned.
///
/// The proof is about a cgroup *id*, and the kernel recycles ids. Once an id
/// that settled as a host process is reused for a container, the entry keeps
/// answering `container_unproven` false from a timestamp hours old, and the
/// record leaves under the default action with no `container_unknown` and no
/// `REFUSE_NOT_CONTAINER` — silence, which is worse than a refused kill.
/// Without a TTL nothing ages a proven entry out below
/// `CONTAINER_FLAG_TRACKED_MAX`, so on a node with a handful of host cgroups
/// the entry is immortal.
///
/// Re-earning costs one refresh round: the entry reopens at `now` and the
/// next accepted sync settles it again. Long enough that kubelet, containerd
/// and sshd are unproven for a couple of seconds every five minutes rather
/// than every couple of seconds; short enough that a recycled id cannot lie
/// for a shift.
pub const UNPROVEN_PROOF_TTL: Duration = Duration::from_secs(300);
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
/// Nothing decodes ring records any more: the reader still drains the ring, so
/// the kernel does not stall, but every record it takes out is discarded
/// before a rule sees it. Terminal in this process — the pump thread is not
/// respawned — so it is latched, not decayed.
pub const RECORD_CHANNEL_GONE: &str =
    "record channel gone: ring records are drained and discarded before any rule sees them";
/// The attached ELF stamps its records with a datapath ABI this decoder does
/// not decode. Proof, from the first record, that the ELF in this image is not
/// the build the userspace was compiled against: the stamp lives in an
/// instruction immediate, so neither `elf_inspect` nor the attach-time map
/// check can see it, and the maps can match field for field while every record
/// is refused. Latched, and on the first record rather than on a window: there
/// is one ELF per attach, nothing in this process replaces it, and a node
/// whose every record is refused must not report healthy merely because it
/// went quiet.
pub const DATAPATH_ABI_MISMATCH: &str =
    "datapath abi mismatch: the attached eBPF ELF stamps ring records with an ABI this agent \
     does not decode, so no record can ever reach a rule";
/// Records keep failing to decode with not one succeeding in between. Unlike
/// a stamp mismatch this is not proof of which build is attached, but a run
/// this long with no success at all is not occasional corruption either: it is
/// a record path that produces nothing a rule can see. Latched for the same
/// reason as the stamp: the condition does not clear on its own, and the
/// decaying window cannot say it while no traffic arrives.
pub const DATAPATH_UNDECODABLE: &str =
    "datapath undecodable: consecutive ring records failed to decode with none succeeding \
     between them, so no record reaches a rule";
/// How long a run of failures with no success in between must get before it
/// stops being corruption and starts being a datapath that decodes nothing.
/// A busy node loses records in bursts — a partial write, a torn record at a
/// ring wrap — and those are separated by records that do decode. Only a run
/// with *zero* successes in it reaches this, so a handful of bad records among
/// many good ones never can, however many of them there are.
pub const DECODE_FAILURE_RUN_MAX: u64 = 64;
/// The datapath writes `bpf_get_current_pid_tgid()`, which is the initial pid
/// namespace. Publishing this process's namespaced pid as `ferrum_self` would
/// flag an unrelated init-ns process as the agent, so nothing is published and
/// EVENT_FLAG_AGENT_SELF is never set: `notAgentSelf` cannot be honoured here.
///
/// Reported always, Degraded only under respond (see
/// `Agent::self_tgid_unpublished`): without `hostPID` this is the shipped
/// observe install on every node, and the deploy linter forbids adding
/// `hostPID: true` to it.
pub const SELF_TGID_UNPUBLISHED: &str =
    "agent self tgid not published: not in the host pid namespace, so notAgentSelf rules \
     cannot be honoured on this node";
/// The reasons `is_degraded` can give, in the words the operator reads in
/// `status.json` and in the transition line. Constants rather than literals:
/// the file and the log line are a surface, and a reason that changes wording
/// between them is a reason nobody can alert on.
pub const DEG_CONTROL_PLANE_DOWN: &str =
    "control plane down: enforcing last-known-good, no bundle updates";
pub const DEG_LOADER: &str = "bundle loader degraded: see the reload error on stderr";
pub const DEG_NOT_ATTACHED: &str = "no kernel attach: nothing feeds the decision path on this node";
pub const DEG_DATAPATH: &str =
    "datapath degraded: a record carried a syscall nr this build cannot name";
pub const DEG_CGROUP_INDEX_EMPTY: &str =
    "cgroup index empty: every namespaced selector misses, whatever the policy says";
pub const DEG_CONTAINER_MAP: &str =
    "container map not ready: EVENT_FLAG_CONTAINER cannot be trusted, so containerOnly rules miss";
pub const DEG_EXPORT_DEAD: &str = "export writer dead: enforcement runs and nothing records it";
pub const DEG_EXPORT_LOSSY: &str = "export lost events recently: a kill may have left no record";
pub const DEG_DECODE_FAILURES: &str = "records failed to decode recently: no rule saw them";
pub const DEG_LABELS_UNKNOWN: &str =
    "labels unknown recently: selectors were resolved fail-closed against caches with nothing in \
     them";
pub const DEG_RING_DROPS: &str = "in-kernel ring drops recently: records no rule ever saw";
pub const DEG_PATH_TRUNCATED: &str =
    "paths truncated recently: a suffix rule was decided without the bytes it names";
pub const DEG_IDENTITY_UNKNOWN: &str = "identity unknown recently: a cgroup the index cannot name";
pub const DEG_LKG_PARTIAL: &str =
    "last-known-good partial: enforcing a subset of the snapshot that was signed";
pub const DEG_CONTAINER_FLAG: &str =
    "container flag disagreement outlived its publish window: the datapath is not flagging \
     containers the index knows";
/// `status.json` could not be written. The node still enforces and still
/// stamps every envelope, but the file a collector reads is gone: this reason
/// is the only thing left that says the surface itself is down, and it rides
/// the envelopes and the transition line rather than the file it is about.
pub const DEG_STATUS_UNWRITABLE: &str =
    "status file unwritable: this node's state cannot be published, so status.json is absent \
     rather than stale";
/// Waivers on this node that can never demote anything here.
pub const WAIVERS_UNJOINED: &str =
    "waivers do not join this agent's policy: they are signed, verified, in scope and apply to \
     nothing here";

/// Bound on the per-cgroup disagreement window map. Beyond this the oldest
/// windows are dropped; a cgroup that keeps disagreeing simply reopens one.
const CONTAINER_FLAG_TRACKED_MAX: usize = 4096;

/// One cgroup's answer to "has a scan been through since this question was
/// first asked". `opened` is what decides that; `seen` is what decides which
/// entries a full map may give up (see `evict_unproven`).
#[derive(Clone, Copy)]
struct UnprovenWindow {
    opened: Instant,
    seen: Instant,
}

/// Make room in the unproven window map.
///
/// The entries this map exists for are the OLD ones: an entry a sync has
/// already passed over is the standing proof that its cgroup is a host
/// process and not a container, and it answers `container_unproven` false for
/// kubelet, containerd and sshd for as long as it lives. Dropping it and
/// reinserting at `now` makes those unproven again until the next refresh —
/// on a node with more than `CONTAINER_FLAG_TRACKED_MAX` distinct unresolved
/// cgroups, forever, which is the permanent REFUSE_NOT_CONTAINER stream
/// `containerOnly` was added to stop.
///
/// So the entries given up first are the ones that carry no proof yet: no
/// sync has been through since they opened, and reopening them at `now` loses
/// nothing they had. Only when every entry is settled is anything proven
/// dropped, and then the least recently *seen* ones go: a cgroup that keeps
/// raising records keeps its proof, a dead one ages out.
///
/// Not the same policy as `container_flag_window` (`note_container_flag_
/// disagreement`), where an entry past grace has already been converted into
/// a fault and removed, so the old entries there are the disposable ones.
fn evict_unproven(
    windows: &mut HashMap<u64, UnprovenWindow>,
    synced_at: Option<Instant>,
    now: Instant,
) {
    let before = windows.len();
    let proven = |w: &UnprovenWindow| {
        synced_at.is_some_and(|at| at > w.opened)
            && now.saturating_duration_since(w.opened) < UNPROVEN_PROOF_TTL
    };
    windows.retain(|_, w| proven(w));
    if windows.len() < before {
        return;
    }
    // Everything here is proven and the map is still full: nothing can be kept
    // for free. Give up the least recently seen eighth.
    let mut seen: Vec<Instant> = windows.values().map(|w| w.seen).collect();
    seen.sort_unstable();
    let cut = seen[before / 8];
    windows.retain(|_, w| w.seen > cut);
}

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
pub use status::{
    status_json, write_status, StatusOutput, StatusPublisher, StatusTick, STATUS_NAME,
    STATUS_TMP_NAME,
};

/// The degraded state at one instant: whether, why, and — once per change —
/// the line to log about it.
#[derive(Debug, Clone)]
pub struct DegradedState {
    pub degraded: bool,
    pub reasons: Vec<String>,
    /// Some only on a transition into or out of Degraded, and only for the
    /// first caller to observe that transition.
    pub transition: Option<String>,
}

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
    /// Consecutive decode failures with no successful decode between them.
    /// Reset by every record that decodes: it separates "some records are
    /// malformed" from "nothing decodes".
    decode_failed_run: AtomicU64,
    /// Records refused because their datapath ABI stamp is not this decoder's.
    datapath_abi_mismatch: AtomicU64,
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
    /// `ferrum_self` was left unconfigured because this process is not in the
    /// initial pid namespace, so `notAgentSelf` cannot be honoured. Latched
    /// (nothing re-enters the host namespace at runtime) but it is only a
    /// Degraded plane under respond; see `is_degraded`.
    self_tgid_unpublished: AtomicBool,
    clock: MonotonicFloor,
    respond_kill: AtomicU64,
    respond_refused: AtomicU64,
    /// Kill/Isolate matches this node never attempted because the role is
    /// observe. Counted apart from `respond_refused` on purpose: see
    /// `respond_role_skipped_total`.
    respond_role_skipped: AtomicU64,
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
    /// First unflagged event seen per cgroup the index does not resolve, i.e.
    /// when the question "is this a container nobody has scanned yet, or a
    /// process on the node that never will be one" was first asked about it,
    /// plus when it was last asked. Bounded by `CONTAINER_FLAG_TRACKED_MAX`;
    /// see `evict_unproven` for which entries a full map gives up.
    container_unproven_window: Mutex<HashMap<u64, UnprovenWindow>>,
    /// `containerOnly` rules that would have decided a record and were skipped
    /// on a caller the agent could not prove was not a container.
    container_unproven: AtomicU64,
    /// The last attempt to publish `status.json` failed, so this node's state
    /// is not readable from the node. Not latched: it clears on the first
    /// write that succeeds.
    status_write_failed: AtomicBool,
    /// How many publishes of `status.json` have failed. Readable in the next
    /// file that does get written, which is the only place a reader can learn
    /// that the surface has been down and is back.
    status_write_failed_count: AtomicU64,
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
    /// Rules the last-known-good snapshot carried that no record can ever
    /// match, dropped so the rest of the snapshot could be restored.
    lkg_rules_dropped: AtomicU64,
    /// The policy in force is a subset of the snapshot that was signed.
    /// Cleared only by a bundle that installs whole.
    lkg_partial: AtomicBool,
    /// Last malformed record. A record that failed to decode carried a syscall
    /// no rule ever saw, exactly like a ring drop, so it decays the same way.
    decode_failed_at: Mutex<Option<Instant>>,
    /// Export losses (full queue, failed write) observed on the sink so far,
    /// so a new loss is told apart from an old total.
    export_lost_seen: AtomicU64,
    /// Last observed export loss. Bursty by nature on a busy node: decayed,
    /// never latched, or it would pin the agent Degraded for the process
    /// lifetime and drown the signals that do recover.
    export_lost_at: Mutex<Option<Instant>>,
    /// A fault nothing in this process will undo: the record path, or the
    /// agent-self identity the datapath needs. First reason wins.
    terminal_fault: Mutex<Option<String>>,
    /// Last degraded state handed to a caller that logs transitions. None
    /// until the first report, so the first tick always says which state the
    /// node started in.
    ///
    /// The reasons, not just the bool: a node that goes from ring drops to a
    /// terminal wrong-ELF fault never flips the bool, and used to change that
    /// state in complete silence on the log surface — the one surface an
    /// operator has when the export directory is gone.
    degraded_reported: Mutex<Option<Vec<String>>>,
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
            decode_failed_run: AtomicU64::new(0),
            datapath_abi_mismatch: AtomicU64::new(0),
            unknown_syscalls: AtomicU64::new(0),
            datapath_degraded: AtomicBool::new(false),
            attached: AtomicBool::new(false),
            responder: None,
            target_check: Box::new(ProcCgroupCheck::new()),
            respond_disabled: Mutex::new(None),
            clock,
            respond_kill: AtomicU64::new(0),
            respond_refused: AtomicU64::new(0),
            respond_role_skipped: AtomicU64::new(0),
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
            container_unproven_window: Mutex::new(HashMap::new()),
            container_unproven: AtomicU64::new(0),
            status_write_failed: AtomicBool::new(false),
            status_write_failed_count: AtomicU64::new(0),
            labels_unknown: AtomicU64::new(0),
            labels_unknown_at: Mutex::new(None),
            ring_drop_at: Mutex::new(None),
            path_truncated: AtomicU64::new(0),
            path_truncated_at: Mutex::new(None),
            lkg_rules_dropped: AtomicU64::new(0),
            lkg_partial: AtomicBool::new(false),
            decode_failed_at: Mutex::new(None),
            export_lost_seen: AtomicU64::new(0),
            export_lost_at: Mutex::new(None),
            terminal_fault: Mutex::new(None),
            self_tgid_unpublished: AtomicBool::new(false),
            degraded_reported: Mutex::new(None),
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
        self.is_degraded_at(Instant::now())
    }

    pub fn is_degraded_at(&self, now: Instant) -> bool {
        !self.degraded_reasons_at(now).is_empty()
    }

    /// Every reason the agent is Degraded, in the words an operator gets in
    /// `status.json` and in the transition line. `is_degraded` is this list
    /// being non-empty and nothing else: a signal that cannot be named here
    /// cannot degrade the node, so no reason can be raised silently.
    pub fn degraded_reasons_at(&self, now: Instant) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        // Every arm pushes a constant or the fault text it already holds.
        if self.cp_down {
            out.push(DEG_CONTROL_PLANE_DOWN.to_string());
        }
        if self.loader.is_degraded() {
            out.push(DEG_LOADER.to_string());
        }
        if !self.pins_attached() {
            out.push(DEG_NOT_ATTACHED.to_string());
        }
        if self.datapath_degraded.load(Ordering::Relaxed) {
            out.push(DEG_DATAPATH.to_string());
        }
        // An empty cgroup index is not "no pods": every lookup misses, so
        // every namespaced selector silently fails to match.
        if self.cgroups.is_empty() {
            out.push(DEG_CGROUP_INDEX_EMPTY.to_string());
        }
        // The index alone proves nothing about the datapath: until those
        // cgroups are in `ferrum_cgroups`, EVENT_FLAG_CONTAINER is never
        // set and every container_only rule (shell, docker.sock) misses.
        if !self.container_map_ready_at(now) {
            match self.container_map_error() {
                Some(err) => out.push(format!("{DEG_CONTAINER_MAP}: {err}")),
                None => out.push(DEG_CONTAINER_MAP.to_string()),
            }
        }
        if self.export_dead.load(Ordering::Relaxed) {
            out.push(DEG_EXPORT_DEAD.to_string());
        }
        // Enforcement that happened and was not written down is the
        // repudiation case: a full queue or a full disk loses the record
        // of a kill on a node that would otherwise report healthy.
        if self.export_lossy_recent_at(now) {
            out.push(DEG_EXPORT_LOSSY.to_string());
        }
        // A record no rule ever saw is the same loss as a ring drop,
        // whichever side of the ring dropped it.
        if self.decode_failures_recent_at(now) {
            out.push(DEG_DECODE_FAILURES.to_string());
        }
        if let Some(fault) = self.terminal_fault() {
            out.push(fault);
        }
        // A selector the agent could not resolve is not a non-match: the
        // rules were applied fail-closed, and that is a Degraded plane
        // until the label caches catch up.
        if self.labels_unknown_recent_at(now) {
            out.push(DEG_LABELS_UNKNOWN.to_string());
        }
        // An in-kernel drop under flood bounds the CPU cost, not the
        // policy: the dropped record carried an event no rule ever saw.
        // That is a missed enforcement, so it is Degraded while it lasts.
        if self.ring_drops_recent_at(now) {
            out.push(DEG_RING_DROPS.to_string());
        }
        // A path the datapath could not carry whole is a suffix rule
        // decided without the bytes it names. The rule still fired, but on
        // an assertion, and a node making those is Degraded.
        if self.path_truncated_recent_at(now) {
            out.push(DEG_PATH_TRUNCATED.to_string());
        }
        // A cgroup the index cannot name makes every namespaced selector
        // answer "no match" for a reason that has nothing to do with the
        // policy. That is a missed enforcement, not an allow.
        if self.identity_unknown_recent_at(now) {
            out.push(DEG_IDENTITY_UNKNOWN.to_string());
        }
        // The node is enforcing less than the snapshot it restored. Not
        // fail-open — the rules that were dropped can match no record —
        // but the running policy is no longer the one that was signed.
        if self.lkg_partial.load(Ordering::Relaxed) {
            out.push(DEG_LKG_PARTIAL.to_string());
        }
        if self.container_flag_degraded_at(now) {
            out.push(DEG_CONTAINER_FLAG.to_string());
        }
        // The reporting surface is itself down. Says nothing about
        // enforcement, which carries on: it says that everything else here
        // is being written nowhere, and the usual cause (ENOSPC on the
        // export directory) is the same one that makes every event write
        // fail. This reason cannot reach the file it is about — that is the
        // point of it — so it travels on the envelopes and on stderr.
        if self.status_write_failed() {
            out.push(DEG_STATUS_UNWRITABLE.to_string());
        }
        if let Some(reason) = self.respond_disabled_reason() {
            out.push(reason);
        }
        // A node holding waivers that name another policy enforces as if it
        // held none, and every counter around them still reads healthy.
        if let Some(reason) = self.waivers_unjoined() {
            out.push(reason);
        }
        // Under respond only. Without `hostPID` the agent cannot publish
        // `ferrum_self`, and that is the shipped base install: observe,
        // no `hostPID`, and `lint-deploy` raises UNNEEDED_HOST_PID if an
        // operator adds it. Treating it as a fault pinned every node in
        // the fleet to Degraded from second one, drowning ring drops,
        // label-unknown, export loss and last-known-good. The consequence
        // there is one audit label the agent will not claim - the only
        // `notAgentSelf` rule in the tree is `audit`. Under respond it is
        // a different thing entirely: a wrong agent-self identity is a
        // wrong kill target, so the operator who asked for respond must
        // see it.
        if self.role.respond_enabled() && self.self_tgid_unpublished() {
            out.push(SELF_TGID_UNPUBLISHED.to_string());
        }
        out
    }

    /// The degraded state, plus the one line to log if it just changed.
    ///
    /// Calling this records the state as reported: the transition is returned
    /// once, to whoever is going to log it. Reports, never acts — see
    /// `status` for why no probe may be wired to this.
    pub fn degraded_state_at(&self, now: Instant) -> DegradedState {
        let reasons = self.degraded_reasons_at(now);
        let degraded = !reasons.is_empty();
        let mut last = self
            .degraded_reported
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // On the reasons, not on the bool. Degraded is not one state: the
        // node that adds a terminal fault to a recoverable one, or recovers
        // from one of two, has changed what an operator must do about it,
        // and a line only on the boolean edge never says so.
        let changed = last.as_deref() != Some(reasons.as_slice());
        *last = Some(reasons.clone());
        drop(last);
        let transition = changed.then(|| {
            serde_json::json!({
                "event": "degraded_transition",
                "degraded": degraded,
                "reasons": reasons,
            })
            .to_string()
        });
        DegradedState {
            degraded,
            reasons,
            transition,
        }
    }

    /// Loaded exceptions whose target names a policy this node is not
    /// running. Every one of them was signed, verified, counted and logged as
    /// reloaded, and can waive nothing here.
    pub fn waivers_unjoined_total(&self) -> u64 {
        self.exceptions
            .iter()
            .filter(|spec| !spec.target.policies.iter().any(|p| *p == self.policy_name))
            .count() as u64
    }

    /// Can this waiver demote anything at all on this node?
    ///
    /// The record-independent half of `exception_applies`, asked through
    /// `exception_applies` itself rather than re-derived: the probe is the
    /// most favourable record this waiver could ever meet — its own target
    /// namespace, its own first named rule. If that record would not satisfy
    /// it, no record can, and the waiver is dead weight on this node.
    ///
    /// A bare `policies.contains(policy_name)` is not this check. It counts
    /// an expired waiver, a self-approved one and one with an empty rules
    /// axis as joined, and every one of those demotes exactly nothing while
    /// reading as a live exemption.
    fn waiver_can_apply(&self, spec: &PolicyExceptionSpec, now: DateTime<Utc>) -> bool {
        if self.policy_name.is_empty() {
            return false;
        }
        let Some(rule) = spec.target.rules.first() else {
            return false;
        };
        ferrum_policy::exception_applies(spec, &spec.target.namespace, &self.policy_name, rule, now)
    }

    /// Loaded exceptions that can demote nothing on this node whatever
    /// arrives. A superset of `waivers_unjoined_total`, which only counts the
    /// policy-name mismatch: this one also has the expired waiver and the
    /// malformed one, both of which name this policy and waive nothing.
    pub fn waivers_inert_total(&self) -> u64 {
        let now = self.now();
        self.exceptions
            .iter()
            .filter(|spec| !self.waiver_can_apply(spec, now))
            .count() as u64
    }

    /// "I hold waivers that can waive nothing here."
    ///
    /// The FRMB carries no policy name, so nothing joins `--policy-name` to
    /// the bundle in the mounted Secret: rename the policy, or run a second
    /// one, and every waiver on the node silently applies to nothing while
    /// kills a live waiver should have demoted keep firing. That join cannot
    /// be proven here without a bundle format change, so it is *stated*
    /// instead — and `lint-deploy` FD024 checks the other end of it, against
    /// objects already deployed.
    ///
    /// Per waiver, not all-or-nothing. One live waiver used to suppress this
    /// for every other waiver on the node, so 49 dead ones out of 50 moved a
    /// counter nobody alerts on and said nothing: the 49 kills they were
    /// meant to demote still fired, and the node read healthy throughout.
    pub fn waivers_unjoined(&self) -> Option<String> {
        let held = self.exceptions.len();
        if held == 0 {
            return None;
        }
        let now = self.now();
        let inert: Vec<&PolicyExceptionSpec> = self
            .exceptions
            .iter()
            .filter(|spec| !self.waiver_can_apply(spec, now))
            .collect();
        if inert.is_empty() {
            return None;
        }
        let names = |specs: &[&PolicyExceptionSpec]| -> String {
            let named: BTreeSet<&str> = specs
                .iter()
                .flat_map(|spec| spec.target.policies.iter().map(String::as_str))
                .collect();
            if named.is_empty() {
                "none".to_string()
            } else {
                named.into_iter().collect::<Vec<_>>().join(", ")
            }
        };
        if self.policy_name.is_empty() {
            return Some(format!(
                "{WAIVERS_UNJOINED}: {held} loaded, and this agent was started without \
                 --policy-name, so no waiver can ever apply (they name: {})",
                names(&inert)
            ));
        }
        // One category each, most specific first: a waiver naming another
        // policy is reported as that even if it has also expired.
        let mut unjoined: Vec<&PolicyExceptionSpec> = Vec::new();
        let mut expired = 0usize;
        let mut rest = 0usize;
        for spec in &inert {
            if !spec.target.policies.iter().any(|p| *p == self.policy_name) {
                unjoined.push(spec);
            } else if now >= spec.expires_at {
                expired += 1;
            } else {
                rest += 1;
            }
        }
        let mut parts = Vec::new();
        if !unjoined.is_empty() {
            parts.push(format!(
                "{} name another policy (they name: {})",
                unjoined.len(),
                names(&unjoined)
            ));
        }
        if expired > 0 {
            parts.push(format!("{expired} expired"));
        }
        if rest > 0 {
            parts.push(format!(
                "{rest} cannot match any record (no rule named, or the four-eyes and TTL checks \
                 refuse them)"
            ));
        }
        Some(format!(
            "{WAIVERS_UNJOINED}: {} of {held} loaded waivers can demote nothing on policy '{}': {}",
            inert.len(),
            self.policy_name,
            parts.join("; ")
        ))
    }

    /// The kernel container map is usable: last sync succeeded and it holds
    /// something. An empty map is not "no pods" — it is every container_only
    /// rule silently not matching.
    pub fn container_map_ready(&self) -> bool {
        self.container_map_ready_at(Instant::now())
    }

    pub fn container_map_ready_at(&self, now: Instant) -> bool {
        self.container_map_synced.load(Ordering::Relaxed)
            && self.container_map_entries.load(Ordering::Relaxed) > 0
            && self.container_map_error().is_none()
            && !self.container_map_stale_at(now)
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

    /// `containerOnly` rules that would have decided a record and were skipped
    /// because the caller could not be shown to be a container.
    pub fn container_unproven_total(&self) -> u64 {
        self.container_unproven.load(Ordering::Relaxed)
    }

    /// Counted, not Degraded, and deliberately: the cgroup of a container
    /// reaches the index one refresh before it reaches `ferrum_cgroups`, so
    /// every pod start opens this window and a node that degraded on it would
    /// degrade on ordinary healthy behaviour. What outlives the window is a
    /// datapath fault, and `note_container_flag_disagreement` already decides
    /// that. What this adds is that the record does not leave silently.
    pub fn record_container_unproven(&self) {
        self.container_unproven.fetch_add(1, Ordering::Relaxed);
    }

    /// Can this record's caller be shown NOT to be a container?
    ///
    /// `container_only` keys on EVENT_FLAG_CONTAINER, which is unset for the
    /// node's own containerd and equally unset for a pod whose cgroup the
    /// refresher has not pushed into `ferrum_cgroups` yet. Nothing in the
    /// record separates them. What does separate them is time: the index is
    /// filled from a scan of the cgroup tree, so once a scan that resolved
    /// AFTER this cgroup was first seen has landed and the cgroup is still not
    /// a pod, it is not one - kubelet, containerd, sshd settle there within
    /// one refresh and stay settled, and this answers false for them forever
    /// after. Until then the honest answer is "unproven".
    ///
    /// False whenever the publish path is not healthy: with no live publisher
    /// nothing will ever resolve, every host process would be unprovable
    /// forever, and the permanent stream of refused kills that `containerOnly`
    /// was added to stop would come straight back. A node in that state is
    /// already Degraded on `container_map_ready`, which is the honest signal
    /// for it.
    pub fn container_unproven(&self, cgroup_id: u64, now: Instant) -> bool {
        if !self.container_map_ready_at(now) {
            return false;
        }
        let synced_at = *self
            .container_map_synced_at
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut windows = self
            .container_unproven_window
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if windows.len() >= CONTAINER_FLAG_TRACKED_MAX && !windows.contains_key(&cgroup_id) {
            evict_unproven(&mut windows, synced_at, now);
        }
        let entry = windows.entry(cgroup_id).or_insert(UnprovenWindow {
            opened: now,
            seen: now,
        });
        entry.seen = now;
        // The proof has a shelf life: cgroup ids are recycled, and an entry
        // that settled hours ago is a statement about whatever held the id
        // then. Reopening re-asks the question; the next accepted sync
        // answers it again within one refresh round.
        if now.saturating_duration_since(entry.opened) >= UNPROVEN_PROOF_TTL {
            entry.opened = now;
        }
        let opened = entry.opened;
        // A scan that resolved after the question was first asked had every
        // container running at that moment in it, this one included.
        !synced_at.is_some_and(|at| at > opened)
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

    /// Reactions the agent was in a position to attempt and would not: a
    /// guard said no. On an observe node this stays 0 — the role skip is not
    /// a refusal, it is the configuration — so an alert on this counter reads
    /// "something stopped a kill that respond was supposed to make".
    pub fn respond_refused_total(&self) -> u64 {
        self.respond_refused.load(Ordering::Relaxed)
    }

    /// Kill/Isolate rules that matched on a node whose role does not react.
    /// Every one of them is exported with REFUSE_ROLE, so the event trail is
    /// unchanged; this is only the aggregate. Separate from
    /// `respond_refused_total` because on the shipped observe default that
    /// counter would otherwise climb with every shell exec on the node and
    /// read as "reactions we refused" while meaning "kill rules that matched".
    pub fn respond_role_skipped_total(&self) -> u64 {
        self.respond_role_skipped.load(Ordering::Relaxed)
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

    /// Record the outcome of one `status.json` publish. Called by the poll
    /// loop after the write, with every guard on the shared agent dropped,
    /// so this must stay lock-free.
    ///
    /// A failed publish is Degraded on purpose. The previous file said
    /// `"degraded": false` and `commit` removes it rather than leave that
    /// standing, so without this the node's state would be readable nowhere:
    /// the reason travels on the exported envelopes and the transition line
    /// instead, and the count survives into the next file that is written.
    pub fn note_status_write(&self, ok: bool) {
        if !ok {
            self.status_write_failed_count
                .fetch_add(1, Ordering::Relaxed);
        }
        self.status_write_failed.store(!ok, Ordering::Relaxed);
    }

    /// The last publish of `status.json` failed.
    pub fn status_write_failed(&self) -> bool {
        self.status_write_failed.load(Ordering::Relaxed)
    }

    pub fn status_write_failed_total(&self) -> u64 {
        self.status_write_failed_count.load(Ordering::Relaxed)
    }

    /// Events the export path lost: dropped by a full queue, or accepted and
    /// never written. Both mean an enforcement that happened left no record.
    pub fn export_lost_total(&self) -> u64 {
        self.export_lost_seen.load(Ordering::Relaxed)
    }

    /// The export lost something recently. Deliberately decaying: a busy node
    /// drops export events in bursts, and a latch here would pin the agent
    /// Degraded for the process lifetime and drown the ring-drop and
    /// label-unknown signals that do recover.
    pub fn export_lossy_recent(&self) -> bool {
        self.export_lossy_recent_at(Instant::now())
    }

    pub fn export_lossy_recent_at(&self, now: Instant) -> bool {
        within(&self.export_lost_at, now, DEGRADED_RECOVERY)
    }

    /// Read what the sink has lost since the last look. `export_writer_dead`
    /// alone only covers a writer that is gone; a full queue and a failed
    /// write lose the record of a kill that really happened while every other
    /// signal still reads healthy (RFC-02 §C, repudiation).
    ///
    /// All three losses are summed. Leaving `export_writer_lost_total` out
    /// froze the number an operator reads at the exact moment it matters
    /// most: after the writer thread dies every further event is counted
    /// there and nowhere else, so `export_lost_total` stood still while the
    /// node lost every record it produced.
    pub fn note_export_state_at<S: EventSink + ?Sized>(&self, sink: &S, now: Instant) {
        if sink.export_writer_dead() {
            self.export_dead.store(true, Ordering::Relaxed);
        }
        let lost = sink
            .export_queue_dropped_total()
            .saturating_add(sink.export_write_failed_total())
            .saturating_add(sink.export_writer_lost_total());
        // `fetch_max`, not `swap`: this has two callers — the event path and
        // the poll tick — and under `poll_status` they hold only read guards,
        // so they run concurrently. A `swap` lets the loser write back the
        // value it read before the winner's update, and `export_lost_total`
        // then DECREASES between two ticks: a consumer computing a rate over
        // a monotonic counter sees a negative delta, and the next read of the
        // real value re-marks `export_lost_at` for a loss that already
        // decayed. The sink's counters only ever grow, so the agent's mirror
        // of them must only ever grow too.
        let seen = self.export_lost_seen.fetch_max(lost, Ordering::Relaxed);
        if lost > seen {
            mark_now(&self.export_lost_at, now);
        }
    }

    /// A fault the process cannot recover from. Latched on purpose: unlike the
    /// decaying signals, nothing here ever clears on its own.
    pub fn terminal_fault(&self) -> Option<String> {
        self.terminal_fault
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// `ferrum_self` was refused: `notAgentSelf` rules cannot be honoured on
    /// this node. Reported on every role; Degraded only under respond.
    pub fn self_tgid_unpublished(&self) -> bool {
        self.self_tgid_unpublished.load(Ordering::Relaxed)
    }

    /// Latched: nothing moves a running process into the initial pid
    /// namespace, so this never clears. Not a terminal fault - see
    /// `is_degraded` for why the consequence depends on the role.
    pub fn mark_self_tgid_unpublished(&self) {
        self.self_tgid_unpublished.store(true, Ordering::Relaxed);
    }

    /// First reason wins: the cause is what an operator needs, not the latest
    /// consequence of it.
    pub fn mark_terminal_fault(&self, reason: impl Into<String>) {
        let mut slot = self
            .terminal_fault
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(reason.into());
        }
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
        self.record_decode_failure_at(n, Instant::now());
    }

    /// Every decode error lands here, whatever its kind: a short or garbled
    /// record, and equally a record whose ABI stamp the decoder refuses. On a
    /// datapath ELF that does not match the decoder that is every record, so
    /// the honesty must not stop at a counter.
    ///
    /// A malformed record is not telemetry: it carried a syscall that no rule
    /// ever matched against, which is the same loss as an in-kernel ring drop
    /// and degrades the agent on the same decaying terms.
    pub fn record_decode_failure_at(&self, n: u64, now: Instant) {
        if n == 0 {
            return;
        }
        self.decode_failed.fetch_add(n, Ordering::Relaxed);
        mark_now(&self.decode_failed_at, now);
        let run = self.decode_failed_run.fetch_add(n, Ordering::Relaxed) + n;
        if run >= DECODE_FAILURE_RUN_MAX {
            self.mark_terminal_fault(DATAPATH_UNDECODABLE);
        }
    }

    /// One record decoded. The only thing that clears the failure run, and the
    /// reason the run means anything: a node with no traffic keeps the run it
    /// last had, while a node that decodes records resets it on every one.
    pub fn record_decode_success(&self, n: u64) {
        if n == 0 {
            return;
        }
        self.decode_failed_run.store(0, Ordering::Relaxed);
    }

    /// Consecutive decode failures with no success between them.
    pub fn decode_failure_run(&self) -> u64 {
        self.decode_failed_run.load(Ordering::Relaxed)
    }

    pub fn datapath_abi_mismatch_total(&self) -> u64 {
        self.datapath_abi_mismatch.load(Ordering::Relaxed)
    }

    /// A record whose ABI stamp is not this decoder's. Counted as a decode
    /// failure like any other refused record - it is one - but latched at
    /// once, because unlike a malformed record it names its cause: the ELF
    /// that wrote it is not the build this agent decodes, and no later record
    /// from that ELF will decode either. Waiting for a window to fill, or for
    /// a decaying one to keep being refreshed, is what let a node with a stale
    /// ELF and no syscall traffic report healthy while its datapath was
    /// entirely undecodable.
    pub fn record_datapath_abi_mismatch(&self, stamp: u16) {
        self.record_datapath_abi_mismatch_at(stamp, Instant::now());
    }

    pub fn record_datapath_abi_mismatch_at(&self, stamp: u16, now: Instant) {
        self.datapath_abi_mismatch.fetch_add(1, Ordering::Relaxed);
        self.record_decode_failure_at(1, now);
        let expected = ferrum_ebpf::DATAPATH_ABI;
        self.mark_terminal_fault(format!(
            "{DATAPATH_ABI_MISMATCH} (record stamp {stamp:#06x}, this agent decodes {expected:#06x})"
        ));
    }

    /// Records failed to decode recently enough to still mean something.
    /// Recoverable: a source that stops emitting garbage stops the signal.
    pub fn decode_failures_recent(&self) -> bool {
        self.decode_failures_recent_at(Instant::now())
    }

    pub fn decode_failures_recent_at(&self, now: Instant) -> bool {
        within(&self.decode_failed_at, now, DEGRADED_RECOVERY)
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
        //
        // A snapshot on disk was signed by whatever compiler was current when
        // it was written; an agent upgraded since then may carry a load gate
        // that compiler did not have. Refusing the whole snapshot for a rule
        // that can match no record would leave an upgraded node with no policy
        // at all while the control plane is down, which is the fail-open this
        // plane exists to avoid. So on this path only, such rules are dropped
        // and counted, and the node stays Degraded until a bundle installs
        // whole. Everything else — bad signature, ABI, kill-all, malformed —
        // still refuses the snapshot outright.
        self.install_verified_with(&bytes, expected.as_ref(), DeadRules::Drop)
            .map(|_| ())
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
        self.install_verified_with(bytes, expected_digest, DeadRules::Reject)
    }

    fn install_verified_with(
        &mut self,
        bytes: &[u8],
        expected_digest: Option<&Digest>,
        dead: DeadRules,
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
        let dropped = self.loader.load_bundle_with(&digest, &raw, dead)?;
        if dropped.is_empty() {
            self.lkg_partial.store(false, Ordering::Relaxed);
        } else {
            self.lkg_rules_dropped
                .fetch_add(dropped.len() as u64, Ordering::Relaxed);
            self.lkg_partial.store(true, Ordering::Relaxed);
            for reason in &dropped {
                eprintln!("ferrum-agent: last-known-good rule dropped: {reason}");
            }
        }
        Ok(digest)
    }

    /// Rules dropped while restoring last-known-good because no record can
    /// match them. Non-zero means the running policy is a subset of the
    /// snapshot that was signed.
    pub fn lkg_rules_dropped_total(&self) -> u64 {
        self.lkg_rules_dropped.load(Ordering::Relaxed)
    }

    /// The policy in force is a subset of the snapshot that was signed.
    pub fn lkg_partial(&self) -> bool {
        self.lkg_partial.load(Ordering::Relaxed)
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
        let at = Instant::now();
        // Whether a `containerOnly` rule skipped on this record is worth
        // reporting. Set in both branches below, for the two ways an unflagged
        // record can still have come from a container.
        let mut container_unproven = false;
        let identity = match self.cgroups.lookup_cgroup(meta.cgroup_id) {
            Ok(id) => {
                if !meta.in_container {
                    // The index resolves this cgroup to a pod, so the caller
                    // is not merely unproven: it IS a container, and every
                    // container_only rule silently did not apply to it.
                    container_unproven = true;
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
                } else {
                    // The other half, and the one `containerOnly` turned
                    // silent: a pod whose cgroup the refresher has not scanned
                    // yet is unflagged and unresolved exactly like the node's
                    // own containerd. `container_unproven` is what tells them
                    // apart, and it answers false for the host processes as
                    // soon as one scan has been through.
                    container_unproven = self.container_unproven(meta.cgroup_id, at);
                }
                WorkloadIdentity::unknown()
            }
        };
        let mut decision = self
            .loader
            .decide_with(event, &identity, container_unproven);
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
        // React on the action the policy decided, not on the one the role
        // allows: `apply_role` rewrites Kill to Audit, and a reaction that
        // never saw a Kill cannot say why it did not kill. The guards in
        // `react` refuse on the role first, so nothing is signalled here that
        // was not signalled before; the difference is that the export now
        // carries REFUSE_ROLE instead of being byte-identical to a rule that
        // really did say audit.
        let (executed, mut respond_error) = self.react(&decision, &meta, &identity, event);
        // Visible, not enforced. The datapath flag stays the authority for a
        // reaction - upgrading a decision from flags the record does not carry
        // is how a kill lands on the wrong process - so this does not make the
        // rule fire. What it undoes is the silence: before `containerOnly` the
        // rule matched and `react` refused it by name, and an operator could
        // see "the kill did not happen, and here is why". Without this the
        // same record leaves under the default action with no reason at all,
        // which is the one thing worse than a refused kill.
        if decision.container_unknown {
            self.record_container_unproven();
            if respond_error.is_none() {
                respond_error = Some(respond::REFUSE_NOT_CONTAINER.into());
            }
        }
        decision.action = apply_role(self.role, decision.action);
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
            // The one field that joins this record to the supply-chain side of
            // the same workload. The pod watch fills it and the selector
            // already matches on it; hardcoding None here made every record
            // the agent ever wrote unjoinable. Absent (not empty) when the
            // index has no digest for the cgroup, so "unknown" stays distinct
            // from "the empty digest".
            image_digest: if identity.image_digest.is_empty() {
                None
            } else {
                Some(Digest::new(identity.image_digest.clone()))
            },
            pod: identity.pod,
            namespace: identity.namespace,
            comm: event.comm.into(),
            syscall: event.syscall.into(),
            pid: meta.pid,
            tgid: meta.tgid,
            executed,
            respond_error,
            // Carried per record: the node counters for these are aggregates,
            // and an investigation looking at one kill cannot tell an asserted
            // match from a proven one without them.
            labels_unknown: decision.labels_unknown,
            path_unknown: decision.path_unknown,
            container_unknown: decision.container_unknown,
            waiver,
        });
        self.note_export_state_at(sink, Instant::now());
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
            Action::Kill | Action::Isolate => {}
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
            // The role skip is the configuration, not a refused reaction: on
            // an observe node — the shipped default — every match of a kill
            // rule reaches here. Counting those as refusals would make
            // `respond_refused_total` mean "kill rules that matched" while
            // still being named for something else. The event still carries
            // REFUSE_ROLE either way.
            if reason == respond::REFUSE_ROLE {
                self.respond_role_skipped.fetch_add(1, Ordering::Relaxed);
            } else {
                self.respond_refused.fetch_add(1, Ordering::Relaxed);
            }
            return (false, Some(reason.into()));
        }
        // Checked after the guards, not before them: under observe an isolate
        // rule did not run because the role is disabled, and that is the
        // reason the operator needs to read.
        if matches!(decision.action, Action::Isolate) {
            self.respond_refused.fetch_add(1, Ordering::Relaxed);
            return (false, Some(respond::REFUSE_ISOLATE.into()));
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

/// Hand one raw ring record to whoever decodes it. A full channel blocks on
/// purpose (backpressure onto the reader, so the kernel drops and counts it);
/// a disconnected one is different in kind — the pump thread is gone, so every
/// record from here on is read out of the ring and discarded before a rule
/// sees it. That is latched, not decayed: nothing respawns the pump. Returns
/// false once the channel is gone.
///
/// Takes the lock, never a guard: no lock on the shared `Agent` may be held
/// across the `send`, because the send blocks whenever the channel is full.
/// A read guard held across that block is a three-thread deadlock — the bundle
/// poller queues as a writer within one reload interval, `RwLock` then admits
/// no new readers, the pump thread cannot take its own read guard, so the
/// channel is never drained and the send never returns. Nothing decodes, kills
/// or exports after that, and nothing says so. The lock is taken only on the
/// disconnect path, after the blocking call has already returned; the hot path
/// takes none at all.
pub fn publish_record(
    agent: &std::sync::RwLock<Agent>,
    tx: &std::sync::mpsc::SyncSender<Vec<u8>>,
    record: Vec<u8>,
) -> bool {
    if tx.send(record).is_ok() {
        return true;
    }
    agent
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .mark_terminal_fault(RECORD_CHANNEL_GONE);
    false
}

/// The tgid to publish as `ferrum_self`, or nothing. The datapath writes
/// `bpf_get_current_pid_tgid()`, which is the initial pid namespace; without
/// hostPID this process's pid names an unrelated process there, so publishing
/// it would exempt that process from every `notAgentSelf` rule and apply those
/// rules to the agent. Nothing is published instead — `ferrum_self` stays 0,
/// which the datapath already reads as "not configured".
///
/// Recorded, not latched as a terminal fault: no `hostPID` is exactly the
/// shipped observe install, so a fault here would pin the whole fleet to
/// Degraded for behaviour the deploy linter mandates. `is_degraded` weighs it
/// against the role.
pub fn self_tgid_to_publish_at(agent: &Agent, ns_link: &Path, tgid: u64) -> Option<u64> {
    if host_pid_namespace_at(ns_link) {
        return Some(tgid);
    }
    agent.mark_self_tgid_unpublished();
    None
}

/// `self_tgid_to_publish_at` against the running host's `/proc`.
pub fn self_tgid_to_publish(agent: &Agent, tgid: u64) -> Option<u64> {
    if host_pid_namespace() {
        return Some(tgid);
    }
    agent.mark_self_tgid_unpublished();
    None
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
/// `out` is where the tick publishes node state: the envelope context so
/// every exported record carries the state at emit time, the `status.json`
/// beside the events, and the stderr line on a degraded transition.
pub fn poll_bundle(
    agent: &mut Agent,
    path: &Path,
    interval: Duration,
    out: &StatusOutput<'_>,
) -> ! {
    // Stat the path as given so kubelet `..data` rotates are visible; do not canonicalize.
    // Start with no stamp so a rotation between first load and this thread is not skipped.
    let mut stamps = PollStamps::default();
    loop {
        std::thread::sleep(interval);
        let tick = poll_once(agent, path, &mut stamps, out);
        let ok = stamps.publisher.commit(&tick, out);
        agent.note_status_write(ok);
    }
}

/// `poll_bundle` for a datapath that is pumping events concurrently: the write
/// lock is taken per tick, not held across the sleep, so reload never blocks
/// the decision path for longer than one reload.
///
/// The guard is also dropped before `status.json` is written. `RwLock` is
/// write-preferring, so a pending writer here blocks the ring-drain and pump
/// threads from taking a read guard: an `fsync` on a hostPath under IO
/// pressure inside that window stalls the drain, `ferrum_events` fills, and
/// the kernel drops records no rule ever sees. The reporting surface is not
/// allowed to cost enforcement, so the write happens with nothing held.
pub fn poll_bundle_shared(
    agent: &std::sync::RwLock<Agent>,
    path: &Path,
    interval: Duration,
    out: &StatusOutput<'_>,
) -> ! {
    let mut stamps = PollStamps::default();
    loop {
        std::thread::sleep(interval);
        let tick = {
            let mut guard = agent.write().unwrap_or_else(|e| e.into_inner());
            poll_once(&mut guard, path, &mut stamps, out)
        };
        let ok = stamps.publisher.commit(&tick, out);
        agent
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .note_status_write(ok);
    }
}

/// The state-publish half of a poll tick, for a caller with no bundle to
/// watch: an agent that never reloads must still say what it is, and must
/// still notice that its exports are being lost.
pub fn poll_status(
    agent: &std::sync::RwLock<Agent>,
    interval: Duration,
    out: &StatusOutput<'_>,
) -> ! {
    let mut publisher = StatusPublisher::default();
    loop {
        std::thread::sleep(interval);
        // Same split as `poll_bundle_shared`: nothing on the shared agent is
        // held across the file write.
        let tick = publisher.tick(&agent.read().unwrap_or_else(|e| e.into_inner()), out);
        let ok = publisher.commit(&tick, out);
        agent
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .note_status_write(ok);
    }
}

#[derive(Default)]
struct PollStamps {
    bundle: Option<source::SourceStamp>,
    exceptions: Option<source::FileStamp>,
    publisher: StatusPublisher,
}

/// Returns the tick to `commit` rather than committing it: the filesystem
/// half runs at the caller, after every guard on the agent is dropped.
fn poll_once(
    agent: &mut Agent,
    path: &Path,
    stamps: &mut PollStamps,
    out: &StatusOutput<'_>,
) -> StatusTick {
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
    stamps.publisher.tick(agent, out)
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

    /// The bound on the unproven window map is part of what `evict_unproven`
    /// promises, so a test has to be able to see it.
    fn unproven_window_len(&self) -> usize {
        self.container_unproven_window
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
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

    /// The §D runtime rules as a **pre-gate** bundle encodes them: `no-module`
    /// with `deny`, `no-runtime-sock` without `containerOnly`. That is not the
    /// policy we ship any more - it is what a last-known-good snapshot written
    /// to disk before cycle 7 looks like, and an upgraded agent must keep
    /// honouring one rather than run with no policy at all. Kept deliberately
    /// out of step with the YAML; `put_prod_restricted_rules` is the encoder
    /// that has to track it.
    fn put_pregate_mvp_rules(w: &mut Writer) {
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
        put_pregate_mvp_rules(&mut w);
        w.finish()
    }

    /// The same three rules as `policies/examples/prod-restricted.yaml` states
    /// them today: `no-module` is `audit`, because a tracepoint fires after the
    /// syscall has already run and cycle 7 made an unexecutable runtime action
    /// a validation error; `no-runtime-sock` is `containerOnly`, because the
    /// node's own containerd and kubelet open those sockets constantly.
    /// `compiler_frmb_round_trip` compares this byte-for-byte against what the
    /// compiler produces from that YAML, so drift here is a test failure and
    /// not a silently wrong reference.
    fn put_prod_restricted_rules(w: &mut Writer) {
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
        w.put_bool(true);
        w.put_str_list(&[]);
        w.put_str_list(&["docker.sock", "containerd.sock", "crio.sock"]);
        w.put_bool(false);
        w.put_str("no-module");
        w.put_str_list(&["init_module", "finit_module", "bpf"]);
        w.put_u8(Action::Audit.as_u8());
        w.put_str_list(&[]);
        w.put_bool(false);
        w.put_str_list(&[]);
        w.put_str_list(&[]);
        w.put_bool(true);
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
        put_prod_restricted_rules(&mut w);
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

    /// The three §D runtime verdicts a loaded bundle must produce.
    ///
    /// `bpf` is a parameter because the two bundle sources here genuinely
    /// disagree about it and both are correct. Compiling
    /// `prod-restricted.yaml` yields `audit`: cycle 7 made a runtime `deny` a
    /// validation error, since a tracepoint fires after the syscall has run.
    /// The hand-encoded FEBPs built from `put_pregate_mvp_rules` still say `deny` —
    /// they are pre-gate bundles, which is exactly what a last-known-good
    /// snapshot on disk is after an agent upgrade, and the agent must keep
    /// honouring one. Collapsing the two would hide which bundle a test is
    /// asserting against.
    fn assert_mvp_actions(agent: &Agent, bpf: Action) {
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
            bpf
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
        // The round trip, and the only thing here that can see drift in a rule
        // body. Splicing the hand-encoded FEBP into the bundle below without
        // this is how `no-module: deny` and a missing `containerOnly` survived
        // in the reference after the YAML changed: nothing compared them, and
        // every behavioural assertion below runs with `in_container = true`,
        // where a wrong `container_only` is invisible.
        let from_compiler = parse_febp(&compiled.ebpf_spec).expect("compiled FEBP");
        assert_eq!(
            from_compiler, parsed,
            "the hand-encoded reference no longer matches what the compiler \
             makes of prod-restricted.yaml"
        );
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
        // audit, not deny: this bundle is the shipped YAML, and the YAML says
        // audit. `Deny` here was what made the drifted reference pass.
        assert_mvp_actions(&agent, Action::Audit);
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
        assert_mvp_actions(&agent, Action::Audit);
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
        assert_mvp_actions(&agent, Action::Deny);
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
        assert_mvp_actions(&agent, Action::Deny);

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
        assert_mvp_actions(&agent, Action::Deny);
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

    /// FEBP an older compiler could emit: the MVP rules plus one whose path
    /// prefix is longer than the datapath buffer, so no record can carry it.
    fn encode_mvp_with_unmatchable_rule() -> Vec<u8> {
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
        let too_long = format!("/{}", "a".repeat(ferrum_ids::PATH_MATCH_MAX));
        w.put_u16(4);
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
        w.put_str("unmatchable");
        w.put_str_list(&["openat"]);
        w.put_u8(Action::Deny.as_u8());
        w.put_str_list(&[]);
        w.put_bool(false);
        w.put_str_list(&[too_long.as_str()]);
        w.put_str_list(&[]);
        w.put_bool(false);
        w.finish()
    }

    /// An LKG snapshot signed before this agent grew the "no record can carry
    /// this predicate" load gate. Refusing it whole would leave an upgraded
    /// node with no policy at all while the control plane is down — the
    /// fail-open LKG exists to prevent — so the restore path drops the rule
    /// (which can match nothing anyway), counts it, and stays Degraded. A new
    /// bundle carrying the same rule is still refused whole: there the
    /// operator has a compiler to fix and a running policy to keep.
    #[test]
    fn lkg_restore_drops_an_unmatchable_rule_instead_of_the_whole_snapshot() {
        let raw = encode_mvp_with_unmatchable_rule();
        let fsig = encode_fsig(&raw, &sign(&raw), &pk()).expect("fsig");

        let mut fresh = Agent::new(cfg());
        match fresh.apply_fsig(&fsig, None) {
            Err(FerrumError::Compile(_)) => {}
            other => panic!("expected Compile on the new-bundle path, got {other:?}"),
        }
        assert!(!fresh.using_last_known_good());

        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        fs::write(dir.join(BUNDLE_FSIG_KEY), &fsig).expect("write fsig");
        fs::write(
            dir.join(BUNDLE_DIGEST_KEY),
            ferrum_crypto::bundle_digest(&raw).as_str(),
        )
        .expect("write digest");

        let restored = Agent::new(AgentConfig {
            trust_root: pk(),
            lkg_dir: Some(dir.clone()),
            role: AgentRole::Respond,
            ..Default::default()
        });
        assert!(restored.using_last_known_good());
        assert_eq!(restored.lkg_rules_dropped_total(), 1);
        assert!(restored.is_degraded());
        // The rules the node can enforce are still enforced.
        assert_eq!(
            restored
                .matched_action(&ev("execve", "sh", "/bin/sh", true, false))
                .action,
            Action::Kill
        );
        assert_eq!(
            restored
                .matched_action(&ev("openat", "app", "/var/run/docker.sock", true, false))
                .action,
            Action::Kill
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The same snapshot without the dead rule restores whole: nothing is
    /// dropped and the partial-policy flag never latches.
    #[test]
    fn a_whole_lkg_snapshot_drops_nothing() {
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
            assert_eq!(agent.lkg_rules_dropped_total(), 0);
        }
        let restored = Agent::new(AgentConfig {
            trust_root: pk(),
            lkg_dir: Some(dir.clone()),
            ..Default::default()
        });
        assert!(restored.using_last_known_good());
        assert_eq!(restored.lkg_rules_dropped_total(), 0);
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
        assert_mvp_actions(&agent, Action::Deny);
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

    /// The nr the decode table itself uses, so a record is built for the same
    /// syscall the evaluator will name, whatever the arch table says.
    fn syscall_nr(arch: ferrum_ebpf::SyscallArch, name: &str) -> u32 {
        (0..1024)
            .find(|nr| ferrum_ebpf::syscall_name(arch, *nr) == Some(name))
            .unwrap_or_else(|| panic!("no syscall nr for {name}"))
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

    /// A record from a pre-cycle-7 ELF: the layout is this one, the stamp is
    /// the `_pad = 0` that build wrote. The maps match, so the attach-time
    /// check passes and the reader drains the ring - and every record is
    /// refused.
    fn stale_ring_record(
        syscall_nr: u32,
        comm: &str,
        path: &str,
        flags: u8,
        cgroup: u64,
    ) -> Vec<u8> {
        let mut wire = ring_record(syscall_nr, comm, path, flags, cgroup);
        wire[22..24].copy_from_slice(&0u16.to_ne_bytes());
        wire
    }

    /// F4. Maps that match let a stale ELF attach; the stamp is not in the ELF
    /// to be checked, so the first refused record is the only evidence there
    /// will ever be. The node must not be able to go quiet and report healthy:
    /// nothing arrives to refresh the decaying window, so the answer has to be
    /// latched at the first record and independent of when it is asked.
    #[test]
    fn a_datapath_whose_every_record_is_refused_is_degraded_without_more_traffic() {
        use ferrum_ebpf::{SyscallArch, EVENT_FLAG_CONTAINER};
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_container_map_synced(1);
        let sink = MemorySink::new();

        let stats = pump_records(
            &agent,
            SyscallArch::X86_64,
            [stale_ring_record(
                59,
                "sh",
                "/bin/sh",
                EVENT_FLAG_CONTAINER,
                7,
            )],
            &sink,
        );
        assert_eq!(
            stats,
            PumpStats {
                handled: 0,
                decode_failed: 1,
                unknown_syscall: 0
            }
        );
        assert!(sink.events().is_empty(), "no rule ever saw the record");
        assert_eq!(agent.datapath_abi_mismatch_total(), 1);
        assert_eq!(agent.records_decode_failed_total(), 1);

        let reason = agent.terminal_fault().expect("one refused stamp is proof");
        assert!(reason.starts_with(DATAPATH_ABI_MISMATCH), "{reason}");
        assert!(
            reason.contains("0x0000"),
            "the stamp that arrived: {reason}"
        );

        // The node now goes quiet: no further record, and long enough that the
        // decaying window has nothing left to say. It stays Degraded.
        let much_later = Instant::now() + DEGRADED_RECOVERY * 4;
        assert!(!agent.decode_failures_recent_at(much_later));
        assert!(
            agent.is_degraded(),
            "a quiet node with a wrong ELF is not healthy"
        );
    }

    /// The same conclusion without the stamp naming it: records that decode to
    /// nothing, one after another, with not one succeeding in between. Latched
    /// only once the run is long enough that corruption is no longer an
    /// explanation.
    #[test]
    fn a_run_of_records_that_all_fail_to_decode_is_degraded_without_more_traffic() {
        use ferrum_ebpf::SyscallArch;
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_container_map_synced(1);
        let sink = MemorySink::new();

        let short: Vec<Vec<u8>> = (0..DECODE_FAILURE_RUN_MAX - 1)
            .map(|_| vec![0u8; 5])
            .collect();
        pump_records(&agent, SyscallArch::X86_64, short, &sink);
        assert_eq!(agent.decode_failure_run(), DECODE_FAILURE_RUN_MAX - 1);
        assert!(
            agent.terminal_fault().is_none(),
            "a run short of the bound is still corruption"
        );

        pump_records(&agent, SyscallArch::X86_64, [vec![0u8; 5]], &sink);
        assert_eq!(
            agent.terminal_fault().as_deref(),
            Some(DATAPATH_UNDECODABLE)
        );
        assert_eq!(agent.datapath_abi_mismatch_total(), 0, "no stamp named it");

        let much_later = Instant::now() + DEGRADED_RECOVERY * 4;
        assert!(!agent.decode_failures_recent_at(much_later));
        assert!(agent.is_degraded());
    }

    /// The other half, and the one that keeps this from becoming the next
    /// finding: a busy node loses records in bursts and keeps decoding the
    /// rest. That is telemetry loss, Degraded while it recurs and clean again
    /// once it stops - never latched, however many bad records go by.
    #[test]
    fn bad_records_among_good_ones_degrade_only_while_they_recur() {
        use ferrum_ebpf::{SyscallArch, EVENT_FLAG_CONTAINER};
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_container_map_synced(1);
        let sink = MemorySink::new();

        // Far more bad records than the run bound, but never two dozen in a
        // row without a record that decodes.
        let mut records: Vec<Vec<u8>> = Vec::new();
        for _ in 0..DECODE_FAILURE_RUN_MAX * 4 {
            records.push(vec![0u8; 5]);
            records.push(vec![0u8; 5]);
            records.push(ring_record(59, "sh", "/bin/sh", EVENT_FLAG_CONTAINER, 7));
        }
        let stats = pump_records(&agent, SyscallArch::X86_64, records, &sink);
        assert_eq!(stats.handled, DECODE_FAILURE_RUN_MAX * 4);
        assert_eq!(stats.decode_failed, DECODE_FAILURE_RUN_MAX * 8);
        assert_eq!(agent.decode_failure_run(), 0, "the last record decoded");
        assert_eq!(agent.datapath_abi_mismatch_total(), 0);
        assert!(
            agent.terminal_fault().is_none(),
            "a node that keeps decoding records has a datapath, not a wrong ELF"
        );

        // Degraded while the losses are recent, and only while.
        assert!(agent.decode_failures_recent());
        assert!(agent.is_degraded());
        let recovered = Instant::now() + DEGRADED_RECOVERY * 2;
        assert!(!agent.decode_failures_recent_at(recovered));
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
    /// what arrived. With the flag the kill rule fires and the node is
    /// Degraded.
    ///
    /// Without the flag it must do the same, and that is the half that
    /// changed. A record with a buffer-filling head and no flag is what an ELF
    /// built before `emit()` flagged a short read writes, so a node running
    /// one after a rolling upgrade would silently miss this rule. The decoder
    /// derives truncation from the buffer instead of trusting the flag, so
    /// both records decide alike, both move `pathTruncatedTotal`, and both
    /// degrade — with decay, so the node recovers on its own.
    #[test]
    fn a_truncated_docker_sock_path_still_kills_and_degrades() {
        use ferrum_ebpf::{SyscallArch, EVENT_FLAG_CONTAINER, EVENT_FLAG_PATH_TRUNCATED};
        let head = format!("/var/run/{}", "./".repeat(130));
        let head = &head[..255];
        let openat = syscall_nr(SyscallArch::X86_64, "openat");

        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_container_map_synced(1);
        let sink = MemorySink::new();
        let record = ring_record(
            openat,
            "app",
            head,
            EVENT_FLAG_CONTAINER | EVENT_FLAG_PATH_TRUNCATED,
            7,
        );
        let stats = pump_records(&agent, SyscallArch::X86_64, [record], &sink);
        assert_eq!(stats.handled, 1);
        assert_eq!(sink.events()[0].action, "kill");
        assert!(sink.events()[0].path_unknown);
        assert_eq!(agent.path_truncated_total(), 1);
        assert!(agent.path_truncated_recent());
        assert!(agent.datapath_degraded());
        assert!(agent.is_degraded());

        // Same bytes, flag cleared: the record a pre-fix ELF writes for this
        // path. It must decide identically — the buffer is the evidence, and
        // it is unchanged.
        let flagless = ring_record(openat, "app", head, EVENT_FLAG_CONTAINER, 7);
        let mut pre_fix = Agent::new(cfg_respond());
        load_signed(&mut pre_fix, &encode_mvp(AGENT_ABI, Mode::Enforce));
        pre_fix.insert_cgroup(7, identity("pod-a"));
        pre_fix.set_container_map_synced(1);
        let seen = MemorySink::new();
        pump_records(&pre_fix, SyscallArch::X86_64, [flagless], &seen);
        assert_eq!(seen.events()[0].action, "kill", "the pre-fix ELF's record");
        assert!(seen.events()[0].path_unknown);
        assert_eq!(pre_fix.path_truncated_total(), 1);
        assert!(pre_fix.datapath_degraded());
        assert!(pre_fix.is_degraded());
        let now = Instant::now();
        assert!(pre_fix
            .degraded_reasons_at(now)
            .iter()
            .any(|r| r == DEG_PATH_TRUNCATED));

        // Degraded with decay, not latched: the counter is a total, the signal
        // is a window. Once no truncated path has been decided for
        // DEGRADED_RECOVERY the node is clean again on this reason.
        let later = now + DEGRADED_RECOVERY;
        assert!(!pre_fix.path_truncated_recent_at(later));
        assert!(!pre_fix
            .degraded_reasons_at(later)
            .iter()
            .any(|r| r == DEG_PATH_TRUNCATED));
        assert_eq!(
            pre_fix.path_truncated_total(),
            1,
            "the total does not decay"
        );

        // A path that fits decides on its bytes and signals nothing: the two
        // verdicts above came from the truncation, not from a match the bytes
        // happened to make.
        let short = ring_record(openat, "app", "/var/run/app.sock", EVENT_FLAG_CONTAINER, 7);
        let mut clean = Agent::new(cfg_respond());
        load_signed(&mut clean, &encode_mvp(AGENT_ABI, Mode::Enforce));
        clean.insert_cgroup(7, identity("pod-a"));
        clean.set_container_map_synced(1);
        let quiet = MemorySink::new();
        pump_records(&clean, SyscallArch::X86_64, [short], &quiet);
        assert_ne!(quiet.events()[0].action, "kill");
        assert!(!quiet.events()[0].path_unknown);
        assert_eq!(clean.path_truncated_total(), 0);
        assert!(!clean.path_truncated_recent());
        assert!(!clean.datapath_degraded());
    }

    /// The other half of the same flag, end to end: the path pointer was in a
    /// non-resident page, the helper returned -EFAULT, the buffer arrived
    /// empty and the openat succeeded anyway. Every path predicate would
    /// answer "no match" on those bytes, so the kill rule must still fire, the
    /// record must say the path was never observed, and the node must degrade.
    #[test]
    fn an_unreadable_path_still_kills_and_degrades() {
        use ferrum_ebpf::{SyscallArch, EVENT_FLAG_CONTAINER, EVENT_FLAG_PATH_TRUNCATED};
        let openat = syscall_nr(SyscallArch::X86_64, "openat");
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_container_map_synced(1);
        let sink = MemorySink::new();
        let record = ring_record(
            openat,
            "app",
            "",
            EVENT_FLAG_CONTAINER | EVENT_FLAG_PATH_TRUNCATED,
            7,
        );
        let stats = pump_records(&agent, SyscallArch::X86_64, [record], &sink);
        assert_eq!(stats.handled, 1);
        assert_eq!(sink.events()[0].action, "kill");
        assert!(sink.events()[0].path_unknown);
        assert!(!sink.events()[0].labels_unknown);
        assert_eq!(agent.path_truncated_total(), 1);
        assert!(agent.is_degraded());

        // Regression anchor: an empty path with no flag is a record from a
        // syscall that carried none, and decides exactly as it did before.
        let honest = ring_record(openat, "app", "", EVENT_FLAG_CONTAINER, 7);
        let mut clean = Agent::new(cfg_respond());
        load_signed(&mut clean, &encode_mvp(AGENT_ABI, Mode::Enforce));
        clean.insert_cgroup(7, identity("pod-a"));
        clean.set_container_map_synced(1);
        let quiet = MemorySink::new();
        pump_records(&clean, SyscallArch::X86_64, [honest], &quiet);
        assert_ne!(quiet.events()[0].action, "kill");
        assert!(!quiet.events()[0].path_unknown);
        assert_eq!(clean.path_truncated_total(), 0);
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

    /// The wall clock a record arrives at. Not a literal date: waiver checks
    /// reject an `expiresAt` more than `MAX_EXCEPTION_DAYS` past the record,
    /// and `waivers_unjoined` asks `Agent::now()`, so a fixed date here would
    /// make these tests pass until it drifts out of that window and then fail
    /// for a reason that has nothing to do with the code.
    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
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

    /// F6. `containerOnly` keys on a flag that is unset for the node's own
    /// containerd and equally unset for a pod whose cgroup the refresher has
    /// not scanned yet. The second is a real container running a rule that
    /// would have killed it, and before `containerOnly` the rule matched and
    /// the reaction was refused by name. It must not leave under the default
    /// action with nothing said about it.
    #[test]
    fn a_container_only_rule_skipped_on_an_unscanned_cgroup_is_reported() {
        const CGROUP_NEW: u64 = 8_808;
        let (agent, fake) = respond_agent_with_fake();
        agent.set_attached(true);
        agent.set_container_map_synced(1);
        assert!(agent.lookup_cgroup(CGROUP_NEW).is_err(), "not scanned yet");

        let sink = MemorySink::new();
        let meta = EventMeta {
            cgroup_id: CGROUP_NEW,
            pid: 4242,
            tgid: 4242,
            in_container: false,
            agent_self: false,
            path_truncated: false,
        };
        let decision =
            agent.handle_event(meta, &ev("execve", "sh", "/bin/sh", false, false), &sink);

        // Reported, not enforced: the flag stays the authority for a kill.
        assert!(decision.container_unknown);
        assert_eq!(agent.container_unproven_total(), 1);
        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].respond_error.as_deref(),
            Some(REFUSE_NOT_CONTAINER),
            "the record must say why the rule did not decide it"
        );
        assert!(!events[0].executed);
        assert_ne!(decision.action, Action::Kill);
        assert!(fake.killed().is_empty());
        assert_eq!(agent.respond_kill_total(), 0);
        // The publish window is ordinary: counted and named, never Degraded.
        assert!(!agent.is_degraded());
    }

    /// The half that keeps the reason from becoming the permanent false stream
    /// `containerOnly` was added to stop: once a scan that resolved after the
    /// cgroup was first seen has landed and it is still not a pod, it is not
    /// one. The node's own containerd settles there and stays silent.
    #[test]
    fn a_host_cgroup_proven_by_a_later_scan_is_silent() {
        const CGROUP_HOST: u64 = 9_909;
        let (agent, _fake) = respond_agent_with_fake();
        agent.set_attached(true);
        agent.set_container_map_synced(1);
        let sink = MemorySink::new();
        let meta = EventMeta {
            cgroup_id: CGROUP_HOST,
            pid: 4242,
            tgid: 4242,
            in_container: false,
            agent_self: false,
            path_truncated: false,
        };
        let shell = ev("execve", "sh", "/bin/sh", false, false);

        // First sighting: nothing has been resolved since, so it is unproven.
        agent.handle_event(meta, &shell, &sink);
        assert_eq!(agent.container_unproven_total(), 1);

        // A scan resolves after that sighting and still does not know the
        // cgroup. Every record from it after that is a host process.
        agent.set_container_map_synced(1);
        for _ in 0..64 {
            agent.handle_event(meta, &shell, &sink);
        }
        assert_eq!(
            agent.container_unproven_total(),
            1,
            "a proven host cgroup must not keep producing refused kills"
        );
        let events = sink.events();
        assert_eq!(
            events[events.len() - 1].respond_error,
            None,
            "and it must not keep producing reasons either"
        );
        assert!(!agent.is_degraded());
    }

    /// With no live publisher nothing will ever resolve, so every host process
    /// would be unprovable forever. The node is already Degraded on the map
    /// itself; it must not also turn its own runtime into a stream of refused
    /// kills.
    #[test]
    fn without_a_synced_container_map_nothing_is_unproven() {
        const CGROUP_HOST: u64 = 7_707;
        let (agent, _fake) = respond_agent_with_fake();
        agent.set_attached(true);
        let sink = MemorySink::new();
        let meta = EventMeta {
            cgroup_id: CGROUP_HOST,
            pid: 4242,
            tgid: 4242,
            in_container: false,
            agent_self: false,
            path_truncated: false,
        };
        let decision =
            agent.handle_event(meta, &ev("execve", "sh", "/bin/sh", false, false), &sink);
        assert!(!decision.container_unknown);
        assert_eq!(agent.container_unproven_total(), 0);
        assert_eq!(sink.events()[0].respond_error, None);
        // Degraded for the reason that is true: the map is not usable.
        assert!(!agent.container_map_ready());
        assert!(agent.is_degraded());
    }

    /// The known-pod half of the same window: the index resolves the cgroup and
    /// the datapath did not flag it, so the caller is not merely unproven, it
    /// is a container. Still not killed - and still not silent.
    #[test]
    fn a_container_only_rule_skipped_on_a_known_pod_is_reported() {
        let (agent, fake) = respond_agent_with_fake();
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
        let decision =
            agent.handle_event(meta, &ev("execve", "sh", "/bin/sh", false, false), &sink);
        assert!(decision.container_unknown);
        assert_eq!(agent.container_unproven_total(), 1);
        assert_eq!(
            sink.events()[0].respond_error.as_deref(),
            Some(REFUSE_NOT_CONTAINER)
        );
        // Carried as a field, not only as a reason string: the node counter is
        // an aggregate, so a collector reading this one record has nothing to
        // filter or group on unless the flag rides along with it.
        assert!(sink.events()[0].container_unknown);
        assert_ne!(decision.action, Action::Kill);
        assert!(fake.killed().is_empty());
    }

    /// The signal must name only the records whose outcome would have differed.
    /// A `containerOnly` rule skipped under a decision that already outranks it
    /// changed nothing, and reporting it would be noise on every record.
    #[test]
    fn a_skipped_rule_that_would_not_have_changed_the_outcome_is_not_reported() {
        const CGROUP_NEW: u64 = 8_809;
        let (agent, _fake) = respond_agent_with_fake();
        agent.set_attached(true);
        agent.set_container_map_synced(1);
        let sink = MemorySink::new();
        let meta = EventMeta {
            cgroup_id: CGROUP_NEW,
            pid: 4242,
            tgid: 4242,
            in_container: false,
            agent_self: false,
            path_truncated: false,
        };
        // `no-module` (deny, no containerOnly) decides this record; `no-shell`
        // is not in play at all, and nothing was skipped that mattered.
        let decision = agent.handle_event(meta, &ev("bpf", "curl", "", false, false), &sink);
        assert_eq!(decision.action, Action::Deny);
        assert!(!decision.container_unknown);
        assert!(!sink.events()[0].container_unknown);
        assert_eq!(agent.container_unproven_total(), 0);
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

    /// A loaded, attached agent with a synced container map and nothing wrong
    /// with it: the baseline every degradation test starts from.
    fn healthy_agent() -> Agent {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.set_attached(true);
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_container_map_synced(1);
        assert!(!agent.is_degraded());
        agent
    }

    /// A record that failed to decode carried a syscall no rule ever saw —
    /// the same loss as an in-kernel ring drop, on the other side of the ring.
    /// It degrades on the same terms, and recovers on them too.
    #[test]
    fn malformed_records_degrade_and_then_recover() {
        let agent = healthy_agent();
        let t0 = Instant::now();

        assert_eq!(
            pump_records(
                &agent,
                ferrum_ebpf::SyscallArch::X86_64,
                [vec![0u8; 3]],
                &MemorySink::new()
            )
            .decode_failed,
            1
        );
        assert!(agent.records_decode_failed_total() >= 1);
        // The pump routes EVERY decode error here, whatever its kind — a short
        // record, and equally an ABI stamp the decoder rejects as Integrity.
        // A mismatched datapath ELF fails every record, so the node degrades
        // rather than counting quietly.
        assert!(agent.decode_failures_recent());

        agent.record_decode_failure_at(4, t0);
        assert_eq!(agent.records_decode_failed_total(), 5);
        assert!(agent.decode_failures_recent_at(t0 + MARGIN));
        assert!(agent.is_degraded(), "a record no rule saw is a lost event");

        // The source stops emitting garbage: the signal decays, unlike a latch
        // that only a restart clears.
        assert!(!agent.decode_failures_recent_at(t0 + DEGRADED_RECOVERY));
    }

    /// Nothing decodes ring records any more. The reader keeps draining so the
    /// kernel does not stall, but every record it takes out is discarded, and
    /// no restart of anything in this process brings the pump back: latched.
    #[test]
    fn a_disconnected_record_channel_latches() {
        let shared = std::sync::RwLock::new(healthy_agent());
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
        assert!(publish_record(&shared, &tx, vec![1, 2, 3]));
        {
            let agent = shared.read().expect("read");
            assert!(agent.terminal_fault().is_none());
            assert!(!agent.is_degraded());
        }

        drop(rx);
        assert!(!publish_record(&shared, &tx, vec![4, 5, 6]));
        let agent = shared.read().expect("read");
        assert_eq!(agent.terminal_fault().as_deref(), Some(RECORD_CHANNEL_GONE));
        // No window to wait out, unlike the decaying signals: nothing in this
        // process respawns the pump, so the reason stays put.
        assert!(agent.is_degraded());
        assert!(!agent.decode_failures_recent_at(Instant::now() + DEGRADED_RECOVERY));
        assert!(agent.terminal_fault().is_some());
    }

    /// The ring thread blocks in `send` whenever the record channel is full -
    /// that is the backpressure, and it must stay. What must never happen is
    /// blocking there while holding a lock on the shared `Agent`: the bundle
    /// poller takes `write()` once per reload interval, a queued writer stops
    /// `RwLock` handing out further read guards, the pump thread then cannot
    /// take its own read guard to drain, so the channel never empties and the
    /// send never returns. Ring, poller and pump park forever, no record is
    /// decoded, no rule runs, no kill happens and no envelope ever says so.
    ///
    /// The probe is the poller's side of that: while the ring thread is parked
    /// inside a full-channel `send`, an exclusive lock must stay available.
    /// Every attempt must succeed, not merely one - a single success could be
    /// won before the ring thread reached the send at all.
    #[test]
    fn a_blocked_record_send_holds_no_lock_on_the_agent() {
        let shared = std::sync::Arc::new(std::sync::RwLock::new(healthy_agent()));
        // Capacity 1, primed: the ring thread's send below can only block,
        // exactly as a full 16k channel behind a slow sink does.
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
        tx.send(vec![0]).expect("prime the channel full");

        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let ring_agent = std::sync::Arc::clone(&shared);
        let ring = std::thread::spawn(move || {
            started_tx.send(()).expect("signal");
            publish_record(&ring_agent, &tx, vec![1, 2, 3])
        });
        started_rx.recv().expect("ring thread running");

        let mut refused = 0u32;
        for _ in 0..20_000 {
            match shared.try_write() {
                Ok(guard) => drop(guard),
                Err(_) => refused += 1,
            }
            std::thread::yield_now();
        }
        assert_eq!(
            refused, 0,
            "a lock on the shared agent was held across a blocking send: the \
             bundle poller cannot reload and the pump cannot drain"
        );

        // The backpressure itself is intact: the send did block, and it
        // completes as soon as the pump takes a record off the channel.
        assert_eq!(rx.recv().expect("primed record"), vec![0]);
        assert_eq!(rx.recv().expect("blocked record"), vec![1, 2, 3]);
        assert!(ring.join().expect("ring thread"), "the channel is alive");
        assert!(shared.read().expect("read").terminal_fault().is_none());
    }

    /// A kill that really happened and was never written down is the
    /// repudiation case: a full export queue or a full `/var/log/ferrum` must
    /// not leave the node reporting healthy. Bursty, so it decays.
    #[test]
    fn a_lossy_export_degrades_and_then_recovers() {
        #[derive(Default)]
        struct LossySink {
            queue_dropped: AtomicU64,
            write_failed: AtomicU64,
        }
        impl EventSink for LossySink {
            fn emit(&self, _event: &EnforcementEvent) {}
            fn export_queue_dropped_total(&self) -> u64 {
                self.queue_dropped.load(Ordering::Relaxed)
            }
            fn export_write_failed_total(&self) -> u64 {
                self.write_failed.load(Ordering::Relaxed)
            }
        }

        let agent = healthy_agent();
        let sink = LossySink::default();
        let t0 = Instant::now();

        // A quiet export proves nothing is wrong and nothing is latched.
        agent.note_export_state_at(&sink, t0);
        assert!(!agent.is_degraded());

        sink.queue_dropped.store(3, Ordering::Relaxed);
        agent.note_export_state_at(&sink, t0);
        assert_eq!(agent.export_lost_total(), 3);
        assert!(agent.export_lossy_recent_at(t0 + MARGIN));
        assert!(agent.is_degraded(), "unrecorded enforcement is Degraded");

        // The burst ends; the totals stand still and the signal decays. A
        // latch here would pin the node Degraded for the process lifetime.
        agent.note_export_state_at(&sink, t0 + DEGRADED_RECOVERY);
        assert!(!agent.export_lossy_recent_at(t0 + DEGRADED_RECOVERY));

        // A failed write counts the same: accepted and never written down.
        sink.write_failed.store(1, Ordering::Relaxed);
        let t1 = t0 + DEGRADED_RECOVERY;
        agent.note_export_state_at(&sink, t1);
        assert_eq!(agent.export_lost_total(), 4);
        assert!(agent.export_lossy_recent_at(t1 + MARGIN));

        // The event path reads it too, not just a direct caller.
        let t2 = t1 + DEGRADED_RECOVERY * 2;
        assert!(!agent.export_lossy_recent_at(t2));
        sink.queue_dropped.store(9, Ordering::Relaxed);
        agent.handle_event(
            container_meta(4242),
            &ev("execve", "sh", "/bin/sh", true, false),
            &sink,
        );
        assert!(agent.export_lossy_recent());
        assert!(agent.is_degraded());
    }

    /// Observe demotes Kill to Audit, which is the sanctioned default — but
    /// the exported event must still say the policy asked for a kill and this
    /// role does not kill, instead of being byte-identical to a rule that
    /// really did say audit.
    #[test]
    fn a_kill_rule_under_observe_exports_the_role_refusal() {
        let agent = healthy_agent();
        assert_eq!(agent.role(), AgentRole::Observe);
        let sink = MemorySink::new();
        let decision = agent.handle_event(
            container_meta(4242),
            &ev("execve", "sh", "/bin/sh", true, false),
            &sink,
        );
        assert_eq!(decision.action, Action::Audit);
        let event = &sink.events()[0];
        assert_eq!(event.action, "audit");
        assert!(!event.executed);
        assert_eq!(event.respond_error.as_deref(), Some(REFUSE_ROLE));
        assert_eq!(agent.respond_kill_total(), 0);
        // The export says REFUSE_ROLE; the refusal counter does not move. On
        // the shipped default every shell exec on the node lands here, and
        // "reactions we refused" would then count "kill rules that matched" —
        // an alert built on it would fire on a node doing exactly its job.
        assert_eq!(agent.respond_refused_total(), 0);
        assert_eq!(agent.respond_role_skipped_total(), 1);
        // Demoting is not a fault: observe is the shipped default.
        assert!(!agent.is_degraded());

        // A rule that genuinely says audit is still distinguishable: no
        // reaction was refused, because none was ever asked for.
        let quiet = healthy_agent();
        let quiet_sink = MemorySink::new();
        quiet.handle_event(
            container_meta(4242),
            &ev("openat", "cat", "/etc/passwd", true, false),
            &quiet_sink,
        );
        let quiet_event = &quiet_sink.events()[0];
        assert_ne!(quiet_event.action, "kill");
        assert_eq!(quiet_event.respond_error, None);
        assert_eq!(quiet.respond_role_skipped_total(), 0);

        // Under respond the same guards are real refusals again: this one is
        // an agent-self event, which respond declines to kill.
        let (responder, fake) = respond_agent_with_fake();
        let mut meta = container_meta(4242);
        meta.agent_self = true;
        responder.handle_event(
            meta,
            &ev("execve", "sh", "/bin/sh", true, true),
            &MemorySink::new(),
        );
        assert!(fake.killed().is_empty());
        assert_eq!(responder.respond_refused_total(), 1);
        assert_eq!(responder.respond_role_skipped_total(), 0);
    }

    /// Outside the initial pid namespace the datapath's tgids name other
    /// processes: publishing this process's pid as `ferrum_self` would exempt
    /// whoever holds that number and aim every notAgentSelf rule at the agent.
    #[test]
    fn a_namespaced_pid_is_not_published_as_the_agent_self() {
        let dir = temp_dir("selfns");
        let host = dir.join("host-pid");
        std::os::unix::fs::symlink(format!("pid:[{HOST_PID_NS_INO}]"), &host).expect("symlink");
        let other = dir.join("other-pid");
        std::os::unix::fs::symlink("pid:[4026533333]", &other).expect("symlink");

        let agent = healthy_agent();
        assert_eq!(self_tgid_to_publish_at(&agent, &host, 1234), Some(1234));
        assert!(!agent.self_tgid_unpublished());
        assert!(!agent.is_degraded());

        // Refusing to publish is the invariant and does not depend on the
        // role. What the refusal *costs* does.
        let elsewhere = healthy_agent();
        assert_eq!(self_tgid_to_publish_at(&elsewhere, &other, 1234), None);
        assert!(elsewhere.self_tgid_unpublished());
        // Not a terminal fault: it would outrank and hide every recoverable
        // signal for the lifetime of a perfectly healthy observe process.
        assert!(elsewhere.terminal_fault().is_none());
        assert!(
            !elsewhere.is_degraded(),
            "observe without hostPID is the shipped install, not a fault"
        );

        // Respond is the case where a wrong agent-self identity means a wrong
        // kill target, so there it is Degraded.
        let mut responder = healthy_agent();
        responder.set_role(AgentRole::Respond);
        assert_eq!(self_tgid_to_publish_at(&responder, &other, 1234), None);
        assert!(responder.self_tgid_unpublished());
        assert!(responder.is_degraded());

        // An unreadable link is the same answer: never guess an identity the
        // datapath will act on.
        let missing = healthy_agent();
        assert_eq!(
            self_tgid_to_publish_at(&missing, &dir.join("absent"), 1234),
            None
        );
        assert!(missing.self_tgid_unpublished());
        assert!(!missing.is_degraded());
        let _ = fs::remove_dir_all(&dir);
    }

    /// The base install, not the function. `deploy/agent/daemonset.yaml` runs
    /// `--role observe` and has no `hostPID` - and cannot get one:
    /// `lint-deploy` raises UNNEEDED_HOST_PID for `hostPID: true` without
    /// `--role respond`, and that gate is in CI. So every node running the
    /// manifests we ship refuses to publish `ferrum_self`. If that were a
    /// fault, the fleet would report Degraded from second one for doing
    /// exactly what it was told, and the real signals - ring drops, label
    /// misses, export loss, last-known-good - would arrive on a node already
    /// crying wolf.
    #[test]
    fn the_shipped_observe_install_is_not_degraded_without_host_pid() {
        let manifest = include_str!("../../../deploy/agent/daemonset.yaml");
        let ds: serde_yaml::Value = serde_yaml::from_str(manifest).expect("daemonset yaml");
        let pod = &ds["spec"]["template"]["spec"];
        assert!(
            pod.get("hostPID").is_none(),
            "the shipped install has no hostPID and the linter forbids adding one"
        );

        let args: Vec<String> = pod["containers"][0]["args"]
            .as_sequence()
            .expect("args")
            .iter()
            .map(|a| a.as_str().expect("arg").to_string())
            .collect();
        let role_flag = args
            .iter()
            .position(|a| a == "--role")
            .and_then(|i| args.get(i + 1))
            .expect("--role in the shipped args");
        let role = AgentRole::parse_name(role_flag).expect("role name");
        assert_eq!(role, AgentRole::Observe);

        let mut agent = healthy_agent();
        agent.set_role(role);
        // What the process does on that node, second one: no host pid
        // namespace, so nothing is published as `ferrum_self`.
        assert_eq!(
            self_tgid_to_publish_at(&agent, Path::new("/proc/self/ns/pid-absent"), 1234),
            None
        );
        assert!(agent.self_tgid_unpublished());
        assert!(agent.terminal_fault().is_none());
        assert!(
            !agent.is_degraded(),
            "the shipped, linter-blessed install must not report Degraded"
        );
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrum-agent-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("tmpdir");
        dir
    }

    /// A5. The digest is what joins a runtime kill to a supply-chain finding
    /// about the same image, and it was hardcoded `None` on every record the
    /// agent ever wrote.
    #[test]
    fn the_record_carries_the_image_digest_the_index_resolved() {
        let mut agent = Agent::new(cfg());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.set_attached(true);
        agent.insert_cgroup(7, pci_identity());
        agent.set_container_map_synced(1);

        let sink = MemorySink::new();
        agent.handle_event(7, &ev("execve", "sh", "/bin/sh", true, false), &sink);
        let event = &sink.events()[0];
        assert_eq!(
            event.image_digest.as_ref().map(Digest::as_str),
            Some("sha256:abc"),
            "the pod watch resolved a digest and the record must carry it"
        );

        // An index entry with no digest stays absent, not empty: "unknown" and
        // "the empty digest" are different answers.
        agent.insert_cgroup(8, identity("pod-b"));
        agent.handle_event(8, &ev("execve", "sh", "/bin/sh", true, false), &sink);
        assert_eq!(sink.events()[1].image_digest, None);
    }

    /// A7. The window map keeps the entries that make an answer "proven": a
    /// settled host cgroup evicted and reopened at `now` is unproven again,
    /// and on a node past `CONTAINER_FLAG_TRACKED_MAX` that repeats forever —
    /// kubelet, containerd and sshd flipping back to REFUSE_NOT_CONTAINER
    /// every couple of seconds with `is_degraded()` false throughout.
    #[test]
    fn a_settled_host_cgroup_survives_a_flood_of_unproven_cgroups() {
        const HOST: u64 = 42;
        let agent = healthy_agent();
        let base = Instant::now();
        agent.set_container_map_synced_at(1, base);

        // First question about the host cgroup: nothing has scanned since, so
        // the honest answer is "unproven".
        assert!(agent.container_unproven(HOST, base));
        // A scan that resolved after the question settles it: not a container,
        // and not one for as long as the entry lives.
        agent.set_container_map_synced_at(1, base + Duration::from_secs(1));
        assert!(!agent.container_unproven(HOST, base + Duration::from_secs(2)));

        // A node whose distinct unresolved-cgroup count crosses the bound,
        // long enough after the host entry opened that an eviction by age
        // would take it.
        let late = base + Duration::from_secs(10);
        agent.set_container_map_synced_at(1, base + Duration::from_secs(9));
        for cgroup in 0..(CONTAINER_FLAG_TRACKED_MAX as u64 + 64) {
            assert!(agent.container_unproven(1_000 + cgroup, late));
        }

        assert!(
            !agent.container_unproven(HOST, late + Duration::from_secs(1)),
            "an old entry here is a settled host cgroup, not a stale one"
        );
        assert!(agent.unproven_window_len() <= CONTAINER_FLAG_TRACKED_MAX);
    }

    /// The bound holds even when every entry is proven and none can be given
    /// up for free.
    #[test]
    fn the_unproven_window_stays_bounded_when_every_entry_is_proven() {
        let agent = healthy_agent();
        let base = Instant::now();
        agent.set_container_map_synced_at(1, base);
        for cgroup in 0..(CONTAINER_FLAG_TRACKED_MAX as u64 * 2) {
            // Each entry opens, then a later sync settles it before the next.
            agent.container_unproven(cgroup, base + Duration::from_millis(cgroup));
            agent.set_container_map_synced_at(1, base + Duration::from_millis(cgroup + 1));
        }
        assert!(agent.unproven_window_len() <= CONTAINER_FLAG_TRACKED_MAX);
    }

    /// A8. Waivers that name another policy are signed, verified, in scope,
    /// counted, logged as reloaded — and apply to nothing. The join cannot be
    /// proven here (the FRMB carries no policy name), so it is stated.
    #[test]
    fn waivers_that_name_another_policy_are_reported_not_silently_ignored() {
        let mut agent = Agent::new(cfg_respond_named("prod-restricted"));
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.set_attached(true);
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_container_map_synced(1);
        assert!(!agent.is_degraded());

        agent.set_exceptions(vec![waiver("ns", "prod-restricted", &["no-runtime-sock"])]);
        assert_eq!(agent.waivers_unjoined(), None);
        assert_eq!(agent.waivers_unjoined_total(), 0);
        assert!(!agent.is_degraded());

        // The policy was renamed, or a second one runs on this node: the
        // waiver still loads, and now waives nothing.
        agent.set_exceptions(vec![waiver("ns", "prod-strict", &["no-runtime-sock"])]);
        let reason = agent.waivers_unjoined().expect("unjoined waivers");
        assert!(reason.contains(WAIVERS_UNJOINED), "{reason}");
        assert!(reason.contains("prod-restricted"), "{reason}");
        assert!(reason.contains("prod-strict"), "{reason}");
        assert_eq!(agent.waivers_unjoined_total(), 1);
        assert!(agent.is_degraded());
        assert!(agent
            .degraded_reasons_at(Instant::now())
            .iter()
            .any(|r| r.contains(WAIVERS_UNJOINED)));

        // The kill the waiver would have demoted still fires, which is why
        // this has to be said out loud.
        let sink = MemorySink::new();
        let d = agent.handle_event_at(
            7,
            &ev("openat", "app", "/var/run/docker.sock", true, false),
            &sink,
            fixed_now(),
        );
        assert_eq!(d.action, Action::Kill);
    }

    /// An empty `--policy-name` is the same defect with no rename involved:
    /// `waiver_applies` returns None on the first line.
    #[test]
    fn an_agent_with_no_policy_name_says_its_waivers_can_never_apply() {
        let mut agent = Agent::new(cfg());
        agent.set_exceptions(vec![waiver("ns", "prod-restricted", &["no-runtime-sock"])]);
        let reason = agent.waivers_unjoined().expect("unjoined waivers");
        assert!(reason.contains("--policy-name"), "{reason}");
        assert_eq!(agent.waivers_unjoined_total(), 1);
    }

    /// A9, the counter half: after the export writer dies every further event
    /// is counted as a writer loss and nowhere else. Leaving that counter out
    /// froze `export_lost_total` at the moment it mattered most.
    #[test]
    fn a_dead_writer_keeps_moving_the_export_loss_counter() {
        struct DeadWriter {
            lost: AtomicU64,
        }
        impl EventSink for DeadWriter {
            fn emit(&self, _event: &EnforcementEvent) {
                self.lost.fetch_add(1, Ordering::Relaxed);
            }
            fn export_writer_lost_total(&self) -> u64 {
                self.lost.load(Ordering::Relaxed)
            }
            fn export_writer_dead(&self) -> bool {
                self.lost.load(Ordering::Relaxed) > 0
            }
        }

        let agent = healthy_agent();
        let sink = DeadWriter {
            lost: AtomicU64::new(0),
        };
        let t0 = Instant::now();
        agent.note_export_state_at(&sink, t0);
        assert_eq!(agent.export_lost_total(), 0);

        sink.emit(&sample_event());
        sink.emit(&sample_event());
        agent.note_export_state_at(&sink, t0);
        assert_eq!(
            agent.export_lost_total(),
            2,
            "every record lost after the writer died must be counted"
        );
        assert!(agent.export_writer_dead());
        assert!(agent.export_lossy_recent_at(t0));
    }

    fn sample_event() -> EnforcementEvent {
        EnforcementEvent {
            policy: PolicyId::new("p"),
            rule: RuleId::new("r"),
            action: "kill".into(),
            image_digest: None,
            pod: "web".into(),
            namespace: "ns".into(),
            comm: "sh".into(),
            syscall: "execve".into(),
            pid: 1,
            tgid: 1,
            executed: false,
            respond_error: None,
            labels_unknown: false,
            path_unknown: false,
            container_unknown: false,
            waiver: None,
        }
    }

    /// A9. Eight cycles of counters had exactly one consumer: a bool on each
    /// envelope. This is the reader — a file beside the events, written whole
    /// or not at all, plus one line per transition. It reports; it never acts.
    #[test]
    fn the_poll_tick_publishes_a_whole_status_file_and_logs_transitions() {
        let dir = temp_dir("status");
        let agent = healthy_agent();
        let sink = MemorySink::new();
        let ctx = ferrum_export::SinkContext::new("node-1", "observe");
        let out = StatusOutput {
            ctx: Some(&ctx),
            sink: Some(&sink),
            status_dir: Some(&dir),
        };
        let mut publisher = StatusPublisher::default();

        let first = publisher.publish(&agent, &out);
        assert!(!first.degraded);
        let line = first.transition.expect("the first tick names the state");
        assert!(line.contains("\"degraded\":false"), "{line}");

        let raw = fs::read_to_string(dir.join(STATUS_NAME)).expect("status.json");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("whole JSON object");
        assert_eq!(value["node"], "node-1");
        assert_eq!(value["degraded"], false);
        assert_eq!(
            value["degradedReasons"].as_array().expect("reasons").len(),
            0
        );
        // The counters that had no reader at all.
        for key in [
            "respondKillTotal",
            "respondRefusedTotal",
            "respondRoleSkippedTotal",
            "respondFailedTotal",
            "respondStaleTargetTotal",
            "exportLostTotal",
            "exportWriterLostTotal",
            "containerFlagDisagreementTotal",
            "containerUnprovenTotal",
            "labelsUnknownTotal",
            "identityUnknownTotal",
            "eventsDroppedTotal",
            "recordsDecodeFailedTotal",
            "decodeFailureRun",
            "datapathAbiMismatchTotal",
            "unknownSyscallTotal",
            "pathTruncatedTotal",
            "exceptionsReloadFailedTotal",
            "lkgRulesDroppedTotal",
            "clockRollbackTotal",
            "waiversUnjoinedTotal",
        ] {
            assert!(value[key].is_u64(), "status.json carries no {key}");
        }

        // A steady state is not a transition: only a change gets a line.
        assert!(publisher.publish(&agent, &out).transition.is_none());

        agent.record_drop_at(3, Instant::now());
        let degraded = publisher.publish(&agent, &out);
        assert!(degraded.degraded);
        let line = degraded.transition.expect("entering Degraded is a line");
        assert!(line.contains(DEG_RING_DROPS), "{line}");
        let raw = fs::read_to_string(dir.join(STATUS_NAME)).expect("status.json");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("whole JSON object");
        assert_eq!(value["degraded"], true);
        assert_eq!(value["eventsDroppedTotal"], 3);
        assert!(value["degradedReasons"]
            .as_array()
            .expect("reasons")
            .iter()
            .any(|r| r == DEG_RING_DROPS));
        // Nothing is left behind for a reader to trip over.
        assert!(!dir.join(STATUS_TMP_NAME).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// The timer is the second caller of `note_export_state_at`: a node that
    /// stops receiving events must not stop noticing that its exports are
    /// being lost.
    #[test]
    fn the_status_tick_reads_export_losses_with_no_events_at_all() {
        let dir = temp_dir("status-export");
        let agent = healthy_agent();
        let sink = MemorySink::new();
        sink.record_drop(5);
        let out = StatusOutput {
            ctx: None,
            sink: Some(&sink),
            status_dir: Some(&dir),
        };
        let state = StatusPublisher::default().publish(&agent, &out);
        assert!(state.degraded);
        assert!(state.reasons.iter().any(|r| r == DEG_EXPORT_LOSSY));
        assert_eq!(agent.export_lost_total(), 5);
        let raw = fs::read_to_string(dir.join(STATUS_NAME)).expect("status.json");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("JSON");
        assert_eq!(value["exportWriteFailedTotal"], 5);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Written whole or not at all: the publish is a rename inside the same
    /// directory, so a reader never sees a partial file and a crash mid-write
    /// cannot truncate the published one.
    #[test]
    fn status_is_published_by_rename_over_a_complete_previous_file() {
        let dir = temp_dir("status-atomic");
        let agent = healthy_agent();
        let out = StatusOutput {
            ctx: None,
            sink: None,
            status_dir: Some(&dir),
        };
        let mut publisher = StatusPublisher::default();
        publisher.publish(&agent, &out);
        let first = fs::read_to_string(dir.join(STATUS_NAME)).expect("status.json");

        // A leftover temp file from a crashed write is overwritten, never
        // appended to, and never becomes the published file by itself.
        fs::write(dir.join(STATUS_TMP_NAME), b"{\"truncated\":").expect("write tmp");
        agent.record_drop_at(1, Instant::now());
        publisher.publish(&agent, &out);
        let second = fs::read_to_string(dir.join(STATUS_NAME)).expect("status.json");
        assert_ne!(first, second);
        serde_json::from_str::<serde_json::Value>(&second).expect("whole JSON object");
        assert!(!dir.join(STATUS_TMP_NAME).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A directory that cannot be written is said once, not once a tick, and
    /// never stops the agent: the surface reports, it does not act. But it is
    /// not silent either — the failure is a degraded reason from the tick
    /// after it, because the file that would have carried it is the file that
    /// could not be written.
    #[test]
    fn an_unwritable_status_dir_does_not_stop_the_tick() {
        let agent = healthy_agent();
        let out = StatusOutput {
            ctx: None,
            sink: None,
            status_dir: Some(Path::new("/proc/ferrum-does-not-exist")),
        };
        let mut publisher = StatusPublisher::default();
        // The first tick's state was computed before its own write failed.
        assert!(!publisher.publish(&agent, &out).degraded);
        let second = publisher.publish(&agent, &out);
        assert!(second.degraded, "a state surface that is down is Degraded");
        assert!(second.reasons.iter().any(|r| r == DEG_STATUS_UNWRITABLE));
        // And the tick keeps running: a status file that stalls the poll loop
        // would be worse than one that lies.
        assert!(publisher.publish(&agent, &out).degraded);
        assert_eq!(agent.status_write_failed_total(), 3);
    }

    /// B3. The previous tick's file is byte-identical and says
    /// `"degraded": false`. The commonest reason a write into --export-dir
    /// fails is the export directory filling up, which is the same condition
    /// that fails every event write — so the moment this reader matters most
    /// is the moment it would freeze on its last healthy answer. It is
    /// removed instead: absence is unambiguous, a frozen `ts` is not.
    #[test]
    fn a_failed_status_write_removes_the_file_rather_than_leave_it_lying() {
        let dir = temp_dir("status-stale");
        let agent = healthy_agent();
        let out = StatusOutput {
            ctx: None,
            sink: None,
            status_dir: Some(&dir),
        };
        let mut publisher = StatusPublisher::default();
        assert!(!publisher.publish(&agent, &out).degraded);
        let healthy = fs::read_to_string(dir.join(STATUS_NAME)).expect("status.json");
        assert!(healthy.contains("\"degraded\":false"));

        // Whatever the cause on the node — ENOSPC, a read-only remount, a
        // vanished mount — the tick cannot lay down its temp file.
        fs::create_dir(dir.join(STATUS_TMP_NAME)).expect("block the temp name");
        let blocked = publisher.publish(&agent, &out);
        assert!(
            !dir.join(STATUS_NAME).exists(),
            "a file that cannot be refreshed must not stay behind claiming {blocked:?}",
        );
        assert!(agent.status_write_failed());

        // Recovered: the file comes back, and it carries the count of the
        // publishes that failed, which is how a reader learns the surface was
        // down at all once it is up again.
        fs::remove_dir(dir.join(STATUS_TMP_NAME)).expect("unblock");
        let back = publisher.publish(&agent, &out);
        assert!(back.reasons.iter().any(|r| r == DEG_STATUS_UNWRITABLE));
        let raw = fs::read_to_string(dir.join(STATUS_NAME)).expect("status.json is back");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("whole JSON object");
        assert_eq!(value["statusWriteFailed"], true);
        assert_eq!(value["statusWriteFailedTotal"], 1);
        assert!(!publisher.publish(&agent, &out).degraded);
        let _ = fs::remove_dir_all(&dir);
    }

    /// B2. The write is off the lock. `poll_bundle_shared` takes the agent's
    /// write lock every reload tick, `RwLock` is write-preferring, and the
    /// ring-drain and pump threads need a read guard to make progress: an
    /// `fsync` on a hostPath under IO pressure inside that window stalls the
    /// drain, `ferrum_events` fills, and the kernel drops records no rule ever
    /// sees. The reporting surface may not cost enforcement.
    ///
    /// What this proves: `commit` completes while another thread holds the
    /// write lock on the shared agent — so it takes no guard on it, and no
    /// caller can hold one through it, since `commit` cannot reach an `Agent`
    /// at all. What it does not prove: anything about how long an `fsync`
    /// takes, which is the property that makes the discipline matter.
    #[test]
    fn the_status_write_holds_no_lock_on_the_shared_agent() {
        let dir = temp_dir("status-lock");
        let agent = std::sync::Arc::new(std::sync::RwLock::new(healthy_agent()));
        let mut publisher = StatusPublisher::default();
        let tick = {
            let guard = agent.read().unwrap_or_else(|e| e.into_inner());
            let out = StatusOutput {
                ctx: None,
                sink: None,
                status_dir: Some(&dir),
            };
            publisher.tick(&guard, &out)
        };

        // Exactly what the poll loop used to hold across the write.
        let held = agent.write().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = std::sync::mpsc::channel();
        let writer_dir = dir.clone();
        std::thread::spawn(move || {
            let out = StatusOutput {
                ctx: None,
                sink: None,
                status_dir: Some(&writer_dir),
            };
            let ok = StatusPublisher::default().commit(&tick, &out);
            let _ = tx.send(ok);
        });
        let published = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the status write must not wait on the agent lock");
        assert!(published);
        drop(held);

        let raw = fs::read_to_string(dir.join(STATUS_NAME)).expect("status.json");
        serde_json::from_str::<serde_json::Value>(&raw).expect("whole JSON object");
        let _ = fs::remove_dir_all(&dir);
    }

    /// F8. Without --export-dir there is no file, and before this the
    /// counters had no reader at all in that configuration. The whole object
    /// goes to stderr on each state change instead — bounded by the changes,
    /// not by the tick rate.
    #[test]
    fn an_agent_with_no_export_dir_still_has_a_reader() {
        let agent = healthy_agent();
        let out = StatusOutput {
            ctx: None,
            sink: None,
            status_dir: None,
        };
        let mut publisher = StatusPublisher::default();
        let first = publisher.tick(&agent, &out);
        assert!(first.state.transition.is_some());
        let json = first
            .json()
            .expect("with no file, the state change carries the whole object");
        assert_eq!(json["degraded"], false);
        assert!(json["eventsDroppedTotal"].is_u64());
        assert!(
            publisher.commit(&first, &out),
            "nothing was asked for, so nothing failed"
        );
        // A steady state is not re-logged once a second.
        assert!(publisher.tick(&agent, &out).json().is_none());
    }

    /// F5. Degraded is not one state. A node that goes from ring drops to a
    /// terminal wrong-ELF fault never flips the boolean, and used to change
    /// what an operator must do about it without a single line on the log
    /// surface — the only surface left when the export directory is gone.
    #[test]
    fn a_degraded_node_that_changes_why_says_so() {
        let agent = healthy_agent();
        let t0 = Instant::now();
        assert!(agent.degraded_state_at(t0).transition.is_some());
        agent.record_drop_at(1, t0);
        let entered = agent.degraded_state_at(t0);
        assert!(entered.degraded);
        assert!(entered
            .transition
            .expect("entering")
            .contains(DEG_RING_DROPS));
        assert!(
            agent.degraded_state_at(t0).transition.is_none(),
            "the same reasons twice is not a transition"
        );

        agent.mark_terminal_fault(DATAPATH_ABI_MISMATCH);
        let worse = agent.degraded_state_at(t0);
        assert!(worse.degraded, "it was degraded before and still is");
        let line = worse
            .transition
            .expect("a new reason on an already-degraded node is a transition");
        assert!(line.contains(DATAPATH_ABI_MISMATCH), "{line}");
        assert!(line.contains(DEG_RING_DROPS), "{line}");
        assert!(agent.degraded_state_at(t0).transition.is_none());
    }

    /// F4. `note_export_state_at` has two callers — the event path and the
    /// poll tick — and under `poll_status` both hold only read guards, so
    /// they run concurrently. A `swap` let the loser write back the reading it
    /// took before the winner's, and a monotonic counter an operator computes
    /// a rate over went backwards.
    #[test]
    fn the_export_loss_mirror_never_moves_backwards() {
        struct Counted(AtomicU64);
        impl EventSink for Counted {
            fn emit(&self, _event: &EnforcementEvent) {}
            fn export_queue_dropped_total(&self) -> u64 {
                self.0.load(Ordering::Relaxed)
            }
        }

        let agent = healthy_agent();
        let t0 = Instant::now();
        let sink = Counted(AtomicU64::new(12));
        agent.note_export_state_at(&sink, t0);
        assert_eq!(agent.export_lost_total(), 12);

        // The other caller read 10 before that update and lands after it.
        sink.0.store(10, Ordering::Relaxed);
        let stale = t0 + DEGRADED_RECOVERY;
        agent.note_export_state_at(&sink, stale);
        assert_eq!(
            agent.export_lost_total(),
            12,
            "the sink's counters only grow, so this mirror of them must too"
        );

        // And the next real reading is not a fresh loss just because the
        // mirror had been knocked down below it.
        sink.0.store(12, Ordering::Relaxed);
        let after = stale + Duration::from_secs(1);
        agent.note_export_state_at(&sink, after);
        assert_eq!(agent.export_lost_total(), 12);
        assert!(
            !agent.export_lossy_recent_at(after),
            "a loss that already decayed must not be re-marked by a stale reading"
        );
    }

    /// F6. The proof is about a cgroup *id*, and the kernel recycles ids.
    /// Nothing aged a proven entry out below `CONTAINER_FLAG_TRACKED_MAX`, so
    /// on a node with a handful of host cgroups it was immortal: an id that
    /// settled as a host process hours ago kept answering "not a container"
    /// for whatever holds it now, and a record from a real container left
    /// under the default action with no `container_unknown` and no
    /// `REFUSE_NOT_CONTAINER` — silence, which is worse than a refused kill.
    #[test]
    fn a_proof_that_a_cgroup_is_not_a_container_has_a_shelf_life() {
        const HOST: u64 = 42;
        let agent = healthy_agent();
        let base = Instant::now();
        agent.set_container_map_synced_at(1, base);

        assert!(agent.container_unproven(HOST, base));
        agent.set_container_map_synced_at(1, base + Duration::from_secs(1));
        assert!(!agent.container_unproven(HOST, base + Duration::from_secs(2)));

        // Long after: the map is still being synced (so the node is healthy
        // and this answer is the one that decides), but the proof is older
        // than an id is guaranteed to be.
        let later = base + UNPROVEN_PROOF_TTL + Duration::from_secs(1);
        agent.set_container_map_synced_at(1, later - Duration::from_secs(1));
        assert!(
            agent.container_unproven(HOST, later),
            "a proof this old is about whatever held the id then"
        );

        // One refresh round re-earns it, so the host processes are unproven
        // for a couple of seconds every TTL, not every couple of seconds.
        agent.set_container_map_synced_at(1, later + Duration::from_secs(1));
        assert!(!agent.container_unproven(HOST, later + Duration::from_secs(2)));
        assert!(agent.unproven_window_len() <= CONTAINER_FLAG_TRACKED_MAX);
    }

    /// F7. One live waiver used to suppress the reason for every other waiver
    /// on the node: 49 dead ones out of 50 moved a counter nobody alerts on
    /// and said nothing, while the 49 kills they were meant to demote fired.
    /// And the check was a bare name comparison, so an expired waiver counted
    /// as joined.
    #[test]
    fn one_live_waiver_does_not_excuse_the_dead_ones() {
        let mut agent = Agent::new(cfg_respond_named("prod-restricted"));
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.set_attached(true);
        agent.insert_cgroup(7, identity("pod-a"));
        agent.set_container_map_synced(1);

        let mut expired = waiver("ns", "prod-restricted", &["no-runtime-sock"]);
        expired.expires_at = fixed_now() - chrono::Days::new(1);
        agent.set_exceptions(vec![
            waiver("ns", "prod-restricted", &["no-runtime-sock"]),
            waiver("ns", "prod-strict", &["no-runtime-sock"]),
            expired,
        ]);

        assert_eq!(agent.waivers_inert_total(), 2);
        assert_eq!(
            agent.waivers_unjoined_total(),
            1,
            "the policy-name counter keeps the meaning it had"
        );
        let reason = agent
            .waivers_unjoined()
            .expect("two of these three waive nothing");
        assert!(reason.contains(WAIVERS_UNJOINED), "{reason}");
        assert!(reason.contains("2 of 3"), "{reason}");
        assert!(reason.contains("prod-strict"), "{reason}");
        assert!(reason.contains("expired"), "{reason}");
        assert!(agent.is_degraded());

        // The live one still demotes: this is a report, not a refusal.
        let sink = MemorySink::new();
        let d = agent.handle_event_at(
            7,
            &ev("openat", "app", "/var/run/docker.sock", true, false),
            &sink,
            fixed_now(),
        );
        assert_eq!(d.action, Action::Audit);
    }
}
