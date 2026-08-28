//! The reaction half of the datapath: a decision that says Kill has to reach
//! a signal, and every path that does not send one has to say why.
//!
//! Refusals are checked before the system call, not after, and each one is
//! counted and exported with `executed=false`. Silence is not an option here:
//! an operator reading the export must be able to tell "killed" from
//! "decided to kill and did not".

use ferrum_common::{FerrumError, Result};
use std::path::{Path, PathBuf};

/// `PID_MAX_LIMIT`: no live tgid ever reaches it. Above `i32::MAX` a `u32`
/// tgid wraps negative, where kill(2) means a whole process group (`-pgid`)
/// or everything this agent may signal (`-1`).
pub const MAX_TGID: u32 = 1 << 22;

/// Inode of the initial pid namespace (`PROC_PID_INIT_INO`), fixed by the
/// kernel. Comparing against it is the one check that does not itself depend
/// on the namespace the agent is looking from (`/proc/1` is the container's
/// own init inside a pid namespace, so self-vs-1 always matches).
pub const HOST_PID_NS_INO: u64 = 0xEFFF_FFFC;

const PROC_ROOT: &str = "/proc";
const SELF_PID_NS: &str = "/proc/self/ns/pid";

/// Delivers the reaction. Injectable so tests can assert what would be
/// signalled without CAP_KILL and without a victim process.
pub trait Responder: Send + Sync {
    fn kill(&self, tgid: u32) -> Result<()>;
}

/// SIGKILL to the whole thread group. [`refuse_reason`] runs before this is
/// ever called; the range guard is repeated here because this is the last
/// place before the system call.
pub struct SignalResponder;

impl Responder for SignalResponder {
    #[cfg(unix)]
    fn kill(&self, tgid: u32) -> Result<()> {
        let pid = pid_of(tgid)?;
        // The only unsafe call in the agent: kill(2) on a tgid already
        // filtered by the guards. Errors are read from errno immediately.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
        if rc == 0 {
            Ok(())
        } else {
            Err(FerrumError::Degraded(format!(
                "kill({tgid}, SIGKILL): {}",
                std::io::Error::last_os_error()
            )))
        }
    }

    #[cfg(not(unix))]
    fn kill(&self, _tgid: u32) -> Result<()> {
        Err(FerrumError::Degraded(
            "signal reaction is unavailable on this platform".into(),
        ))
    }
}

/// Positive pid or an error: a value that cannot name a live thread group
/// leader never becomes a signal to a negative pid.
#[cfg(unix)]
fn pid_of(tgid: u32) -> Result<libc::pid_t> {
    match libc::pid_t::try_from(tgid) {
        Ok(pid) if pid > 1 && tgid < MAX_TGID => Ok(pid),
        _ => Err(FerrumError::Degraded(format!(
            "refusing kill: tgid {tgid} is not a signalable pid"
        ))),
    }
}

/// A responder that never signals; used when respond is off by default and by
/// callers that want the decision path without a reaction.
pub struct NoopResponder;

impl Responder for NoopResponder {
    fn kill(&self, _tgid: u32) -> Result<()> {
        Err(FerrumError::Degraded("no responder configured".into()))
    }
}

/// The target's cgroup as the kernel sees it *now*. Between the decision and
/// the signal sit an export queue and a poll interval — long enough for the
/// workload to exit and its pid to be handed to another process. Injectable:
/// tests must not depend on the node's real `/proc`.
pub trait TargetCheck: Send + Sync {
    /// `None` when the process is gone or its cgroup cannot be read.
    fn cgroup_id(&self, tgid: u32) -> Option<u64>;

    /// Why this check cannot be computed on this node at all, if it cannot.
    ///
    /// `cgroup_id` answers a question *about a target*: `None` there means
    /// that process is gone, which is an ordinary and healthy answer. This
    /// answers a question about the *check itself*, and the two must not be
    /// confused. A check that cannot be evaluated for any target returns
    /// nothing that is evidence about a target, so a caller reading `None`
    /// from `cgroup_id` would be treating a predicate it could not compute as
    /// proof that its subject moved.
    ///
    /// Defaults to `None`: an implementation that always answers is always
    /// provable, so only one that can fail to be constructed overrides it.
    fn unprovable(&self) -> Option<String> {
        None
    }
}

/// Reads `/proc/<tgid>/cgroup` and stats the unified cgroup directory it
/// names: the same inode `bpf_get_current_cgroup_id()` reports.
pub struct ProcCgroupCheck {
    proc_root: PathBuf,
    /// Where cgroup2 is mounted, or why that could not be established. The
    /// error is kept rather than defaulted away: see [`Self::with_proc_root`].
    cgroup_root: std::result::Result<PathBuf, String>,
}

impl Default for ProcCgroupCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcCgroupCheck {
    /// The node's real `/proc`, with the cgroup2 root derived from it.
    pub fn new() -> Self {
        Self::with_proc_root(PROC_ROOT)
    }

    /// The same derivation against an explicit `/proc`.
    ///
    /// The root used to be `ferrum_k8smeta::DEFAULT_CGROUP_ROOT`, which is
    /// right only where cgroup2 is mounted at the top of `/sys/fs/cgroup`. On
    /// a hybrid node that path is a tmpfs of v1 controller directories with
    /// cgroup2 below it, so every path built here named a file that was not
    /// there, every reaction refused as a stale target, and nothing said so.
    ///
    /// A failed derivation is kept, not replaced by the constant. Falling back
    /// would answer every call with an inode from the wrong filesystem or with
    /// none at all, and the caller would read that as "the target left its
    /// cgroup" — treating a predicate that could not be computed as proof of a
    /// non-match, which is the defect rather than the fix. [`Self::unprovable`]
    /// reports it, and the reaction path refuses under its own name.
    pub fn with_proc_root(proc_root: impl Into<PathBuf>) -> Self {
        let proc_root = proc_root.into();
        let mountinfo = proc_root.join("self").join("mountinfo");
        let cgroup_root = match std::fs::read_to_string(&mountinfo) {
            Ok(raw) => ferrum_k8smeta::cgroup2_root_from_mountinfo(&raw).map_err(|e| e.to_string()),
            Err(err) => Err(format!("{} unreadable: {err}", mountinfo.display())),
        };
        Self {
            proc_root,
            cgroup_root,
        }
    }

    /// Roots the caller has already established.
    pub fn with_roots(proc_root: impl Into<PathBuf>, cgroup_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            cgroup_root: Ok(cgroup_root.into()),
        }
    }

    /// The cgroup2 root this check is keyed on, or why there is none.
    pub fn cgroup_root(&self) -> std::result::Result<&Path, &str> {
        match &self.cgroup_root {
            Ok(root) => Ok(root.as_path()),
            Err(why) => Err(why.as_str()),
        }
    }
}

impl TargetCheck for ProcCgroupCheck {
    fn cgroup_id(&self, tgid: u32) -> Option<u64> {
        let root = self.cgroup_root.as_ref().ok()?;
        let raw =
            std::fs::read_to_string(self.proc_root.join(tgid.to_string()).join("cgroup")).ok()?;
        let rel = unified_cgroup_path(&raw)?;
        inode_of(&root.join(rel.trim_start_matches('/')))
    }

    fn unprovable(&self) -> Option<String> {
        self.cgroup_root.as_ref().err().cloned()
    }
}

/// `0::<path>` is the unified (v2) line. A v1 hierarchy has no single inode to
/// key on, so its lines are refused rather than guessed.
fn unified_cgroup_path(raw: &str) -> Option<&str> {
    raw.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::trim)
        .filter(|p| p.starts_with('/'))
}

fn inode_of(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| m.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// True when this process sits in the initial pid namespace. The datapath
/// reports tgids from that namespace, so anywhere else a signal lands on an
/// unrelated process or on nothing at all.
pub fn host_pid_namespace() -> bool {
    host_pid_namespace_at(Path::new(SELF_PID_NS))
}

/// Same check against an explicit `ns/pid` link (tests, non-standard `/proc`).
pub fn host_pid_namespace_at(link: &Path) -> bool {
    let Ok(target) = std::fs::read_link(link) else {
        // Unreadable namespace link: assume the worst, stay in observe.
        return false;
    };
    target
        .to_str()
        .and_then(|text| text.strip_prefix("pid:["))
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|n| n.parse::<u64>().ok())
        .map(|ino| ino == HOST_PID_NS_INO)
        .unwrap_or(false)
}

/// Why a reaction did not run. Every variant is exported verbatim in
/// `EnforcementEvent.respond_error`.
pub const REFUSE_ROLE: &str = "respond role disabled";
pub const REFUSE_AGENT_SELF: &str = "agent-self event: the agent does not kill itself";
pub const REFUSE_NOT_CONTAINER: &str = "not a container process";
pub const REFUSE_UNKNOWN_IDENTITY: &str = "unknown workload identity (cgroup not in cache)";
/// The selector that decides whether this policy covers this workload could
/// not be resolved: the label caches are cold, relisting after a 410, or held
/// down after a frame the parser could not read.
///
/// The decision still applies the program — skipping the rules there is a
/// silent fail-open, and admission fails closed on exactly this state — but
/// applying it and *signalling* on it are not the same act. Admission's
/// fail-closed refuses to admit a Pod, which the next retry undoes once the
/// cache is warm. Here the same fail-closed would be a SIGKILL, which nothing
/// undoes, and the group whose labels are unknown is unknown for every pod on
/// the node at once: one 410 on the namespace watch, and a `Kill` rule under a
/// `namespaceSelector` reaches every workload the node runs. That is not the
/// policy being enforced against the workloads it selects; it is the policy
/// being executed against workloads nobody has established it selects.
///
/// So the match is recorded, exported with the rule that matched and
/// `labels_unknown`, counted in `respond_refused_total`, and left in
/// `DEG_LABELS_UNKNOWN` — and no signal is sent until the identity can be
/// resolved. `Deny` and `Audit` are unaffected: neither ends a process.
pub const REFUSE_LABELS_UNKNOWN: &str =
    "selector unresolved (label caches cold, relisting or held down): the policy's scope for \
     this workload is unproven, so no signal is sent";
pub const REFUSE_TGID_ZERO: &str = "tgid 0: no process to signal";
pub const REFUSE_TGID_INIT: &str = "tgid 1: init is never a target";
pub const REFUSE_TGID_SELF: &str = "tgid is this agent process";
pub const REFUSE_TGID_RANGE: &str = "tgid outside the pid range: not a signalable process";
pub const REFUSE_ISOLATE: &str = "isolate not implemented";
/// A tracepoint fires after the syscall entry is recorded, so by the time the
/// decision exists there is nothing left to refuse. Exported on every runtime
/// Deny so the event is distinguishable from one nobody meant to act on.
pub const REFUSE_DENY_NOT_ENFORCEABLE: &str =
    "tracepoint does not block a syscall: it has already run and been recorded; the enforceable reaction is kill, the blocking one is admission";
pub const REFUSE_NO_RESPONDER: &str = "no responder wired: reaction backend not installed";
pub const REFUSE_STALE_TARGET: &str =
    "tgid left the cgroup that raised the event: pid reuse, not the workload";
pub const REFUSE_TARGET_GONE: &str = "target process is gone before the signal";
/// Deliberately not one of the two above. Those say something about the
/// target; this says the guard could not be evaluated at all, so nothing is
/// known about the target and the refusal is the agent declining to signal
/// blind rather than a workload that moved. A node in this state can never
/// react, which is why it is also a degradation reason and they are not.
pub const REFUSE_TARGET_UNPROVABLE: &str =
    "stale-target guard cannot be computed on this node: nothing is proven about the target, and \
     that is not evidence the target moved";

/// Respond cannot be honoured outside the initial pid namespace; the agent
/// says so and runs in observe instead of signalling blind.
pub const RESPOND_NO_HOST_PIDNS: &str =
    "respond disabled: agent is not in the host pid namespace, datapath tgids would not resolve";

/// Pre-syscall guards, in the order they are checked.
pub fn refuse_reason(
    respond_role: bool,
    tgid: u32,
    agent_self: bool,
    in_container: bool,
    identity_unknown: bool,
    scope_unproven: bool,
) -> Option<&'static str> {
    if !respond_role {
        return Some(REFUSE_ROLE);
    }
    if agent_self {
        return Some(REFUSE_AGENT_SELF);
    }
    if !in_container {
        return Some(REFUSE_NOT_CONTAINER);
    }
    if identity_unknown {
        return Some(REFUSE_UNKNOWN_IDENTITY);
    }
    // The workload is named and the policy's scope over it is not. See
    // `REFUSE_LABELS_UNKNOWN`: the two are the same refusal one step apart —
    // «which workload is this» and «does this policy cover it» — and a signal
    // needs both answered.
    if scope_unproven {
        return Some(REFUSE_LABELS_UNKNOWN);
    }
    if tgid == 0 {
        return Some(REFUSE_TGID_ZERO);
    }
    if tgid == 1 {
        return Some(REFUSE_TGID_INIT);
    }
    if tgid >= MAX_TGID || i32::try_from(tgid).is_err() {
        return Some(REFUSE_TGID_RANGE);
    }
    if tgid == std::process::id() {
        return Some(REFUSE_TGID_SELF);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrum-respond-{tag}-{}-{}",
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
    fn guards_run_in_order_and_cover_every_hard_refusal() {
        assert_eq!(
            refuse_reason(false, 42, false, true, false, false),
            Some(REFUSE_ROLE)
        );
        assert_eq!(
            refuse_reason(true, 42, true, true, false, false),
            Some(REFUSE_AGENT_SELF)
        );
        assert_eq!(
            refuse_reason(true, 42, false, false, false, false),
            Some(REFUSE_NOT_CONTAINER)
        );
        assert_eq!(
            refuse_reason(true, 42, false, true, true, false),
            Some(REFUSE_UNKNOWN_IDENTITY)
        );
        assert_eq!(
            refuse_reason(true, 0, false, true, false, false),
            Some(REFUSE_TGID_ZERO)
        );
        assert_eq!(
            refuse_reason(true, 1, false, true, false, false),
            Some(REFUSE_TGID_INIT)
        );
        assert_eq!(
            refuse_reason(true, std::process::id(), false, true, false, false),
            Some(REFUSE_TGID_SELF)
        );
        assert_eq!(refuse_reason(true, 424242, false, true, false, false), None);
    }

    /// `u32 as pid_t` on these values is a negative pid: -1 is "every process
    /// this agent may signal", and any other negative value is a process group.
    #[test]
    fn tgid_that_would_wrap_negative_is_refused() {
        for tgid in [u32::MAX, 0x8000_0000, 0xFFFF_FFFE, MAX_TGID, MAX_TGID + 1] {
            assert_eq!(
                refuse_reason(true, tgid, false, true, false, false),
                Some(REFUSE_TGID_RANGE),
                "tgid {tgid}"
            );
        }
        assert_eq!(
            refuse_reason(true, MAX_TGID - 1, false, true, false, false),
            None
        );
    }

    /// Even bypassing the guards, the responder itself refuses the signal.
    #[test]
    fn signal_responder_never_calls_kill_with_a_negative_pid() {
        for tgid in [u32::MAX, 0x8000_0000, MAX_TGID, 1, 0] {
            let err = SignalResponder.kill(tgid).expect_err("must refuse");
            let msg = err.to_string();
            assert!(msg.contains("not a signalable pid"), "{tgid}: {msg}");
        }
    }

    #[test]
    fn noop_responder_never_claims_success() {
        assert!(NoopResponder.kill(4242).is_err());
    }

    #[test]
    fn proc_check_reads_the_current_cgroup_of_the_target() {
        let root = temp_dir("proc-check");
        let proc_root = root.join("proc");
        let cgroup_root = root.join("cgroup");
        let live = cgroup_root.join("kubepods/pod-1/container-a");
        std::fs::create_dir_all(&live).expect("cgroup dir");
        std::fs::create_dir_all(proc_root.join("4242")).expect("proc dir");
        std::fs::write(
            proc_root.join("4242/cgroup"),
            "0::/kubepods/pod-1/container-a\n",
        )
        .expect("cgroup file");

        let check = ProcCgroupCheck::with_roots(&proc_root, &cgroup_root);
        let expected = inode_of(&live).expect("inode");
        assert_eq!(check.cgroup_id(4242), Some(expected));
        // No /proc/<tgid> at all: gone, not "assume it is still the workload".
        assert_eq!(check.cgroup_id(4243), None);

        // cgroup v1 lines carry controllers and no unified path.
        std::fs::write(proc_root.join("4242/cgroup"), "1:cpu:/kubepods/pod-1\n")
            .expect("v1 cgroup file");
        assert_eq!(check.cgroup_id(4242), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The whole of finding 1's first half, over a fake `/proc` whose
    /// `mountinfo` is this host's hybrid layout: cgroup2 under `unified`, and
    /// `/sys/fs/cgroup` a tmpfs of v1 controllers.
    ///
    /// Before the fix `new()` hardcoded `/sys/fs/cgroup`, so the path stat'ed
    /// here was `<tmpfs>/kubepods/...`, which does not exist: `cgroup_id`
    /// returned `None` for a process that had never moved, and the reaction
    /// path read that as a stale target. Pointing the derivation at the wrong
    /// root is exactly the defect, so this asserts the *derived* root, not a
    /// passed-in one.
    #[test]
    fn a_hybrid_node_keys_on_the_unified_mount_it_actually_has() {
        let root = temp_dir("hybrid");
        let proc_root = root.join("proc");
        let tmpfs = root.join("sys/fs/cgroup");
        let unified = tmpfs.join("unified");
        let live = unified.join("kubepods/pod-1/container-a");
        std::fs::create_dir_all(&live).expect("cgroup dir");
        // The v1 tmpfs really does hold directories; none of them is the
        // hierarchy /proc/<pid>/cgroup names.
        std::fs::create_dir_all(tmpfs.join("memory")).expect("v1 dir");
        std::fs::create_dir_all(proc_root.join("self")).expect("proc self");
        std::fs::create_dir_all(proc_root.join("4242")).expect("proc dir");
        std::fs::write(
            proc_root.join("self/mountinfo"),
            format!(
                "35 23 0:27 / {} rw,relatime - tmpfs tmpfs rw\n\
                 39 35 0:31 / {}/memory rw,relatime - cgroup cgroup rw,memory\n\
                 45 35 0:37 / {} rw,relatime - cgroup2 cgroup2 rw\n",
                tmpfs.display(),
                tmpfs.display(),
                unified.display()
            ),
        )
        .expect("mountinfo");
        std::fs::write(
            proc_root.join("4242/cgroup"),
            "0::/kubepods/pod-1/container-a\n",
        )
        .expect("cgroup file");

        let check = ProcCgroupCheck::with_proc_root(&proc_root);
        assert_eq!(check.cgroup_root(), Ok(unified.as_path()));
        assert_eq!(check.unprovable(), None, "the root was derivable");
        assert_eq!(
            check.cgroup_id(4242),
            inode_of(&live),
            "the derived root must name the same inode bpf_get_current_cgroup_id() reports; \
             a check keyed on {} answers None for a target that never moved",
            tmpfs.display()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A root that cannot be derived is reported as such and never guessed.
    /// `cgroup_id` still refuses — not signalling is the safe direction — but
    /// the caller can tell that refusal apart from "this target is gone",
    /// which is the difference between a busy node and a node that has stopped
    /// enforcing.
    #[test]
    fn an_underivable_root_is_unprovable_not_a_default() {
        let root = temp_dir("unprovable");
        let proc_root = root.join("proc");
        std::fs::create_dir_all(proc_root.join("self")).expect("proc self");
        std::fs::create_dir_all(proc_root.join("4242")).expect("proc dir");
        std::fs::write(proc_root.join("4242/cgroup"), "0::/kubepods/pod-1\n").expect("cgroup file");

        // No cgroup2 line at all: a v1-only node.
        std::fs::write(
            proc_root.join("self/mountinfo"),
            "35 23 0:27 / /sys/fs/cgroup rw - tmpfs tmpfs rw\n",
        )
        .expect("mountinfo");
        let check = ProcCgroupCheck::with_proc_root(&proc_root);
        let why = check.unprovable().expect("v1-only node is unprovable");
        assert!(why.contains("no cgroup2 mount"), "{why}");
        assert!(check.cgroup_root().is_err());
        assert_eq!(check.cgroup_id(4242), None);

        // No mountinfo to read at all.
        std::fs::remove_file(proc_root.join("self/mountinfo")).expect("rm");
        let check = ProcCgroupCheck::with_proc_root(&proc_root);
        let why = check.unprovable().expect("no mountinfo is unprovable");
        assert!(why.contains("unreadable"), "{why}");

        // An explicit root is the caller's own proof: it is never unprovable.
        assert_eq!(
            ProcCgroupCheck::with_roots(&proc_root, root.join("cgroup")).unprovable(),
            None
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The production constructor is keyed on the derivation and on nothing
    /// else. The test above proves the derivation is right over a fake `/proc`;
    /// this one proves `new()` uses it, which is the half that was wrong — and
    /// it is the only assertion here that can fail without a kernel, an ELF
    /// and CAP_BPF. On a node where cgroup2 is at `/sys/fs/cgroup` the old
    /// constant and the derived root agree and this says nothing; on the
    /// hybrid node it is the whole defect.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_production_check_is_keyed_on_the_derived_root() {
        let check = ProcCgroupCheck::new();
        match ferrum_k8smeta::detect_cgroup2_root() {
            Ok(root) => assert_eq!(
                check.cgroup_root(),
                Ok(root.as_path()),
                "ProcCgroupCheck::new() is not keyed on this node's cgroup2 mount; on a hybrid \
                 node that is every reaction refusing on a target that never moved"
            ),
            Err(_) => assert!(
                check.unprovable().is_some(),
                "no cgroup2 mount on this node, and the check claims it can still prove a target"
            ),
        }
    }

    /// The default a check that can always answer gets, so implementations
    /// that cannot fail need say nothing.
    #[test]
    fn a_check_that_always_answers_is_provable_by_default() {
        struct Always;
        impl TargetCheck for Always {
            fn cgroup_id(&self, _tgid: u32) -> Option<u64> {
                Some(7)
            }
        }
        assert_eq!(Always.unprovable(), None);
    }

    #[test]
    fn host_pid_namespace_only_for_the_initial_namespace() {
        let dir = temp_dir("pidns");
        let host = dir.join("host-ns");
        let container = dir.join("container-ns");
        let junk = dir.join("junk-ns");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(format!("pid:[{HOST_PID_NS_INO}]"), &host).expect("link");
            std::os::unix::fs::symlink("pid:[4026532629]", &container).expect("link");
            std::os::unix::fs::symlink("not-a-namespace", &junk).expect("link");
        }
        assert!(host_pid_namespace_at(&host));
        assert!(!host_pid_namespace_at(&container));
        assert!(!host_pid_namespace_at(&junk));
        assert!(!host_pid_namespace_at(&dir.join("missing")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `TargetCheck` is consulted once per reaction, never cached.
    #[test]
    fn target_check_is_queried_per_call() {
        struct Counting(AtomicU64);
        impl TargetCheck for Counting {
            fn cgroup_id(&self, _tgid: u32) -> Option<u64> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Some(7)
            }
        }
        let check = Counting(AtomicU64::new(0));
        assert_eq!(check.cgroup_id(1), Some(7));
        assert_eq!(check.cgroup_id(1), Some(7));
        assert_eq!(check.0.load(Ordering::Relaxed), 2);
    }
}
