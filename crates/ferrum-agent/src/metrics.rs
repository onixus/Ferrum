//! `/metrics` for the node agent, derived from `status.json` rather than
//! written beside it.
//!
//! `status.rs` argued against a port on this DaemonSet and gave three reasons.
//! Two of them have been answered and the third has not, so the shape here is
//! what is left after taking them seriously rather than a reversal:
//!
//!  * *"an HTTP stack is a dependency this crate's boundary forbids"* — still
//!    true, and still refused. `ferrum-metrics` has no dependencies at all;
//!    what it adds to this crate's graph is `std::net`, which the webhook has
//!    carried since it was written.
//!  * *"a scrape config does not exist in `deploy/`"* — it does now: a named
//!    container port, a headless Service, the scrape annotations, and a
//!    NetworkPolicy that says who may reach the port. Without those this file
//!    would be code nobody collects, which is the state the counters were in.
//!  * *"a listening port on a DaemonSet that runs on every node is a second
//!    attack surface"* — **unanswered, and it stays that way.** It is a real
//!    cost, paid deliberately, and the mitigations are: the port is off unless
//!    `--metrics-listen` is passed; it answers `GET /metrics` and nothing
//!    else, never reading a request body; it is a strictly weaker surface than
//!    `status.json`, because what it exposes is a chosen subset of that file
//!    (see `NON_NUMERIC_KEYS`) and never the free-text fields; and the
//!    manifests default-deny it to everything but a labelled monitoring
//!    namespace.
//!
//! Derived, not parallel. Every counter here comes from the object
//! `status_json` already builds, walked mechanically: a `bool` becomes a 0/1
//! gauge, a number ending in `Total` a counter, any other number a gauge, and
//! every non-numeric key must be named in [`NON_NUMERIC_KEYS`] with what is
//! done about it. So a counter added to `status.json` appears here without
//! anyone remembering to add it, a counter renamed there is renamed here, and
//! a *new* key of a type this walk cannot place raises
//! `ferrum_agent_status_keys_unmapped` instead of vanishing. That last one is
//! the whole reason the walk is mechanical: a second hand-written list of
//! counters is a second thing to forget, and this tree has already paid for
//! twenty-two counters nobody read.
//!
//! Nothing here can lose a count. The render reads the live atomics of the
//! process when a scrape asks; there is no queue between the counter and the
//! reader, so a scrape that fails loses a reading and never a count — and
//! `status.json` keeps publishing regardless, so this endpoint is a second
//! reader of the node's state and never its only one.

use std::net::TcpListener;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use ferrum_export::{EventSink, SinkContext};
use ferrum_metrics::{snake_case, Exposition, ServeConfig};
use serde_json::Value;

use crate::status::status_json;
use crate::{Agent, DegradedState};

/// Prefix for every family this process publishes.
pub const PREFIX: &str = "ferrum_agent";

/// Keys of `status.json` that are not numbers and not booleans, and what
/// becomes of each.
///
/// Exhaustive by gate: [`exposition`] counts any key it cannot place into
/// `ferrum_agent_status_keys_unmapped`, and the metrics gate asserts that
/// count is zero on a rendered agent. A key added to `status.json` and not
/// decided about here is therefore a red gate, not a silently missing metric.
///
/// The second column is the decision, and three of them are refusals. The
/// endpoint is reachable from inside the cluster; every string this agent
/// holds about *what it is enforcing* or *what went wrong on which cgroup* is
/// reconnaissance for whoever is already inside. Those stay in `status.json`,
/// which is a 0600 file on the node.
pub const NON_NUMERIC_KEYS: [(&str, Disposition); 9] = [
    // The scrape has its own timestamp, and a metric of "when this process
    // last looked at the clock" is one an operator would have to diff against
    // the scraper's own to read at all.
    ("ts", Disposition::NotAMetric),
    // Identity of the target is the scraper's job: Prometheus attaches
    // `instance`, and the Kubernetes SD attaches the node. A second copy in a
    // label is cardinality with no new information in it.
    ("node", Disposition::NotAMetric),
    // Observe or respond, as a label on `ferrum_agent_info`. This one is
    // operational rather than descriptive: "which nodes are allowed to kill"
    // is the first question after an unexpected kill, and it is not
    // reconstructible from anything else here.
    ("agentRole", Disposition::InfoLabel),
    // The digest of the bundle in force, as a label on
    // `ferrum_agent_bundle_info`. A content hash names no policy and no rule;
    // it is what joins this node to a published bundle, which is the whole of
    // what a fleet-wide rollout view needs.
    ("bundleDigest", Disposition::BundleLabel),
    // Refused. The operator-chosen name of the policy this node enforces is
    // the one string here that tells a reader *what is being enforced*, and
    // the digest above already answers "is this node on the current bundle"
    // without it.
    ("policyName", Disposition::Withheld),
    // One series per known reason id, always all of them. See
    // `DEGRADED_REASON_IDS`.
    ("degradedReasons", Disposition::ReasonSeries),
    // Refused: free text. The terminal fault line carries an ELF path or a map
    // name, the respond line carries why signalling was given up on, the
    // container-map line carries a cgroup error verbatim, and the waiver line
    // names policies. Each is reachable here as a reason id, which is what an
    // alert needs; the sentence stays in the 0600 file on the node.
    ("terminalFault", Disposition::Withheld),
    ("respondDisabledReason", Disposition::Withheld),
    ("containerMapError", Disposition::Withheld),
];

/// The tenth non-numeric key. Kept out of the array above only because
/// `waiversUnjoined` is `null` on a healthy node and the array is indexed by
/// name, not by position; it is checked by the same gate.
pub const WAIVERS_UNJOINED_KEY: (&str, Disposition) = ("waiversUnjoined", Disposition::Withheld);

/// What [`exposition`] does with a non-numeric `status.json` key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disposition {
    /// Deliberately not published: the scraper already knows it, or it is not
    /// a measurement.
    NotAMetric,
    /// Deliberately not published because publishing it would tell a reader
    /// inside the cluster something about enforcement that the digest and the
    /// reason ids do not.
    Withheld,
    /// A label on `ferrum_agent_info`.
    InfoLabel,
    /// A label on `ferrum_agent_bundle_info`.
    BundleLabel,
    /// Expanded into `ferrum_agent_degraded_reason`.
    ReasonSeries,
}

/// Stable short ids for every reason this agent can raise.
///
/// The reason constants are sentences — they are what an operator reads in
/// `status.json` and in the transition line, and that is the right shape
/// there. A sentence is the wrong shape for a label: it is rewritten whenever
/// the wording improves, and every alert written against it then stops firing
/// with nothing red anywhere. So the label carries an id that is allowed to
/// outlive the wording, and the metrics gate holds the table total over the
/// same three scans `boundary_gate.rs` uses to find reasons in the first
/// place.
///
/// Matched by prefix, longest first: `DEG_CONTAINER_MAP` and several others
/// reach `degraded_reasons_at` with a fault text appended.
pub const DEGRADED_REASON_IDS: [(&str, &str); 30] = [
    (crate::CGROUP_ROOT_UNDERIVABLE, "cgroup_root_underivable"),
    (crate::DATAPATH_ABI_MISMATCH, "datapath_abi_mismatch"),
    (crate::DATAPATH_UNDECODABLE, "datapath_undecodable"),
    (crate::DEG_BUNDLE_UNREADABLE, "bundle_unreadable"),
    (crate::DEG_CGROUP_INDEX_EMPTY, "cgroup_index_empty"),
    (
        crate::DEG_CLOCK_FLOOR_UNPERSISTED,
        "clock_floor_unpersisted",
    ),
    (crate::DEG_CLOCK_ROLLBACK, "clock_rollback"),
    (crate::DEG_CONTAINER_FLAG, "container_flag_disagreement"),
    (crate::DEG_CONTAINER_MAP, "container_map_not_ready"),
    (crate::DEG_CONTROL_PLANE_DOWN, "control_plane_down"),
    (crate::DEG_DATAPATH, "datapath_unknown_syscall"),
    (crate::DEG_DECODE_FAILURES, "decode_failures"),
    (crate::DEG_EXPORT_DEAD, "export_dead"),
    (crate::DEG_EXPORT_LOSSY, "export_lossy"),
    (crate::DEG_IDENTITY_UNKNOWN, "identity_unknown"),
    (crate::DEG_LABELS_UNKNOWN, "labels_unknown"),
    (crate::DEG_LKG_PARTIAL, "lkg_partial"),
    (crate::DEG_LOADER, "loader_degraded"),
    (crate::DEG_NOT_ATTACHED, "not_attached"),
    (crate::DEG_PATH_TRUNCATED, "path_truncated"),
    (crate::DEG_RING_DROPS, "ring_drops"),
    (crate::DEG_STATUS_UNWRITABLE, "status_unwritable"),
    (crate::DEG_WAIVERS_DROPPED, "waivers_dropped"),
    (crate::RECORD_CHANNEL_GONE, "record_channel_gone"),
    (crate::RESPOND_NO_HOST_PIDNS, "respond_no_host_pidns"),
    (crate::RESPOND_SIGNAL_FAILING, "respond_signal_failing"),
    (crate::SELF_TGID_UNPUBLISHED, "self_tgid_unpublished"),
    (crate::TARGET_CHECK_UNPROVABLE, "target_check_unprovable"),
    (crate::TARGET_NEVER_PROVEN, "target_never_proven"),
    (crate::WAIVERS_UNJOINED, "waivers_unjoined"),
];

/// The id a reason string is published under, or [`UNMAPPED_REASON_ID`].
///
/// Never `None`: a reason with no id must still be *counted*, because the
/// alternative is a degraded node whose degradation is invisible to the
/// surface built to show it. The gate keeps the table total so this fallback
/// stays unreachable; if it ever fires, the series that lights up says a
/// reason exists that this build cannot name, which is itself the alert.
pub fn degraded_reason_id(reason: &str) -> &'static str {
    let mut best: Option<(usize, &'static str)> = None;
    for (text, id) in DEGRADED_REASON_IDS {
        if reason.starts_with(text) && best.is_none_or(|(len, _)| text.len() > len) {
            best = Some((text.len(), id));
        }
    }
    best.map(|(_, id)| id).unwrap_or(UNMAPPED_REASON_ID)
}

pub const UNMAPPED_REASON_ID: &str = "unmapped";

/// The families this agent publishes, built from the live process.
pub fn exposition(
    agent: &Agent,
    ctx: Option<&SinkContext>,
    sink: Option<&(dyn EventSink + Sync)>,
    state: &DegradedState,
) -> Exposition {
    let status = status_json(agent, ctx, sink, state);
    let mut out = Exposition::new();
    let mut unmapped = 0u64;
    let mut role = String::new();
    let mut digest = String::new();

    let object = status.as_object().cloned().unwrap_or_default();
    for (key, value) in &object {
        let name = format!("{PREFIX}_{}", snake_case(key));
        match value {
            Value::Bool(flag) => {
                out.bool_gauge(&name, help_for(key), *flag);
            }
            Value::Number(number) => {
                let n = number.as_u64().unwrap_or(0);
                if key.ends_with("Total") {
                    out.counter(&name, help_for(key), n);
                } else {
                    out.gauge(&name, help_for(key), n);
                }
            }
            _ => match disposition(key) {
                Some(Disposition::InfoLabel) => {
                    role = value.as_str().unwrap_or_default().to_string();
                }
                Some(Disposition::BundleLabel) => {
                    digest = value.as_str().unwrap_or_default().to_string();
                }
                Some(Disposition::NotAMetric)
                | Some(Disposition::Withheld)
                | Some(Disposition::ReasonSeries) => {}
                None => unmapped += 1,
            },
        }
    }

    // Identity of the software, not of the node. `role` is the one thing here
    // an incident asks first and cannot get anywhere else.
    out.labelled_gauge(
        "ferrum_agent_info",
        "1, labelled with the version of this agent and the role it is running in",
        vec![(
            vec![
                ("version".into(), env!("CARGO_PKG_VERSION").into()),
                ("role".into(), role),
            ],
            1,
        )],
    );
    // Always emitted, empty digest included: a node that has loaded no bundle
    // is a different state from a node this scrape did not reach, and a family
    // that disappears cannot tell them apart.
    out.labelled_gauge(
        "ferrum_agent_bundle_info",
        "1, labelled with the digest of the PolicyBundle this node is enforcing; empty means \
         none has been loaded",
        vec![(vec![("digest".into(), digest)], 1)],
    );

    // Every id, every scrape, 0 for the ones not raised. A family that emits
    // only what is currently true makes an absent series mean both "healthy"
    // and "this build has no such reason", and an alert written on the first
    // never fires under the second.
    let raised: Vec<&'static str> = state
        .reasons
        .iter()
        .map(|reason| degraded_reason_id(reason))
        .collect();
    let mut series: Vec<(Vec<(String, String)>, u64)> = DEGRADED_REASON_IDS
        .iter()
        .map(|(_, id)| {
            (
                vec![("reason".to_string(), (*id).to_string())],
                u64::from(raised.contains(id)),
            )
        })
        .collect();
    series.push((
        vec![("reason".to_string(), UNMAPPED_REASON_ID.to_string())],
        u64::from(raised.contains(&UNMAPPED_REASON_ID)),
    ));
    out.labelled_gauge(
        "ferrum_agent_degraded_reason",
        "1 while this node is raising the named degradation reason, 0 otherwise; every reason \
         this build can raise is present on every scrape",
        series,
    );

    out.gauge(
        "ferrum_agent_status_keys_unmapped",
        "keys of status.json this build could not place into a metric; anything but 0 means a \
         counter exists on this node that nothing here publishes",
        unmapped,
    );
    out
}

/// The whole response body.
pub fn metrics_text(
    agent: &Agent,
    ctx: Option<&SinkContext>,
    sink: Option<&(dyn EventSink + Sync)>,
    state: &DegradedState,
) -> String {
    exposition(agent, ctx, sink, state).render()
}

fn disposition(key: &str) -> Option<Disposition> {
    if key == WAIVERS_UNJOINED_KEY.0 {
        return Some(WAIVERS_UNJOINED_KEY.1);
    }
    NON_NUMERIC_KEYS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, disposition)| *disposition)
}

/// `# HELP` for a mechanically derived family.
///
/// Generic on purpose, and it is not a placeholder: the specific meaning of
/// every one of these counters is a paragraph in `ferrum-agent`, and a HELP
/// line that tried to carry it would be a third copy to drift. What it must do
/// is send the reader to the one place that is kept correct, and name the key
/// it came from so the join is mechanical.
fn help_for(key: &str) -> &'static str {
    // Leaked once per distinct key of a fixed object, i.e. bounded by the
    // shape of `status.json` and not by the number of scrapes.
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<String, &'static str>>,
    > = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(text) = cache.get(key) {
        return text;
    }
    let text: &'static str = Box::leak(
        format!("`{key}` of the agent status surface; see crates/ferrum-agent/src/status.rs")
            .into_boxed_str(),
    );
    cache.insert(key.to_string(), text);
    text
}

/// Answer scrapes on `listener` until it fails, on a thread of its own.
///
/// Two properties this signature exists to enforce:
///
///  * The listener is **already bound**. Binding here would turn a taken port
///    or a bad address into a line on stderr from a detached thread; binding
///    in `main` makes it exit(2) before anything claims to be running.
///  * The render reads through [`Agent::degraded_snapshot_at`], never
///    `degraded_state_at`. The latter latches the transition and hands it to
///    exactly one caller; a scrape that took it would delete the operator's
///    stderr line for that change. The reporting surface may not erase the
///    report.
///
/// The read guard is held for the length of a render — walking a JSON object
/// and formatting a few kilobytes — and no filesystem work happens under it.
/// That is the same half of a tick `StatusPublisher::tick` performs, and the
/// reason `commit` was split away from it in the first place.
pub fn spawn_metrics<S>(
    listener: TcpListener,
    agent: Arc<RwLock<Agent>>,
    ctx: SinkContext,
    sink: Arc<S>,
) where
    S: EventSink + Send + Sync + 'static,
{
    std::thread::spawn(move || {
        let render = move || {
            let guard = agent.read().unwrap_or_else(|e| e.into_inner());
            let state = guard.degraded_snapshot_at(Instant::now());
            metrics_text(&guard, Some(&ctx), Some(sink.as_ref()), &state)
        };
        if let Err(err) = ferrum_metrics::serve_listener(listener, ServeConfig::default(), render) {
            // Not fatal: enforcement does not depend on being scraped, and a
            // process that ended here would take the datapath down to fix a
            // monitoring fault. It is said once, and `status.json` keeps
            // publishing everything this port was showing.
            eprintln!("ferrum-agent: metrics listener stopped: {err}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_id_is_unique_and_a_label_safe_identifier() {
        let mut ids: Vec<&str> = DEGRADED_REASON_IDS.iter().map(|(_, id)| *id).collect();
        ids.push(UNMAPPED_REASON_ID);
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(count, ids.len(), "two reasons share one id: {ids:?}");
        for id in ids {
            assert!(!id.is_empty());
            assert!(
                id.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "reason id {id:?} is not snake_case ascii"
            );
        }
    }

    /// The one reason whose text reaches `degraded_reasons_at` with a fault
    /// appended. A prefix match is what makes it resolvable at all, and a
    /// longest-prefix match is what keeps it from resolving to a sibling.
    #[test]
    fn a_reason_carrying_an_appended_fault_still_resolves_to_its_own_id() {
        let raised = format!("{}: cgroup v1 on this node", crate::DEG_CONTAINER_MAP);
        assert_eq!(degraded_reason_id(&raised), "container_map_not_ready");
        assert_eq!(
            degraded_reason_id(crate::DEG_CONTAINER_FLAG),
            "container_flag_disagreement"
        );
        assert_eq!(
            degraded_reason_id("a reason no build of this agent has ever raised"),
            UNMAPPED_REASON_ID
        );
    }
}
