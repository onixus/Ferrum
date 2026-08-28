//! Node state as a file beside the events, not as a port.
//!
//! Every counter this agent keeps had exactly one consumer — a bool stamped
//! into each exported envelope — so a counter could change meaning and nothing
//! would notice. This module gives them a reader: `status.json`, rewritten in
//! `--export-dir` on every poll tick, next to `events.jsonl` and collected by
//! the same `cat`.
//!
//! Deliberately not `/metrics`: a listening port on a DaemonSet that runs on
//! every node is a second attack surface on the process the threat model
//! already calls the second target after the kubelet, an HTTP stack is a
//! dependency this crate's boundary forbids, and a scrape config does not
//! exist in `deploy/`. The file needs no port, no RBAC and no dependency. A
//! metrics exporter, if one is ever wanted, reads this file.
//!
//! The surface reports; it never acts. Nothing here is a probe, and no
//! liveness check may be wired to it: every degraded signal is either
//! recoverable (cold caches, a burst) or terminal (a wrong ELF), and a restart
//! on the first turns a node's first seconds into a crash loop while a restart
//! on the second is an infinite loop that never lives long enough to log why.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use ferrum_export::{EventSink, SinkContext};
use serde_json::{json, Value};

use crate::{Agent, DegradedState};

/// Written into `--export-dir`, beside `events.jsonl`.
pub const STATUS_NAME: &str = "status.json";
/// Same directory, so the rename that publishes it is atomic on one
/// filesystem. A reader never sees a half-written file, and a crash mid-write
/// leaves this behind rather than a truncated `status.json`.
pub const STATUS_TMP_NAME: &str = ".status.json.tmp";

/// Everything the agent knows about itself, as one JSON object. Field names
/// are the accessor names, so a reader of this file and a reader of the code
/// are looking at the same counter.
pub fn status_json(
    agent: &Agent,
    ctx: Option<&SinkContext>,
    sink: Option<&(dyn EventSink + Sync)>,
    state: &DegradedState,
) -> Value {
    let mut out = json!({
        "ts": agent.now().to_rfc3339(),
        "node": ctx.map(|c| c.node()).unwrap_or(""),
        "agentRole": ctx.map(|c| c.agent_role()).unwrap_or(""),
        "bundleDigest": agent.last_good_digest().map(|d| d.as_str().to_string()),
        "policyName": agent.policy_name(),
        "degraded": state.degraded,
        "degradedReasons": state.reasons,
        "attached": agent.pins_attached(),
        "controlPlaneDown": agent.control_plane_down(),
        "usingLastKnownGood": agent.using_last_known_good(),
        "lkgPartial": agent.lkg_partial(),
        "terminalFault": agent.terminal_fault(),
        "respondDisabledReason": agent.respond_disabled_reason(),
        "selfTgidUnpublished": agent.self_tgid_unpublished(),
        "containerMapSynced": agent.container_map_synced(),
        "containerMapEntries": agent.container_map_entries(),
        "containerMapStale": agent.container_map_stale(),
        "containerMapError": agent.container_map_error(),
        "exportWriterDead": agent.export_writer_dead(),
        "exceptionsHeld": agent.exceptions().len(),
        "waiversUnjoinedTotal": agent.waivers_unjoined_total(),
        "waiversUnjoined": agent.waivers_unjoined(),
        "respondKillTotal": agent.respond_kill_total(),
        "respondRefusedTotal": agent.respond_refused_total(),
        "respondRoleSkippedTotal": agent.respond_role_skipped_total(),
        "respondFailedTotal": agent.respond_failed_total(),
        "respondStaleTargetTotal": agent.respond_stale_target_total(),
        "exportLostTotal": agent.export_lost_total(),
        "containerFlagDisagreementTotal": agent.container_flag_disagreement_total(),
        "containerUnprovenTotal": agent.container_unproven_total(),
        "labelsUnknownTotal": agent.labels_unknown_total(),
        "identityUnknownTotal": agent.identity_unknown_total(),
        "eventsDroppedTotal": agent.events_dropped_total(),
        "recordsDecodeFailedTotal": agent.records_decode_failed_total(),
        "decodeFailureRun": agent.decode_failure_run(),
        "datapathAbiMismatchTotal": agent.datapath_abi_mismatch_total(),
        "unknownSyscallTotal": agent.unknown_syscall_total(),
        "pathTruncatedTotal": agent.path_truncated_total(),
        "exceptionsReloadFailedTotal": agent.exceptions_reload_failed_total(),
        "lkgRulesDroppedTotal": agent.lkg_rules_dropped_total(),
        "clockRollbackTotal": agent.clock_rollback_total(),
    });
    // The three export counters are the sink's, not the agent's: `agent` only
    // keeps the sum it has already seen.
    let (queue_dropped, write_failed, writer_lost) = match sink {
        Some(sink) => (
            sink.export_queue_dropped_total(),
            sink.export_write_failed_total(),
            sink.export_writer_lost_total(),
        ),
        None => (0, 0, 0),
    };
    if let Some(map) = out.as_object_mut() {
        map.insert("exportQueueDroppedTotal".into(), json!(queue_dropped));
        map.insert("exportWriteFailedTotal".into(), json!(write_failed));
        map.insert("exportWriterLostTotal".into(), json!(writer_lost));
    }
    out
}

/// Write `status.json` into `dir` atomically: a temp file in the same
/// directory, flushed and fsynced, then renamed over the published name.
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
            // Same reasoning as events.jsonl: the reasons can name a pod's
            // cgroup error text, and nothing on the node but the agent (and
            // root) has business reading it.
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

/// Publishes the poll tick's view of the node: envelope context, the stderr
/// line on a degraded transition, and `status.json`. Holds only the "already
/// complained about the status file" flag, so a directory that cannot be
/// written logs once instead of once per tick.
#[derive(Default)]
pub struct StatusPublisher {
    status_error_logged: bool,
}

/// Where a poll tick publishes to. Every part is optional: a build with no
/// export directory still stamps envelopes, and a build with neither still
/// logs its degraded transitions.
pub struct StatusOutput<'a> {
    pub ctx: Option<&'a SinkContext>,
    /// Read for export losses. The event path reads it too, but a node that
    /// stops receiving events must not stop noticing that its exports are
    /// being lost.
    pub sink: Option<&'a (dyn EventSink + Sync)>,
    /// `--export-dir`. None means no `status.json` (stdout export).
    pub status_dir: Option<&'a Path>,
}

impl StatusPublisher {
    /// One tick. Returns the state it published, so a caller (and a test) can
    /// assert on it without recomputing.
    pub fn publish(&mut self, agent: &Agent, out: &StatusOutput<'_>) -> DegradedState {
        let now = Instant::now();
        if let Some(sink) = out.sink {
            agent.note_export_state_at(sink, now);
        }
        let state = agent.degraded_state_at(now);
        if let Some(line) = &state.transition {
            eprintln!("ferrum-agent: {line}");
        }
        if let Some(ctx) = out.ctx {
            ctx.set_bundle_digest(agent.last_good_digest().cloned());
            ctx.set_degraded(state.degraded);
        }
        if let Some(dir) = out.status_dir {
            match write_status(dir, &status_json(agent, out.ctx, out.sink, &state)) {
                Ok(()) => self.status_error_logged = false,
                Err(err) if !self.status_error_logged => {
                    self.status_error_logged = true;
                    eprintln!(
                        "ferrum-agent: cannot write {}: {err}; node state is not readable on this \
                         node until it succeeds",
                        dir.join(STATUS_NAME).display()
                    );
                }
                Err(_) => {}
            }
        }
        state
    }
}
