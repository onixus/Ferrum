//! Event loop: raw ring records → decode → policy → export sink.
//!
//! The record source is abstract (any iterator or an mpsc channel), so tests
//! and a future kernel ring reader share one path. A record that fails to
//! decode is counted as a drop — it is telemetry loss, never a reason to stop
//! the loop or to fail open.

use crate::Agent;
use ferrum_ebpf::{decode_event, syscall_event, SyscallArch};
use ferrum_export::EventSink;
use std::sync::mpsc::Receiver;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PumpStats {
    /// Records decoded and pushed through `handle_event`.
    pub handled: u64,
    /// Malformed records, also added to `events_dropped_total`.
    pub decode_failed: u64,
}

/// Drain an iterator of raw ring records through the agent.
pub fn pump_records<S, I, R>(agent: &Agent, arch: SyscallArch, records: I, sink: &S) -> PumpStats
where
    S: EventSink,
    I: IntoIterator<Item = R>,
    R: AsRef<[u8]>,
{
    let mut stats = PumpStats::default();
    for record in records {
        match decode_event(record.as_ref()) {
            Ok(event) => {
                let view = syscall_event(&event, arch);
                agent.handle_event(event.cgroup_id, &view, sink);
                stats.handled += 1;
            }
            Err(_) => {
                stats.decode_failed += 1;
                agent.record_drop(1);
            }
        }
    }
    stats
}

/// Block on an mpsc channel until every sender hangs up, pumping each record.
pub fn pump_channel<S: EventSink>(
    agent: &Agent,
    arch: SyscallArch,
    records: Receiver<Vec<u8>>,
    sink: &S,
) -> PumpStats {
    pump_records(agent, arch, records.iter(), sink)
}
