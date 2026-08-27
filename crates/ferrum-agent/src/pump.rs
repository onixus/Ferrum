//! Event loop: raw ring records → decode → policy → export sink.
//!
//! The record source is abstract (any iterator or an mpsc channel), so tests
//! and a future kernel ring reader share one path. A record that fails to
//! decode is counted separately from in-kernel ring drops — same loss, other
//! side of the ring: it carried a syscall that no rule ever matched against,
//! so it degrades the agent on the same decaying terms rather than being
//! written off as telemetry. It is never a reason to stop the loop or to fail
//! open. A record whose syscall nr is outside the decode table marks the agent
//! Degraded: the table and the event source disagree, so enforce matching can
//! no longer be trusted; the event is still exported for visibility.

use crate::Agent;
use ferrum_common::{FerrumError, Result};
use ferrum_ebpf::{decode_event, event_meta, syscall_event, syscall_name, SyscallArch};
use ferrum_export::EventSink;
use std::sync::mpsc::Receiver;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PumpStats {
    /// Records decoded, named, and pushed through `handle_event`.
    pub handled: u64,
    /// Malformed records, counted in `records_decode_failed_total`, not in
    /// `events_dropped_total` (that one is the in-kernel ring counter). Each
    /// one is an event no rule saw, and degrades the agent while it recurs.
    pub decode_failed: u64,
    /// Records with a syscall nr outside the decode table; each marks the
    /// agent Degraded via `record_unknown_syscall`.
    pub unknown_syscall: u64,
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
                if syscall_name(arch, event.syscall_nr).is_none() {
                    stats.unknown_syscall += 1;
                    agent.record_unknown_syscall();
                } else {
                    stats.handled += 1;
                }
                agent.handle_event(event_meta(&event), &view, sink);
            }
            Err(_) => {
                stats.decode_failed += 1;
                agent.record_decode_failure(1);
            }
        }
    }
    stats
}

/// `pump_records` with the arch taken from the running host. Refuses to start
/// on a host the decode table does not cover instead of silently mis-naming
/// every record.
pub fn pump_records_host<S, I, R>(agent: &Agent, records: I, sink: &S) -> Result<PumpStats>
where
    S: EventSink,
    I: IntoIterator<Item = R>,
    R: AsRef<[u8]>,
{
    let arch = host_arch()?;
    Ok(pump_records(agent, arch, records, sink))
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

/// `pump_channel` with the arch taken from the running host.
pub fn pump_channel_host<S: EventSink>(
    agent: &Agent,
    records: Receiver<Vec<u8>>,
    sink: &S,
) -> Result<PumpStats> {
    let arch = host_arch()?;
    Ok(pump_channel(agent, arch, records, sink))
}

fn host_arch() -> Result<SyscallArch> {
    SyscallArch::host()
        .ok_or_else(|| FerrumError::Degraded("no syscall decode table for this host arch".into()))
}
