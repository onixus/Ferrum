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
//!
//! This loop is also the only place that sees successes and failures side by
//! side, which is what tells a node losing the odd record from a node whose
//! datapath decodes nothing at all. The decaying window cannot: it says
//! "recently" and a node that stops receiving syscalls stops refreshing it,
//! so a wrong ELF plus a quiet minute reported healthy. Every decoded record
//! is reported, so a run of failures with none in between is a real run.

use crate::Agent;
use ferrum_common::{FerrumError, Result};
use ferrum_ebpf::{
    abi_stamp_mismatch, decode_event, event_meta, syscall_event, syscall_name, SyscallArch,
};
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
                // Reported before anything else is done with it: the agent
                // separates "some records are malformed" from "nothing
                // decodes" by whether any record in between decoded at all,
                // and only this loop sees both sides.
                agent.record_decode_success(1);
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
                // A stamp this decoder does not know is not a malformed
                // record: it is a full-length record from an ELF that is not
                // this build, so every record it writes will be refused the
                // same way. Told apart here because the ELF cannot be asked -
                // the stamp is an instruction immediate, invisible to the
                // attach-time map check.
                match abi_stamp_mismatch(record.as_ref()) {
                    Some(stamp) => agent.record_datapath_abi_mismatch(stamp),
                    None => agent.record_decode_failure(1),
                }
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
