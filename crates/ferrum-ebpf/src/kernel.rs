//! Real kernel attach, behind the opt-in `attach` feature.
//!
//! Not covered by CI: attaching needs CAP_BPF/CAP_PERFMON and a kernel, and
//! the programs ELF is built separately (nightly, bpfel-unknown-none) from
//! `ferrum-ebpf-progs`. Every error surfaces as Degraded; a partial attach is
//! rolled back by dropping the handle, never reported as Ok.

use crate::TRACEPOINTS;
use aya::maps::{Array, HashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::TracePoint;
use aya::Bpf;
use ferrum_common::{FerrumError, Result};
use ferrum_ebpf_progs::{EVENTS_DROPPED_TOTAL, MAP_CGROUPS, MAP_EVENTS, MAP_SELF};

/// Owns the loaded programs and maps; dropping it detaches everything.
pub struct KernelHandle {
    bpf: Bpf,
}

impl KernelHandle {
    /// Load a compiled `ferrum-ebpf-progs` ELF and attach all tracepoints.
    /// Any missing program or failed attach aborts the whole handle.
    pub fn attach(elf: &[u8]) -> Result<Self> {
        let mut bpf = Bpf::load(elf).map_err(|err| degraded("load eBPF ELF", err))?;
        for (prog, category, name) in TRACEPOINTS {
            let program = bpf.program_mut(prog).ok_or_else(|| {
                FerrumError::Degraded(format!("program {prog} missing from eBPF ELF"))
            })?;
            let tracepoint: &mut TracePoint =
                program.try_into().map_err(|err| degraded(prog, err))?;
            tracepoint.load().map_err(|err| degraded(prog, err))?;
            tracepoint
                .attach(category, name)
                .map_err(|err| degraded(prog, err))?;
        }
        Ok(Self { bpf })
    }

    /// Sum of the per-CPU in-kernel drop counter.
    pub fn events_dropped_total(&self) -> Result<u64> {
        let map = self
            .bpf
            .map(EVENTS_DROPPED_TOTAL)
            .ok_or_else(|| missing(EVENTS_DROPPED_TOTAL))?;
        let counters: PerCpuArray<_, u64> =
            PerCpuArray::try_from(map).map_err(|err| degraded(EVENTS_DROPPED_TOTAL, err))?;
        let values = counters
            .get(&0, 0)
            .map_err(|err| degraded(EVENTS_DROPPED_TOTAL, err))?;
        Ok(values.iter().sum())
    }

    /// Publish the agent's own tgid so the datapath can flag agent-self events.
    pub fn set_self_tgid(&mut self, tgid: u64) -> Result<()> {
        let map = self
            .bpf
            .map_mut(MAP_SELF)
            .ok_or_else(|| missing(MAP_SELF))?;
        let mut slot: Array<_, u64> =
            Array::try_from(map).map_err(|err| degraded(MAP_SELF, err))?;
        slot.set(0, tgid, 0).map_err(|err| degraded(MAP_SELF, err))
    }

    /// Mark a cgroup id as a pod container for the in-kernel container flag.
    pub fn insert_container_cgroup(&mut self, cgroup_id: u64) -> Result<()> {
        let map = self
            .bpf
            .map_mut(MAP_CGROUPS)
            .ok_or_else(|| missing(MAP_CGROUPS))?;
        let mut cgroups: HashMap<_, u64, u8> =
            HashMap::try_from(map).map_err(|err| degraded(MAP_CGROUPS, err))?;
        cgroups
            .insert(cgroup_id, 1, 0)
            .map_err(|err| degraded(MAP_CGROUPS, err))
    }

    pub fn remove_container_cgroup(&mut self, cgroup_id: u64) -> Result<()> {
        let map = self
            .bpf
            .map_mut(MAP_CGROUPS)
            .ok_or_else(|| missing(MAP_CGROUPS))?;
        let mut cgroups: HashMap<_, u64, u8> =
            HashMap::try_from(map).map_err(|err| degraded(MAP_CGROUPS, err))?;
        cgroups
            .remove(&cgroup_id)
            .map_err(|err| degraded(MAP_CGROUPS, err))
    }

    /// Take ownership of the event ring wrapped in a [`RingReader`].
    pub fn take_ring_reader(&mut self) -> Result<RingReader> {
        self.take_ring().map(RingReader::new)
    }

    /// Take ownership of the event ring for a reader loop; each item is one
    /// wire `Event` record for `decode_event`.
    pub fn take_ring(&mut self) -> Result<RingBuf<MapData>> {
        let map = self
            .bpf
            .take_map(MAP_EVENTS)
            .ok_or_else(|| missing(MAP_EVENTS))?;
        RingBuf::try_from(map).map_err(|err| degraded(MAP_EVENTS, err))
    }
}

/// Consumer side of `ferrum_events`.
///
/// Limitation: no epoll/AsyncFd here, so the caller polls — `drain` returns
/// what is currently in the ring and the loop sleeps between empty passes;
/// latency is bounded by that sleep, not by the kernel waking us.
pub struct RingReader {
    ring: RingBuf<MapData>,
}

impl RingReader {
    pub fn new(ring: RingBuf<MapData>) -> Self {
        Self { ring }
    }

    /// Hand every record currently in the ring to `f`, returning how many.
    /// The slice is only valid for the callback: copy what you keep.
    pub fn drain(&mut self, mut f: impl FnMut(&[u8])) -> usize {
        let mut n = 0;
        while let Some(item) = self.ring.next() {
            f(&item);
            n += 1;
        }
        n
    }
}

fn degraded(what: &str, err: impl std::fmt::Display) -> FerrumError {
    FerrumError::Degraded(format!("{what}: {err}"))
}

fn missing(map: &str) -> FerrumError {
    FerrumError::Degraded(format!("map {map} missing from eBPF ELF"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_elf_never_attaches() {
        match KernelHandle::attach(b"not an ELF") {
            Err(FerrumError::Degraded(msg)) => assert!(msg.contains("load eBPF ELF"), "{msg}"),
            other => panic!("expected Degraded, got {:?}", other.map(|_| ())),
        }
        match KernelHandle::attach(&[]) {
            Err(FerrumError::Degraded(_)) => {}
            other => panic!("expected Degraded, got {:?}", other.map(|_| ())),
        }
    }
}
