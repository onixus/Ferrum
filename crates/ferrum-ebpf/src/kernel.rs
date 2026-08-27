//! Container-cgroup sync planning, plus real kernel attach behind the opt-in
//! `attach` feature.
//!
//! The planner sits outside the feature gate on purpose: it decides which
//! cgroups the datapath flags as containers, and every `container_only` rule
//! (shell, docker.sock) is dead without it, so it must be covered by the
//! ordinary CI build, which has neither aya nor CAP_BPF.
//!
//! Attach itself is not covered by CI: it needs CAP_BPF/CAP_PERFMON and a
//! kernel, and the programs ELF is built separately (nightly,
//! bpfel-unknown-none) from `ferrum-ebpf-progs`. Every error surfaces as
//! Degraded; a partial attach is rolled back by dropping the handle, never
//! reported as Ok.

#[cfg(feature = "attach")]
use crate::TRACEPOINTS;
#[cfg(feature = "attach")]
use aya::maps::{Array, HashMap, MapData, PerCpuArray, RingBuf};
#[cfg(feature = "attach")]
use aya::programs::TracePoint;
#[cfg(feature = "attach")]
use aya::Bpf;
use ferrum_common::{FerrumError, Result};
use ferrum_ebpf_progs::{CGROUPS_MAX_ENTRIES, MAP_CGROUPS};
#[cfg(feature = "attach")]
use ferrum_ebpf_progs::{EVENTS_DROPPED_TOTAL, MAP_EVENTS, MAP_SELF};
use std::collections::BTreeSet;

/// One diff to apply to `ferrum_cgroups`: which cgroup ids gain the container
/// flag and which lose it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupSyncPlan {
    pub insert: Vec<u64>,
    pub remove: Vec<u64>,
}

impl CgroupSyncPlan {
    pub fn is_empty(&self) -> bool {
        self.insert.is_empty() && self.remove.is_empty()
    }

    /// Number of map operations the plan performs.
    pub fn len(&self) -> usize {
        self.insert.len() + self.remove.len()
    }
}

/// What a sync applied, and how many entries the map holds afterwards.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncStats {
    pub inserted: usize,
    pub removed: usize,
    pub entries: usize,
}

/// Diff the cgroup ids currently flagged in the kernel against the ids the
/// userspace index now knows.
///
/// An oversized `next` is Degraded, never a truncated plan: truncation would
/// leave an arbitrary subset of pods unflagged, and `container_only` rules
/// would then allow in exactly those pods.
pub fn plan_cgroup_sync(current: &BTreeSet<u64>, next: &BTreeSet<u64>) -> Result<CgroupSyncPlan> {
    if next.len() > CGROUPS_MAX_ENTRIES as usize {
        return Err(FerrumError::Degraded(format!(
            "cgroup sync: {} container cgroups do not fit the {CGROUPS_MAX_ENTRIES}-entry \
             {MAP_CGROUPS} map; refusing a truncated sync that would leave arbitrary pods \
             unflagged",
            next.len()
        )));
    }
    Ok(CgroupSyncPlan {
        insert: next.difference(current).copied().collect(),
        remove: current.difference(next).copied().collect(),
    })
}

/// Owns the loaded programs and maps; dropping it detaches everything.
#[cfg(feature = "attach")]
pub struct KernelHandle {
    bpf: Bpf,
    /// Mirror of what this handle actually wrote into `ferrum_cgroups`; the
    /// next plan is diffed against it, so a failed sync is not forgotten.
    container_cgroups: BTreeSet<u64>,
}

#[cfg(feature = "attach")]
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
        Ok(Self {
            bpf,
            container_cgroups: BTreeSet::new(),
        })
    }

    /// Cgroup ids this handle has flagged as containers. Plan the next sync
    /// against this, not against the index snapshot of the previous tick.
    pub fn container_cgroups(&self) -> &BTreeSet<u64> {
        &self.container_cgroups
    }

    pub fn container_map_entries(&self) -> usize {
        self.container_cgroups.len()
    }

    /// Apply one [`CgroupSyncPlan`] to `ferrum_cgroups`. Removals run first so
    /// a full map can never reject an insert the plan already sized to fit.
    /// A partial application is Degraded with what did land: the datapath is
    /// then flagging some pods and not others, which is not a healthy agent.
    pub fn sync_container_cgroups(&mut self, plan: &CgroupSyncPlan) -> Result<SyncStats> {
        let mut stats = SyncStats::default();
        for id in &plan.remove {
            if let Err(err) = self.remove_container_cgroup(*id) {
                stats.entries = self.container_cgroups.len();
                return Err(partial_sync(stats, err));
            }
            self.container_cgroups.remove(id);
            stats.removed += 1;
        }
        for id in &plan.insert {
            if let Err(err) = self.insert_container_cgroup(*id) {
                stats.entries = self.container_cgroups.len();
                return Err(partial_sync(stats, err));
            }
            self.container_cgroups.insert(*id);
            stats.inserted += 1;
        }
        stats.entries = self.container_cgroups.len();
        Ok(stats)
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
#[cfg(feature = "attach")]
pub struct RingReader {
    ring: RingBuf<MapData>,
}

#[cfg(feature = "attach")]
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

#[cfg(feature = "attach")]
fn degraded(what: &str, err: impl std::fmt::Display) -> FerrumError {
    FerrumError::Degraded(format!("{what}: {err}"))
}

#[cfg(feature = "attach")]
fn missing(map: &str) -> FerrumError {
    FerrumError::Degraded(format!("map {map} missing from eBPF ELF"))
}

#[cfg(feature = "attach")]
fn partial_sync(stats: SyncStats, err: FerrumError) -> FerrumError {
    FerrumError::Degraded(format!(
        "{MAP_CGROUPS} sync applied {} removes and {} inserts before failing ({} entries live): \
         {err}",
        stats.removed, stats.inserted, stats.entries
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[u64]) -> BTreeSet<u64> {
        ids.iter().copied().collect()
    }

    #[test]
    fn plan_inserts_and_removes_the_difference() {
        let plan = plan_cgroup_sync(&set(&[1, 2, 3]), &set(&[2, 3, 4])).expect("plan");
        assert_eq!(plan.insert, vec![4]);
        assert_eq!(plan.remove, vec![1]);
        assert_eq!(plan.len(), 2);
        assert!(!plan.is_empty());
    }

    #[test]
    fn plan_is_idempotent_when_nothing_moved() {
        let now = set(&[7, 8, 9]);
        let plan = plan_cgroup_sync(&now, &now).expect("plan");
        assert!(plan.is_empty(), "{plan:?}");
        let first = plan_cgroup_sync(&set(&[]), &now).expect("plan");
        assert_eq!(first.insert, vec![7, 8, 9]);
        assert!(first.remove.is_empty());
        // Applying it means current == next, so the next plan is a no-op.
        assert!(plan_cgroup_sync(&now, &now).expect("plan").is_empty());
    }

    /// Every pod gone means every entry gone: a stale container flag keeps a
    /// dead cgroup id matching `container_only` rules for a reused id.
    #[test]
    fn empty_next_clears_the_whole_map() {
        let plan = plan_cgroup_sync(&set(&[1, 2, 3]), &set(&[])).expect("plan");
        assert!(plan.insert.is_empty());
        assert_eq!(plan.remove, vec![1, 2, 3]);
        assert!(!plan.is_empty(), "clearing the map is not a no-op");
    }

    #[test]
    fn oversized_next_is_degraded_not_truncated() {
        let next: BTreeSet<u64> = (0..=u64::from(CGROUPS_MAX_ENTRIES)).collect();
        assert_eq!(next.len(), CGROUPS_MAX_ENTRIES as usize + 1);
        match plan_cgroup_sync(&set(&[]), &next) {
            Err(FerrumError::Degraded(msg)) => {
                assert!(msg.contains(MAP_CGROUPS), "{msg}");
                assert!(msg.contains("truncated"), "{msg}");
            }
            other => panic!("expected Degraded, got {:?}", other.map(|p| p.len())),
        }
        let full: BTreeSet<u64> = (0..u64::from(CGROUPS_MAX_ENTRIES)).collect();
        assert_eq!(
            plan_cgroup_sync(&set(&[]), &full)
                .expect("full map fits")
                .len(),
            CGROUPS_MAX_ENTRIES as usize
        );
    }

    #[cfg(feature = "attach")]
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
