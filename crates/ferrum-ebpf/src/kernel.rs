//! Container-cgroup sync planning and static map-ABI inspection of a compiled
//! bpf ELF, plus real kernel attach behind the opt-in `attach` feature.
//!
//! Both sit outside the feature gate on purpose. The planner decides which
//! cgroups the datapath flags as containers, and every `container_only` rule
//! (shell, docker.sock) is dead without it; the map inspection is what joins
//! the out-of-tree ELF to this userspace. Both must be covered by the ordinary
//! CI build, which has neither aya nor CAP_BPF.
//!
//! Attach itself is not covered by CI: it needs CAP_BPF/CAP_PERFMON and a
//! kernel, and the programs ELF is built separately (nightly,
//! bpfel-unknown-none) from `ferrum-ebpf-progs`. Every error surfaces as
//! Degraded; a partial attach is rolled back by dropping the handle, never
//! reported as Ok.

#[cfg(feature = "attach")]
use crate::SyscallArch;
#[cfg(feature = "attach")]
use aya::maps::{Array, HashMap, MapData, PerCpuArray, RingBuf};
#[cfg(feature = "attach")]
use aya::programs::TracePoint;
#[cfg(feature = "attach")]
use aya::Bpf;
use ferrum_common::{FerrumError, Result};
#[cfg(feature = "attach")]
use ferrum_ebpf_progs::EVENTS_DROPPED_TOTAL;
use ferrum_ebpf_progs::{
    CGROUPS_MAX_ENTRIES, EVENTS_RING_BYTES, MAP_CGROUPS, MAP_EVENTS, MAP_SELF,
};
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

/// uapi `bpf_map_type` numbers for the maps the datapath declares. Spelled out
/// here, not taken from aya, so the check compiles in the ordinary stable
/// build that has neither aya nor CAP_BPF.
const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_RINGBUF: u32 = 27;

/// `bpf_map_def` as aya-ebpf emits it into the `maps` section: seven u32s
/// (type, key_size, value_size, max_entries, map_flags, id, pinning).
pub const MAP_DEF_LEN: usize = 28;

/// The shape of one map, as the userspace side of this crate uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapDef {
    pub name: &'static str,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

/// Every map this crate reads or writes, with the definition the ELF must
/// declare for that access to mean what it says.
///
/// The bpf ELF is built out of tree (nightly, bpfel-unknown-none) and shipped
/// in the image; the agent attaches whatever `--bpf-elf` names. Nothing else
/// joins the two, so the map layout is checked against the ELF before it is
/// loaded: a `ferrum_cgroups` whose key stopped being a cgroup id, or a
/// `ferrum_events` that is no longer a ring buffer, silently unflags every
/// container or silently stops delivering records.
pub const REQUIRED_MAPS: &[MapDef] = &[
    MapDef {
        name: MAP_EVENTS,
        map_type: BPF_MAP_TYPE_RINGBUF,
        key_size: 0,
        value_size: 0,
        max_entries: EVENTS_RING_BYTES,
    },
    MapDef {
        // Single u32-indexed slot holding the agent's own tgid as a u64;
        // `set_self_tgid` writes it and the datapath compares against it, so a
        // narrower value would flag the agent's own syscalls as a workload's.
        name: MAP_SELF,
        map_type: BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
    },
    MapDef {
        name: MAP_CGROUPS,
        map_type: BPF_MAP_TYPE_HASH,
        key_size: 8,
        value_size: 1,
        max_entries: CGROUPS_MAX_ENTRIES,
    },
];

/// Read one map definition out of a compiled bpf ELF's `maps` section.
///
/// Hand-rolled ELF64LE (section headers + symtab) to keep this crate free of
/// ELF crates and free of aya in the default build. Every read is bounds
/// checked: a malformed ELF is Degraded, never a panic in the agent.
pub fn elf_map_def(elf: &[u8], name: &'static str) -> Result<MapDef> {
    let def = map_def_bytes(elf, name)?;
    Ok(MapDef {
        name,
        map_type: def[0],
        key_size: def[1],
        value_size: def[2],
        max_entries: def[3],
    })
}

/// Check every [`REQUIRED_MAPS`] definition in a compiled bpf ELF.
///
/// A mismatch is Degraded: the datapath in that ELF does not agree with this
/// userspace, and attaching it would enforce against maps that mean something
/// else. Callers must not load the ELF after this fails.
pub fn verify_map_defs(elf: &[u8]) -> Result<()> {
    for expected in REQUIRED_MAPS {
        let found = elf_map_def(elf, expected.name)?;
        if found != *expected {
            return Err(FerrumError::Degraded(format!(
                "map {} in the eBPF ELF is {found:?}, this agent requires {expected:?}",
                expected.name
            )));
        }
    }
    Ok(())
}

/// The seven u32s of `name`'s `bpf_map_def`.
fn map_def_bytes(elf: &[u8], name: &str) -> Result<[u32; 7]> {
    let sections = elf_sections(elf)?;
    let shstrndx = u16_at(elf, 0x3e).ok_or_else(|| malformed("truncated ELF header"))? as usize;
    let shstrtab = section_bytes(elf, &sections, shstrndx)?;

    let symtab = sections
        .iter()
        .find(|s| s.kind == SHT_SYMTAB)
        .ok_or_else(|| malformed("no symtab in the eBPF ELF"))?;
    let strtab = section_bytes(elf, &sections, symtab.link)?;
    let symbols = elf
        .get(symtab.offset..symtab.offset + symtab.size)
        .ok_or_else(|| malformed("symtab runs past the end of the eBPF ELF"))?;
    let entsize = if symtab.entsize == 0 {
        SYM_ENTRY_LEN
    } else {
        symtab.entsize
    };
    if entsize < SYM_ENTRY_LEN {
        return Err(malformed("symtab entries are shorter than an Elf64_Sym"));
    }

    for entry in symbols.chunks_exact(entsize) {
        let name_off = u32_at(entry, 0).ok_or_else(|| malformed("truncated symbol"))? as usize;
        if cstr_at(strtab, name_off) != Some(name) {
            continue;
        }
        let info = entry[4] & 0xf;
        if info != STT_OBJECT {
            return Err(malformed(&format!("{name} is not a map object")));
        }
        let shndx = u16_at(entry, 6).ok_or_else(|| malformed("truncated symbol"))? as usize;
        let section_name = sections
            .get(shndx)
            .and_then(|s| cstr_at(shstrtab, s.name_off));
        if section_name != Some("maps") {
            return Err(malformed(&format!("{name} is outside the maps section")));
        }
        let value = u64_at(entry, 8).ok_or_else(|| malformed("truncated symbol"))? as usize;
        let size = u64_at(entry, 16).ok_or_else(|| malformed("truncated symbol"))? as usize;
        if size != MAP_DEF_LEN {
            return Err(malformed(&format!(
                "{name} is {size} bytes, expected a {MAP_DEF_LEN}-byte bpf_map_def"
            )));
        }
        let data = section_bytes(elf, &sections, shndx)?;
        let def = data
            .get(value..value + MAP_DEF_LEN)
            .ok_or_else(|| malformed(&format!("{name} runs past the maps section")))?;
        let mut fields = [0u32; 7];
        for (i, field) in fields.iter_mut().enumerate() {
            *field = u32_at(def, i * 4).ok_or_else(|| malformed("truncated bpf_map_def"))?;
        }
        return Ok(fields);
    }
    Err(FerrumError::Degraded(format!(
        "map {name} missing from the eBPF ELF"
    )))
}

const SHT_SYMTAB: u32 = 2;
const STT_OBJECT: u8 = 1;
const SYM_ENTRY_LEN: usize = 24;

struct ElfSection {
    name_off: usize,
    kind: u32,
    offset: usize,
    size: usize,
    link: usize,
    entsize: usize,
}

fn elf_sections(elf: &[u8]) -> Result<Vec<ElfSection>> {
    if elf.get(..4) != Some(b"\x7fELF") || elf.get(4) != Some(&2) || elf.get(5) != Some(&1) {
        return Err(malformed("not an ELF64 little-endian object"));
    }
    let shoff = u64_at(elf, 0x28).ok_or_else(|| malformed("truncated ELF header"))? as usize;
    let shentsize = u16_at(elf, 0x3a).ok_or_else(|| malformed("truncated ELF header"))? as usize;
    let shnum = u16_at(elf, 0x3c).ok_or_else(|| malformed("truncated ELF header"))? as usize;
    if shentsize < 64 {
        return Err(malformed("section headers are shorter than an Elf64_Shdr"));
    }
    (0..shnum)
        .map(|i| {
            let base = shoff + i * shentsize;
            Ok(ElfSection {
                name_off: u32_at(elf, base).ok_or_else(|| malformed("truncated section header"))?
                    as usize,
                kind: u32_at(elf, base + 4).ok_or_else(|| malformed("truncated section header"))?,
                offset: u64_at(elf, base + 24)
                    .ok_or_else(|| malformed("truncated section header"))?
                    as usize,
                size: u64_at(elf, base + 32).ok_or_else(|| malformed("truncated section header"))?
                    as usize,
                link: u32_at(elf, base + 40).ok_or_else(|| malformed("truncated section header"))?
                    as usize,
                entsize: u64_at(elf, base + 56)
                    .ok_or_else(|| malformed("truncated section header"))?
                    as usize,
            })
        })
        .collect()
}

fn section_bytes<'a>(elf: &'a [u8], sections: &[ElfSection], index: usize) -> Result<&'a [u8]> {
    let section = sections
        .get(index)
        .ok_or_else(|| malformed("section index out of range"))?;
    elf.get(section.offset..section.offset + section.size)
        .ok_or_else(|| malformed("section runs past the end of the eBPF ELF"))
}

fn cstr_at(strtab: &[u8], off: usize) -> Option<&str> {
    let tail = strtab.get(off..)?;
    let end = tail.iter().position(|&b| b == 0)?;
    core::str::from_utf8(&tail[..end]).ok()
}

fn u16_at(data: &[u8], off: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(off..off.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(off..off.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn u64_at(data: &[u8], off: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(off..off.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn malformed(what: &str) -> FerrumError {
    FerrumError::Degraded(format!("eBPF ELF map inspection: {what}"))
}

/// Owns the loaded programs and maps; dropping it detaches everything.
#[cfg(feature = "attach")]
pub struct KernelHandle {
    bpf: Bpf,
    /// Mirror of what this handle actually wrote into `ferrum_cgroups`; the
    /// next plan is diffed against it, so a failed sync is not forgotten.
    container_cgroups: BTreeSet<u64>,
    /// Syscalls with no tracepoint on this arch or in this kernel's tracefs,
    /// hence unhooked here.
    unhooked_syscalls: Vec<&'static str>,
}

#[cfg(feature = "attach")]
impl KernelHandle {
    /// Load a compiled `ferrum-ebpf-progs` ELF and attach every tracepoint
    /// this host has. A missing program or a failed attach still aborts the
    /// whole handle.
    ///
    /// The map definitions are checked against [`REQUIRED_MAPS`] *before*
    /// the ELF is loaded: an ELF whose maps disagree with this userspace is
    /// never put in the kernel, and no handle is returned for it.
    pub fn attach(elf: &[u8]) -> Result<Self> {
        let arch = SyscallArch::host().ok_or_else(|| {
            FerrumError::Degraded(
                "no syscall decode table for this host arch; refusing to attach".into(),
            )
        })?;
        Self::attach_for_arch(elf, arch)
    }

    /// Attach the tracepoints that exist on `arch` *and* on this kernel.
    ///
    /// Two different absences, one answer. A syscall the arch does not have
    /// (`open` on aarch64) has no tracepoint to attach to; so does a syscall
    /// this kernel was built without — no `CONFIG_MODULES` means no
    /// `init_module`/`finit_module` and no tracepoint for either, which was
    /// measured on a Firecracker microVM where the arch table said the
    /// syscalls exist and the whole attach failed. Either way the hook is
    /// skipped and reported by [`Self::unhooked_syscalls`]; treating it as
    /// fatal left the node with no hooks at all, the whole runtime plane dead.
    ///
    /// Absence is established from tracefs *before* anything is loaded, never
    /// inferred from a failure. Every other attach failure is still fatal, and
    /// a host with no tracefs to read skips nothing: "the tracepoint is not
    /// there" must not widen into "swallow attach errors".
    pub fn attach_for_arch(elf: &[u8], arch: SyscallArch) -> Result<Self> {
        verify_map_defs(elf)?;
        let mut unhooked = crate::tracepoints_absent_on_arch(arch);
        let mut wanted = crate::tracepoints_for_arch(arch);
        wanted.retain(|tp| {
            if crate::tracepoint_in_tracefs(tp.1, tp.2) != Some(false) {
                return true;
            }
            unhooked.push(crate::tracepoint_syscall(tp).unwrap_or(tp.2));
            false
        });
        if wanted.is_empty() {
            return Err(FerrumError::Degraded(format!(
                "no datapath tracepoint on this node: {unhooked:?} are absent from {} or \
                 from this kernel; the runtime plane would be blind",
                arch.as_str()
            )));
        }
        let mut bpf = Bpf::load(elf).map_err(|err| degraded("load eBPF ELF", err))?;
        for (prog, category, name) in wanted {
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
            unhooked_syscalls: unhooked,
        })
    }

    /// Datapath syscalls with no hook on this node — absent from the arch, or
    /// from this kernel's tracefs. Non-empty means rules naming them are dead
    /// here, which is a Degraded fact, not a healthy one.
    pub fn unhooked_syscalls(&self) -> &[&'static str] {
        &self.unhooked_syscalls
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
        for garbage in [&b"not an ELF"[..], &[][..]] {
            match KernelHandle::attach(garbage) {
                Err(FerrumError::Degraded(msg)) => {
                    assert!(msg.contains("not an ELF64"), "{msg}")
                }
                other => panic!("expected Degraded, got {:?}", other.map(|_| ())),
            }
        }
    }

    /// Minimal ELF64LE with a `maps` section and a symtab describing it, so
    /// the inspection the agent runs before every attach is covered by the
    /// ordinary stable build, which has no compiled bpf ELF.
    fn elf_with_maps(defs: &[(&str, [u32; 7])]) -> Vec<u8> {
        let names: Vec<&str> = defs.iter().map(|(name, _)| *name).collect();
        let mut strtab = vec![0u8];
        let mut name_offsets = Vec::new();
        for name in &names {
            name_offsets.push(strtab.len());
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }

        let mut shstrtab = vec![0u8];
        let mut section_name_off = Vec::new();
        for name in [".shstrtab", "maps", ".symtab", ".strtab"] {
            section_name_off.push(shstrtab.len());
            shstrtab.extend_from_slice(name.as_bytes());
            shstrtab.push(0);
        }

        let mut maps = Vec::new();
        let mut values = Vec::new();
        for (_, def) in defs {
            values.push(maps.len());
            for field in def {
                maps.extend_from_slice(&field.to_le_bytes());
            }
        }

        let mut symtab = vec![0u8; SYM_ENTRY_LEN];
        for (i, _) in defs.iter().enumerate() {
            let mut entry = Vec::new();
            entry.extend_from_slice(&(name_offsets[i] as u32).to_le_bytes());
            entry.push(0x10 | STT_OBJECT); // GLOBAL | OBJECT
            entry.push(0);
            entry.extend_from_slice(&2u16.to_le_bytes()); // maps section index
            entry.extend_from_slice(&(values[i] as u64).to_le_bytes());
            entry.extend_from_slice(&(MAP_DEF_LEN as u64).to_le_bytes());
            assert_eq!(entry.len(), SYM_ENTRY_LEN);
            symtab.extend_from_slice(&entry);
        }

        // [0] null, [1] .shstrtab, [2] maps, [3] .symtab, [4] .strtab
        let bodies = [&shstrtab, &maps, &symtab, &strtab];
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        let mut offsets = Vec::new();
        for body in bodies {
            offsets.push(elf.len());
            elf.extend_from_slice(body);
        }

        let shoff = elf.len();
        let mut header = |name_off: usize, kind: u32, offset: usize, size: usize, link: usize| {
            let mut shdr = vec![0u8; 64];
            shdr[0..4].copy_from_slice(&(name_off as u32).to_le_bytes());
            shdr[4..8].copy_from_slice(&kind.to_le_bytes());
            shdr[24..32].copy_from_slice(&(offset as u64).to_le_bytes());
            shdr[32..40].copy_from_slice(&(size as u64).to_le_bytes());
            shdr[40..44].copy_from_slice(&(link as u32).to_le_bytes());
            elf.extend_from_slice(&shdr);
        };
        header(0, 0, 0, 0, 0);
        header(section_name_off[0], 3, offsets[0], shstrtab.len(), 0);
        header(section_name_off[1], 1, offsets[1], maps.len(), 0);
        header(section_name_off[2], SHT_SYMTAB, offsets[2], symtab.len(), 4);
        header(section_name_off[3], 3, offsets[3], strtab.len(), 0);

        elf[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        elf[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        elf[0x3c..0x3e].copy_from_slice(&5u16.to_le_bytes());
        elf[0x3e..0x40].copy_from_slice(&1u16.to_le_bytes());
        elf
    }

    fn required_defs() -> Vec<(&'static str, [u32; 7])> {
        REQUIRED_MAPS
            .iter()
            .map(|m| {
                (
                    m.name,
                    [m.map_type, m.key_size, m.value_size, m.max_entries, 0, 0, 0],
                )
            })
            .collect()
    }

    #[test]
    fn an_elf_declaring_the_required_maps_is_accepted() {
        let elf = elf_with_maps(&required_defs());
        verify_map_defs(&elf).expect("matching ELF");
        for expected in REQUIRED_MAPS {
            assert_eq!(elf_map_def(&elf, expected.name).expect("def"), *expected);
        }
    }

    /// Every field of every required map is load-bearing: a drifted key width
    /// or a shrunken ring is not a cosmetic difference, it is a datapath that
    /// no longer means what this crate reads.
    #[test]
    fn any_drifted_map_field_refuses_the_elf() {
        for map in 0..REQUIRED_MAPS.len() {
            for field in 0..4 {
                let mut defs = required_defs();
                defs[map].1[field] ^= 1;
                let elf = elf_with_maps(&defs);
                match verify_map_defs(&elf) {
                    Err(FerrumError::Degraded(msg)) => {
                        assert!(msg.contains(REQUIRED_MAPS[map].name), "{msg}");
                    }
                    other => panic!(
                        "{} field {field} drifted but was accepted: {:?}",
                        REQUIRED_MAPS[map].name,
                        other.map(|_| ())
                    ),
                }
            }
        }
    }

    #[test]
    fn a_missing_map_refuses_the_elf() {
        let mut defs = required_defs();
        defs.remove(0);
        match verify_map_defs(&elf_with_maps(&defs)) {
            Err(FerrumError::Degraded(msg)) => {
                assert!(msg.contains(MAP_EVENTS) && msg.contains("missing"), "{msg}");
            }
            other => panic!("expected Degraded, got {:?}", other.map(|_| ())),
        }
    }

    /// A truncated or non-ELF blob must be Degraded, never a panic: the agent
    /// reads this file from disk and an unreadable file is not a crash.
    #[test]
    fn malformed_elf_is_degraded_not_a_panic() {
        let elf = elf_with_maps(&required_defs());
        for len in [0usize, 4, 32, 64, elf.len() / 2, elf.len() - 1] {
            assert!(verify_map_defs(&elf[..len]).is_err(), "len {len} accepted");
        }
        assert!(verify_map_defs(b"not an ELF").is_err());
    }
}
