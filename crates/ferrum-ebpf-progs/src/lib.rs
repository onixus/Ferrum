//! eBPF map names and ring-buffer layout, shared by the bpf-target programs
//! in `src/main.rs` and the userspace decoder in `ferrum-ebpf`.
//!
//! This lib stays `no_std`, allocation-free, and buildable on stable 1.75.
//! aya-ebpf is linked only for `target_arch = "bpf"` (see Cargo.toml), which
//! requires nightly + build-std; the default host build never compiles it.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub const MAP_EVENTS: &str = "ferrum_events";
pub const MAP_RULES: &str = "ferrum_rules";
/// Single-slot array holding the agent's own tgid; programs flag matching
/// events `EVENT_FLAG_AGENT_SELF`. Zero means "not yet configured".
pub const MAP_SELF: &str = "ferrum_self";
/// cgroup ids known to belong to pod containers (fed from the userspace
/// cgroup→pod index); programs flag matching events `EVENT_FLAG_CONTAINER`.
pub const MAP_CGROUPS: &str = "ferrum_cgroups";

/// In-kernel drop counter (per-CPU, single slot; userspace sums the CPUs).
/// Userspace must surface this; never fail-open on flood.
pub const EVENTS_DROPPED_TOTAL: &str = "events_dropped_total";

/// Ring capacity: kernel requires a power-of-2 multiple of the page size.
pub const EVENTS_RING_BYTES: u32 = 1 << 18;
pub const CGROUPS_MAX_ENTRIES: u32 = 65536;

pub const ACTION_ALLOW: u8 = 0;
pub const ACTION_AUDIT: u8 = 1;
pub const ACTION_DENY: u8 = 2;
pub const ACTION_KILL: u8 = 3;
pub const ACTION_ISOLATE: u8 = 4;

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;

pub const EVENT_FLAG_CONTAINER: u8 = 1 << 0;
pub const EVENT_FLAG_AGENT_SELF: u8 = 1 << 1;
/// The `path` buffer does not hold the whole argument: the string did not fit
/// in `PATH_LEN` (head kept), or the pointer could not be read at all
/// (`-EFAULT`, buffer left empty). One flag for both, because either way the
/// bytes present are not the argument; userspace separates the two by whether
/// the buffer is empty, and must not decide any path predicate against an
/// empty one.
///
/// Truncation is NOT an error return. `bpf_probe_read_user_str` truncates and
/// reports the buffer size, which is inside the bounds `aya_ebpf`'s wrapper
/// checks, so the wrapper answers `Ok` — measured on Linux 6.18/x86_64, a
/// 384-byte `openat` pathname arrived as a 255-byte head with this flag
/// unset. The datapath therefore sets it on a read that filled the buffer,
/// not only on one that failed.
///
/// An object built before that fix sets nothing, so userspace does not trust
/// the flag alone: `ferrum_ebpf::path_truncated` also reads the buffer shape
/// — the helper spends the last byte on a terminator, so a string with
/// nowhere to put one did not fit. A node still running a pre-fix object
/// after a rolling upgrade is therefore covered without waiting for its image
/// to be replaced. Keep the two in step: this flag and that derivation state
/// the same comparison, one against the length the helper returned and one
/// against the bytes that arrived.
pub const EVENT_FLAG_PATH_TRUNCATED: u8 = 1 << 2;

/// Layout stamp carried by every ring record in `Event::_pad`.
///
/// The bpf ELF is built out of tree and shipped in the image; nothing else
/// joins it to the decoder, so the record carries the join itself. Bump this
/// BY HAND whenever any `Event` field moves, changes width or changes meaning
/// — a same-size layout with reordered fields is exactly the drift the record
/// length cannot catch. The decoder refuses any other value outright: there is
/// one ELF per image, so a mismatch is refused, never negotiated.
///
/// The high byte is a fixed marker; the low byte is the layout generation.
/// Both bytes are outside the `EVENT_FLAG_*` range so a stamp slot filled from
/// a flags byte (a shifted or zeroed record) can never read as valid.
pub const DATAPATH_ABI: u16 = 0xFE10;

/// Ring-buffer record. No `String`; fixed buffers only.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Event {
    pub cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub syscall_nr: u32,
    pub action: u8,
    pub flags: u8,
    /// Layout stamp, always [`DATAPATH_ABI`]; see `decode_event`.
    pub _pad: u16,
    pub comm: [u8; COMM_LEN],
    pub path: [u8; PATH_LEN],
}

impl Event {
    pub const fn new() -> Self {
        Self {
            cgroup_id: 0,
            pid: 0,
            tgid: 0,
            syscall_nr: 0,
            action: ACTION_DENY,
            flags: 0,
            _pad: DATAPATH_ABI,
            comm: [0; COMM_LEN],
            path: [0; PATH_LEN],
        }
    }

    pub const fn in_container(self) -> bool {
        self.flags & EVENT_FLAG_CONTAINER != 0
    }

    pub const fn agent_self(self) -> bool {
        self.flags & EVENT_FLAG_AGENT_SELF != 0
    }

    pub const fn path_truncated(self) -> bool {
        self.flags & EVENT_FLAG_PATH_TRUNCATED != 0
    }
}

impl Default for Event {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn map_names() {
        assert_eq!(MAP_EVENTS, "ferrum_events");
        assert_eq!(MAP_RULES, "ferrum_rules");
        assert_eq!(MAP_SELF, "ferrum_self");
        assert_eq!(MAP_CGROUPS, "ferrum_cgroups");
        assert_eq!(EVENTS_DROPPED_TOTAL, "events_dropped_total");
        assert!(EVENTS_RING_BYTES.is_power_of_two());
    }

    #[test]
    fn event_is_fixed_layout() {
        assert_eq!(size_of::<Event>(), 296);
        let event = Event::new();
        assert_eq!(event.action, ACTION_DENY);
        assert_eq!(event._pad, DATAPATH_ABI);
        assert!(!event.in_container());
        assert!(!event.agent_self());
        assert!(!event.path_truncated());
    }

    #[test]
    fn flags_are_distinct_bits_of_one_byte() {
        let all = EVENT_FLAG_CONTAINER | EVENT_FLAG_AGENT_SELF | EVENT_FLAG_PATH_TRUNCATED;
        assert_eq!(all.count_ones(), 3);
        let mut event = Event::new();
        event.flags = EVENT_FLAG_PATH_TRUNCATED;
        assert!(event.path_truncated());
        assert!(!event.in_container());
        assert!(!event.agent_self());
    }

    /// A record whose stamp slot was filled from a flags byte, or left as the
    /// zero padding an older datapath wrote, must not read as a valid stamp.
    #[test]
    fn abi_stamp_is_not_confusable_with_flags_or_zero() {
        assert_ne!(DATAPATH_ABI, 0);
        let all_flags = EVENT_FLAG_CONTAINER | EVENT_FLAG_AGENT_SELF;
        for byte in DATAPATH_ABI.to_ne_bytes() {
            assert!(byte > all_flags, "stamp byte {byte:#04x} is in flag range");
        }
    }
}
