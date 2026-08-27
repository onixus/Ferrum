//! Safe decode of `ferrum_events` ring records into `SyscallEvent`.
//!
//! The wire format is the `#[repr(C)]` `Event` written by the bpf programs on
//! the same machine, so integers use native endianness. Decoding is
//! field-by-field (no unsafe transmute) and fails closed on any size mismatch
//! or on any record whose layout stamp is not the one this build decodes.

use crate::eval::{EventMeta, SyscallEvent};
use ferrum_common::{FerrumError, Result};
use ferrum_ebpf_progs::{Event, COMM_LEN, DATAPATH_ABI, PATH_LEN};

/// Exact size of one ring record.
pub const EVENT_WIRE_LEN: usize = core::mem::size_of::<Event>();

/// Name reported when a record carries a syscall nr outside the decode table.
/// It matches no rule list, so the spec's default action applies.
pub const SYSCALL_UNKNOWN: &str = "unknown";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallArch {
    X86_64,
    Aarch64,
}

impl SyscallArch {
    /// Arch of this build, `None` on hosts the table does not cover.
    pub fn host() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Self::Aarch64)
        } else {
            None
        }
    }

    /// Spelled as `ferrum_ids::datapath_syscalls_for_arch` expects it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// syscall nr → name for the syscalls the datapath programs hook.
pub fn syscall_name(arch: SyscallArch, nr: u32) -> Option<&'static str> {
    match arch {
        SyscallArch::X86_64 => match nr {
            2 => Some("open"),
            59 => Some("execve"),
            175 => Some("init_module"),
            257 => Some("openat"),
            313 => Some("finit_module"),
            321 => Some("bpf"),
            322 => Some("execveat"),
            _ => None,
        },
        // aarch64 has no plain open; openat only.
        SyscallArch::Aarch64 => match nr {
            56 => Some("openat"),
            105 => Some("init_module"),
            221 => Some("execve"),
            273 => Some("finit_module"),
            280 => Some("bpf"),
            281 => Some("execveat"),
            _ => None,
        },
    }
}

/// Decode one ring record. Anything but exactly `EVENT_WIRE_LEN` bytes is
/// Integrity: a partial record must never become a half-parsed event.
///
/// The length alone does not pin the layout — fields can move inside a
/// same-size record — so the record's [`DATAPATH_ABI`] stamp is checked too. A
/// record from a datapath that does not agree with this decoder field for
/// field is refused, never decoded best effort: there is one ELF per image, so
/// the answer to a mismatch is refuse, not adapt.
pub fn decode_event(bytes: &[u8]) -> Result<Event> {
    if bytes.len() != EVENT_WIRE_LEN {
        return Err(FerrumError::Integrity(format!(
            "ring record must be {EVENT_WIRE_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let abi = u16::from_ne_bytes(bytes[22..24].try_into().expect("2 bytes"));
    if abi != DATAPATH_ABI {
        return Err(FerrumError::Integrity(format!(
            "ring record carries datapath ABI {abi:#06x}, this agent decodes {DATAPATH_ABI:#06x}: \
             the attached eBPF ELF is not the build this agent was compiled against"
        )));
    }
    let mut event = Event::new();
    event.cgroup_id = u64::from_ne_bytes(bytes[0..8].try_into().expect("8 bytes"));
    event.pid = u32::from_ne_bytes(bytes[8..12].try_into().expect("4 bytes"));
    event.tgid = u32::from_ne_bytes(bytes[12..16].try_into().expect("4 bytes"));
    event.syscall_nr = u32::from_ne_bytes(bytes[16..20].try_into().expect("4 bytes"));
    event.action = bytes[20];
    event.flags = bytes[21];
    event._pad = u16::from_ne_bytes(bytes[22..24].try_into().expect("2 bytes"));
    event.comm.copy_from_slice(&bytes[24..24 + COMM_LEN]);
    event
        .path
        .copy_from_slice(&bytes[24 + COMM_LEN..24 + COMM_LEN + PATH_LEN]);
    Ok(event)
}

/// Encode an `Event` in the ring record layout (tests, replay, fixtures).
pub fn encode_event(event: &Event) -> Vec<u8> {
    let mut out = Vec::with_capacity(EVENT_WIRE_LEN);
    out.extend_from_slice(&event.cgroup_id.to_ne_bytes());
    out.extend_from_slice(&event.pid.to_ne_bytes());
    out.extend_from_slice(&event.tgid.to_ne_bytes());
    out.extend_from_slice(&event.syscall_nr.to_ne_bytes());
    out.push(event.action);
    out.push(event.flags);
    out.extend_from_slice(&event._pad.to_ne_bytes());
    out.extend_from_slice(&event.comm);
    out.extend_from_slice(&event.path);
    debug_assert_eq!(out.len(), EVENT_WIRE_LEN);
    out
}

/// Bridge a decoded record to the policy-evaluation view. Unknown syscall nrs
/// map to [`SYSCALL_UNKNOWN`] instead of failing: the record still reaches the
/// spec's default action.
pub fn syscall_event(event: &Event, arch: SyscallArch) -> SyscallEvent<'_> {
    SyscallEvent {
        syscall: syscall_name(arch, event.syscall_nr).unwrap_or(SYSCALL_UNKNOWN),
        comm: nul_trimmed_str(&event.comm),
        path: nul_trimmed_str(&event.path),
        in_container: event.in_container(),
        agent_self: event.agent_self(),
        path_truncated: event.path_truncated(),
    }
}

/// Structural half of the same record: cgroup for identity lookup, pid/tgid
/// for a reaction. Kept separate from `SyscallEvent`, whose shape is part of
/// the policy-evaluation contract other crates instantiate.
pub fn event_meta(event: &Event) -> EventMeta {
    EventMeta {
        cgroup_id: event.cgroup_id,
        pid: event.pid,
        tgid: event.tgid,
        in_container: event.in_container(),
        agent_self: event.agent_self(),
        path_truncated: event.path_truncated(),
    }
}

/// Bytes up to the first NUL; a non-UTF-8 tail is cut, not propagated, so a
/// hostile comm/path cannot poison the export path.
fn nul_trimmed_str(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let trimmed = &buf[..end];
    match core::str::from_utf8(trimmed) {
        Ok(s) => s,
        Err(err) => core::str::from_utf8(&trimmed[..err.valid_up_to()]).unwrap_or(""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_ebpf_progs::{EVENT_FLAG_AGENT_SELF, EVENT_FLAG_CONTAINER};

    fn sample() -> Event {
        let mut event = Event::new();
        event.cgroup_id = 0xdead_beef_cafe;
        event.pid = 41;
        event.tgid = 42;
        event.syscall_nr = 59;
        event.flags = EVENT_FLAG_CONTAINER;
        event.comm[..2].copy_from_slice(b"sh");
        event.path[..7].copy_from_slice(b"/bin/sh");
        event
    }

    #[test]
    fn round_trip_event_to_syscall_event() {
        let event = sample();
        let wire = encode_event(&event);
        // The record is an ABI: userspace and the bpf programs are built
        // separately and only agree by size.
        assert_eq!(EVENT_WIRE_LEN, 296);
        assert_eq!(wire.len(), EVENT_WIRE_LEN);
        let back = decode_event(&wire).expect("decode");
        assert_eq!(back.cgroup_id, event.cgroup_id);
        assert_eq!(back.pid, event.pid);
        assert_eq!(back.tgid, event.tgid);
        assert_eq!(back.syscall_nr, event.syscall_nr);
        assert_eq!(back.flags, event.flags);
        assert_eq!(back.comm, event.comm);
        assert_eq!(back.path, event.path);
        let view = syscall_event(&back, SyscallArch::X86_64);
        assert_eq!(
            view,
            SyscallEvent {
                syscall: "execve",
                comm: "sh",
                path: "/bin/sh",
                in_container: true,
                agent_self: false,
                path_truncated: false,
            }
        );
    }

    #[test]
    fn event_meta_keeps_pid_and_tgid() {
        let event = sample();
        let meta = event_meta(&event);
        assert_eq!(meta.cgroup_id, event.cgroup_id);
        assert_eq!(meta.pid, 41);
        assert_eq!(meta.tgid, 42);
        assert!(meta.in_container);
        assert!(!meta.agent_self);
        // The cgroup-only shim must never carry a killable tgid.
        assert_eq!(EventMeta::from(7u64).tgid, 0);
    }

    #[test]
    fn truncated_or_oversize_record_is_integrity() {
        let wire = encode_event(&sample());
        for bad in [&wire[..EVENT_WIRE_LEN - 1], &[][..]] {
            match decode_event(bad) {
                Err(FerrumError::Integrity(_)) => {}
                other => panic!("expected Integrity, got {:?}", other.map(|_| ())),
            }
        }
        let mut long = wire.clone();
        long.push(0);
        assert!(decode_event(&long).is_err());
    }

    /// A datapath whose record layout drifted stamps something else. Its
    /// records must not decode at all: a same-size layout with moved fields
    /// decodes to a plausible-looking event with the wrong cgroup and tgid,
    /// and nothing downstream can tell.
    #[test]
    fn stale_abi_stamp_is_integrity_not_a_decoded_event() {
        let mut wire = encode_event(&sample());
        for stale in [0u16, DATAPATH_ABI - 1, DATAPATH_ABI + 1, u16::MAX] {
            wire[22..24].copy_from_slice(&stale.to_ne_bytes());
            match decode_event(&wire) {
                Err(FerrumError::Integrity(msg)) => {
                    assert!(
                        msg.contains(&format!("{stale:#06x}")),
                        "message lost the record's ABI: {msg}"
                    );
                    assert!(
                        msg.contains(&format!("{DATAPATH_ABI:#06x}")),
                        "message lost the decoder's ABI: {msg}"
                    );
                }
                other => panic!("expected Integrity, got {:?}", other.map(|_| ())),
            }
        }
    }

    /// The stamp slot sits next to `flags`; a record shifted by two bytes, or
    /// one an older datapath left as zero padding, must not read as valid.
    #[test]
    fn a_flags_byte_in_the_stamp_slot_is_not_a_valid_stamp() {
        let mut wire = encode_event(&sample());
        for flags in 0u8..=(EVENT_FLAG_CONTAINER | EVENT_FLAG_AGENT_SELF) {
            wire[22..24].copy_from_slice(&u16::from(flags).to_ne_bytes());
            assert!(
                decode_event(&wire).is_err(),
                "flags {flags} read as a stamp"
            );
            wire[22..24].copy_from_slice(&(u16::from(flags) << 8).to_ne_bytes());
            assert!(
                decode_event(&wire).is_err(),
                "flags {flags} read as a stamp in the high byte"
            );
        }
    }

    /// The stamp travels with the record: an `Event::new()`-derived record
    /// carries it without the producer knowing, and round-trips.
    #[test]
    fn current_abi_stamp_round_trips() {
        let event = sample();
        assert_eq!(event._pad, DATAPATH_ABI);
        let back = decode_event(&encode_event(&event)).expect("decode");
        assert_eq!(back._pad, DATAPATH_ABI);
        assert_eq!(back.cgroup_id, event.cgroup_id);
        assert_eq!(back.tgid, event.tgid);
    }

    #[test]
    fn unknown_syscall_nr_does_not_panic() {
        let mut event = sample();
        event.syscall_nr = u32::MAX;
        let view = syscall_event(&event, SyscallArch::X86_64);
        assert_eq!(view.syscall, SYSCALL_UNKNOWN);
        let view = syscall_event(&event, SyscallArch::Aarch64);
        assert_eq!(view.syscall, SYSCALL_UNKNOWN);
    }

    #[test]
    fn syscall_tables_cover_both_arches() {
        for (nr, name) in [
            (2u32, "open"),
            (59, "execve"),
            (175, "init_module"),
            (257, "openat"),
            (313, "finit_module"),
            (321, "bpf"),
            (322, "execveat"),
        ] {
            assert_eq!(syscall_name(SyscallArch::X86_64, nr), Some(name));
        }
        for (nr, name) in [
            (56u32, "openat"),
            (105, "init_module"),
            (221, "execve"),
            (273, "finit_module"),
            (280, "bpf"),
            (281, "execveat"),
        ] {
            assert_eq!(syscall_name(SyscallArch::Aarch64, nr), Some(name));
        }
        assert_eq!(syscall_name(SyscallArch::Aarch64, 2), None);
        assert!(SyscallArch::host().is_some());
    }

    /// `COMM_MATCH_MAX` / `PATH_MATCH_MAX` and `COMM_LEN` / `PATH_LEN` are two
    /// independent spellings of one kernel fact, and this is the only place
    /// they meet. Widening a buffer without moving the contract (or the
    /// reverse) has to fail the build, not ship a rule that cannot match.
    #[test]
    fn match_bounds_track_the_datapath_buffers() {
        assert_eq!(ferrum_ids::COMM_MATCH_MAX, COMM_LEN - 1);
        assert_eq!(ferrum_ids::PATH_MATCH_MAX, PATH_LEN - 1);
    }

    /// A record whose path did not fit reaches userspace as a valid-looking
    /// head. Only the flag distinguishes it, so it must survive the wire.
    #[test]
    fn path_truncation_survives_encode_decode() {
        let mut event = sample();
        event.flags |= ferrum_ebpf_progs::EVENT_FLAG_PATH_TRUNCATED;
        event.path = [b'a'; PATH_LEN];
        let back = decode_event(&encode_event(&event)).expect("decode");
        assert!(back.path_truncated());
        let view = syscall_event(&back, SyscallArch::X86_64);
        assert!(view.path_truncated);
        assert_eq!(
            view.path.len(),
            PATH_LEN,
            "no NUL: the whole buffer is path"
        );
        assert!(event_meta(&back).path_truncated);

        let clean = decode_event(&encode_event(&sample())).expect("decode");
        assert!(!syscall_event(&clean, SyscallArch::X86_64).path_truncated);
        assert!(!event_meta(&clean).path_truncated);
    }

    /// The decode table is one of the three places the datapath's syscall set
    /// is written down. It must cover exactly what `DATAPATH_SYSCALLS` claims
    /// for that arch: a name it cannot produce is a rule that never fires, a
    /// name it produces but the list omits is a rule nobody can validate.
    #[test]
    fn decode_table_matches_datapath_syscalls_per_arch() {
        // Every hooked nr on both arches is well under this bound.
        const NR_MAX: u32 = 1024;
        for (arch, arch_name) in [
            (SyscallArch::X86_64, "x86_64"),
            (SyscallArch::Aarch64, "aarch64"),
        ] {
            let mut decoded: Vec<&str> = (0..NR_MAX)
                .filter_map(|nr| syscall_name(arch, nr))
                .collect();
            decoded.sort_unstable();
            decoded.dedup();
            let want = ferrum_ids::datapath_syscalls_for_arch(arch_name);
            assert_eq!(decoded, want, "decode table drifted on {arch_name}");
        }
    }

    #[test]
    fn flags_and_nul_trim() {
        let mut event = sample();
        event.flags = EVENT_FLAG_AGENT_SELF;
        event.comm = *b"ferrum-agent\0\0\0\0";
        let view = syscall_event(&event, SyscallArch::X86_64);
        assert!(view.agent_self);
        assert!(!view.in_container);
        assert_eq!(view.comm, "ferrum-agent");

        // Invalid UTF-8 tail is cut, and a NUL-free buffer is bounded.
        event.comm = [0xff; 16];
        let view = syscall_event(&event, SyscallArch::X86_64);
        assert_eq!(view.comm, "");
        event.comm = *b"sh\xff\xff\0\0\0\0\0\0\0\0\0\0\0\0";
        let view = syscall_event(&event, SyscallArch::X86_64);
        assert_eq!(view.comm, "sh");
    }
}
