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

/// Byte offset of `flags` inside a wire record.
///
/// Public because of the one thing that cannot be done any other way honestly:
/// building the record an ELF predating cycle 8 writes for an over-long path.
/// Re-encoding an `Event` with the bit dropped produces a *synthesised* record
/// and proves nothing about a producer, so the join takes the record this
/// kernel wrote and clears the bit in the bytes. That needs the offset, and
/// this is it — the same one [`decode_event`] reads `flags` from, so the two
/// cannot drift apart.
pub const EVENT_FLAGS_OFFSET: usize = 21;

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
    event.flags = bytes[EVENT_FLAGS_OFFSET];
    event._pad = u16::from_ne_bytes(bytes[22..24].try_into().expect("2 bytes"));
    event.comm.copy_from_slice(&bytes[24..24 + COMM_LEN]);
    event
        .path
        .copy_from_slice(&bytes[24 + COMM_LEN..24 + COMM_LEN + PATH_LEN]);
    Ok(event)
}

/// The ABI stamp a full-length record carries when it disagrees with this
/// decoder's, `None` when the record is either the right build or not a
/// full-length record at all.
///
/// `decode_event` refuses both a malformed record and a stamp mismatch as
/// `Integrity`, and the two do not mean the same thing. A short or garbled
/// record is one lost event. A stamp mismatch is proof, from the first record,
/// that the attached ELF is not the build this decoder was compiled against,
/// so *every* record it ever writes will be refused. The stamp lives in an
/// instruction immediate, not in the ELF's map definitions, so this is the
/// only place it can be observed; nothing here relaxes the refusal, it only
/// reads the one field whose offset is fixed for every build of the record.
pub fn abi_stamp_mismatch(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != EVENT_WIRE_LEN {
        return None;
    }
    let abi = u16::from_ne_bytes(bytes[22..24].try_into().ok()?);
    (abi != DATAPATH_ABI).then_some(abi)
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

/// Whether this record's path did not fit, read from the flag AND from the
/// buffer, because for one producer still deployed the flag is not written.
///
/// `bpf_probe_read_user_str` always terminates what it copies: it writes at
/// most `PATH_LEN` bytes and spends the last of them on the NUL. So a string
/// that reached the last usable byte — `PATH_LEN - 1` bytes before a
/// terminator, or no terminator at all — is a string the buffer could not
/// prove whole. That is the comparison the datapath's `emit()` makes on the
/// helper's return value (`len < PATH_LEN - 1` fits), restated against the
/// bytes that arrived, so the two halves cannot disagree about one record.
///
/// It is derived rather than trusted because the flag is the *newer* half. An
/// ELF built before `emit()` learned that the helper reports truncation as
/// success writes the head and no flag, and after a rolling upgrade this
/// decoder runs in front of exactly that object — measured on Linux 6.18: a
/// 384-byte `openat` pathname arrived as a 255-byte head with the flag unset,
/// leaving `path_suffix` free to reject a `docker.sock` rule on a tail nobody
/// saw. Reading the buffer closes that window on objects already deployed,
/// which no new kernel flag can reach.
///
/// The cost is a path that really did occupy exactly `PATH_LEN - 1` bytes: it
/// is called truncated, so every rule naming a path applies to it and the
/// decision is marked `path_unknown`. That is the trade this flag already
/// makes — over-enforce with a signal rather than under-enforce in silence —
/// and the datapath makes it identically, because the helper's return value
/// cannot separate those two cases either.
pub fn path_truncated(event: &Event) -> bool {
    event.path_truncated() || path_bytes(&event.path).len() >= PATH_LEN - 1
}

/// Bridge a decoded record to the policy-evaluation view. Unknown syscall nrs
/// map to [`SYSCALL_UNKNOWN`] instead of failing: the record still reaches the
/// spec's default action.
///
/// `path_truncated` is [`path_truncated`], not the raw flag: see there for why
/// the buffer is read as well.
pub fn syscall_event(event: &Event, arch: SyscallArch) -> SyscallEvent<'_> {
    SyscallEvent {
        syscall: syscall_name(arch, event.syscall_nr).unwrap_or(SYSCALL_UNKNOWN),
        comm: nul_trimmed_str(&event.comm),
        path: nul_trimmed_str(&event.path),
        in_container: event.in_container(),
        agent_self: event.agent_self(),
        path_truncated: path_truncated(event),
    }
}

/// Structural half of the same record: cgroup for identity lookup, pid/tgid
/// for a reaction. Kept separate from `SyscallEvent`, whose shape is part of
/// the policy-evaluation contract other crates instantiate.
///
/// `path_truncated` is read the same way as in [`syscall_event`]; the two
/// views of one record must not disagree about whether its path is whole.
pub fn event_meta(event: &Event) -> EventMeta {
    EventMeta {
        cgroup_id: event.cgroup_id,
        pid: event.pid,
        tgid: event.tgid,
        in_container: event.in_container(),
        agent_self: event.agent_self(),
        path_truncated: path_truncated(event),
    }
}

/// Bytes the datapath wrote, up to the first NUL. Not the string view: a
/// non-UTF-8 tail is still bytes the helper copied, and buffer shape must be
/// read from the bytes, never from what survives UTF-8 validation.
fn path_bytes(buf: &[u8]) -> &[u8] {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..end]
}

/// Bytes up to the first NUL; a non-UTF-8 tail is cut, not propagated, so a
/// hostile comm/path cannot poison the export path.
fn nul_trimmed_str(buf: &[u8]) -> &str {
    let trimmed = path_bytes(buf);
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

    /// The classifier must answer for exactly the records `decode_event`
    /// refuses on the stamp, and for no others: a short record is a lost
    /// event, not proof of a wrong ELF.
    #[test]
    fn abi_stamp_mismatch_names_only_a_wrong_build() {
        let wire = encode_event(&sample());
        assert_eq!(abi_stamp_mismatch(&wire), None, "this build's own record");
        assert_eq!(
            abi_stamp_mismatch(&[]),
            None,
            "a short record is not a stamp"
        );
        assert_eq!(abi_stamp_mismatch(&wire[..EVENT_WIRE_LEN - 1]), None);
        for stale in [0u16, DATAPATH_ABI - 1, DATAPATH_ABI + 1, u16::MAX] {
            let mut wire = encode_event(&sample());
            wire[22..24].copy_from_slice(&stale.to_ne_bytes());
            assert_eq!(abi_stamp_mismatch(&wire), Some(stale));
            assert!(decode_event(&wire).is_err(), "and it is still refused");
        }
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

    /// The rolling-upgrade window, closed here rather than in the kernel.
    ///
    /// The record below is what an ELF built before `emit()` flagged a short
    /// read writes for an over-long path: the head fills the buffer and no
    /// flag is set. The datapath in this tree no longer produces it, but a
    /// rolling upgrade — new agent, old ELF still in the image — puts this
    /// decoder in front of the object that does, and a new kernel flag cannot
    /// reach an object already deployed. So the fact is derived from the
    /// buffer: the helper spends the last byte on a terminator, so a string
    /// occupying `PATH_LEN - 1` bytes had nowhere to put one.
    ///
    /// Both views must derive it, and both must agree with the flagged record
    /// they are standing in for: the flag becomes the *only* difference that
    /// makes no difference.
    #[test]
    fn a_buffer_filling_path_is_read_as_truncated_without_the_flag() {
        let mut event = sample();
        event.path = [0; PATH_LEN];
        let head = format!("/var/run/{}", "./".repeat(130));
        event.path[..PATH_LEN - 1].copy_from_slice(&head.as_bytes()[..PATH_LEN - 1]);
        assert_eq!(
            event.flags & ferrum_ebpf_progs::EVENT_FLAG_PATH_TRUNCATED,
            0,
            "a pre-fix ELF sets nothing"
        );

        let back = decode_event(&encode_event(&event)).expect("decode");
        let view = syscall_event(&back, SyscallArch::X86_64);
        assert_eq!(view.path.len(), PATH_LEN - 1, "the head fills the buffer");
        assert!(view.path_truncated, "no flag, but the buffer says so");
        assert!(event_meta(&back).path_truncated, "and both views say it");
        assert!(path_truncated(&back));

        // The same record from the current datapath: the flag is the only
        // thing that changed, and it changes nothing.
        let mut flagged = event;
        flagged.flags |= ferrum_ebpf_progs::EVENT_FLAG_PATH_TRUNCATED;
        let back = decode_event(&encode_event(&flagged)).expect("decode");
        assert!(syscall_event(&back, SyscallArch::X86_64).path_truncated);
        assert!(event_meta(&back).path_truncated);
    }

    /// `EVENT_FLAGS_OFFSET` names the byte the decoder reads `flags` from, and
    /// `attach_join.rs` reaches into a live ring record at that offset to
    /// produce what a pre-fix ELF writes without rebuilding the record from
    /// parts. An offset that drifted would silently clear some other field —
    /// the low byte of `_pad`, which is the ABI stamp — and the join would then
    /// be proving something about a record no producer emits. So it is pinned
    /// here against the encoder: masking that one byte changes `flags` and
    /// nothing else.
    #[test]
    fn the_flags_offset_addresses_flags_and_nothing_else() {
        let mut event = sample();
        event.flags =
            ferrum_ebpf_progs::EVENT_FLAG_CONTAINER | ferrum_ebpf_progs::EVENT_FLAG_PATH_TRUNCATED;
        let wire = encode_event(&event);

        let mut cleared = wire.clone();
        cleared[EVENT_FLAGS_OFFSET] &= !ferrum_ebpf_progs::EVENT_FLAG_PATH_TRUNCATED;
        assert_eq!(
            wire.iter().zip(&cleared).filter(|(a, b)| a != b).count(),
            1,
            "clearing the bit at EVENT_FLAGS_OFFSET touched more than one byte"
        );

        let back = decode_event(&cleared).expect("decode");
        assert_eq!(back.flags, ferrum_ebpf_progs::EVENT_FLAG_CONTAINER);
        assert_eq!(back.cgroup_id, event.cgroup_id);
        assert_eq!(back.pid, event.pid);
        assert_eq!(back.tgid, event.tgid);
        assert_eq!(back.syscall_nr, event.syscall_nr);
        assert_eq!(back.action, event.action);
        assert_eq!(back._pad, event._pad, "the ABI stamp survived");
        assert_eq!(back.comm, event.comm);
        assert_eq!(back.path, event.path);
    }

    /// The derivation is the datapath's own comparison restated, so it must
    /// break where `emit()` breaks and nowhere else: `emit()` calls a read
    /// short when `len < PATH_LEN - 1`, so a path one byte under the buffer's
    /// usable size is whole and every longer one is not.
    ///
    /// The lower bound matters as much as the upper: a decoder that called
    /// every path truncated would pin the node to Degraded and make every
    /// path rule unconditional, which is not enforcement, it is noise.
    #[test]
    fn the_derivation_breaks_where_the_datapath_breaks() {
        for len in [0usize, 1, 7, PATH_LEN - 2] {
            let mut event = sample();
            event.path = [0; PATH_LEN];
            event.path[..len].fill(b'a');
            assert!(
                !path_truncated(&event),
                "{len} bytes plus a terminator fits in {PATH_LEN}"
            );
            assert!(!syscall_event(&event, SyscallArch::X86_64).path_truncated);
            assert!(!event_meta(&event).path_truncated);
        }

        // PATH_LEN - 1 bytes: the terminator took the last byte, so the
        // datapath's helper returned the buffer size and `emit()` flags it.
        // No NUL at all is the same shape one byte further on.
        for len in [PATH_LEN - 1, PATH_LEN] {
            let mut event = sample();
            event.path = [0; PATH_LEN];
            event.path[..len].fill(b'a');
            assert!(path_truncated(&event), "{len} bytes had nowhere to end");
        }

        // An unreadable pointer left the buffer empty and only the flag says
        // so. The derivation must not swallow it: `path_unreadable` in
        // `eval` is exactly "flag set and buffer empty".
        let mut efault = sample();
        efault.path = [0; PATH_LEN];
        efault.flags |= ferrum_ebpf_progs::EVENT_FLAG_PATH_TRUNCATED;
        assert!(path_truncated(&efault));
        let view = syscall_event(&efault, SyscallArch::X86_64);
        assert!(view.path_truncated);
        assert!(view.path.is_empty());
    }

    /// Buffer shape is a fact about bytes, not about UTF-8. A hostile path
    /// that fills the buffer with invalid UTF-8 is trimmed to nothing for the
    /// export, and must still be read as truncated — otherwise writing one
    /// bad byte into a long path turns the derivation off.
    #[test]
    fn a_non_utf8_full_buffer_is_still_truncated() {
        let mut event = sample();
        event.path = [0xff; PATH_LEN];
        event.path[..2].copy_from_slice(b"/a");
        let view = syscall_event(&event, SyscallArch::X86_64);
        assert_eq!(view.path, "/a", "the tail is cut for the export");
        assert!(view.path_truncated);
        assert!(event_meta(&event).path_truncated);
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
