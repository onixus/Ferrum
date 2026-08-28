//! Ring records for replay: a logical event turned into the exact bytes the
//! datapath writes into `ferrum_events`, through the shipping `encode_event`.
//!
//! Nothing here lives in the fixture library: it exists to feed the agent's
//! own decode path, so it must not become a second wire format the product
//! depends on.

use ferrum_ebpf::{
    encode_event, syscall_name, Event, SyscallArch, EVENT_FLAG_AGENT_SELF, EVENT_FLAG_CONTAINER,
    EVENT_FLAG_PATH_TRUNCATED,
};

/// Upper bound of the reverse search. Every hooked nr on both arches is far
/// below it. The nr is looked up instead of written down because a constant
/// in a test drifts from the decode table without anything failing.
const NR_SCAN_MAX: u32 = 1024;

/// The nr the decode table maps to `name` on `arch`, or `None` when the
/// syscall does not exist there (`open` on aarch64).
pub fn syscall_nr(arch: SyscallArch, name: &str) -> Option<u32> {
    (0..NR_SCAN_MAX).find(|&nr| syscall_name(arch, nr) == Some(name))
}

#[derive(Debug, Clone)]
pub struct RecordBuilder {
    pub syscall: String,
    pub comm: Vec<u8>,
    pub path: Vec<u8>,
    pub in_container: bool,
    pub agent_self: bool,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    /// `None` follows the datapath: the flag is set exactly when the path did
    /// not fit. `Some` forces it, which is only honest for proving that the
    /// flag — and not the bytes — is what makes the verdict.
    pub path_truncated: Option<bool>,
}

impl RecordBuilder {
    pub fn new(syscall: &str) -> Self {
        Self {
            syscall: syscall.into(),
            comm: Vec::new(),
            path: Vec::new(),
            in_container: true,
            agent_self: false,
            pid: 0,
            tgid: 0,
            cgroup_id: 0,
            path_truncated: None,
        }
    }

    pub fn comm(mut self, comm: &str) -> Self {
        self.comm = comm.as_bytes().to_vec();
        self
    }

    /// A comm the kernel copied verbatim: not necessarily valid UTF-8.
    pub fn comm_raw(mut self, comm: &[u8]) -> Self {
        self.comm = comm.to_vec();
        self
    }

    pub fn path(mut self, path: &str) -> Self {
        self.path = path.as_bytes().to_vec();
        self
    }

    /// Overrides what the path length implies. Use it to build the record the
    /// kernel cannot: the same truncated bytes without the flag.
    pub fn path_truncated(mut self, path_truncated: bool) -> Self {
        self.path_truncated = Some(path_truncated);
        self
    }

    pub fn in_container(mut self, in_container: bool) -> Self {
        self.in_container = in_container;
        self
    }

    pub fn agent_self(mut self, agent_self: bool) -> Self {
        self.agent_self = agent_self;
        self
    }

    pub fn process(mut self, pid: u32, tgid: u32) -> Self {
        self.pid = pid;
        self.tgid = tgid;
        self
    }

    pub fn cgroup(mut self, cgroup_id: u64) -> Self {
        self.cgroup_id = cgroup_id;
        self
    }

    /// `None` when `arch` has no nr for this syscall.
    pub fn event(&self, arch: SyscallArch) -> Option<Event> {
        Some(self.event_with_nr(syscall_nr(arch, &self.syscall)?))
    }

    /// The same record with the nr forced, for nrs no table maps.
    pub fn event_with_nr(&self, nr: u32) -> Event {
        let mut event = Event::new();
        event.cgroup_id = self.cgroup_id;
        event.pid = self.pid;
        event.tgid = self.tgid;
        event.syscall_nr = nr;
        event.flags = 0;
        if self.in_container {
            event.flags |= EVENT_FLAG_CONTAINER;
        }
        if self.agent_self {
            event.flags |= EVENT_FLAG_AGENT_SELF;
        }
        // comm comes from `bpf_get_current_comm`, which has no overflow to
        // report: only the path carries a truncation flag.
        let _ = fill(&mut event.comm, &self.comm);
        let path_overflow = fill(&mut event.path, &self.path);
        if self.path_truncated.unwrap_or(path_overflow) {
            event.flags |= EVENT_FLAG_PATH_TRUNCATED;
        }
        event
    }

    pub fn try_build(&self, arch: SyscallArch) -> Option<Vec<u8>> {
        self.event(arch).as_ref().map(encode_event)
    }

    pub fn build(&self, arch: SyscallArch) -> Vec<u8> {
        self.try_build(arch)
            .unwrap_or_else(|| panic!("{} has no nr on {}", self.syscall, arch.as_str()))
    }

    pub fn build_with_nr(&self, nr: u32) -> Vec<u8> {
        encode_event(&self.event_with_nr(nr))
    }
}

/// A value longer than the buffer is written the way the kernel writes it.
///
/// `bpf_probe_read_user_str` always terminates: it copies at most `len() - 1`
/// bytes and spends the last on the NUL, so an over-long value arrives as a
/// `len() - 1` byte head *plus a terminator*, never as a full buffer of bytes.
/// Writing the full buffer here made testkit's truncated records one byte
/// longer than any the kernel can produce, which was harmless only while
/// nothing read the buffer's shape — the decoder now derives truncation from
/// exactly that shape, so the two must agree.
///
/// Returns whether the value overflowed. A value that fills `len() - 1` bytes
/// already overflows: its terminator took the last byte, the helper then
/// returns the buffer size, and neither the datapath nor the decoder can tell
/// it from a value that was cut.
fn fill(dst: &mut [u8], src: &[u8]) -> bool {
    let n = src.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
    src.len() >= dst.len() - 1
}
