//! eBPF map names and ring-buffer layout.
//!
//! aya-ebpf is not linked: the workspace rust-toolchain is stable 1.75, and
//! aya-ebpf requires nightly. This crate stays `no_std` and allocation-free
//! on the syscall path. Kernel attach lives in userspace as `Err(Degraded)`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub const MAP_EVENTS: &str = "ferrum_events";
pub const MAP_RULES: &str = "ferrum_rules";

/// In-kernel drop counter. Userspace must surface this; never fail-open on flood.
pub const EVENTS_DROPPED_TOTAL: &str = "events_dropped_total";

pub const ACTION_ALLOW: u8 = 0;
pub const ACTION_AUDIT: u8 = 1;
pub const ACTION_DENY: u8 = 2;
pub const ACTION_KILL: u8 = 3;
pub const ACTION_ISOLATE: u8 = 4;

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;

pub const EVENT_FLAG_CONTAINER: u8 = 1 << 0;
pub const EVENT_FLAG_AGENT_SELF: u8 = 1 << 1;

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
            _pad: 0,
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
        assert_eq!(EVENTS_DROPPED_TOTAL, "events_dropped_total");
    }

    #[test]
    fn event_is_fixed_layout() {
        assert_eq!(size_of::<Event>(), 296);
        let event = Event::new();
        assert_eq!(event.action, ACTION_DENY);
        assert!(!event.in_container());
        assert!(!event.agent_self());
    }
}
