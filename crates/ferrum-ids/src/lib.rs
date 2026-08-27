use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! id_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            pub fn new(v: impl Into<String>) -> Self {
                Self(v.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_newtype!(ClusterId);
id_newtype!(PolicyId);
id_newtype!(RuleId);
id_newtype!(TenantId);
id_newtype!(Digest);

pub const AGENT_ABI: u32 = 1;
pub const ADMISSION_ABI: u32 = 1;

/// Syscalls the eBPF datapath actually hooks, sorted, no duplicates.
///
/// A runtime rule naming anything outside this set compiles, signs and loads,
/// and then never fires: no tracepoint ever produces such an event. The set is
/// therefore part of `AGENT_ABI` — move one and the other moves with it, or
/// bundles built against the old set silently stop matching.
pub const DATAPATH_SYSCALLS: &[&str] = &[
    "bpf",
    "execve",
    "execveat",
    "finit_module",
    "init_module",
    "open",
    "openat",
];

/// A datapath syscall only some architectures have. A rule naming one is
/// enforced on `arches` and dead everywhere else, while the signed bundle is
/// one artifact for the whole cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchRestrictedSyscall {
    pub syscall: &'static str,
    pub arches: &'static [&'static str],
    /// Syscall covering the same operation on every arch, when one exists.
    pub portable_companion: Option<&'static str>,
}

pub const ARCH_RESTRICTED_SYSCALLS: &[ArchRestrictedSyscall] = &[ArchRestrictedSyscall {
    syscall: "open",
    arches: &["x86_64"],
    portable_companion: Some("openat"),
}];

pub fn is_datapath_syscall(name: &str) -> bool {
    DATAPATH_SYSCALLS.contains(&name)
}

pub fn arch_restricted_syscall(name: &str) -> Option<&'static ArchRestrictedSyscall> {
    ARCH_RESTRICTED_SYSCALLS.iter().find(|r| r.syscall == name)
}

/// Datapath syscalls observable on `arch`.
pub fn datapath_syscalls_for_arch(arch: &str) -> Vec<&'static str> {
    DATAPATH_SYSCALLS
        .iter()
        .copied()
        .filter(|name| match arch_restricted_syscall(name) {
            Some(r) => r.arches.contains(&arch),
            None => true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datapath_syscalls_are_sorted_unique_and_non_empty() {
        assert!(!DATAPATH_SYSCALLS.is_empty());
        let mut sorted = DATAPATH_SYSCALLS.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, DATAPATH_SYSCALLS.to_vec(), "keep the list sorted");
        sorted.dedup();
        assert_eq!(sorted.len(), DATAPATH_SYSCALLS.len(), "duplicate syscall");
        assert!(DATAPATH_SYSCALLS.iter().all(|s| !s.trim().is_empty()));
    }

    #[test]
    fn arch_restrictions_name_real_datapath_syscalls() {
        for r in ARCH_RESTRICTED_SYSCALLS {
            assert!(is_datapath_syscall(r.syscall), "{}", r.syscall);
            assert!(!r.arches.is_empty(), "{}", r.syscall);
            if let Some(companion) = r.portable_companion {
                assert!(is_datapath_syscall(companion), "{companion}");
                assert!(arch_restricted_syscall(companion).is_none());
            }
        }
    }

    #[test]
    fn aarch64_loses_open_only() {
        let x86 = datapath_syscalls_for_arch("x86_64");
        let arm = datapath_syscalls_for_arch("aarch64");
        assert_eq!(x86, DATAPATH_SYSCALLS.to_vec());
        assert!(!arm.contains(&"open"));
        assert!(arm.contains(&"openat"));
        assert_eq!(arm.len(), DATAPATH_SYSCALLS.len() - 1);
    }
}
