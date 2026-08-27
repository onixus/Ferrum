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
}

pub const ARCH_RESTRICTED_SYSCALLS: &[ArchRestrictedSyscall] = &[ArchRestrictedSyscall {
    syscall: "open",
    arches: &["x86_64"],
}];

/// Spellings of one kernel operation. Where an arch serves several of them the
/// caller picks the number freely and the datapath reports the one it was
/// called with, so a rule naming part of a class is bypassed by calling another
/// member: `openat` alone misses `open(2)` on x86_64, `open` alone is dead on
/// aarch64. The gates therefore demand the whole class, in both directions.
pub const SYSCALL_EQUIVALENCE_CLASSES: &[&[&str]] = &[&["open", "openat"]];

pub fn is_datapath_syscall(name: &str) -> bool {
    DATAPATH_SYSCALLS.contains(&name)
}

pub fn arch_restricted_syscall(name: &str) -> Option<&'static ArchRestrictedSyscall> {
    ARCH_RESTRICTED_SYSCALLS.iter().find(|r| r.syscall == name)
}

pub fn syscall_equivalence_class(name: &str) -> Option<&'static [&'static str]> {
    SYSCALL_EQUIVALENCE_CLASSES
        .iter()
        .copied()
        .find(|class| class.contains(&name))
}

/// First `(listed, missing)` pair where `listed` is a syscall the rule names
/// and `missing` another spelling of the same operation it does not. `None`
/// means every class the rule touches is named in full.
pub fn uncovered_equivalent_syscall<S: AsRef<str>>(
    named: &[S],
) -> Option<(&'static str, &'static str)> {
    let names: Vec<&str> = named.iter().map(|s| s.as_ref().trim()).collect();
    for class in SYSCALL_EQUIVALENCE_CLASSES {
        let Some(listed) = class.iter().copied().find(|m| names.contains(m)) else {
            continue;
        };
        if let Some(missing) = class.iter().copied().find(|m| !names.contains(m)) {
            return Some((listed, missing));
        }
    }
    None
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
            // An arch-restricted syscall with no equivalent elsewhere would be
            // unenforceable on the other arches with nothing to name instead.
            let class = syscall_equivalence_class(r.syscall)
                .unwrap_or_else(|| panic!("{} needs an equivalence class", r.syscall));
            assert!(class.iter().any(|m| arch_restricted_syscall(m).is_none()));
        }
    }

    #[test]
    fn equivalence_classes_name_real_datapath_syscalls() {
        for class in SYSCALL_EQUIVALENCE_CLASSES {
            assert!(class.len() > 1, "a one-member class constrains nothing");
            for member in *class {
                assert!(is_datapath_syscall(member), "{member}");
                assert_eq!(syscall_equivalence_class(member), Some(*class));
            }
        }
    }

    #[test]
    fn partial_equivalence_class_is_reported_in_both_directions() {
        assert_eq!(
            uncovered_equivalent_syscall(&["openat"]),
            Some(("openat", "open"))
        );
        assert_eq!(
            uncovered_equivalent_syscall(&[" open ".to_string()]),
            Some(("open", "openat"))
        );
        assert_eq!(uncovered_equivalent_syscall(&["open", "openat"]), None);
        assert_eq!(uncovered_equivalent_syscall(&["execve"]), None);
        assert_eq!(uncovered_equivalent_syscall::<&str>(&[]), None);
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
