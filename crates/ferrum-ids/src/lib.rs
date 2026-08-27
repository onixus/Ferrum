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

/// Longest `comm` a rule may name. The kernel copies at most
/// `TASK_COMM_LEN` bytes including the NUL, so a longer literal describes a
/// string `bpf_get_current_comm()` can never produce: the rule compiles,
/// signs, loads and never fires.
pub const COMM_MATCH_MAX: usize = 15;

/// Longest path fragment a rule may name. The datapath path buffer is
/// `PATH_LEN` bytes including the NUL; a longer literal cannot be contained
/// in, prefixed by, or suffixed to anything the datapath reports.
pub const PATH_MATCH_MAX: usize = 255;

/// First `comm` literal the kernel buffer cannot hold. Byte length, not chars:
/// the kernel copies bytes.
pub fn unobservable_comm<S: AsRef<str>>(named: &[S]) -> Option<(&str, usize)> {
    first_over_limit(named, COMM_MATCH_MAX)
}

/// First path fragment longer than the datapath path buffer can carry.
pub fn unobservable_path_pattern<S: AsRef<str>>(named: &[S]) -> Option<(&str, usize)> {
    first_over_limit(named, PATH_MATCH_MAX)
}

fn first_over_limit<S: AsRef<str>>(named: &[S], limit: usize) -> Option<(&str, usize)> {
    named
        .iter()
        .map(|s| s.as_ref())
        .find(|s| s.len() > limit)
        .map(|s| (s, s.len()))
}

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
    fn match_bounds_are_the_kernel_buffers_minus_the_nul() {
        for (what, bound) in [("comm", COMM_MATCH_MAX), ("path", PATH_MATCH_MAX)] {
            assert!(bound > 0, "{what} bound must leave room for a predicate");
            // One byte shorter than the buffer: the NUL is the only byte lost.
            assert!(bound < usize::MAX, "{what}");
        }
        assert_eq!(
            [COMM_MATCH_MAX, PATH_MATCH_MAX]
                .iter()
                .copied()
                .max()
                .expect("two bounds"),
            PATH_MATCH_MAX,
            "a path fragment can be longer than a comm"
        );
    }

    #[test]
    fn a_predicate_one_byte_over_the_bound_is_unobservable() {
        assert_eq!(unobservable_comm(&["", "sh"]), None);
        let exact = "x".repeat(COMM_MATCH_MAX);
        assert_eq!(unobservable_comm(&[exact.clone()]), None);
        let over = "x".repeat(COMM_MATCH_MAX + 1);
        assert_eq!(
            unobservable_comm(&[exact.clone(), over.clone()]),
            Some((over.as_str(), COMM_MATCH_MAX + 1))
        );
        assert_eq!(
            unobservable_comm(&["kubectl-exec-helper"]),
            Some(("kubectl-exec-helper", 19))
        );

        assert_eq!(unobservable_path_pattern::<&str>(&[]), None);
        let exact = "p".repeat(PATH_MATCH_MAX);
        assert_eq!(unobservable_path_pattern(&[exact.clone()]), None);
        let over = "p".repeat(PATH_MATCH_MAX + 1);
        assert_eq!(
            unobservable_path_pattern(&[over.clone()]),
            Some((over.as_str(), PATH_MATCH_MAX + 1))
        );
    }

    #[test]
    fn bounds_are_counted_in_bytes_not_chars() {
        // 8 chars, 16 bytes: the kernel buffer holds bytes, so this comm is
        // one byte past what `bpf_get_current_comm` can ever report.
        let multibyte = "\u{00e9}".repeat(8);
        assert_eq!(multibyte.chars().count(), 8);
        assert_eq!(multibyte.len(), 16);
        assert_eq!(
            unobservable_comm(&[multibyte.clone()]),
            Some((multibyte.as_str(), 16))
        );
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
