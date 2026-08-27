//! Userspace FEBP loader. Last-known-good in memory; kernel pins are not implied.

#![deny(unsafe_code)]

mod envelope;
mod eval;
mod event;
mod kernel;
mod loader;
mod prefilter;
mod spec;

pub use envelope::{extract_febp, BUNDLE_FORMAT, BUNDLE_MAGIC};
pub use eval::{
    decide, decide_with, matched_action, matched_action_with, selector_match, selector_matches,
    Decision, EventMeta, SelectorMatch, SyscallEvent,
};
pub use event::{
    abi_stamp_mismatch, decode_event, encode_event, event_meta, syscall_event, syscall_name,
    SyscallArch, EVENT_WIRE_LEN, SYSCALL_UNKNOWN,
};
pub use ferrum_ebpf_progs::{
    Event, CGROUPS_MAX_ENTRIES, COMM_LEN, DATAPATH_ABI, EVENTS_DROPPED_TOTAL, EVENTS_RING_BYTES,
    EVENT_FLAG_AGENT_SELF, EVENT_FLAG_CONTAINER, EVENT_FLAG_PATH_TRUNCATED, MAP_CGROUPS,
    MAP_EVENTS, MAP_RULES, MAP_SELF, PATH_LEN,
};
pub use ferrum_ids::{AGENT_ABI, DATAPATH_SYSCALLS};
pub use kernel::{
    elf_map_def, plan_cgroup_sync, verify_map_defs, CgroupSyncPlan, MapDef, SyncStats, MAP_DEF_LEN,
    REQUIRED_MAPS,
};
#[cfg(feature = "attach")]
pub use kernel::{KernelHandle, RingReader};
pub use loader::{LoadedBundle, Loader, PIN_PATH};
pub use prefilter::{prefilter_image, PrefilterImage, PATH_BEARING_SYSCALLS};
pub use spec::{
    parse_febp, parse_febp_with, Action, DeadRules, EbpfSpec, ImageSelector, LabelRequirement,
    LabelSelector, Mode, PolicySelector, Rule, EBPF_MAGIC,
};

use ferrum_common::Result;
use ferrum_ids::Digest;

/// (program symbol in the ELF, tracepoint category, tracepoint name).
///
/// Lives outside the `attach` gate so ELF inspection (CI symbol check,
/// `tests/elf_inspect.rs`) can use the same list without CAP_BPF or aya.
pub const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("ferrum_sys_enter_execve", "syscalls", "sys_enter_execve"),
    (
        "ferrum_sys_enter_execveat",
        "syscalls",
        "sys_enter_execveat",
    ),
    ("ferrum_sys_enter_open", "syscalls", "sys_enter_open"),
    ("ferrum_sys_enter_openat", "syscalls", "sys_enter_openat"),
    ("ferrum_sys_enter_bpf", "syscalls", "sys_enter_bpf"),
    (
        "ferrum_sys_enter_init_module",
        "syscalls",
        "sys_enter_init_module",
    ),
    (
        "ferrum_sys_enter_finit_module",
        "syscalls",
        "sys_enter_finit_module",
    ),
];

/// One entry of [`TRACEPOINTS`]: program symbol, category, tracepoint name.
pub type Tracepoint = (&'static str, &'static str, &'static str);

/// The syscall a tracepoint observes, or `None` if the name is not a
/// `sys_enter_*` hook.
pub fn tracepoint_syscall(tracepoint: &Tracepoint) -> Option<&'static str> {
    tracepoint.2.strip_prefix("sys_enter_")
}

/// Tracepoints that exist on `arch`.
///
/// A syscall absent on an arch has no tracepoint there, and attaching to it
/// fails with ENOENT. Attaching the whole set unconditionally therefore left
/// the agent with no hooks at all on such a host, so the arch-restricted ones
/// are filtered out here rather than allowed to fail: a real attach error
/// must stay an error.
pub fn tracepoints_for_arch(arch: SyscallArch) -> Vec<&'static Tracepoint> {
    let observable = ferrum_ids::datapath_syscalls_for_arch(arch.as_str());
    TRACEPOINTS
        .iter()
        .filter(|tp| match tracepoint_syscall(tp) {
            Some(syscall) => observable.contains(&syscall),
            None => true,
        })
        .collect()
}

/// Tracepoints skipped on `arch` because the syscall does not exist there.
pub fn tracepoints_absent_on_arch(arch: SyscallArch) -> Vec<&'static str> {
    let observable = ferrum_ids::datapath_syscalls_for_arch(arch.as_str());
    TRACEPOINTS
        .iter()
        .filter_map(tracepoint_syscall)
        .filter(|syscall| !observable.contains(syscall))
        .collect()
}

/// Parse `spec` as FEBP and install it on `loader` as last-known-good.
pub fn load_bundle(loader: &mut Loader, digest: &Digest, spec: &[u8]) -> Result<()> {
    loader.load_bundle(digest, spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_common::FerrumError;
    use ferrum_k8smeta::WorkloadIdentity;
    use std::fs;

    fn digest_of(bytes: &[u8]) -> Digest {
        ferrum_crypto::bundle_digest(bytes)
    }

    /// Third copy of the datapath's syscall set: what is attached. A hook here
    /// with no entry in `DATAPATH_SYSCALLS` is a syscall no rule may name; an
    /// entry there with no hook is a rule that validates and never fires.
    ///
    /// Per arch, not against the whole list: `open` has no tracepoint on
    /// aarch64, and pinning the attach set to the full list is what made a
    /// single missing tracepoint kill every hook there.
    #[test]
    fn tracepoints_match_datapath_syscalls_per_arch() {
        for arch in [SyscallArch::X86_64, SyscallArch::Aarch64] {
            let mut hooked: Vec<&str> = tracepoints_for_arch(arch)
                .iter()
                .map(|tp| {
                    assert_eq!(tp.1, "syscalls");
                    tracepoint_syscall(tp).expect("tracepoint name is sys_enter_<syscall>")
                })
                .collect();
            hooked.sort_unstable();
            let mut want = ferrum_ids::datapath_syscalls_for_arch(arch.as_str());
            want.sort_unstable();
            assert_eq!(hooked, want, "TRACEPOINTS drifted on {}", arch.as_str());
            assert!(!hooked.is_empty(), "no hooks left on {}", arch.as_str());
        }
    }

    /// The skip list is exactly what the arch lacks, and nothing more: a
    /// tracepoint dropped for any other reason is a silently blind hook.
    #[test]
    fn only_arch_missing_tracepoints_are_skipped() {
        assert!(tracepoints_absent_on_arch(SyscallArch::X86_64).is_empty());
        assert_eq!(
            tracepoints_absent_on_arch(SyscallArch::Aarch64),
            vec!["open"]
        );
        for arch in [SyscallArch::X86_64, SyscallArch::Aarch64] {
            assert_eq!(
                tracepoints_for_arch(arch).len() + tracepoints_absent_on_arch(arch).len(),
                TRACEPOINTS.len()
            );
        }
    }

    struct Writer(Vec<u8>);

    impl Writer {
        fn new() -> Self {
            Self(Vec::new())
        }
        fn put_magic(&mut self, magic: &[u8; 4]) {
            self.0.extend_from_slice(magic);
        }
        fn put_u8(&mut self, v: u8) {
            self.0.push(v);
        }
        fn put_u16(&mut self, v: u16) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn put_u32(&mut self, v: u32) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn put_i32(&mut self, v: i32) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn put_bool(&mut self, v: bool) {
            self.put_u8(u8::from(v));
        }
        fn put_str(&mut self, s: &str) {
            self.put_u16(s.len() as u16);
            self.0.extend_from_slice(s.as_bytes());
        }
        fn put_str_list(&mut self, items: &[&str]) {
            self.put_u16(items.len() as u16);
            for item in items {
                self.put_str(item);
            }
        }
        fn finish(self) -> Vec<u8> {
            self.0
        }
    }

    fn put_empty_label_selector(w: &mut Writer) {
        w.put_u16(0);
        w.put_u16(0);
    }

    fn put_empty_selector(w: &mut Writer) {
        for _ in 0..4 {
            put_empty_label_selector(w);
        }
        w.put_str_list(&[]);
        w.put_bool(false);
    }

    struct RuleSpec<'a> {
        id: &'a str,
        syscalls: &'a [&'a str],
        action: Action,
        comm_in: &'a [&'a str],
        container_only: bool,
        path_prefix: &'a [&'a str],
        path_suffix: &'a [&'a str],
        not_agent_self: bool,
    }

    fn encode(
        abi: u32,
        mode: Mode,
        disabled: bool,
        default_action: Action,
        rules: &[RuleSpec<'_>],
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_magic(&EBPF_MAGIC);
        w.put_u32(abi);
        w.put_u8(mode.as_u8());
        w.put_bool(disabled);
        w.put_i32(0);
        w.put_u8(default_action.as_u8());
        put_empty_selector(&mut w);
        w.put_u16(rules.len() as u16);
        for rule in rules {
            w.put_str(rule.id);
            w.put_str_list(rule.syscalls);
            w.put_u8(rule.action.as_u8());
            w.put_str_list(rule.comm_in);
            w.put_bool(rule.container_only);
            w.put_str_list(rule.path_prefix);
            w.put_str_list(rule.path_suffix);
            w.put_bool(rule.not_agent_self);
        }
        w.finish()
    }

    fn mvp_enforce() -> Vec<u8> {
        encode(
            AGENT_ABI,
            Mode::Enforce,
            false,
            Action::Audit,
            &[
                RuleSpec {
                    id: "no-shell",
                    syscalls: &["execve", "execveat"],
                    action: Action::Kill,
                    comm_in: &["sh", "bash", "ash", "dash", "zsh"],
                    container_only: true,
                    path_prefix: &[],
                    path_suffix: &[],
                    not_agent_self: false,
                },
                RuleSpec {
                    id: "no-runtime-sock",
                    syscalls: &[],
                    action: Action::Kill,
                    comm_in: &[],
                    container_only: false,
                    path_prefix: &[],
                    path_suffix: &["docker.sock", "containerd.sock", "crio.sock"],
                    not_agent_self: false,
                },
                RuleSpec {
                    id: "no-module",
                    syscalls: &["init_module", "finit_module", "bpf"],
                    action: Action::Deny,
                    comm_in: &[],
                    container_only: false,
                    path_prefix: &[],
                    path_suffix: &[],
                    not_agent_self: true,
                },
            ],
        )
    }

    fn load_mvp(loader: &mut Loader) {
        let spec = mvp_enforce();
        load_bundle(loader, &digest_of(&spec), &spec).expect("mvp load");
    }

    fn pci_identity() -> WorkloadIdentity {
        let mut id = WorkloadIdentity {
            namespace: "prod".into(),
            pod: "web".into(),
            container: "app".into(),
            service_account: "sa".into(),
            image: "registry.internal.example/app@sha256:abc".into(),
            image_digest: "sha256:abc".into(),
            ..Default::default()
        };
        id.namespace_labels
            .insert("ferrum.io/zone".into(), "pci".into());
        id
    }

    fn ev<'a>(
        syscall: &'a str,
        comm: &'a str,
        path: &'a str,
        in_container: bool,
        agent_self: bool,
    ) -> SyscallEvent<'a> {
        SyscallEvent {
            syscall,
            comm,
            path,
            in_container,
            agent_self,
            path_truncated: false,
        }
    }

    fn assert_degraded<T: std::fmt::Debug>(result: Result<T>) {
        match result {
            Err(FerrumError::Degraded(_)) => {}
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    fn assert_compile<T: std::fmt::Debug>(result: Result<T>) {
        match result {
            Err(FerrumError::Compile(_)) => {}
            other => panic!("expected Compile, got {other:?}"),
        }
    }

    #[test]
    fn maps_are_named() {
        assert_eq!(MAP_EVENTS, "ferrum_events");
        assert_eq!(MAP_RULES, "ferrum_rules");
        assert_eq!(EVENTS_DROPPED_TOTAL, "events_dropped_total");
    }

    /// `DeadRules::Drop` relaxes exactly one thing. A rule that can match no
    /// record is dropped so the rest of a last-known-good snapshot can still
    /// be restored; a kill-all rule, a bad ABI and a malformed spec are still
    /// refused whole, because dropping those would change what the node
    /// enforces rather than only what it cannot.
    #[test]
    fn dropping_dead_rules_relaxes_nothing_else() {
        let long = format!("/{}", "a".repeat(ferrum_ids::PATH_MATCH_MAX));
        let spec = encode(
            AGENT_ABI,
            Mode::Enforce,
            false,
            Action::Allow,
            &[
                RuleSpec {
                    id: "unmatchable",
                    syscalls: &["openat"],
                    action: Action::Deny,
                    comm_in: &[],
                    container_only: false,
                    path_prefix: &[long.as_str()],
                    path_suffix: &[],
                    not_agent_self: false,
                },
                RuleSpec {
                    id: "no-proc-poke",
                    syscalls: &["openat"],
                    action: Action::Deny,
                    comm_in: &[],
                    container_only: false,
                    path_prefix: &["/proc/"],
                    path_suffix: &[],
                    not_agent_self: false,
                },
            ],
        );
        assert_compile(parse_febp(&spec));
        let (parsed, dropped) =
            parse_febp_with(&spec, DeadRules::Drop).expect("the rest of the spec still loads");
        assert_eq!(dropped.len(), 1);
        assert!(dropped[0].contains("unmatchable"));
        assert_eq!(parsed.rules.len(), 1);
        assert_eq!(parsed.rules[0].id, "no-proc-poke");
        assert_eq!(
            matched_action(&parsed, &ev("openat", "app", "/proc/1/mem", true, false)).action,
            Action::Deny
        );

        let kill_all = encode(
            AGENT_ABI,
            Mode::Enforce,
            false,
            Action::Allow,
            &[RuleSpec {
                id: "kill-all",
                syscalls: &[],
                action: Action::Kill,
                comm_in: &[],
                container_only: false,
                path_prefix: &[],
                path_suffix: &[],
                not_agent_self: false,
            }],
        );
        assert_compile(parse_febp_with(&kill_all, DeadRules::Drop));
        assert_degraded(parse_febp_with(
            &encode(AGENT_ABI + 1, Mode::Enforce, false, Action::Allow, &[]),
            DeadRules::Drop,
        ));
        assert_compile(parse_febp_with(b"XXXX", DeadRules::Drop));
    }

    #[test]
    fn parse_rejects_bad_magic_and_truncation() {
        assert_compile(parse_febp(b"XXXX"));
        let mut spec = mvp_enforce();
        spec.pop();
        assert_compile(parse_febp(&spec));
        assert_compile(parse_febp(&[]));
    }

    #[test]
    fn parse_priority_and_selector() {
        let mut w = Writer::new();
        w.put_magic(&EBPF_MAGIC);
        w.put_u32(AGENT_ABI);
        w.put_u8(Mode::Enforce.as_u8());
        w.put_bool(false);
        w.put_i32(100);
        w.put_u8(Action::Audit.as_u8());
        put_empty_label_selector(&mut w);
        w.put_u16(0);
        w.put_u16(1);
        w.put_str("ferrum.io/zone");
        w.put_str("In");
        w.put_str_list(&["pci", "secrets"]);
        put_empty_label_selector(&mut w);
        put_empty_label_selector(&mut w);
        w.put_str_list(&["registry.internal.example"]);
        w.put_bool(true);
        w.put_u16(0);
        let spec = parse_febp(&w.finish()).expect("parse");
        assert_eq!(spec.priority, 100);
        assert_eq!(spec.selector.namespace_selector.match_expressions.len(), 1);
        assert_eq!(
            spec.selector.namespace_selector.match_expressions[0].key,
            "ferrum.io/zone"
        );
        assert_eq!(
            spec.selector.namespace_selector.match_expressions[0].values,
            vec!["pci".to_string(), "secrets".to_string()]
        );
        assert_eq!(
            spec.selector.image.registries_allow,
            vec!["registry.internal.example".to_string()]
        );
        assert!(spec.selector.image.require_digest);
        assert!(spec.selector.cluster_selector.match_labels.is_empty());
        assert!(spec.rules.is_empty());
    }

    #[test]
    fn parse_rejects_abi_mismatch() {
        let spec = encode(
            AGENT_ABI.saturating_add(1),
            Mode::Enforce,
            false,
            Action::Audit,
            &[],
        );
        match parse_febp(&spec) {
            Err(FerrumError::Degraded(msg)) => {
                assert!(msg.contains("incompatible"), "{msg}");
            }
            other => panic!("expected Degraded ABI mismatch, got {other:?}"),
        }
    }

    #[test]
    fn execve_shell_is_kill() {
        let spec = parse_febp(&mvp_enforce()).expect("parse");
        let d = matched_action(&spec, &ev("execve", "sh", "/bin/sh", true, false));
        assert_eq!(d.action, Action::Kill);
        assert_eq!(d.rule_id.as_deref(), Some("no-shell"));
        let bash = matched_action(&spec, &ev("execve", "bash", "/bin/bash", true, false));
        assert_eq!(bash.action, Action::Kill);
    }

    #[test]
    fn docker_sock_is_kill() {
        let spec = parse_febp(&mvp_enforce()).expect("parse");
        let d = matched_action(
            &spec,
            &ev("openat", "app", "/var/run/docker.sock", true, false),
        );
        assert_eq!(d.action, Action::Kill);
        assert_eq!(d.rule_id.as_deref(), Some("no-runtime-sock"));
    }

    /// The datapath buffer is 256 bytes; `open("/var/run/" + "./"*130 +
    /// "docker.sock")` resolves fine in the kernel and arrives here as a head
    /// that ends in neither sock name. Without the flag `ends_with` says "no
    /// match" and the kill rule silently does not fire.
    #[test]
    fn a_truncated_path_cannot_talk_a_suffix_rule_out_of_firing() {
        let spec = parse_febp(&mvp_enforce()).expect("parse");
        let head = format!("/var/run/{}", "./".repeat(130));
        let mut event = ev("openat", "app", &head[..255], true, false);
        event.path_truncated = true;
        let d = matched_action(&spec, &event);
        assert_eq!(d.action, Action::Kill);
        assert_eq!(d.rule_id.as_deref(), Some("no-runtime-sock"));
        assert!(d.path_unknown);

        // Same bytes without the flag: the head really is the whole path, so
        // the suffix genuinely does not match. This is the regression anchor.
        let mut honest = event.clone();
        honest.path_truncated = false;
        let d = matched_action(&spec, &honest);
        assert_eq!(d.action, Action::Audit);
        assert!(d.rule_id.is_none());
        assert!(!d.path_unknown);
    }

    /// The flag says nothing about `comm` or the syscall, so it must not leak
    /// into a decision that never consulted the path.
    #[test]
    fn truncation_does_not_infect_a_decision_taken_without_the_path() {
        let spec = parse_febp(&mvp_enforce()).expect("parse");
        let long = "x".repeat(255);
        let mut event = ev("execve", "sh", &long, true, false);
        event.path_truncated = true;
        let d = matched_action(&spec, &event);
        assert_eq!(d.action, Action::Kill);
        assert_eq!(d.rule_id.as_deref(), Some("no-shell"));
        assert!(!d.path_unknown);
    }

    /// Truncation must not turn a prefix rule into a guess: the head is
    /// exactly the part a prefix looks at, and it arrived intact.
    #[test]
    fn a_prefix_rule_is_still_decided_on_a_truncated_path() {
        let spec = encode(
            AGENT_ABI,
            Mode::Enforce,
            false,
            Action::Allow,
            &[RuleSpec {
                id: "no-proc-poke",
                syscalls: &["openat"],
                action: Action::Deny,
                comm_in: &[],
                container_only: false,
                path_prefix: &["/proc/"],
                path_suffix: &[],
                not_agent_self: false,
            }],
        );
        let spec = parse_febp(&spec).expect("parse");
        let deep = format!("/proc/{}", "a".repeat(249));
        let mut hit = ev("openat", "app", &deep, true, false);
        hit.path_truncated = true;
        assert_eq!(matched_action(&spec, &hit).action, Action::Deny);
        let elsewhere = "/srv/".repeat(51);
        let mut miss = ev("openat", "app", &elsewhere, true, false);
        miss.path_truncated = true;
        let d = matched_action(&spec, &miss);
        assert_eq!(d.action, Action::Allow);
        assert!(!d.path_unknown);
    }

    /// The other half of the same flag. `bpf_probe_read_user_*` cannot fault
    /// in a non-resident page, so a path string on one (mmap, or
    /// `madvise(MADV_DONTNEED)` before the call) comes back `-EFAULT` while
    /// the syscall itself succeeds: the buffer is empty, and a prefix rule
    /// asked to decide on it would answer "no match" for every prefix there
    /// is. Nothing is known about that path, so the rule applies and says so.
    #[test]
    fn an_unreadable_path_cannot_talk_a_prefix_rule_out_of_firing() {
        let spec = encode(
            AGENT_ABI,
            Mode::Enforce,
            false,
            Action::Allow,
            &[RuleSpec {
                id: "no-proc-poke",
                syscalls: &["openat"],
                action: Action::Deny,
                comm_in: &[],
                container_only: false,
                path_prefix: &["/proc/"],
                path_suffix: &[],
                not_agent_self: false,
            }],
        );
        let spec = parse_febp(&spec).expect("parse");
        let mut unreadable = ev("openat", "app", "", true, false);
        unreadable.path_truncated = true;
        let d = matched_action(&spec, &unreadable);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.rule_id.as_deref(), Some("no-proc-poke"));
        assert!(d.path_unknown);

        // Regression anchor: an empty path with no flag is an honest record
        // from a syscall that carried no path, and must decide as before.
        let honest = ev("openat", "app", "", true, false);
        let d = matched_action(&spec, &honest);
        assert_eq!(d.action, Action::Allow);
        assert!(d.rule_id.is_none());
        assert!(!d.path_unknown);
    }

    /// Same failure against the MVP bundle: the docker.sock rule names a
    /// suffix, and an unreadable path must not silently take it out either.
    #[test]
    fn an_unreadable_path_still_kills_on_the_runtime_sock_rule() {
        let spec = parse_febp(&mvp_enforce()).expect("parse");
        let mut unreadable = ev("openat", "app", "", true, false);
        unreadable.path_truncated = true;
        let d = matched_action(&spec, &unreadable);
        assert_eq!(d.action, Action::Kill);
        assert_eq!(d.rule_id.as_deref(), Some("no-runtime-sock"));
        assert!(d.path_unknown);
    }

    #[test]
    fn bpf_not_agent_is_deny() {
        let spec = parse_febp(&mvp_enforce()).expect("parse");
        let d = matched_action(&spec, &ev("bpf", "attacker", "", true, false));
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.rule_id.as_deref(), Some("no-module"));
        let self_bpf = matched_action(&spec, &ev("bpf", "ferrum-agent", "", false, true));
        assert_eq!(self_bpf.action, Action::Audit);
        assert!(self_bpf.rule_id.is_none());
    }

    #[test]
    fn host_shell_does_not_match_container_only() {
        let spec = parse_febp(&mvp_enforce()).expect("parse");
        let d = matched_action(&spec, &ev("execve", "sh", "/bin/sh", false, false));
        assert_eq!(d.action, Action::Audit);
        assert!(d.rule_id.is_none());
    }

    #[test]
    fn audit_mode_does_not_kill() {
        let spec = encode(
            AGENT_ABI,
            Mode::Audit,
            false,
            Action::Audit,
            &[RuleSpec {
                id: "no-shell",
                syscalls: &["execve"],
                action: Action::Kill,
                comm_in: &["sh"],
                container_only: false,
                path_prefix: &[],
                path_suffix: &[],
                not_agent_self: false,
            }],
        );
        let parsed = parse_febp(&spec).expect("parse");
        assert_eq!(
            matched_action(&parsed, &ev("execve", "sh", "", true, false)).action,
            Action::Kill
        );
        assert_eq!(
            decide(
                &parsed,
                &ev("execve", "sh", "", true, false),
                &WorkloadIdentity::unknown()
            )
            .action,
            Action::Audit
        );
    }

    #[test]
    fn empty_loader_is_deny_not_allow() {
        let loader = Loader::new();
        assert!(loader.is_degraded());
        assert!(loader.last_good().is_none());
        assert_eq!(
            loader
                .decide(
                    &ev("execve", "sh", "", true, false),
                    &WorkloadIdentity::unknown()
                )
                .action,
            Action::Deny
        );
    }

    #[test]
    fn failed_initial_load_stays_deny() {
        let mut loader = Loader::new();
        let garbage = b"not-febp";
        assert_compile(loader.load_bundle(&digest_of(garbage), garbage));
        assert!(loader.is_degraded());
        assert!(loader.last_good().is_none());
        assert_eq!(
            loader
                .decide(
                    &ev("connect", "app", "", true, false),
                    &WorkloadIdentity::unknown()
                )
                .action,
            Action::Deny
        );
    }

    #[test]
    fn abi_mismatch_keeps_last_known_good() {
        let mut loader = Loader::new();
        load_mvp(&mut loader);
        assert!(!loader.is_degraded());
        let good = loader.last_good().expect("lkg").digest.clone();

        let bad = encode(99, Mode::Enforce, false, Action::Allow, &[]);
        assert_degraded(loader.load_bundle(&digest_of(&bad), &bad));
        assert!(loader.is_degraded());
        let kept = loader.last_good().expect("lkg kept");
        assert_eq!(kept.digest, good);
        assert_eq!(
            loader
                .matched_action(&ev("execve", "sh", "/bin/sh", true, false))
                .action,
            Action::Kill
        );
        assert_ne!(
            loader
                .matched_action(&ev("execve", "sh", "/bin/sh", true, false))
                .action,
            Action::Allow
        );
    }

    #[test]
    fn truncation_keeps_last_known_good() {
        let mut loader = Loader::new();
        load_mvp(&mut loader);
        let good = mvp_enforce();
        let mut truncated = good.clone();
        truncated.truncate(truncated.len() / 2);
        assert_compile(loader.load_bundle(&digest_of(&truncated), &truncated));
        assert!(loader.is_degraded());
        assert_eq!(loader.last_good().expect("lkg").digest, digest_of(&good));
    }

    #[test]
    fn digest_mismatch_keeps_lkg() {
        let mut loader = Loader::new();
        load_mvp(&mut loader);
        let good = loader.last_good().expect("lkg").digest.clone();
        let spec = mvp_enforce();
        match loader.load_bundle(&Digest::new("aa".repeat(32)), &spec) {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
        assert!(loader.is_degraded());
        assert_eq!(loader.last_good().expect("lkg").digest, good);
    }

    #[test]
    fn empty_digest_rejected() {
        let mut loader = Loader::new();
        match loader.load_bundle(&Digest::new(""), &mvp_enforce()) {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
        assert!(loader.last_good().is_none());
        assert!(loader.is_degraded());
    }

    #[test]
    fn load_bundle_does_not_write_unsigned_febp() {
        let dir = std::env::temp_dir().join(format!(
            "ferrum-ebpf-lkg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("tmpdir");
        {
            let mut loader = Loader::with_lkg_dir(&dir);
            load_mvp(&mut loader);
            assert!(!loader.is_degraded());
        }
        assert!(!dir.join("lkg.febp").exists());
        assert!(!dir.join("lkg.digest").exists());
        let restored = Loader::with_lkg_dir(&dir);
        assert!(restored.last_good().is_none());
        assert_eq!(
            restored
                .decide(
                    &ev("bpf", "x", "", true, false),
                    &WorkloadIdentity::unknown()
                )
                .action,
            Action::Deny
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn kill_all_is_rejected() {
        let spec = encode(
            AGENT_ABI,
            Mode::Enforce,
            false,
            Action::Audit,
            &[RuleSpec {
                id: "oops",
                syscalls: &[],
                action: Action::Kill,
                comm_in: &[],
                container_only: false,
                path_prefix: &[],
                path_suffix: &[],
                not_agent_self: false,
            }],
        );
        assert_compile(parse_febp(&spec));
        let mut loader = Loader::new();
        load_mvp(&mut loader);
        let good = loader.last_good().expect("lkg").digest.clone();
        assert_compile(loader.load_bundle(&digest_of(&spec), &spec));
        assert_eq!(loader.last_good().expect("lkg").digest, good);
    }

    fn one_rule(id: &str, syscalls: &[&str], action: Action) -> Vec<u8> {
        encode(
            AGENT_ABI,
            Mode::Enforce,
            false,
            Action::Audit,
            &[RuleSpec {
                id,
                syscalls,
                action,
                comm_in: &["sh"],
                container_only: false,
                path_prefix: &[],
                path_suffix: &[],
                not_agent_self: false,
            }],
        )
    }

    /// The validator and the compiler compare `trim()`ed syscall names, so
    /// `syscalls: [" execve"]` from YAML passes both gates and gets signed.
    /// The matcher has to see the same name, or the rule is dead in a bundle
    /// everything upstream called valid.
    #[test]
    fn whitespace_around_a_syscall_name_still_matches() {
        for raw in [" execve", "execve\r", "\texecve\n", "  execve  "] {
            let spec = parse_febp(&one_rule("no-shell", &[raw], Action::Kill))
                .unwrap_or_else(|err| panic!("parse {raw:?}: {err}"));
            assert_eq!(spec.rules[0].syscalls, vec!["execve".to_string()]);
            let d = matched_action(&spec, &ev("execve", "sh", "/bin/sh", true, false));
            assert_eq!(d.action, Action::Kill, "{raw:?} did not match");
            assert_eq!(d.rule_id.as_deref(), Some("no-shell"));
        }
    }

    /// Load-path copy of the compiler gate: a bundle produced by anything
    /// that calls the encoder directly must not install a rule the datapath
    /// never observes.
    #[test]
    fn unobservable_syscall_is_rejected_on_load() {
        for name in ["ptrace", "", " ", "execve2", "sys_enter_execve"] {
            match parse_febp(&one_rule("dead", &[name], Action::Deny)) {
                Err(FerrumError::Compile(msg)) => {
                    assert!(msg.contains("not hooked by the datapath"), "{msg}")
                }
                other => panic!("expected Compile for {name:?}, got {other:?}"),
            }
        }
        // Every hooked syscall still loads, whitespace included.
        for name in ferrum_ids::DATAPATH_SYSCALLS {
            parse_febp(&one_rule("ok", &[name], Action::Audit)).expect("hooked syscall loads");
            let padded = format!(" {name}\r\n");
            parse_febp(&one_rule("ok", &[padded.as_str()], Action::Audit)).expect("trimmed loads");
        }
        // Last-known-good survives the rejection.
        let spec = one_rule("dead", &["ptrace"], Action::Deny);
        let mut loader = Loader::new();
        load_mvp(&mut loader);
        let good = loader.last_good().expect("lkg").digest.clone();
        assert_compile(loader.load_bundle(&digest_of(&spec), &spec));
        assert_eq!(loader.last_good().expect("lkg").digest, good);
    }

    /// The other half of the same load-path gate. A bundle built by a compiler
    /// that predates the length bound is signed and well-formed; it must still
    /// not install a predicate no record can carry.
    #[test]
    fn an_unobservable_predicate_is_rejected_on_load() {
        let over_comm = "x".repeat(ferrum_ids::COMM_MATCH_MAX + 1);
        let over_path = "p".repeat(ferrum_ids::PATH_MATCH_MAX + 1);
        struct Case<'a> {
            what: &'a str,
            comm_in: &'a [&'a str],
            path_prefix: &'a [&'a str],
            path_suffix: &'a [&'a str],
            needle: &'a str,
        }
        let cases = [
            Case {
                what: "comm",
                comm_in: &[over_comm.as_str()],
                path_prefix: &[],
                path_suffix: &[],
                needle: "the kernel reports",
            },
            Case {
                what: "prefix",
                comm_in: &[],
                path_prefix: &[over_path.as_str()],
                path_suffix: &[],
                needle: "path buffer",
            },
            Case {
                what: "suffix",
                comm_in: &[],
                path_prefix: &[],
                path_suffix: &[over_path.as_str()],
                needle: "path buffer",
            },
        ];
        for Case {
            what,
            comm_in,
            path_prefix,
            path_suffix,
            needle,
        } in cases
        {
            let spec = encode(
                AGENT_ABI,
                Mode::Enforce,
                false,
                Action::Allow,
                &[RuleSpec {
                    id: "too-long",
                    syscalls: &[],
                    action: Action::Deny,
                    comm_in,
                    container_only: false,
                    path_prefix,
                    path_suffix,
                    not_agent_self: false,
                }],
            );
            match parse_febp(&spec) {
                Err(FerrumError::Compile(msg)) => {
                    assert!(msg.contains(needle), "{what}: {msg}");
                    // The message must name the length and the bound, not
                    // just call the rule invalid.
                    assert!(msg.contains("bytes"), "{what}: {msg}");
                }
                other => panic!("expected Compile for {what}, got {other:?}"),
            }
            // Last-known-good survives the rejection.
            let mut loader = Loader::new();
            load_mvp(&mut loader);
            let good = loader.last_good().expect("lkg").digest.clone();
            assert_compile(loader.load_bundle(&digest_of(&spec), &spec));
            assert_eq!(loader.last_good().expect("lkg").digest, good);
        }

        // Exactly at the bound still loads: the NUL is the only byte lost.
        let at_comm = "x".repeat(ferrum_ids::COMM_MATCH_MAX);
        let at_path = "p".repeat(ferrum_ids::PATH_MATCH_MAX);
        let spec = encode(
            AGENT_ABI,
            Mode::Enforce,
            false,
            Action::Allow,
            &[RuleSpec {
                id: "at-bound",
                syscalls: &[],
                action: Action::Deny,
                comm_in: &[at_comm.as_str()],
                container_only: false,
                path_prefix: &[at_path.as_str()],
                path_suffix: &[at_path.as_str()],
                not_agent_self: false,
            }],
        );
        parse_febp(&spec).expect("a predicate the buffers can hold must load");
    }

    /// Enforcing program whose namespace selector is `ferrum.io/zone In
    /// (pci, secrets)`, with one container-only shell kill rule.
    fn zone_selected_spec() -> EbpfSpec {
        let mut w = Writer::new();
        w.put_magic(&EBPF_MAGIC);
        w.put_u32(AGENT_ABI);
        w.put_u8(Mode::Enforce.as_u8());
        w.put_bool(false);
        w.put_i32(100);
        w.put_u8(Action::Audit.as_u8());
        put_empty_label_selector(&mut w);
        w.put_u16(0);
        w.put_u16(1);
        w.put_str("ferrum.io/zone");
        w.put_str("In");
        w.put_str_list(&["pci", "secrets"]);
        put_empty_label_selector(&mut w);
        put_empty_label_selector(&mut w);
        w.put_str_list(&[]);
        w.put_bool(false);
        w.put_u16(1);
        w.put_str("no-shell");
        w.put_str_list(&["execve"]);
        w.put_u8(Action::Kill.as_u8());
        w.put_str_list(&["sh"]);
        w.put_bool(true);
        w.put_str_list(&[]);
        w.put_str_list(&[]);
        w.put_bool(false);
        parse_febp(&w.finish()).expect("parse")
    }

    /// The label caches are cold, relisting or dead: the pod is known, its
    /// namespace labels are not. Empty labels are not a non-match, and the
    /// program must not be silently skipped — admission fails closed on the
    /// very same condition.
    #[test]
    fn unobserved_labels_are_not_a_non_match() {
        let spec = zone_selected_spec();
        let shell = ev("execve", "sh", "/bin/sh", true, false);
        let mut cold = pci_identity();
        cold.namespace_labels.clear();

        assert_eq!(
            selector_match(&spec.selector, &cold),
            SelectorMatch::LabelsUnknown
        );
        assert!(!selector_matches(&spec.selector, &cold));

        let decision = decide(&spec, &shell, &cold);
        assert_eq!(
            decision.action,
            Action::Kill,
            "a rule must not be skipped because its selector could not be resolved"
        );
        assert!(decision.labels_unknown);

        // Resolved identities are unaffected in both directions.
        let hot = pci_identity();
        assert_eq!(selector_match(&spec.selector, &hot), SelectorMatch::Match);
        assert!(!decide(&spec, &shell, &hot).labels_unknown);
        let mut public = pci_identity();
        public
            .namespace_labels
            .insert("ferrum.io/zone".into(), "public".into());
        assert_eq!(
            selector_match(&spec.selector, &public),
            SelectorMatch::NoMatch
        );
        let miss = decide(&spec, &shell, &public);
        assert_eq!(miss.action, Action::Allow);
        assert!(!miss.labels_unknown);
    }

    /// An unresolved selector still reports through the loader, so the carrier
    /// can degrade on it.
    #[test]
    fn loader_reports_unresolved_labels() {
        let mut loader = Loader::new();
        load_mvp(&mut loader);
        let mut cold = pci_identity();
        cold.namespace_labels.clear();
        // The MVP bundle has no selector at all: nothing to resolve.
        assert!(
            !loader
                .decide(&ev("execve", "sh", "/bin/sh", true, false), &cold)
                .labels_unknown
        );
    }

    #[test]
    fn namespaced_selector_does_not_match_unknown_identity() {
        let mut w = Writer::new();
        w.put_magic(&EBPF_MAGIC);
        w.put_u32(AGENT_ABI);
        w.put_u8(Mode::Enforce.as_u8());
        w.put_bool(false);
        w.put_i32(100);
        w.put_u8(Action::Audit.as_u8());
        put_empty_label_selector(&mut w);
        w.put_u16(0);
        w.put_u16(1);
        w.put_str("ferrum.io/zone");
        w.put_str("In");
        w.put_str_list(&["pci", "secrets"]);
        put_empty_label_selector(&mut w);
        put_empty_label_selector(&mut w);
        w.put_str_list(&[]);
        w.put_bool(false);
        w.put_u16(1);
        w.put_str("no-shell");
        w.put_str_list(&["execve"]);
        w.put_u8(Action::Kill.as_u8());
        w.put_str_list(&["sh"]);
        w.put_bool(true);
        w.put_str_list(&[]);
        w.put_str_list(&[]);
        w.put_bool(false);
        let spec = parse_febp(&w.finish()).expect("parse");
        let shell = ev("execve", "sh", "/bin/sh", true, false);
        assert_eq!(
            decide(&spec, &shell, &WorkloadIdentity::unknown()).action,
            Action::Allow
        );
        assert_eq!(decide(&spec, &shell, &pci_identity()).action, Action::Kill);
        let mut other = pci_identity();
        other
            .namespace_labels
            .insert("ferrum.io/zone".into(), "public".into());
        assert_eq!(decide(&spec, &shell, &other).action, Action::Allow);
    }

    #[test]
    fn attach_pins_is_degraded_stub() {
        let mut loader = Loader::new();
        load_mvp(&mut loader);
        match loader.attach_pins() {
            Err(FerrumError::Degraded(msg)) => {
                assert!(
                    msg.contains("not wired") || msg.contains("not loaded"),
                    "{msg}"
                );
                assert!(msg.contains(PIN_PATH), "{msg}");
            }
            other => panic!("pins must not pretend to load, got {other:?}"),
        }
        assert!(loader.last_good().is_some());
    }

    #[test]
    fn drops_are_counted() {
        let loader = Loader::new();
        loader.record_drop(3);
        assert_eq!(loader.events_dropped_total(), 3);
    }
}
