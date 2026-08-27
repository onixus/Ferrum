//! Userspace FEBP loader. Last-known-good in memory; kernel pins are not implied.

#![deny(unsafe_code)]

mod envelope;
mod eval;
mod event;
mod kernel;
mod loader;
mod spec;

pub use envelope::{extract_febp, BUNDLE_FORMAT, BUNDLE_MAGIC};
pub use eval::{decide, matched_action, selector_matches, Decision, EventMeta, SyscallEvent};
pub use event::{
    decode_event, encode_event, event_meta, syscall_event, syscall_name, SyscallArch,
    EVENT_WIRE_LEN, SYSCALL_UNKNOWN,
};
pub use ferrum_ebpf_progs::{
    Event, CGROUPS_MAX_ENTRIES, COMM_LEN, EVENTS_DROPPED_TOTAL, EVENT_FLAG_AGENT_SELF,
    EVENT_FLAG_CONTAINER, MAP_CGROUPS, MAP_EVENTS, MAP_RULES, MAP_SELF, PATH_LEN,
};
pub use ferrum_ids::AGENT_ABI;
pub use kernel::{plan_cgroup_sync, CgroupSyncPlan, SyncStats};
#[cfg(feature = "attach")]
pub use kernel::{KernelHandle, RingReader};
pub use loader::{LoadedBundle, Loader, PIN_PATH};
pub use spec::{
    parse_febp, Action, EbpfSpec, ImageSelector, LabelRequirement, LabelSelector, Mode,
    PolicySelector, Rule, EBPF_MAGIC,
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
