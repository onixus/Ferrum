//! Node agent: signed FEBP, last-known-good, observe vs respond.
//! Kernel attach is not implied by a successful userspace load.

#![deny(unsafe_code)]

use ferrum_common::{FerrumError, Result};
use ferrum_ebpf::{extract_febp, Action, Decision, Loader, SyscallEvent};
use ferrum_export::EventSink;
use ferrum_ids::{Digest, PolicyId, RuleId};
use ferrum_k8smeta::{CgroupIndex, WorkloadIdentity};
use ferrum_proto::EnforcementEvent;
use std::fs;
use std::path::{Path, PathBuf};

const LKG_RAW: &str = "lkg.raw";
const LKG_SIG: &str = "lkg.sig";
const LKG_PK: &str = "lkg.pk";

/// Observe is default. Kill/Isolate execute only when Respond is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AgentRole {
    #[default]
    Observe,
    Respond,
}

impl AgentRole {
    pub fn respond_enabled(self) -> bool {
        matches!(self, Self::Respond)
    }
}

#[derive(Debug, Clone, Default)]
pub struct AgentConfig {
    pub role: AgentRole,
    pub lkg_dir: Option<PathBuf>,
    /// Pinned Ed25519 trust-root. Restore refuses unsigned FEBP without this.
    pub trust_root: Vec<u8>,
}

pub struct Agent {
    role: AgentRole,
    loader: Loader,
    cgroups: CgroupIndex,
    cp_down: bool,
    lkg_dir: Option<PathBuf>,
    trust_root: Vec<u8>,
}

impl Agent {
    pub fn new(config: AgentConfig) -> Self {
        let loader = match &config.lkg_dir {
            Some(dir) => Loader::with_lkg_dir(dir.clone()),
            None => Loader::new(),
        };
        let mut agent = Self {
            role: config.role,
            loader,
            cgroups: CgroupIndex::new(),
            cp_down: false,
            lkg_dir: config.lkg_dir,
            trust_root: config.trust_root,
        };
        let _ = agent.restore_last_known_good();
        agent
    }

    pub fn role(&self) -> AgentRole {
        self.role
    }

    pub fn set_role(&mut self, role: AgentRole) {
        self.role = role;
    }

    pub fn is_degraded(&self) -> bool {
        self.cp_down || self.loader.is_degraded() || !self.pins_attached()
    }

    pub fn pins_attached(&self) -> bool {
        false
    }

    pub fn using_last_known_good(&self) -> bool {
        self.loader.last_good().is_some()
    }

    pub fn last_good_digest(&self) -> Option<&Digest> {
        self.loader.last_good().map(|b| &b.digest)
    }

    pub fn events_dropped_total(&self) -> u64 {
        self.loader.events_dropped_total()
    }

    pub fn record_drop(&self, n: u64) {
        self.loader.record_drop(n);
    }

    /// CP down: keep LKG, never fail-open.
    pub fn mark_control_plane_down(&mut self) {
        self.cp_down = true;
    }

    pub fn mark_control_plane_up(&mut self) {
        self.cp_down = false;
    }

    pub fn control_plane_down(&self) -> bool {
        self.cp_down
    }

    pub fn restore_last_known_good(&mut self) -> Result<()> {
        let dir = match &self.lkg_dir {
            Some(dir) => dir.clone(),
            None => return Ok(()),
        };
        let raw_path = dir.join(LKG_RAW);
        let sig_path = dir.join(LKG_SIG);
        if !raw_path.exists() && !sig_path.exists() {
            return Ok(());
        }
        if self.trust_root.is_empty() {
            self.loader.mark_degraded();
            return Err(FerrumError::Degraded(
                "LKG present but no pinned trust-root; unsigned FEBP is not applied".into(),
            ));
        }
        let raw = fs::read(&raw_path).map_err(|e| {
            self.loader.mark_degraded();
            FerrumError::Degraded(format!("read LKG raw: {e}"))
        })?;
        let sig = fs::read(&sig_path).map_err(|e| {
            self.loader.mark_degraded();
            FerrumError::Degraded(format!("read LKG signature: {e}"))
        })?;
        let pk_path = dir.join(LKG_PK);
        if pk_path.exists() {
            let stored_pk = fs::read(&pk_path).map_err(|e| {
                self.loader.mark_degraded();
                FerrumError::Degraded(format!("read LKG public key: {e}"))
            })?;
            if stored_pk != self.trust_root {
                self.loader.mark_degraded();
                return Err(FerrumError::Integrity(
                    "LKG public key does not match pinned trust-root".into(),
                ));
            }
        }
        let digest = match ferrum_crypto::verify_bundle_signature(&raw, &sig, &self.trust_root) {
            Ok(d) => d,
            Err(err) => {
                self.loader.mark_degraded();
                return Err(err);
            }
        };
        self.loader.load_bundle(&digest, &raw)
    }

    pub fn insert_cgroup(&mut self, inode: u64, identity: WorkloadIdentity) {
        self.cgroups.insert(inode, identity);
    }

    pub fn lookup_cgroup(&self, inode: u64) -> Result<WorkloadIdentity> {
        self.cgroups.lookup_cgroup(inode)
    }

    /// Verify signature, then digest, then `load_bundle`. On failure the
    /// previous spec remains. Empty signature is Integrity, never a fake Ok.
    /// Persists the verified envelope + signature, not inner unsigned FEBP.
    pub fn apply_bundle(&mut self, raw: &[u8], sig: &[u8], public_key: &[u8]) -> Result<Digest> {
        let digest = ferrum_crypto::verify_bundle_signature(raw, sig, public_key)?;
        ferrum_crypto::verify_bundle_digest(raw, &digest)?;
        if let Err(err) = extract_febp(raw) {
            self.loader.mark_degraded();
            return Err(err);
        }
        self.loader.load_bundle(&digest, raw)?;
        if let Err(err) = self.persist_signed(raw, sig, public_key) {
            self.loader.mark_degraded();
            return Err(err);
        }
        Ok(digest)
    }

    fn persist_signed(&self, raw: &[u8], sig: &[u8], public_key: &[u8]) -> Result<()> {
        let dir = match &self.lkg_dir {
            Some(dir) => dir,
            None => return Ok(()),
        };
        fs::create_dir_all(dir)
            .map_err(|e| FerrumError::Degraded(format!("create LKG dir: {e}")))?;
        atomic_write(&dir.join(LKG_RAW), raw)?;
        atomic_write(&dir.join(LKG_SIG), sig)?;
        atomic_write(&dir.join(LKG_PK), public_key)?;
        Ok(())
    }

    pub fn matched_action(&self, event: &SyscallEvent<'_>) -> Decision {
        self.loader.matched_action(event)
    }

    pub fn handle_event<S: EventSink>(
        &self,
        cgroup: u64,
        event: &SyscallEvent<'_>,
        sink: &S,
    ) -> Decision {
        let identity = match self.cgroups.lookup_cgroup(cgroup) {
            Ok(id) => id,
            Err(_) => WorkloadIdentity::unknown(),
        };
        let mut decision = self.loader.decide(event, &identity);
        decision.action = apply_role(self.role, decision.action);
        let policy = match self.loader.last_good() {
            Some(loaded) => PolicyId::new(loaded.digest.as_str()),
            None => PolicyId::new("none"),
        };
        let rule = match &decision.rule_id {
            Some(id) => RuleId::new(id.clone()),
            None => RuleId::new("default"),
        };
        sink.emit(&EnforcementEvent {
            policy,
            rule,
            action: decision.action.as_str().into(),
            image_digest: None,
            pod: identity.pod,
            namespace: identity.namespace,
            comm: event.comm.into(),
            syscall: event.syscall.into(),
        });
        decision
    }

    /// Does not create pins. LSM on `PIN_PATH` is required in production.
    pub fn attach_pins(&self) -> Result<()> {
        self.loader.attach_pins()
    }
}

pub fn apply_role(role: AgentRole, action: Action) -> Action {
    match (role, action) {
        (AgentRole::Observe, Action::Kill | Action::Isolate) => Action::Audit,
        (_, action) => action,
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| FerrumError::Degraded(format!("write LKG: {e}")))?;
    fs::rename(&tmp, path).map_err(|e| FerrumError::Degraded(format!("rename LKG: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_common::FerrumError;
    use ferrum_ebpf::{parse_febp, Action, Mode, EBPF_MAGIC, PIN_PATH};
    use ferrum_export::MemorySink;
    use ferrum_ids::AGENT_ABI;
    use std::fs;
    use std::path::PathBuf;

    const SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

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

    fn put_mvp_rules(w: &mut Writer) {
        w.put_u16(3);
        w.put_str("no-shell");
        w.put_str_list(&["execve", "execveat"]);
        w.put_u8(Action::Kill.as_u8());
        w.put_str_list(&["sh", "bash", "ash", "dash", "zsh"]);
        w.put_bool(true);
        w.put_str_list(&[]);
        w.put_str_list(&[]);
        w.put_bool(false);
        w.put_str("no-runtime-sock");
        w.put_str_list(&[]);
        w.put_u8(Action::Kill.as_u8());
        w.put_str_list(&[]);
        w.put_bool(false);
        w.put_str_list(&[]);
        w.put_str_list(&["docker.sock", "containerd.sock", "crio.sock"]);
        w.put_bool(false);
        w.put_str("no-module");
        w.put_str_list(&["init_module", "finit_module", "bpf"]);
        w.put_u8(Action::Deny.as_u8());
        w.put_str_list(&[]);
        w.put_bool(false);
        w.put_str_list(&[]);
        w.put_str_list(&[]);
        w.put_bool(true);
    }

    fn encode_mvp(abi: u32, mode: Mode) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_magic(&EBPF_MAGIC);
        w.put_u32(abi);
        w.put_u8(mode.as_u8());
        w.put_bool(false);
        w.put_i32(0);
        w.put_u8(Action::Audit.as_u8());
        for _ in 0..4 {
            put_empty_label_selector(&mut w);
        }
        w.put_str_list(&[]);
        w.put_bool(false);
        put_mvp_rules(&mut w);
        w.finish()
    }

    /// FEBP matching `policies/examples/prod-restricted.yaml` runtime + selector.
    fn encode_prod_restricted_ebpf(abi: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_magic(&EBPF_MAGIC);
        w.put_u32(abi);
        w.put_u8(Mode::Audit.as_u8());
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
        put_mvp_rules(&mut w);
        w.finish()
    }

    fn pk() -> Vec<u8> {
        ferrum_crypto::public_key_from_secret(&SK).expect("pk")
    }

    fn sign(raw: &[u8]) -> Vec<u8> {
        ferrum_crypto::sign_bundle(raw, &SK).expect("sign")
    }

    fn load_signed(agent: &mut Agent, raw: &[u8]) -> Digest {
        agent.apply_bundle(raw, &sign(raw), &pk()).expect("apply")
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

    fn identity(pod: &str) -> WorkloadIdentity {
        WorkloadIdentity {
            namespace: "ns".into(),
            pod: pod.into(),
            container: "app".into(),
            service_account: "sa".into(),
            ..Default::default()
        }
    }

    fn pci_identity() -> WorkloadIdentity {
        let mut id = identity("web");
        id.namespace = "prod".into();
        id.namespace_labels
            .insert("ferrum.io/zone".into(), "pci".into());
        id.image = "registry.internal.example/app@sha256:abc".into();
        id.image_digest = "sha256:abc".into();
        id
    }

    fn temp_lkg() -> PathBuf {
        std::env::temp_dir().join(format!(
            "ferrum-agent-lkg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    fn assert_integrity<T: std::fmt::Debug>(result: Result<T>) {
        match result {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
    }

    fn assert_degraded<T: std::fmt::Debug>(result: Result<T>) {
        match result {
            Err(FerrumError::Degraded(_)) => {}
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn default_role_is_observe() {
        let agent = Agent::new(AgentConfig::default());
        assert_eq!(agent.role(), AgentRole::Observe);
        assert!(!agent.role().respond_enabled());
        assert!(!agent.using_last_known_good());
        assert!(agent.is_degraded());
        assert_eq!(apply_role(AgentRole::Observe, Action::Kill), Action::Audit);
        assert_eq!(apply_role(AgentRole::Respond, Action::Kill), Action::Kill);
        assert_eq!(apply_role(AgentRole::Observe, Action::Deny), Action::Deny);
    }

    #[test]
    fn unsigned_bundle_is_integrity_and_keeps_lkg() {
        let mut agent = Agent::new(AgentConfig::default());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );

        assert_integrity(agent.apply_bundle(&good, &[], &pk()));
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );
        assert_eq!(
            agent
                .matched_action(&ev("execve", "sh", "/bin/sh", true, false))
                .action,
            Action::Kill
        );
    }

    #[test]
    fn abi_mismatch_keeps_last_known_good() {
        let mut agent = Agent::new(AgentConfig::default());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);

        let bad = encode_mvp(AGENT_ABI.saturating_add(1), Mode::Enforce);
        assert_degraded(agent.apply_bundle(&bad, &sign(&bad), &pk()));
        assert!(agent.using_last_known_good());
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );
        assert_eq!(
            agent
                .matched_action(&ev("execve", "bash", "/bin/bash", true, false))
                .action,
            Action::Kill
        );
    }

    #[test]
    fn control_plane_down_keeps_lkg_not_allow() {
        let mut agent = Agent::new(AgentConfig::default());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        load_signed(&mut agent, &good);
        agent.set_role(AgentRole::Respond);
        agent.mark_control_plane_down();
        assert!(agent.control_plane_down());
        assert!(agent.is_degraded());
        assert!(agent.using_last_known_good());
        let sink = MemorySink::new();
        let d = agent.handle_event(1, &ev("execve", "sh", "/bin/sh", true, false), &sink);
        assert_eq!(d.action, Action::Kill);
        assert_ne!(d.action, Action::Allow);
    }

    #[test]
    fn mvp_execve_shell_kill_when_respond() {
        let mut agent = Agent::new(AgentConfig {
            role: AgentRole::Respond,
            ..Default::default()
        });
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        let sink = MemorySink::new();
        let d = agent.handle_event(7, &ev("execve", "sh", "/bin/sh", true, false), &sink);
        assert_eq!(d.action, Action::Kill);
        assert_eq!(d.rule_id.as_deref(), Some("no-shell"));
        assert_eq!(sink.events()[0].action, "kill");
        assert_eq!(sink.events()[0].syscall, "execve");
    }

    #[test]
    fn mvp_docker_sock_kill_when_respond() {
        let mut agent = Agent::new(AgentConfig {
            role: AgentRole::Respond,
            ..Default::default()
        });
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        let d = agent.handle_event(
            1,
            &ev("openat", "app", "/var/run/docker.sock", true, false),
            &MemorySink::new(),
        );
        assert_eq!(d.action, Action::Kill);
        assert_eq!(d.rule_id.as_deref(), Some("no-runtime-sock"));
    }

    #[test]
    fn mvp_bpf_not_agent_deny() {
        let mut agent = Agent::new(AgentConfig::default());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        let d = agent.handle_event(
            1,
            &ev("bpf", "attacker", "", true, false),
            &MemorySink::new(),
        );
        assert_eq!(d.action, Action::Deny);
        let self_bpf = agent.handle_event(
            1,
            &ev("bpf", "ferrum-agent", "", false, true),
            &MemorySink::new(),
        );
        assert_eq!(self_bpf.action, Action::Audit);
    }

    #[test]
    fn observe_does_not_execute_kill() {
        let mut agent = Agent::new(AgentConfig::default());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        let d = agent.handle_event(
            1,
            &ev("execve", "sh", "/bin/sh", true, false),
            &MemorySink::new(),
        );
        assert_eq!(d.action, Action::Audit);
        assert_eq!(
            agent
                .matched_action(&ev("execve", "sh", "/bin/sh", true, false))
                .action,
            Action::Kill
        );
    }

    #[test]
    fn cgroup_miss_does_not_spoof_pod() {
        let mut agent = Agent::new(AgentConfig {
            role: AgentRole::Respond,
            ..Default::default()
        });
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(10, identity("pod-a"));
        let sink = MemorySink::new();
        agent.handle_event(99, &ev("execve", "sh", "/bin/sh", true, false), &sink);
        assert!(sink.events()[0].pod.is_empty());
        assert_ne!(sink.events()[0].pod, "pod-a");
        assert_eq!(agent.lookup_cgroup(10).expect("hit").pod, "pod-a");
        match agent.lookup_cgroup(99) {
            Err(FerrumError::Degraded(_)) => {}
            other => panic!("expected Degraded identity, got {other:?}"),
        }
    }

    #[test]
    fn attach_pins_does_not_pretend() {
        let mut agent = Agent::new(AgentConfig::default());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        assert!(!agent.pins_attached());
        match agent.attach_pins() {
            Err(FerrumError::Degraded(msg)) => {
                assert!(msg.contains(PIN_PATH), "{msg}");
            }
            other => panic!("expected Degraded attach, got {other:?}"),
        }
        assert!(agent.using_last_known_good());
    }

    #[test]
    fn compiler_frmb_round_trip() {
        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        let obj: ferrum_api::ClusterSecurityPolicy =
            serde_yaml::from_str(yaml).expect("example yaml");
        let compiled = ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile");
        let ebpf = encode_prod_restricted_ebpf(AGENT_ABI);
        let parsed = parse_febp(&ebpf).expect("FEBP");
        assert_eq!(parsed.priority, obj.spec.priority);
        assert_eq!(
            parsed.selector.image.registries_allow,
            obj.spec.selector.image.registries_allow
        );
        assert_eq!(
            parsed.selector.image.require_digest,
            obj.spec.selector.image.require_digest
        );
        assert_eq!(
            parsed
                .selector
                .namespace_selector
                .match_expressions
                .first()
                .map(|e| e.key.as_str()),
            Some("ferrum.io/zone")
        );
        let material = ferrum_compiler::bundle_digest_material(
            AGENT_ABI,
            ferrum_ids::ADMISSION_ABI,
            &compiled.admission_program,
            &ebpf,
            &compiled.wasm,
        )
        .expect("material");
        let mut agent = Agent::new(AgentConfig::default());
        let digest = load_signed(&mut agent, &material);
        assert_eq!(digest, ferrum_crypto::bundle_digest(&material));
        assert_eq!(
            agent
                .matched_action(&ev("execve", "sh", "/bin/sh", true, false))
                .action,
            Action::Kill
        );
        assert_eq!(
            agent
                .matched_action(&ev("openat", "x", "/run/docker.sock", true, false))
                .action,
            Action::Kill
        );
        assert_eq!(
            agent
                .matched_action(&ev("bpf", "x", "", true, false))
                .action,
            Action::Deny
        );
    }

    #[test]
    fn frmb_abi_mismatch_keeps_lkg() {
        let mut agent = Agent::new(AgentConfig::default());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);

        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        let obj: ferrum_api::ClusterSecurityPolicy =
            serde_yaml::from_str(yaml).expect("example yaml");
        let compiled = ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile");
        let mut material = ferrum_compiler::bundle_digest_material(
            AGENT_ABI.saturating_add(1),
            ferrum_ids::ADMISSION_ABI,
            &compiled.admission_program,
            &compiled.ebpf_spec,
            &compiled.wasm,
        )
        .expect("material");
        material[8..12].copy_from_slice(&AGENT_ABI.saturating_add(1).to_le_bytes());
        assert_degraded(agent.apply_bundle(&material, &sign(&material), &pk()));
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );
    }

    #[test]
    fn namespaced_selector_skips_unknown_cgroup() {
        let mut agent = Agent::new(AgentConfig {
            role: AgentRole::Respond,
            ..Default::default()
        });
        load_signed(&mut agent, &encode_prod_restricted_ebpf(AGENT_ABI));
        let unknown = agent.handle_event(
            99,
            &ev("execve", "sh", "/bin/sh", true, false),
            &MemorySink::new(),
        );
        assert_eq!(unknown.action, Action::Allow);
        agent.insert_cgroup(1, pci_identity());
        let hit = agent.handle_event(
            1,
            &ev("execve", "sh", "/bin/sh", true, false),
            &MemorySink::new(),
        );
        assert_eq!(hit.action, Action::Audit);
        assert_eq!(hit.rule_id.as_deref(), Some("no-shell"));
    }

    #[test]
    fn signed_lkg_restore_requires_trust_root() {
        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        let raw = encode_mvp(AGENT_ABI, Mode::Enforce);
        {
            let mut agent = Agent::new(AgentConfig {
                trust_root: pk(),
                lkg_dir: Some(dir.clone()),
                ..Default::default()
            });
            load_signed(&mut agent, &raw);
            assert!(agent.using_last_known_good());
            assert!(dir.join("lkg.raw").exists());
            assert!(dir.join("lkg.sig").exists());
            assert!(!dir.join("lkg.febp").exists());
        }
        let restored = Agent::new(AgentConfig {
            trust_root: pk(),
            lkg_dir: Some(dir.clone()),
            role: AgentRole::Respond,
        });
        assert!(restored.using_last_known_good());
        assert_eq!(
            restored
                .matched_action(&ev("execve", "sh", "/bin/sh", true, false))
                .action,
            Action::Kill
        );

        let unsigned = Agent::new(AgentConfig {
            lkg_dir: Some(dir.clone()),
            ..Default::default()
        });
        assert!(!unsigned.using_last_known_good());
        assert_eq!(
            unsigned
                .handle_event(
                    1,
                    &ev("execve", "sh", "/bin/sh", true, false),
                    &MemorySink::new()
                )
                .action,
            Action::Deny
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn drops_surface() {
        let agent = Agent::new(AgentConfig::default());
        agent.record_drop(2);
        assert_eq!(agent.events_dropped_total(), 2);
    }
}
