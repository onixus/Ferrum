//! Node agent: signed FEBP, last-known-good, observe vs respond.
//! Kernel attach is not implied by a successful userspace load.

#![deny(unsafe_code)]

mod pump;
mod source;

use ferrum_common::{FerrumError, Result};
use ferrum_ebpf::{extract_febp, Action, Decision, Loader, SyscallEvent};
use ferrum_export::EventSink;
use ferrum_ids::{Digest, PolicyId, RuleId};
use ferrum_k8smeta::{CgroupIndex, WorkloadIdentity};
use ferrum_proto::EnforcementEvent;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

static LKG_SNAP_SEQ: AtomicU64 = AtomicU64::new(0);

pub use pump::{pump_channel, pump_channel_host, pump_records, pump_records_host, PumpStats};
pub use source::{
    decode_fsig, encode_fsig, extract_fsig, load_path, load_source, parse_trust_root,
    read_source_path, ExtractedFsig, BUNDLE_DIGEST_KEY, BUNDLE_FSIG_KEY, KUBELET_DATA_DIR,
    SIGNED_FORMAT, SIGNED_MAGIC,
};

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

    pub fn parse_name(s: &str) -> Result<Self> {
        match s {
            "observe" => Ok(Self::Observe),
            "respond" => Ok(Self::Respond),
            other => Err(FerrumError::Validation(format!(
                "unknown role {other}; expected observe or respond"
            ))),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AgentConfig {
    pub role: AgentRole,
    pub lkg_dir: Option<PathBuf>,
    /// Pinned Ed25519 trust-root. Restore refuses unsigned FEBP without this.
    pub trust_root: Vec<u8>,
    /// kubelet Secret mount, `bundle.fsig` file, or raw FSIG.
    pub bundle_path: Option<PathBuf>,
}

pub struct Agent {
    role: AgentRole,
    loader: Loader,
    cgroups: CgroupIndex,
    cp_down: bool,
    lkg_dir: Option<PathBuf>,
    trust_root: Vec<u8>,
    bundle_path: Option<PathBuf>,
    decode_failed: AtomicU64,
    unknown_syscalls: AtomicU64,
    /// Set when the decode table and the event source disagree (unknown nr):
    /// enforce rules can no longer be trusted to match, so the agent is
    /// Degraded even though the loaded bundle itself is fine.
    datapath_degraded: AtomicBool,
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
            bundle_path: config.bundle_path,
            decode_failed: AtomicU64::new(0),
            unknown_syscalls: AtomicU64::new(0),
            datapath_degraded: AtomicBool::new(false),
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
        self.cp_down
            || self.loader.is_degraded()
            || !self.pins_attached()
            || self.datapath_degraded.load(Ordering::Relaxed)
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

    /// In-kernel ring drops only (RFC-02 §C). Userspace decode failures go to
    /// `record_decode_failure` so a burst of malformed records cannot pose as
    /// ring-buffer pressure or vice versa.
    pub fn record_drop(&self, n: u64) {
        self.loader.record_drop(n);
    }

    pub fn records_decode_failed_total(&self) -> u64 {
        self.decode_failed.load(Ordering::Relaxed)
    }

    pub fn record_decode_failure(&self, n: u64) {
        self.decode_failed.fetch_add(n, Ordering::Relaxed);
    }

    pub fn unknown_syscall_total(&self) -> u64 {
        self.unknown_syscalls.load(Ordering::Relaxed)
    }

    pub fn record_unknown_syscall(&self) {
        self.unknown_syscalls.fetch_add(1, Ordering::Relaxed);
        self.datapath_degraded.store(true, Ordering::Relaxed);
    }

    pub fn datapath_degraded(&self) -> bool {
        self.datapath_degraded.load(Ordering::Relaxed)
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

    pub fn bundle_path(&self) -> Option<&Path> {
        self.bundle_path.as_deref()
    }

    pub fn restore_last_known_good(&mut self) -> Result<()> {
        let dir = match &self.lkg_dir {
            Some(dir) => dir.clone(),
            None => return Ok(()),
        };
        if !lkg_present(&dir) {
            return Ok(());
        }
        if self.trust_root.is_empty() {
            self.loader.mark_degraded();
            return Err(FerrumError::Degraded(
                "LKG present but no pinned trust-root; unsigned FEBP is not applied".into(),
            ));
        }
        let (bytes, expected) = match read_source_path(&dir) {
            Ok(v) => v,
            Err(err) => {
                self.loader.mark_degraded();
                return Err(err);
            }
        };
        // Install only: do not persist back over the snapshot being restored.
        self.install_verified(&bytes, expected.as_ref()).map(|_| ())
    }

    pub fn insert_cgroup(&mut self, inode: u64, identity: WorkloadIdentity) {
        self.cgroups.insert(inode, identity);
    }

    pub fn lookup_cgroup(&self, inode: u64) -> Result<WorkloadIdentity> {
        self.cgroups.lookup_cgroup(inode)
    }

    /// Verify FSIG with the pinned trust-root, then `load_bundle`. On failure the
    /// previous spec remains and the agent is Degraded. Empty signature is
    /// Integrity, never a fake Ok. Persists `bundle.fsig` + UTF-8 hex `digest`
    /// as one snapshot.
    pub fn apply_fsig(&mut self, bytes: &[u8], expected_digest: Option<&Digest>) -> Result<Digest> {
        let digest = self.install_verified(bytes, expected_digest)?;
        if let Err(err) = self.persist_fsig(bytes, &digest) {
            self.loader.mark_degraded();
            return Err(err);
        }
        Ok(digest)
    }

    /// Load a file or directory mount. Directory `digest` mismatch does not swap.
    pub fn apply_path(&mut self, path: &Path) -> Result<Digest> {
        let (bytes, expected) = match read_source_path(path) {
            Ok(v) => v,
            Err(err) => {
                self.loader.mark_degraded();
                return Err(err);
            }
        };
        self.apply_fsig(&bytes, expected.as_ref())
    }

    fn install_verified(
        &mut self,
        bytes: &[u8],
        expected_digest: Option<&Digest>,
    ) -> Result<Digest> {
        let (raw, digest) = match load_source(bytes, &self.trust_root, expected_digest) {
            Ok(v) => v,
            Err(err) => {
                self.loader.mark_degraded();
                return Err(err);
            }
        };
        if let Err(err) = extract_febp(&raw) {
            self.loader.mark_degraded();
            return Err(err);
        }
        self.loader.load_bundle(&digest, &raw)?;
        Ok(digest)
    }

    fn persist_fsig(&self, fsig: &[u8], digest: &Digest) -> Result<()> {
        let dir = match &self.lkg_dir {
            Some(dir) => dir,
            None => return Ok(()),
        };
        fs::create_dir_all(dir)
            .map_err(|e| FerrumError::Degraded(format!("create LKG dir: {e}")))?;
        if lkg_digest_on_disk(dir).as_deref() == Some(digest.as_str()) {
            return Ok(());
        }
        let snap_name = format!(
            "..snap-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            LKG_SNAP_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let snap = dir.join(&snap_name);
        if let Err(err) = write_snap(&snap, fsig, digest) {
            let _ = fs::remove_dir_all(&snap);
            return Err(err);
        }
        if let Err(err) = atomic_symlink(dir, KUBELET_DATA_DIR, &snap_name) {
            let _ = fs::remove_dir_all(&snap);
            return Err(err);
        }
        atomic_symlink(
            dir,
            BUNDLE_FSIG_KEY,
            &format!("{KUBELET_DATA_DIR}/{BUNDLE_FSIG_KEY}"),
        )?;
        atomic_symlink(
            dir,
            BUNDLE_DIGEST_KEY,
            &format!("{KUBELET_DATA_DIR}/{BUNDLE_DIGEST_KEY}"),
        )?;
        remove_stale_snaps(dir, &snap_name);
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

/// Watch `path` (file, or directory containing `bundle.fsig` + `digest`).
/// Uses mtime+len and follows kubelet `..data`; a vanished file keeps last-good.
pub fn poll_bundle(agent: &mut Agent, path: &Path, interval: Duration) -> ! {
    // Stat the path as given so kubelet `..data` rotates are visible; do not canonicalize.
    // Start with no stamp so a rotation between first load and this thread is not skipped.
    let mut stamp = None;
    loop {
        std::thread::sleep(interval);
        let Some(next) = source::source_stamp(path) else {
            continue;
        };
        if Some(next) == stamp {
            continue;
        }
        stamp = Some(next);
        if let Err(err) = agent.apply_path(path) {
            eprintln!("ferrum-agent: bundle reload failed, keeping last-known-good: {err}");
        }
    }
}

fn lkg_present(dir: &Path) -> bool {
    dir.join(BUNDLE_FSIG_KEY).exists()
        || dir.join(BUNDLE_DIGEST_KEY).exists()
        || dir.join(KUBELET_DATA_DIR).exists()
}

fn lkg_digest_on_disk(dir: &Path) -> Option<String> {
    let snap = source::source_snapshot_dir(dir)?;
    let bytes = fs::read(snap.join(BUNDLE_DIGEST_KEY)).ok()?;
    let hex = std::str::from_utf8(&bytes).ok()?.trim();
    if hex.is_empty() {
        None
    } else {
        Some(hex.to_string())
    }
}

fn remove_stale_snaps(dir: &Path, keep_name: &str) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for ent in rd.filter_map(|e| e.ok()) {
        let name = ent.file_name();
        let Some(n) = name.to_str() else {
            continue;
        };
        if n.starts_with("..snap-") && n != keep_name {
            let _ = fs::remove_dir_all(ent.path());
        }
    }
}

fn write_snap(snap: &Path, fsig: &[u8], digest: &Digest) -> Result<()> {
    fs::create_dir_all(snap).map_err(|e| FerrumError::Degraded(format!("create LKG snap: {e}")))?;
    fs::write(snap.join(BUNDLE_FSIG_KEY), fsig)
        .map_err(|e| FerrumError::Degraded(format!("write LKG fsig: {e}")))?;
    fs::write(snap.join(BUNDLE_DIGEST_KEY), digest.as_str().as_bytes())
        .map_err(|e| FerrumError::Degraded(format!("write LKG digest: {e}")))?;
    Ok(())
}

fn atomic_symlink(dir: &Path, link_name: &str, target: &str) -> Result<()> {
    let link = dir.join(link_name);
    let tmp = dir.join(format!("{link_name}.tmp"));
    let _ = fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp)
        .map_err(|e| FerrumError::Degraded(format!("symlink LKG {link_name}: {e}")))?;
    fs::rename(&tmp, link)
        .map_err(|e| FerrumError::Degraded(format!("rename LKG {link_name}: {e}")))?;
    Ok(())
}

#[cfg(test)]
impl Agent {
    fn apply_bundle(&mut self, raw: &[u8], sig: &[u8], public_key: &[u8]) -> Result<Digest> {
        let fsig = encode_fsig(raw, sig, public_key)?;
        self.apply_fsig(&fsig, None)
    }

    fn policy_degraded(&self) -> bool {
        self.loader.is_degraded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_common::FerrumError;
    use ferrum_ebpf::{parse_febp, Action, Mode, EBPF_MAGIC, PIN_PATH};
    use ferrum_export::MemorySink;
    use ferrum_ids::AGENT_ABI;
    use std::fs;
    use std::path::{Path, PathBuf};

    const SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const SK2: [u8; 32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
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

    fn cfg() -> AgentConfig {
        AgentConfig {
            trust_root: pk(),
            ..Default::default()
        }
    }

    fn cfg_respond() -> AgentConfig {
        AgentConfig {
            role: AgentRole::Respond,
            trust_root: pk(),
            ..Default::default()
        }
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

    fn snap_count(dir: &Path) -> usize {
        fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| {
                        e.file_name()
                            .to_str()
                            .map(|n| n.starts_with("..snap-"))
                            .unwrap_or(false)
                    })
                    .count()
            })
            .unwrap_or(0)
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

    fn compile_prod_restricted() -> (Vec<u8>, Digest) {
        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        let obj: ferrum_api::ClusterSecurityPolicy =
            serde_yaml::from_str(yaml).expect("example yaml");
        let compiled = ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile");
        let material = ferrum_compiler::bundle_digest_material(
            AGENT_ABI,
            ferrum_ids::ADMISSION_ABI,
            &compiled.admission_program,
            &compiled.ebpf_spec,
            &compiled.wasm,
        )
        .expect("material");
        let digest = compiled.digest;
        (material, digest)
    }

    fn assert_mvp_actions(agent: &Agent) {
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
    fn default_role_is_observe() {
        let agent = Agent::new(AgentConfig::default());
        assert_eq!(agent.role(), AgentRole::Observe);
        assert!(!agent.role().respond_enabled());
        assert!(!agent.using_last_known_good());
        assert!(agent.is_degraded());
        assert_eq!(apply_role(AgentRole::Observe, Action::Kill), Action::Audit);
        assert_eq!(apply_role(AgentRole::Respond, Action::Kill), Action::Kill);
        assert_eq!(apply_role(AgentRole::Observe, Action::Deny), Action::Deny);
        assert_eq!(
            AgentRole::parse_name("observe").unwrap(),
            AgentRole::Observe
        );
        assert_eq!(
            AgentRole::parse_name("respond").unwrap(),
            AgentRole::Respond
        );
    }

    #[test]
    fn unsigned_bundle_is_integrity_and_keeps_lkg() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );

        assert_integrity(agent.apply_bundle(&good, &[], &pk()));
        assert_integrity(agent.apply_fsig(&good, None));
        assert!(agent.is_degraded());
        assert!(agent.policy_degraded());
        assert!(agent.using_last_known_good());
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
    fn unsigned_integrity_empty_is_deny() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        assert_integrity(agent.apply_fsig(&good, None));
        assert!(!agent.using_last_known_good());
        assert_eq!(
            agent
                .handle_event(
                    1,
                    &ev("execve", "sh", "/bin/sh", true, false),
                    &MemorySink::new()
                )
                .action,
            Action::Deny
        );
    }

    #[test]
    fn abi_mismatch_keeps_last_known_good() {
        let mut agent = Agent::new(cfg());
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
        let mut agent = Agent::new(cfg());
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
        let mut agent = Agent::new(cfg_respond());
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
        let mut agent = Agent::new(cfg_respond());
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
        let mut agent = Agent::new(cfg());
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
        let mut agent = Agent::new(cfg());
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
        let mut agent = Agent::new(cfg_respond());
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
        let mut agent = Agent::new(cfg());
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
        let mut agent = Agent::new(cfg());
        let digest = load_signed(&mut agent, &material);
        assert_eq!(digest, ferrum_crypto::bundle_digest(&material));
        assert_mvp_actions(&agent);
    }

    #[test]
    fn compiler_fsig_of_prod_restricted() {
        let (material, compiled_digest) = compile_prod_restricted();
        let fsig = encode_fsig(&material, &sign(&material), &pk()).expect("fsig");
        let mut agent = Agent::new(cfg());
        let digest = agent
            .apply_fsig(&fsig, Some(&compiled_digest))
            .expect("apply");
        assert_eq!(digest, compiled_digest);
        assert_mvp_actions(&agent);
    }

    #[test]
    fn matching_dir_loads_mvp_actions() {
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let fsig = encode_fsig(&good, &sign(&good), &pk()).expect("fsig");
        let digest = ferrum_crypto::bundle_digest(&good);
        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        fs::write(dir.join(BUNDLE_FSIG_KEY), fsig).expect("bundle.fsig");
        fs::write(dir.join(BUNDLE_DIGEST_KEY), digest.as_str().as_bytes()).expect("digest");
        let mut agent = Agent::new(cfg());
        agent.apply_path(&dir).expect("dir load");
        assert_mvp_actions(&agent);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn digest_mismatch_keeps_lkg() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);
        let fsig = encode_fsig(&good, &sign(&good), &pk()).expect("fsig");
        assert_integrity(agent.apply_fsig(&fsig, Some(&Digest::new("00".repeat(32)))));
        assert!(agent.is_degraded());
        assert!(agent.policy_degraded());
        assert!(agent.using_last_known_good());
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );
        assert_mvp_actions(&agent);

        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        fs::write(dir.join(BUNDLE_FSIG_KEY), fsig).expect("bundle.fsig");
        fs::write(dir.join(BUNDLE_DIGEST_KEY), "00".repeat(32).as_bytes()).expect("digest");
        assert_integrity(agent.apply_path(&dir));
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_digest_is_integrity() {
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let fsig = encode_fsig(&good, &sign(&good), &pk()).expect("fsig");
        let dir = temp_lkg();
        fs::create_dir_all(&dir).expect("tmpdir");
        fs::write(dir.join(BUNDLE_FSIG_KEY), fsig).expect("bundle.fsig");
        let mut agent = Agent::new(cfg());
        assert_integrity(agent.apply_path(&dir));
        assert!(!agent.using_last_known_good());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_pin_is_integrity() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);
        let other_pk = ferrum_crypto::public_key_from_secret(&SK2).expect("pk2");
        let other_sig = ferrum_crypto::sign_bundle(&good, &SK2).expect("sig2");
        assert_integrity(agent.apply_bundle(&good, &other_sig, &other_pk));
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );

        let mut empty = Agent::new(AgentConfig {
            trust_root: other_pk,
            ..Default::default()
        });
        assert_integrity(empty.apply_bundle(&good, &sign(&good), &pk()));
        assert!(!empty.using_last_known_good());
        assert_eq!(
            empty
                .handle_event(
                    1,
                    &ev("execve", "sh", "/bin/sh", true, false),
                    &MemorySink::new()
                )
                .action,
            Action::Deny
        );
    }

    #[test]
    fn frmb_abi_mismatch_keeps_lkg() {
        let mut agent = Agent::new(cfg());
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
    fn abi_too_new_is_degraded() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        let digest = load_signed(&mut agent, &good);
        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        let obj: ferrum_api::ClusterSecurityPolicy =
            serde_yaml::from_str(yaml).expect("example yaml");
        let compiled = ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile");
        let material = ferrum_compiler::bundle_digest_material(
            AGENT_ABI.saturating_add(1),
            ferrum_ids::ADMISSION_ABI,
            &compiled.admission_program,
            &compiled.ebpf_spec,
            &compiled.wasm,
        )
        .expect("material");
        let fsig = encode_fsig(&material, &sign(&material), &pk()).expect("fsig");
        assert_degraded(agent.apply_fsig(&fsig, None));
        assert!(agent.using_last_known_good());
        assert_eq!(
            agent.last_good_digest().map(|d| d.as_str()),
            Some(digest.as_str())
        );
        assert_mvp_actions(&agent);
    }

    #[test]
    fn namespaced_selector_skips_unknown_cgroup() {
        let mut agent = Agent::new(cfg_respond());
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
    fn signed_lkg_restore_from_dir() {
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
            load_signed(&mut agent, &raw);
            assert_eq!(snap_count(&dir), 1);
            assert!(agent.using_last_known_good());
            assert!(dir.join(KUBELET_DATA_DIR).exists());
            assert!(dir.join(BUNDLE_FSIG_KEY).exists());
            assert!(dir.join(BUNDLE_DIGEST_KEY).exists());
            assert!(!dir.join("lkg.raw").exists());
            assert!(!dir.join("lkg.sig").exists());
            assert!(!dir.join("lkg.pk").exists());
            assert!(!dir.join("lkg.febp").exists());
        }
        let snaps_before = snap_count(&dir);
        assert_eq!(snaps_before, 1);
        let restored = Agent::new(AgentConfig {
            trust_root: pk(),
            lkg_dir: Some(dir.clone()),
            role: AgentRole::Respond,
            ..Default::default()
        });
        assert_eq!(snap_count(&dir), snaps_before);
        assert!(restored.using_last_known_good());
        assert_eq!(
            restored
                .matched_action(&ev("execve", "sh", "/bin/sh", true, false))
                .action,
            Action::Kill
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_without_pin_and_files_is_degraded() {
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
        }
        let mut unsigned = Agent::new(AgentConfig {
            lkg_dir: Some(dir.clone()),
            ..Default::default()
        });
        assert!(!unsigned.using_last_known_good());
        assert_degraded(unsigned.restore_last_known_good());
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
    fn vanished_mount_keeps_lkg() {
        let mut agent = Agent::new(cfg());
        let good = encode_mvp(AGENT_ABI, Mode::Enforce);
        load_signed(&mut agent, &good);
        let missing = temp_lkg().join("gone");
        assert_integrity(agent.apply_path(&missing));
        assert!(agent.using_last_known_good());
        assert_mvp_actions(&agent);
    }

    #[test]
    fn drops_surface() {
        let agent = Agent::new(AgentConfig::default());
        agent.record_drop(2);
        assert_eq!(agent.events_dropped_total(), 2);
    }

    fn ring_record(syscall_nr: u32, comm: &str, path: &str, flags: u8, cgroup: u64) -> Vec<u8> {
        let mut event = ferrum_ebpf::Event::new();
        event.cgroup_id = cgroup;
        event.pid = 100;
        event.tgid = 100;
        event.syscall_nr = syscall_nr;
        event.flags = flags;
        event.comm[..comm.len()].copy_from_slice(comm.as_bytes());
        event.path[..path.len()].copy_from_slice(path.as_bytes());
        ferrum_ebpf::encode_event(&event)
    }

    #[test]
    fn pump_ring_records_round_trip() {
        use ferrum_ebpf::{SyscallArch, EVENT_FLAG_CONTAINER};
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        agent.insert_cgroup(7, identity("pod-a"));
        let sink = MemorySink::new();
        // x86_64 numbers: 59 execve, 257 openat.
        let records = vec![
            ring_record(59, "sh", "/bin/sh", EVENT_FLAG_CONTAINER, 7),
            ring_record(257, "app", "/var/run/docker.sock", EVENT_FLAG_CONTAINER, 7),
        ];
        let stats = pump_records(&agent, SyscallArch::X86_64, records, &sink);
        assert_eq!(
            stats,
            PumpStats {
                handled: 2,
                decode_failed: 0,
                unknown_syscall: 0
            }
        );
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].syscall, "execve");
        assert_eq!(events[0].comm, "sh");
        assert_eq!(events[0].action, "kill");
        assert_eq!(events[0].pod, "pod-a");
        assert_eq!(events[1].syscall, "openat");
        assert_eq!(events[1].action, "kill");
        assert_eq!(agent.events_dropped_total(), 0);
    }

    #[test]
    fn pump_unknown_syscall_and_garbage_do_not_panic() {
        use ferrum_ebpf::SyscallArch;
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        let sink = MemorySink::new();
        let records: Vec<Vec<u8>> = vec![
            ring_record(u32::MAX, "sh", "/bin/sh", 0, 1),
            vec![0u8; 5],
            Vec::new(),
        ];
        assert!(!agent.datapath_degraded());
        let stats = pump_records(&agent, SyscallArch::X86_64, records, &sink);
        assert_eq!(
            stats,
            PumpStats {
                handled: 0,
                decode_failed: 2,
                unknown_syscall: 1
            }
        );
        // The unknown nr is still exported for visibility, but the datapath is
        // no longer trusted: the agent is Degraded, not silently auditing.
        assert_eq!(sink.events().len(), 1);
        assert_eq!(sink.events()[0].syscall, ferrum_ebpf::SYSCALL_UNKNOWN);
        assert!(agent.datapath_degraded());
        assert!(agent.is_degraded());
        assert_eq!(agent.unknown_syscall_total(), 1);
        // Decode failures are not in-kernel ring drops.
        assert_eq!(agent.events_dropped_total(), 0);
        assert_eq!(agent.records_decode_failed_total(), 2);
    }

    #[test]
    fn pump_channel_drains_until_hangup() {
        use ferrum_ebpf::{SyscallArch, EVENT_FLAG_CONTAINER};
        let mut agent = Agent::new(cfg_respond());
        load_signed(&mut agent, &encode_mvp(AGENT_ABI, Mode::Enforce));
        let sink = MemorySink::new();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(ring_record(
            59,
            "bash",
            "/bin/bash",
            EVENT_FLAG_CONTAINER,
            1,
        ))
        .expect("send");
        drop(tx);
        let stats = pump_channel(&agent, SyscallArch::X86_64, rx, &sink);
        assert_eq!(stats.handled, 1);
        assert_eq!(sink.events()[0].action, "kill");
    }

    #[test]
    fn cargo_toml_forbids_hot_path_deps() {
        let toml = include_str!("../Cargo.toml");
        let deps = toml
            .split("[dev-dependencies]")
            .next()
            .expect("split dev")
            .split("[dependencies]")
            .nth(1)
            .expect("dependencies");
        for forbidden in [
            "kube",
            "tokio",
            "aya",
            "serde_yaml",
            "ferrum-compiler",
            "ferrum-admission",
            "ferrum-controller",
        ] {
            for line in deps.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                    continue;
                }
                let name = line.split([' ', '=', '\t']).next().unwrap_or("").trim();
                assert_ne!(
                    name, forbidden,
                    "{forbidden} must not appear in [dependencies]"
                );
            }
        }
    }
}
