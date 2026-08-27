//! Shared setup for the replay harness: the same signed bundle the §D
//! acceptance runs, plus the two injectable halves of the reaction path.
//!
//! `signed_bundle` is spelled out here rather than shared with
//! `acceptance.rs`: integration tests are separate binaries, and the
//! acceptance file is the gate this harness is measured against, so it stays
//! untouched.

pub mod wire;

use ferrum_agent::{encode_fsig, Agent, AgentConfig, AgentRole, Responder, TargetCheck};
use ferrum_api::PolicyMode;
use ferrum_common::Result;
use ferrum_compiler::{bundle_digest_material, compile_cluster_policy};
use ferrum_crypto::{public_key_from_secret, sign_bundle};
use ferrum_ids::{Digest, ADMISSION_ABI, AGENT_ABI};
use ferrum_k8smeta::WorkloadIdentity;
use ferrum_testkit::prod_restricted;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// RFC 8032 §7.1 test-1 seed: fixture only, not a prod key.
pub const SK: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// The cgroup the replay records carry, resolved to `payments_identity`.
pub const CGROUP_PAYMENTS: u64 = 7;
/// tgid of the workload in the records: signalable, not this process.
pub const TGID_WORKLOAD: u32 = 4242;

/// compile → sign: FSIG over the FRMB material of `prod-restricted` (enforce).
pub fn signed_bundle() -> (Vec<u8>, Digest) {
    signed_bundle_mutated(|_| {})
}

/// The same bundle with the decoded spec handed to `mutate` first. For tests
/// that need one field of the shipped policy to differ so that a verdict which
/// is otherwise ambiguous — two rules that agree on an action, say — becomes
/// readable again. The example file itself stays untouched.
pub fn signed_bundle_mutated(
    mutate: impl FnOnce(&mut ferrum_api::ClusterSecurityPolicySpec),
) -> (Vec<u8>, Digest) {
    let mut spec = prod_restricted().spec;
    spec.mode = PolicyMode::Enforce;
    mutate(&mut spec);
    let bundle = compile_cluster_policy(&spec).expect("compile prod-restricted");
    let frmb = bundle_digest_material(
        AGENT_ABI,
        ADMISSION_ABI,
        &bundle.admission_program,
        &bundle.ebpf_spec,
        &bundle.wasm,
    )
    .expect("frmb material");
    let pk = public_key_from_secret(&SK).expect("public key");
    let sig = sign_bundle(&frmb, &SK).expect("sign");
    let fsig = encode_fsig(&frmb, &sig, &pk).expect("fsig");
    (fsig, bundle.digest)
}

pub fn respond_agent(lkg_dir: Option<PathBuf>) -> Agent {
    Agent::new(AgentConfig {
        role: AgentRole::Respond,
        lkg_dir,
        trust_root: public_key_from_secret(&SK).expect("public key"),
        policy_name: "prod-restricted".into(),
        ..Default::default()
    })
}

/// Matches the prod-restricted selector (pci zone, pinned registry).
pub fn payments_identity() -> WorkloadIdentity {
    let mut id = WorkloadIdentity {
        namespace: "payments".into(),
        pod: "web-1".into(),
        container: "app".into(),
        service_account: "web".into(),
        ..Default::default()
    };
    id.namespace_labels
        .insert("ferrum.io/zone".into(), "pci".into());
    id.image = "registry.internal.example/app@sha256:abc".into();
    id.image_digest = "sha256:abc".into();
    id
}

/// An agent with the signed bundle applied, the replay cgroup resolved, and
/// both halves of the reaction path wired to test doubles. Returns the list
/// the responder appends every signalled tgid to.
pub fn replay_agent(lkg_dir: Option<PathBuf>) -> (Agent, Arc<Mutex<Vec<u32>>>) {
    let (fsig, digest) = signed_bundle();
    let mut agent = respond_agent(lkg_dir);
    let applied = agent.apply_fsig(&fsig, Some(&digest)).expect("apply FSIG");
    assert_eq!(applied, digest);
    let killed = wire_reaction(&mut agent);
    (agent, killed)
}

/// Resolve the replay cgroup and install both test doubles of the reaction
/// path. Split out so a restarted agent (last-known-good from disk, no FSIG
/// applied) gets exactly the same wiring.
pub fn wire_reaction(agent: &mut Agent) -> Arc<Mutex<Vec<u32>>> {
    agent.insert_cgroup(CGROUP_PAYMENTS, payments_identity());
    let (responder, killed) = RecordingResponder::new();
    agent.set_responder(Box::new(responder));
    agent.set_target_check(Box::new(FixedCgroupCheck::new(CGROUP_PAYMENTS)));
    killed
}

/// Records what would be signalled: the harness must not need CAP_KILL or a
/// victim process to prove a kill was carried out.
pub struct RecordingResponder {
    killed: Arc<Mutex<Vec<u32>>>,
}

impl RecordingResponder {
    pub fn new() -> (Self, Arc<Mutex<Vec<u32>>>) {
        let killed = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                killed: Arc::clone(&killed),
            },
            killed,
        )
    }
}

impl Responder for RecordingResponder {
    fn kill(&self, tgid: u32) -> Result<()> {
        self.killed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(tgid);
        Ok(())
    }
}

/// Stands in for `/proc`: every tgid still sits in the cgroup given here, so
/// the pid-reuse guard passes for the records the scenarios replay.
pub struct FixedCgroupCheck {
    cgroup_id: u64,
}

impl FixedCgroupCheck {
    pub fn new(cgroup_id: u64) -> Self {
        Self { cgroup_id }
    }
}

impl TargetCheck for FixedCgroupCheck {
    fn cgroup_id(&self, _tgid: u32) -> Option<u64> {
        Some(self.cgroup_id)
    }
}

pub fn killed_tgids(killed: &Arc<Mutex<Vec<u32>>>) -> Vec<u32> {
    killed.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

pub fn temp_lkg() -> PathBuf {
    std::env::temp_dir().join(format!(
        "ferrum-replay-lkg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ))
}
