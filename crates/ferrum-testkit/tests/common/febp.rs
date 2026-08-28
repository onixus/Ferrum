//! A hand-encoded FEBP, for bundles no current compiler will emit.
//!
//! `ferrum-compiler` validates before it encodes, so the only way to get a
//! pre-gate bundle — one carrying a runtime action cycle 7 made a validation
//! error — is to write the bytes. That is also the only way such a bundle
//! reaches a node in production: signed by a controller older than the gate.
//! The layout is `ferrum_ebpf::spec`; a change there breaks the parse loudly
//! rather than silently producing a different bundle.

use ferrum_agent::encode_fsig;
use ferrum_compiler::{bundle_digest_material, compile_cluster_policy};
use ferrum_crypto::{public_key_from_secret, sign_bundle};
use ferrum_ebpf::{Action, Mode, EBPF_MAGIC};
use ferrum_ids::{Digest, ADMISSION_ABI, AGENT_ABI};

use super::SK;

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn bool(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn str(&mut self, s: &str) {
        self.u16(s.len() as u16);
        self.buf.extend_from_slice(s.as_bytes());
    }

    pub fn str_list(&mut self, items: &[&str]) {
        self.u16(items.len() as u16);
        for item in items {
            self.str(item);
        }
    }

    /// Empty label selector: no matchLabels, no matchExpressions.
    pub fn empty_label_selector(&mut self) {
        self.u16(0);
        self.u16(0);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// One rule, `action: deny`, matching `bpf` / `init_module` / `finit_module`
/// from anything that is not the agent itself — the shape `prod-restricted`
/// shipped before cycle 7 refused it. The selector is empty so the rule is
/// what the test measures, not the selector.
pub fn pre_gate_deny_febp() -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(&EBPF_MAGIC);
    w.u32(AGENT_ABI);
    w.u8(Mode::Enforce.as_u8());
    w.bool(false);
    w.i32(0);
    w.u8(Action::Audit.as_u8());
    for _ in 0..4 {
        w.empty_label_selector();
    }
    w.str_list(&[]);
    w.bool(false);
    w.u16(1);
    w.str("no-module");
    w.str_list(&["init_module", "finit_module", "bpf"]);
    w.u8(Action::Deny.as_u8());
    w.str_list(&[]);
    w.bool(false);
    w.str_list(&[]);
    w.str_list(&[]);
    w.bool(true);
    w.finish()
}

/// The FEBP above, signed the way a controller signs one: same FRMB envelope
/// and the same trust root the replay agent pins. Admission program and wasm
/// come from a real compile, so only the eBPF half is hand-made.
pub fn signed_pre_gate_deny_bundle() -> (Vec<u8>, Digest) {
    let compiled = compile_cluster_policy(&ferrum_testkit::prod_restricted().spec)
        .expect("compile prod-restricted");
    let material = bundle_digest_material(
        AGENT_ABI,
        ADMISSION_ABI,
        &compiled.admission_program,
        &pre_gate_deny_febp(),
        &compiled.wasm,
    )
    .expect("frmb material");
    let digest = ferrum_crypto::bundle_digest(&material);
    let pk = public_key_from_secret(&SK).expect("public key");
    let sig = sign_bundle(&material, &SK).expect("sign");
    let fsig = encode_fsig(&material, &sig, &pk).expect("fsig");
    (fsig, digest)
}
