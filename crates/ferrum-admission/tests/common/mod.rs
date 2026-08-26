//! Test-only FADM writer. Layout must match the compiler: each trust root is
//! name | keyless_issuer_allow[] | public_keys[].

use ferrum_admission::ADMISSION_ABI;
use ferrum_api::{
    AdmitDeny, AdmitMutate, ClusterSecurityPolicySpec, FailurePolicy, LabelSelector, PolicyMode,
    PolicySelector, PssProfile, SecurityPolicySpec, SupplySpec,
};

pub fn encode_cluster(spec: &ClusterSecurityPolicySpec) -> Vec<u8> {
    encode(
        spec.mode,
        spec.disabled,
        spec.priority,
        &spec.supply,
        spec.admit.failure_policy,
        spec.admit.pss,
        &spec.admit.deny,
        &spec.admit.mutate,
        &spec.selector,
    )
}

pub fn encode_namespaced(spec: &SecurityPolicySpec) -> Vec<u8> {
    encode(
        spec.mode,
        spec.disabled,
        spec.priority,
        &spec.supply,
        spec.admit.failure_policy,
        spec.admit.pss,
        &spec.admit.deny,
        &spec.admit.mutate,
        &spec.selector,
    )
}

#[allow(clippy::too_many_arguments)]
fn encode(
    mode: PolicyMode,
    disabled: bool,
    priority: i32,
    supply: &SupplySpec,
    failure_policy: FailurePolicy,
    pss: PssProfile,
    deny: &AdmitDeny,
    mutate: &AdmitMutate,
    selector: &PolicySelector,
) -> Vec<u8> {
    let mut w = Writer(Vec::new());
    w.0.extend_from_slice(b"FADM");
    w.put_u32(ADMISSION_ABI);
    w.put_u8(match mode {
        PolicyMode::Observe => 0,
        PolicyMode::Audit => 1,
        PolicyMode::Enforce => 2,
    });
    w.put_bool(disabled);
    w.put_i32(priority);
    w.put_u8(match failure_policy {
        FailurePolicy::Fail => 0,
        FailurePolicy::Ignore => 1,
    });
    w.put_u8(match pss {
        PssProfile::Privileged => 0,
        PssProfile::Baseline => 1,
        PssProfile::Restricted => 2,
        PssProfile::Custom => 3,
    });
    encode_supply(&mut w, supply);
    encode_deny(&mut w, deny);
    w.put_bool(mutate.inject_seccomp_runtime_default);
    w.put_bool(mutate.drop_all_capabilities);
    w.put_bool(mutate.read_only_root_filesystem);
    encode_selector(&mut w, selector);
    w.0
}

fn encode_supply(w: &mut Writer, supply: &SupplySpec) {
    w.put_bool(supply.require_signed);
    w.put_bool(supply.deny_unsigned);
    w.put_bool(supply.deny_latest_tag);
    w.put_u16(u16::try_from(supply.trust_roots.len()).expect("trust root count"));
    for root in &supply.trust_roots {
        w.put_str(&root.name);
        w.put_str_list(&root.keyless_issuer_allow);
        w.put_str_list(&root.public_keys);
    }
}

fn encode_deny(w: &mut Writer, deny: &AdmitDeny) {
    w.put_bool(deny.privileged);
    w.put_bool(deny.host_pid);
    w.put_bool(deny.host_ipc);
    w.put_bool(deny.host_network);
    w.put_bool(deny.host_path);
    w.put_bool(deny.allow_privilege_escalation);
    w.put_bool(deny.run_as_root);
    w.put_bool(deny.wildcards_rbac);
    w.put_bool(deny.cluster_admin_bind);
    w.put_str_list(&deny.added_capabilities);
}

fn encode_selector(w: &mut Writer, selector: &PolicySelector) {
    encode_label_selector(w, &selector.cluster_selector);
    encode_label_selector(w, &selector.namespace_selector);
    encode_label_selector(w, &selector.workload_selector);
    encode_label_selector(w, &selector.service_account_selector);
    w.put_str_list(&selector.image.registries_allow);
    w.put_bool(selector.image.require_digest);
}

fn encode_label_selector(w: &mut Writer, selector: &LabelSelector) {
    w.put_u16(u16::try_from(selector.match_labels.len()).expect("matchLabels"));
    for (key, value) in &selector.match_labels {
        w.put_str(key);
        w.put_str(value);
    }
    w.put_u16(u16::try_from(selector.match_expressions.len()).expect("matchExpressions"));
    for expr in &selector.match_expressions {
        w.put_str(&expr.key);
        w.put_str(&expr.operator);
        w.put_str_list(&expr.values);
    }
}

struct Writer(Vec<u8>);

impl Writer {
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
        self.put_u16(u16::try_from(s.len()).expect("string"));
        self.0.extend_from_slice(s.as_bytes());
    }

    fn put_str_list(&mut self, items: &[String]) {
        self.put_u16(u16::try_from(items.len()).expect("list"));
        for item in items {
            self.put_str(item);
        }
    }
}
