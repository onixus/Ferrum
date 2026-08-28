use chrono::{DateTime, Utc};
use ferrum_ids::{Digest, PolicyId, RuleId};
use serde::{Deserialize, Serialize};

/// Audit trail of the exception that demoted an enforcing action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WaiverRef {
    pub ticket: String,
    pub requested_by: String,
    pub approved_by: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnforcementEvent {
    pub policy: PolicyId,
    pub rule: RuleId,
    pub action: String,
    pub image_digest: Option<Digest>,
    pub pod: String,
    pub namespace: String,
    pub comm: String,
    pub syscall: String,
    /// Structural identity of the process the record came from. Absent in
    /// pre-reaction records, hence `default`.
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub tgid: u32,
    /// True only when the reaction for `action` actually ran (a signal was
    /// delivered). Audit/observe records and every refusal stay false.
    #[serde(default)]
    pub executed: bool,
    /// Why the reaction did not run, when it did not.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub respond_error: Option<String>,
    /// The selector was matched against labels nobody had observed yet: the
    /// rules were applied fail-closed, so this record is an assertion about
    /// the workload, not a resolved match.
    #[serde(default)]
    pub labels_unknown: bool,
    /// A path predicate was accepted against a path the datapath could not
    /// carry whole. Without this an investigation cannot tell a record whose
    /// path was never observed from one that genuinely named the file: the
    /// node counter for it is an aggregate and cannot be joined to a record.
    #[serde(default)]
    pub path_unknown: bool,
    /// A `containerOnly` rule that would have decided this record was skipped
    /// because the datapath did not flag the caller as a container, on a
    /// caller nothing has yet proven is not one. Unlike the two above it does
    /// not mark the verdict fail-closed — the flag stays the authority — but
    /// it is the one signal saying the verdict was reached without knowing
    /// whether the process was in a container. The node counter for it is an
    /// aggregate and cannot be joined to a record, so without this field a
    /// single exported event carries only a reason string and downstream can
    /// neither filter nor aggregate on it.
    #[serde(default)]
    pub container_unknown: bool,
    /// Set only on waived events.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub waiver: Option<WaiverRef>,
}

/// Self-contained export record: readable without access to the cluster
/// that produced it (etcd is not the SIEM).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventEnvelope {
    pub ts: DateTime<Utc>,
    pub node: String,
    /// None until the agent has loaded its first bundle.
    pub bundle_digest: Option<Digest>,
    pub agent_role: String,
    pub degraded: bool,
    pub event: EnforcementEvent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip_camel_case() {
        let env = EventEnvelope {
            ts: Utc::now(),
            node: "node-a".into(),
            bundle_digest: Some(Digest::new("sha256:abc")),
            agent_role: "observe".into(),
            degraded: true,
            event: EnforcementEvent {
                policy: PolicyId::new("p"),
                rule: RuleId::new("no-shell"),
                action: "kill".into(),
                image_digest: None,
                pod: "web".into(),
                namespace: "prod".into(),
                comm: "sh".into(),
                syscall: "execve".into(),
                pid: 0,
                tgid: 0,
                executed: false,
                labels_unknown: false,
                path_unknown: false,
                container_unknown: false,
                respond_error: None,
                waiver: None,
            },
        };
        let json = serde_json::to_string(&env).expect("serialize");
        assert!(json.contains("\"bundleDigest\":\"sha256:abc\""));
        assert!(json.contains("\"agentRole\":\"observe\""));
        assert!(json.contains("\"degraded\":true"));
        assert!(json.contains("\"ts\":"));
        assert!(!json.contains("\"waiver\""));
        let back: EventEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.node, "node-a");
        assert_eq!(back.ts, env.ts);
        assert_eq!(back.event.rule.to_string(), "no-shell");
        assert_eq!(back.event.waiver, None);
    }

    /// All three flags are per-record: a reader of one event must be able to
    /// tell a match taken on an unobserved path, unresolved labels or an
    /// unproven container from a proven one. Records written before the fields
    /// existed still decode.
    #[test]
    fn unknown_flags_round_trip_and_default_on_legacy_records() {
        let mut ev = EnforcementEvent {
            policy: PolicyId::new("p"),
            rule: RuleId::new("no-runtime-sock"),
            action: "kill".into(),
            image_digest: None,
            pod: "web".into(),
            namespace: "payments".into(),
            comm: "curl".into(),
            syscall: "openat".into(),
            pid: 7,
            tgid: 7,
            executed: true,
            respond_error: None,
            labels_unknown: true,
            path_unknown: true,
            container_unknown: true,
            waiver: None,
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        assert!(json.contains("\"labelsUnknown\":true"));
        assert!(json.contains("\"pathUnknown\":true"));
        assert!(json.contains("\"containerUnknown\":true"));
        let back: EnforcementEvent = serde_json::from_str(&json).expect("deserialize");
        assert!(back.labels_unknown);
        assert!(back.path_unknown);
        assert!(back.container_unknown);

        ev.labels_unknown = false;
        ev.path_unknown = false;
        ev.container_unknown = false;
        let json = serde_json::to_string(&ev).expect("serialize");
        assert!(json.contains("\"pathUnknown\":false"));
        assert!(json.contains("\"containerUnknown\":false"));

        let legacy = r#"{"policy":"p","rule":"r","action":"kill","imageDigest":null,
            "pod":"w","namespace":"n","comm":"sh","syscall":"execve"}"#;
        let back: EnforcementEvent = serde_json::from_str(legacy).expect("deserialize");
        assert!(!back.labels_unknown);
        assert!(!back.path_unknown);
        assert!(!back.container_unknown);
    }

    #[test]
    fn waiver_ref_camel_case_and_absent_field_decodes() {
        let ev = EnforcementEvent {
            policy: PolicyId::new("p"),
            rule: RuleId::new("no-runtime-sock"),
            action: "waived".into(),
            image_digest: None,
            pod: "web".into(),
            namespace: "payments".into(),
            comm: "curl".into(),
            syscall: "openat".into(),
            pid: 7,
            tgid: 7,
            executed: false,
            labels_unknown: false,
            path_unknown: false,
            container_unknown: false,
            respond_error: None,
            waiver: Some(WaiverRef {
                ticket: "JIRA-1".into(),
                requested_by: "sre".into(),
                approved_by: "sec-arch".into(),
                expires_at: Utc::now(),
            }),
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        assert!(json.contains("\"waiver\":{\"ticket\":\"JIRA-1\""));
        assert!(json.contains("\"requestedBy\":\"sre\""));
        assert!(json.contains("\"approvedBy\":\"sec-arch\""));
        assert!(json.contains("\"expiresAt\":"));
        // Pre-waiver records (no `waiver` key) still decode.
        let legacy = r#"{"policy":"p","rule":"r","action":"kill","imageDigest":null,
            "pod":"w","namespace":"n","comm":"sh","syscall":"execve"}"#;
        let back: EnforcementEvent = serde_json::from_str(legacy).expect("deserialize");
        assert_eq!(back.waiver, None);
        assert_eq!(back.tgid, 0);
        assert!(!back.executed);
        assert_eq!(back.respond_error, None);
    }
}
