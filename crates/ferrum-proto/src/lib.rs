use chrono::{DateTime, Utc};
use ferrum_ids::{Digest, PolicyId, RuleId};
use serde::{Deserialize, Serialize};

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
            },
        };
        let json = serde_json::to_string(&env).expect("serialize");
        assert!(json.contains("\"bundleDigest\":\"sha256:abc\""));
        assert!(json.contains("\"agentRole\":\"observe\""));
        assert!(json.contains("\"degraded\":true"));
        assert!(json.contains("\"ts\":"));
        let back: EventEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.node, "node-a");
        assert_eq!(back.ts, env.ts);
        assert_eq!(back.event.rule.to_string(), "no-shell");
    }
}
