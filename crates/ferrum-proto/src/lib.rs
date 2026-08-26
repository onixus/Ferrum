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
