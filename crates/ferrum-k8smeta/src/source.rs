//! Pod metadata layer: what the node knows about the pods bound to it.
//!
//! The source of truth is the apiserver (`spec.nodeName=$NODE`). The rejected
//! alternatives are recorded here because they keep being proposed: kubelet
//! :10255 is unauthenticated, :10250 needs `nodes/proxy` (node-local EoP), and
//! the CRI socket would mean mounting the runtime socket into the agent — the
//! exact move rule T1610 exists to kill.

use crate::cgroupfs::{container_id_matches, strip_container_scheme};
use crate::labels::LabelCache;
use crate::WorkloadIdentity;
use ferrum_common::{FerrumError, Result};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How long the pod cache may go without a frame from the watch before its
/// contents stop counting as this node's current identity. Two expected
/// bookmark intervals: the apiserver bookmarks a quiet watch about once a
/// minute, so five minutes is several missed heartbeats, not one late one.
/// Deliberately not the two hours of the last-known-good bundle: that budget
/// buys a control plane outage the enforcement rules survive, while pod
/// identity older than a few minutes describes containers that may no longer
/// exist on this node.
pub const POD_WATCH_BUDGET: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerRecord {
    pub name: String,
    /// Runtime id with the CRI scheme stripped.
    pub id: String,
    pub image: String,
    pub image_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PodRecord {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub node_name: String,
    pub service_account: String,
    pub resource_version: String,
    pub labels: BTreeMap<String, String>,
    /// Joined in from the Namespace/ServiceAccount caches, not from the Pod
    /// object: neither set of labels exists on a Pod.
    pub namespace_labels: BTreeMap<String, String>,
    pub service_account_labels: BTreeMap<String, String>,
    pub containers: Vec<ContainerRecord>,
}

impl PodRecord {
    pub fn container_by_id(&self, cgroup_container_id: &str) -> Option<&ContainerRecord> {
        self.containers
            .iter()
            .find(|c| container_id_matches(cgroup_container_id, &c.id))
    }

    /// Identity for one container. Never called with a container the pod does
    /// not own: a partial identity is a false match waiting to happen.
    pub fn identity(&self, container: &ContainerRecord) -> WorkloadIdentity {
        WorkloadIdentity {
            namespace: self.namespace.clone(),
            pod: self.name.clone(),
            container: container.name.clone(),
            service_account: self.service_account.clone(),
            cluster_labels: BTreeMap::new(),
            namespace_labels: self.namespace_labels.clone(),
            workload_labels: self.labels.clone(),
            service_account_labels: self.service_account_labels.clone(),
            image: container.image.clone(),
            image_digest: container.image_digest.clone(),
        }
    }
}

/// Snapshot of the pods this node is allowed to resolve.
pub trait PodMetadataSource {
    fn snapshot(&self) -> Result<Vec<PodRecord>>;
}

impl PodMetadataSource for Vec<PodRecord> {
    fn snapshot(&self) -> Result<Vec<PodRecord>> {
        Ok(self.clone())
    }
}

/// Pods keyed by UID, scoped to one node. Everything scheduled elsewhere is
/// dropped on the way in, so a compromised watch stream cannot inject a pod
/// this node never ran.
#[derive(Debug, Default)]
pub struct PodCache {
    node_name: String,
    pods: HashMap<String, PodRecord>,
    resource_version: String,
    namespaces: LabelCache,
    service_accounts: LabelCache,
    labels_unknown: AtomicU64,
    /// Last frame the pod watch delivered (list, event or bookmark). `None`
    /// means no list ever completed. Without it a frozen watch that still
    /// answers `snapshot()` is indistinguishable from a quiet cluster.
    last_applied: Option<Instant>,
}

impl Clone for PodCache {
    fn clone(&self) -> Self {
        Self {
            node_name: self.node_name.clone(),
            pods: self.pods.clone(),
            resource_version: self.resource_version.clone(),
            namespaces: self.namespaces.clone(),
            service_accounts: self.service_accounts.clone(),
            labels_unknown: AtomicU64::new(self.labels_unknown_total()),
            last_applied: self.last_applied,
        }
    }
}

impl PodCache {
    pub fn new(node_name: impl Into<String>) -> Self {
        Self {
            node_name: node_name.into(),
            ..Default::default()
        }
    }

    pub fn namespaces(&self) -> &LabelCache {
        &self.namespaces
    }

    pub fn namespaces_mut(&mut self) -> &mut LabelCache {
        &mut self.namespaces
    }

    pub fn service_accounts(&self) -> &LabelCache {
        &self.service_accounts
    }

    pub fn service_accounts_mut(&mut self) -> &mut LabelCache {
        &mut self.service_accounts
    }

    /// Pods whose namespace or ServiceAccount was not in the label caches when
    /// their identity was built. Those pods carry EMPTY labels, so a policy
    /// selector will not match them; the counter is how that stays visible
    /// instead of looking like a deliberate non-match.
    pub fn labels_unknown_total(&self) -> u64 {
        self.labels_unknown.load(Ordering::Relaxed)
    }

    /// Record that the watch delivered something. Takes the instant so a
    /// caller (or a test) can place it in the past without waiting.
    pub fn mark_applied_at(&mut self, at: Instant) {
        self.last_applied = Some(at);
    }

    /// Time since the last watch frame. `None` until the first list lands.
    pub fn applied_age(&self) -> Option<Duration> {
        self.applied_age_at(Instant::now())
    }

    pub fn applied_age_at(&self, now: Instant) -> Option<Duration> {
        self.last_applied
            .map(|at| now.saturating_duration_since(at))
    }

    /// Fresh means a frame arrived within [`POD_WATCH_BUDGET`].
    pub fn is_fresh_at(&self, now: Instant) -> bool {
        self.applied_age_at(now)
            .is_some_and(|age| age < POD_WATCH_BUDGET)
    }

    fn freshness(&self, now: Instant) -> Result<()> {
        match self.applied_age_at(now) {
            None => Err(FerrumError::Degraded(
                "pod watch has not delivered a list yet: no cgroup can be matched to a pod".into(),
            )),
            Some(age) if age >= POD_WATCH_BUDGET => Err(FerrumError::Degraded(format!(
                "pod watch frozen: last frame {age:?} ago, past the {POD_WATCH_BUDGET:?} budget; \
                 cgroups are not matched to pods off a cache of that age"
            ))),
            Some(_) => Ok(()),
        }
    }

    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    pub fn resource_version(&self) -> &str {
        &self.resource_version
    }

    pub fn set_resource_version(&mut self, rv: impl Into<String>) {
        let rv = rv.into();
        if !rv.is_empty() {
            self.resource_version = rv;
        }
    }

    pub fn len(&self) -> usize {
        self.pods.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pods.is_empty()
    }

    pub fn get(&self, uid: &str) -> Option<&PodRecord> {
        self.pods.get(uid)
    }

    /// Returns false when the pod belongs to another node.
    pub fn upsert(&mut self, pod: PodRecord) -> bool {
        if !self.owns(&pod) {
            // A MODIFIED that moves the pod away must also evict it.
            self.pods.remove(&pod.uid);
            return false;
        }
        self.pods.insert(pod.uid.clone(), pod);
        true
    }

    pub fn remove(&mut self, uid: &str) -> Option<PodRecord> {
        self.pods.remove(uid)
    }

    pub fn replace_all(&mut self, pods: Vec<PodRecord>) {
        self.pods.clear();
        for pod in pods {
            self.upsert(pod);
        }
    }

    fn owns(&self, pod: &PodRecord) -> bool {
        !pod.uid.is_empty() && (self.node_name.is_empty() || pod.node_name == self.node_name)
    }
}

impl PodMetadataSource for PodCache {
    /// Joins the label caches in on the way out, so every consumer of a
    /// `PodRecord` gets namespace/ServiceAccount labels without knowing they
    /// come from two other watches.
    fn snapshot(&self) -> Result<Vec<PodRecord>> {
        self.freshness(Instant::now())?;
        Ok(self
            .pods
            .values()
            .map(|pod| {
                let mut pod = pod.clone();
                let mut unknown = 0u64;
                match self.namespaces.labels_of("", &pod.namespace) {
                    Some(labels) => pod.namespace_labels = labels.clone(),
                    None => unknown += 1,
                }
                match self
                    .service_accounts
                    .labels_of(&pod.namespace, &pod.service_account)
                {
                    Some(labels) => pod.service_account_labels = labels.clone(),
                    None => unknown += 1,
                }
                if unknown > 0 {
                    self.labels_unknown.fetch_add(unknown, Ordering::Relaxed);
                }
                pod
            })
            .collect())
    }
}

/// Normalize a runtime-reported container id for storage in [`ContainerRecord`].
pub fn normalize_runtime_id(raw: &str) -> String {
    strip_container_scheme(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_common::FerrumError;

    fn pod(uid: &str, node: &str) -> PodRecord {
        PodRecord {
            uid: uid.into(),
            namespace: "prod".into(),
            name: format!("pod-{uid}"),
            node_name: node.into(),
            ..Default::default()
        }
    }

    #[test]
    fn foreign_node_pod_is_refused() {
        let mut cache = PodCache::new("node-a");
        assert!(cache.upsert(pod("u1", "node-a")));
        assert!(!cache.upsert(pod("u2", "node-b")));
        assert_eq!(cache.len(), 1);
        assert!(cache.get("u2").is_none());
    }

    #[test]
    fn a_filled_cache_with_no_stamp_is_degraded() {
        let mut cache = PodCache::new("node-a");
        cache.replace_all(vec![pod("u1", "node-a")]);
        assert_eq!(cache.len(), 1);
        assert!(cache.applied_age().is_none());
        match cache.snapshot() {
            Err(FerrumError::Degraded(msg)) => {
                assert!(msg.contains("list"), "{msg}");
                assert!(msg.contains("matched"), "{msg}");
            }
            other => panic!("unstamped cache must be Degraded, got {other:?}"),
        }
        cache.mark_applied_at(Instant::now());
        assert_eq!(cache.snapshot().expect("fresh").len(), 1);
    }

    #[test]
    fn a_stamp_past_the_budget_names_the_age() {
        let mut cache = PodCache::new("node-a");
        cache.replace_all(vec![pod("u1", "node-a")]);
        let Some(old) = Instant::now().checked_sub(POD_WATCH_BUDGET * 3) else {
            return;
        };
        cache.mark_applied_at(old);
        assert!(cache.applied_age().expect("stamped") >= POD_WATCH_BUDGET);
        assert!(!cache.is_fresh_at(Instant::now()));
        match cache.snapshot() {
            Err(FerrumError::Degraded(msg)) => {
                assert!(msg.contains("frozen"), "{msg}");
                assert!(msg.contains("900") || msg.contains("ago"), "{msg}");
                assert!(msg.contains("matched"), "{msg}");
            }
            other => panic!("stale cache must be Degraded, got {other:?}"),
        }
        // The pods themselves are untouched: this is a freshness verdict, not
        // an eviction.
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn budget_is_watch_scale_not_bundle_scale() {
        assert_eq!(POD_WATCH_BUDGET, Duration::from_secs(300));
        assert!(POD_WATCH_BUDGET < crate::labels::DEFAULT_MAX_AGE);
    }

    #[test]
    fn clone_carries_the_stamp() {
        let mut cache = PodCache::new("node-a");
        cache.replace_all(vec![pod("u1", "node-a")]);
        cache.mark_applied_at(Instant::now());
        assert_eq!(cache.clone().snapshot().expect("clone is fresh").len(), 1);
    }

    #[test]
    fn reschedule_evicts_from_this_node() {
        let mut cache = PodCache::new("node-a");
        cache.upsert(pod("u1", "node-a"));
        assert!(!cache.upsert(pod("u1", "node-b")));
        assert!(cache.get("u1").is_none());
    }
}
