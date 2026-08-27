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
use ferrum_common::Result;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};

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
    fn reschedule_evicts_from_this_node() {
        let mut cache = PodCache::new("node-a");
        cache.upsert(pod("u1", "node-a"));
        assert!(!cache.upsert(pod("u1", "node-b")));
        assert!(cache.get("u1").is_none());
    }
}
