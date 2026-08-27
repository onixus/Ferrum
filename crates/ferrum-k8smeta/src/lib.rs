//! cgroup inode → pod identity. Cache miss is Degraded; never spoof another pod.

#![deny(unsafe_code)]

use ferrum_common::{FerrumError, Result};
use std::collections::{BTreeMap, HashMap};

pub mod cgroupfs;
pub mod index;
pub mod labels;
pub mod resolver;
pub mod source;
pub mod watch;

pub use cgroupfs::{scan, CgroupEntry, CgroupFs, StdCgroupFs, DEFAULT_CGROUP_ROOT};
pub use index::SharedCgroupIndex;
pub use labels::{
    apply_labels_event, apply_labels_stream, label_key, try_apply_labels_event, LabelCache,
    LabelObject, LabelWatchEvent, DEFAULT_MAX_AGE, MAX_LABEL_ENTRIES, MAX_OBJECT_LABEL_BYTES,
    MAX_TOTAL_LABEL_BYTES,
};
pub use resolver::{CgroupResolver, RefreshStats};
pub use source::{ContainerRecord, PodCache, PodMetadataSource, PodRecord, POD_WATCH_BUDGET};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkloadIdentity {
    pub namespace: String,
    pub pod: String,
    pub container: String,
    pub service_account: String,
    pub cluster_labels: BTreeMap<String, String>,
    pub namespace_labels: BTreeMap<String, String>,
    pub workload_labels: BTreeMap<String, String>,
    pub service_account_labels: BTreeMap<String, String>,
    pub image: String,
    pub image_digest: String,
}

impl WorkloadIdentity {
    pub fn unknown() -> Self {
        Self::default()
    }

    pub fn is_unknown(&self) -> bool {
        self.pod.is_empty()
    }
}

#[derive(Debug, Default)]
pub struct CgroupIndex {
    by_inode: HashMap<u64, WorkloadIdentity>,
}

impl CgroupIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, inode: u64, identity: WorkloadIdentity) {
        self.by_inode.insert(inode, identity);
    }

    pub fn remove(&mut self, inode: u64) -> Option<WorkloadIdentity> {
        self.by_inode.remove(&inode)
    }

    /// Cache miss is `Degraded`. Never returns a different pod's identity.
    pub fn lookup_cgroup(&self, inode: u64) -> Result<WorkloadIdentity> {
        self.by_inode
            .get(&inode)
            .cloned()
            .ok_or_else(|| FerrumError::Degraded(format!("cgroup {inode} not in cache")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(pod: &str) -> WorkloadIdentity {
        WorkloadIdentity {
            namespace: "ns".into(),
            pod: pod.into(),
            container: "app".into(),
            service_account: "sa".into(),
            ..Default::default()
        }
    }

    #[test]
    fn hit_returns_that_pod() {
        let mut idx = CgroupIndex::new();
        idx.insert(10, ident("pod-a"));
        idx.insert(11, ident("pod-b"));
        let got = idx.lookup_cgroup(10).expect("hit");
        assert_eq!(got.pod, "pod-a");
        assert_eq!(idx.lookup_cgroup(11).expect("hit").pod, "pod-b");
    }

    #[test]
    fn miss_is_degraded_not_another_pod() {
        let mut idx = CgroupIndex::new();
        idx.insert(10, ident("pod-a"));
        match idx.lookup_cgroup(99) {
            Err(FerrumError::Degraded(msg)) => {
                assert!(msg.contains("99"), "{msg}");
                assert!(!msg.contains("pod-a"), "{msg}");
            }
            other => panic!("miss must be Degraded, got {other:?}"),
        }
        assert!(WorkloadIdentity::unknown().is_unknown());
    }
}
