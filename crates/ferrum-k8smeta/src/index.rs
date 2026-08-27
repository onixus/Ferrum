//! Concurrent cgroup index. A miss is `Degraded`; never another pod.

use crate::WorkloadIdentity;
use ferrum_common::{FerrumError, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Cloneable handle over one shared map: the refresher writes, the event path
/// reads. Lookup clones under a read lock so no lock is held across a decision.
#[derive(Debug, Clone, Default)]
pub struct SharedCgroupIndex {
    inner: Arc<RwLock<HashMap<u64, WorkloadIdentity>>>,
}

impl SharedCgroupIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, inode: u64, identity: WorkloadIdentity) {
        self.write().insert(inode, identity);
    }

    pub fn remove(&self, inode: u64) -> Option<WorkloadIdentity> {
        self.write().remove(&inode)
    }

    /// Swap the whole map. Entries absent from `next` are gone: a stale
    /// identity is worse than none, it matches the wrong policy.
    pub fn replace_all(&self, next: HashMap<u64, WorkloadIdentity>) {
        *self.write() = next;
    }

    pub fn len(&self) -> usize {
        self.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    pub fn snapshot(&self) -> HashMap<u64, WorkloadIdentity> {
        self.read().clone()
    }

    pub fn lookup_cgroup(&self, inode: u64) -> Result<WorkloadIdentity> {
        self.read()
            .get(&inode)
            .cloned()
            .ok_or_else(|| FerrumError::Degraded(format!("cgroup {inode} not in cache")))
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<u64, WorkloadIdentity>> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<u64, WorkloadIdentity>> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(pod: &str) -> WorkloadIdentity {
        WorkloadIdentity {
            namespace: "prod".into(),
            pod: pod.into(),
            container: "app".into(),
            ..Default::default()
        }
    }

    #[test]
    fn clones_share_one_map_and_miss_is_degraded() {
        let a = SharedCgroupIndex::new();
        let b = a.clone();
        a.insert(7, ident("pod-a"));
        assert_eq!(b.lookup_cgroup(7).expect("hit").pod, "pod-a");
        match b.lookup_cgroup(8) {
            Err(FerrumError::Degraded(msg)) => assert!(msg.contains('8'), "{msg}"),
            other => panic!("miss must be Degraded, got {other:?}"),
        }
        b.remove(7);
        assert!(a.lookup_cgroup(7).is_err());
        assert!(a.is_empty());
    }
}
