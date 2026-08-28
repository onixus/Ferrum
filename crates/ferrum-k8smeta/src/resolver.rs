//! Join layer 1 (cgroup scan) with layer 2 (pod metadata).
//!
//! Every refresh rebuilds the map from scratch, which is what expires entries:
//! a cgroup directory that vanished is no longer scanned, a pod that was
//! deleted is no longer in the snapshot, and either way the inode drops out.

use crate::cgroupfs::{scan, CgroupEntry, CgroupFs};
use crate::index::SharedCgroupIndex;
use crate::source::{PodMetadataSource, PodRecord};
use crate::WorkloadIdentity;
use ferrum_common::Result;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RefreshStats {
    pub scanned: usize,
    pub resolved: usize,
    /// cgroups whose podUID is not in the snapshot: deliberately left out of
    /// the index so the lookup is a miss rather than a half-filled identity.
    pub unknown_pod: usize,
    /// Pod is known but the runtime has not reported that container id yet.
    pub unknown_container: usize,
    pub evicted: usize,
}

#[derive(Debug, Clone, Default)]
pub struct CgroupResolver {
    index: SharedCgroupIndex,
}

impl CgroupResolver {
    pub fn new(index: SharedCgroupIndex) -> Self {
        Self { index }
    }

    pub fn index(&self) -> &SharedCgroupIndex {
        &self.index
    }

    /// Scan the cgroup tree, join against the snapshot, swap the index.
    /// A failed scan (v1, unreadable root) leaves the previous map untouched.
    pub fn refresh(
        &self,
        fs: &dyn CgroupFs,
        root: &Path,
        source: &dyn PodMetadataSource,
    ) -> Result<RefreshStats> {
        let entries = scan(fs, root)?;
        let pods = source.snapshot()?;
        Ok(self.apply(&entries, &pods))
    }

    /// Pure join; `refresh` is this plus I/O.
    pub fn apply(&self, entries: &[CgroupEntry], pods: &[PodRecord]) -> RefreshStats {
        let by_uid: HashMap<&str, &PodRecord> = pods.iter().map(|p| (p.uid.as_str(), p)).collect();
        let mut next: HashMap<u64, WorkloadIdentity> = HashMap::with_capacity(entries.len());
        let mut stats = RefreshStats {
            scanned: entries.len(),
            ..Default::default()
        };
        for entry in entries {
            let Some(pod) = by_uid.get(entry.pod_uid.as_str()) else {
                stats.unknown_pod += 1;
                continue;
            };
            let Some(container) = pod.container_by_id(&entry.container_id) else {
                stats.unknown_container += 1;
                continue;
            };
            next.insert(entry.inode, pod.identity(container));
            stats.resolved += 1;
        }
        let before = self.index.len();
        self.index.replace_all(next);
        stats.evicted = before.saturating_sub(stats.resolved);
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ContainerRecord;
    use std::path::PathBuf;

    fn hash(seed: char) -> String {
        std::iter::repeat_n(seed, 64).collect()
    }

    fn entry(inode: u64, uid: &str, cid: &str) -> CgroupEntry {
        CgroupEntry {
            inode,
            path: PathBuf::from(format!("/sys/fs/cgroup/pod{uid}/{cid}")),
            pod_uid: uid.into(),
            container_id: cid.into(),
        }
    }

    fn two_container_pod(uid: &str) -> PodRecord {
        PodRecord {
            uid: uid.into(),
            namespace: "prod".into(),
            name: "web".into(),
            node_name: "node-a".into(),
            service_account: "web-sa".into(),
            containers: vec![
                ContainerRecord {
                    name: "app".into(),
                    id: hash('a'),
                    image: "registry/app:1".into(),
                    image_digest: "sha256:aa".into(),
                },
                ContainerRecord {
                    name: "sidecar".into(),
                    id: hash('b'),
                    image: "registry/side:1".into(),
                    image_digest: "sha256:bb".into(),
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn containers_of_one_pod_are_distinct() {
        let r = CgroupResolver::default();
        let pods = vec![two_container_pod("uid-1")];
        let entries = vec![
            entry(10, "uid-1", &hash('a')),
            entry(11, "uid-1", &hash('b')),
        ];
        let stats = r.apply(&entries, &pods);
        assert_eq!(stats.resolved, 2);
        assert_eq!(r.index().lookup_cgroup(10).unwrap().container, "app");
        assert_eq!(r.index().lookup_cgroup(11).unwrap().container, "sidecar");
        assert_eq!(r.index().lookup_cgroup(10).unwrap().namespace, "prod");
    }

    #[test]
    fn unknown_pod_uid_is_a_miss_not_an_empty_identity() {
        let r = CgroupResolver::default();
        let stats = r.apply(
            &[entry(10, "ghost", &hash('a'))],
            &[two_container_pod("uid-1")],
        );
        assert_eq!(stats.unknown_pod, 1);
        assert_eq!(stats.resolved, 0);
        assert!(r.index().lookup_cgroup(10).is_err());
        assert!(r.index().is_empty());
    }

    #[test]
    fn vanished_cgroup_directory_evicts() {
        let r = CgroupResolver::default();
        let pods = vec![two_container_pod("uid-1")];
        r.apply(
            &[
                entry(10, "uid-1", &hash('a')),
                entry(11, "uid-1", &hash('b')),
            ],
            &pods,
        );
        let stats = r.apply(&[entry(10, "uid-1", &hash('a'))], &pods);
        assert_eq!(stats.evicted, 1);
        assert!(r.index().lookup_cgroup(11).is_err());
        assert!(r.index().lookup_cgroup(10).is_ok());
    }

    #[test]
    fn deleted_pod_clears_all_of_its_cgroups() {
        let r = CgroupResolver::default();
        let entries = vec![
            entry(10, "uid-1", &hash('a')),
            entry(11, "uid-1", &hash('b')),
        ];
        let pods = vec![two_container_pod("uid-1")];
        assert_eq!(r.apply(&entries, &pods).resolved, 2);
        // Pod gone from the snapshot, cgroups not yet reaped by the kubelet.
        let stats = r.apply(&entries, &[]);
        assert_eq!(stats.unknown_pod, 2);
        assert!(r.index().is_empty());
        assert!(r.index().lookup_cgroup(10).is_err());
        assert!(r.index().lookup_cgroup(11).is_err());
    }

    #[test]
    fn container_not_yet_reported_is_left_out() {
        let r = CgroupResolver::default();
        let stats = r.apply(
            &[entry(10, "uid-1", &hash('c'))],
            &[two_container_pod("uid-1")],
        );
        assert_eq!(stats.unknown_container, 1);
        assert!(r.index().lookup_cgroup(10).is_err());
    }
}
