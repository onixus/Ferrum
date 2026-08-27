//! Offline join of a recorded cgroup tree with a recorded pod watch.

use ferrum_common::FerrumError;
use ferrum_k8smeta::cgroupfs::{scan, CgroupFs, StdCgroupFs};
use ferrum_k8smeta::source::{PodCache, PodMetadataSource};
use ferrum_k8smeta::watch::{
    apply_watch_event, apply_watch_stream, parse_pod_list, parse_watch_event, PodWatchEvent,
    WatchOutcome,
};
use ferrum_k8smeta::{CgroupResolver, SharedCgroupIndex};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

const NODE: &str = "node-a";
const WEB_UID: &str = "3f8a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8";
const API_UID: &str = "9c1d2e3f-4a5b-6c7d-8e9f-0a1b2c3d4e5f";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Inodes come from the fixture, not from the filesystem: a real temp dir would
/// make every assertion depend on inode allocation order.
struct FakeCgroupFs {
    children: HashMap<PathBuf, Vec<PathBuf>>,
    inodes: HashMap<PathBuf, u64>,
    root: PathBuf,
}

impl FakeCgroupFs {
    fn load(name: &str) -> Self {
        let root = PathBuf::from("/fixture");
        let text = std::fs::read_to_string(fixture(name)).expect("fixture");
        let mut children: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
        let mut inodes = HashMap::new();
        for (i, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            let path = root.join(line.trim());
            inodes.insert(path.clone(), 100_000 + i as u64);
            let parent = path.parent().expect("parent").to_path_buf();
            children.entry(parent).or_default().push(path);
        }
        children.entry(root.clone()).or_default();
        Self {
            children,
            inodes,
            root,
        }
    }

    fn inode_of(&self, relative: &str) -> u64 {
        *self
            .inodes
            .get(&self.root.join(relative))
            .unwrap_or_else(|| panic!("fixture has no {relative}"))
    }
}

impl CgroupFs for FakeCgroupFs {
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.children
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "not a directory"))
    }

    fn inode(&self, path: &Path) -> io::Result<u64> {
        self.inodes
            .get(path)
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such path"))
    }
}

fn list_into_cache() -> PodCache {
    let bytes = std::fs::read(fixture("pods-list.json")).expect("list fixture");
    let (rv, pods) = parse_pod_list(&bytes).expect("parse list");
    assert_eq!(rv, "1001");
    let mut cache = PodCache::new(NODE);
    cache.replace_all(pods);
    cache.set_resource_version(rv);
    cache
}

#[test]
fn systemd_tree_resolves_both_containers_of_the_pod() {
    let fs = FakeCgroupFs::load("cgroup-systemd.paths");
    let entries = scan(&fs, Path::new("/fixture")).expect("scan");
    assert_eq!(entries.len(), 3, "{entries:#?}");

    let cache = list_into_cache();
    let resolver = CgroupResolver::new(SharedCgroupIndex::new());
    let stats = resolver
        .refresh(&fs, Path::new("/fixture"), &cache)
        .expect("refresh");
    assert_eq!(stats.resolved, 2);

    let app_inode = fs.inode_of(
        "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3f8a1b2c_4d5e_6f70_8192_a3b4c5d6e7f8.slice/cri-containerd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope",
    );
    let side_inode = fs.inode_of(
        "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3f8a1b2c_4d5e_6f70_8192_a3b4c5d6e7f8.slice/cri-containerd-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.scope",
    );
    let app = resolver.index().lookup_cgroup(app_inode).expect("app");
    let side = resolver.index().lookup_cgroup(side_inode).expect("sidecar");
    assert_eq!(app.namespace, "prod");
    assert_eq!(app.pod, "web-0");
    assert_eq!(app.container, "app");
    assert_eq!(app.service_account, "web-sa");
    assert_eq!(app.image, "registry.example.com/app:1.4");
    assert!(app.image_digest.starts_with("sha256:1111"));
    assert_eq!(
        app.workload_labels.get("tier").map(String::as_str),
        Some("frontend")
    );
    assert_eq!(side.container, "sidecar");
    assert_eq!(side.pod, "web-0");
    assert_ne!(app.container, side.container);
}

#[test]
fn foreign_node_cgroup_is_a_miss_not_that_pod() {
    let fs = FakeCgroupFs::load("cgroup-systemd.paths");
    let cache = list_into_cache();
    assert!(cache.get("deadbeef-0000-1111-2222-333344445555").is_none());

    let resolver = CgroupResolver::new(SharedCgroupIndex::new());
    let stats = resolver
        .refresh(&fs, Path::new("/fixture"), &cache)
        .expect("refresh");
    assert_eq!(stats.unknown_pod, 1, "intruder cgroup must stay unresolved");

    let intruder = fs.inode_of(
        "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddeadbeef_0000_1111_2222_333344445555.slice/docker-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.scope",
    );
    match resolver.index().lookup_cgroup(intruder) {
        Err(FerrumError::Degraded(msg)) => assert!(msg.contains(&intruder.to_string()), "{msg}"),
        other => panic!("foreign-node cgroup must be Degraded, got {other:?}"),
    }
}

#[test]
fn cgroupfs_driver_tree_resolves_both_qos_layouts() {
    let fs = FakeCgroupFs::load("cgroup-cgroupfs.paths");
    let entries = scan(&fs, Path::new("/fixture")).expect("scan");
    assert_eq!(entries.len(), 3, "{entries:#?}");
    let uids: Vec<&str> = entries.iter().map(|e| e.pod_uid.as_str()).collect();
    assert!(uids.contains(&WEB_UID));
    assert!(uids.contains(&API_UID));
}

#[test]
fn cgroup_v1_is_degraded_with_a_reason() {
    let fs = FakeCgroupFs::load("cgroup-v1.paths");
    match scan(&fs, Path::new("/fixture")) {
        Err(FerrumError::Degraded(msg)) => {
            assert!(msg.contains("cgroup v1"), "{msg}");
            assert!(msg.contains("cgroup.controllers"), "{msg}");
        }
        other => panic!("cgroup v1 must be Degraded, got {other:?}"),
    }
}

#[test]
fn deleted_pod_clears_every_cgroup_of_that_pod() {
    let fs = FakeCgroupFs::load("cgroup-systemd.paths");
    let mut cache = list_into_cache();
    let resolver = CgroupResolver::new(SharedCgroupIndex::new());
    assert_eq!(
        resolver
            .refresh(&fs, Path::new("/fixture"), &cache)
            .expect("refresh")
            .resolved,
        2
    );

    let stream = std::fs::read(fixture("pod-watch.jsonl")).expect("watch fixture");
    apply_watch_stream(&mut cache, &stream).expect("apply stream");
    assert_eq!(cache.resource_version(), "1006");
    // api-0 added, web-0 deleted, both node-b pods refused.
    assert_eq!(cache.len(), 1);
    assert!(cache.get(API_UID).is_some());
    assert!(cache.get(WEB_UID).is_none());
    assert!(cache.get("feedface-0000-1111-2222-333344445555").is_none());

    // cgroup dirs are still on disk; the pod is gone, so the index must not be.
    let stats = resolver
        .refresh(&fs, Path::new("/fixture"), &cache)
        .expect("refresh");
    assert_eq!(stats.resolved, 0);
    assert_eq!(stats.evicted, 2);
    assert!(resolver.index().is_empty());
}

#[test]
fn vanished_cgroup_directory_drops_the_entry() {
    let mut fs = FakeCgroupFs::load("cgroup-systemd.paths");
    let cache = list_into_cache();
    let resolver = CgroupResolver::new(SharedCgroupIndex::new());
    resolver
        .refresh(&fs, Path::new("/fixture"), &cache)
        .expect("refresh");

    let pod_slice = PathBuf::from("/fixture/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3f8a1b2c_4d5e_6f70_8192_a3b4c5d6e7f8.slice");
    let side_inode = fs.inode_of(
        "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3f8a1b2c_4d5e_6f70_8192_a3b4c5d6e7f8.slice/cri-containerd-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.scope",
    );
    assert!(resolver.index().lookup_cgroup(side_inode).is_ok());

    let kept: Vec<PathBuf> = fs.children[&pod_slice]
        .iter()
        .filter(|p| !p.to_string_lossy().contains("bbbb"))
        .cloned()
        .collect();
    fs.children.insert(pod_slice, kept);

    let stats = resolver
        .refresh(&fs, Path::new("/fixture"), &cache)
        .expect("refresh");
    assert_eq!(stats.resolved, 1);
    assert!(resolver.index().lookup_cgroup(side_inode).is_err());
}

#[test]
fn expired_resource_version_demands_a_relist() {
    let bytes = std::fs::read(fixture("pod-watch-expired.jsonl")).expect("fixture");
    let line = bytes.split(|b| *b == b'\n').next().expect("line");
    match parse_watch_event(line).expect("parse") {
        PodWatchEvent::Gone(msg) => assert!(msg.contains("too old resource version"), "{msg}"),
        other => panic!("410 must be Gone, got {other:?}"),
    }
    let mut cache = list_into_cache();
    let before = cache.snapshot().expect("snapshot").len();
    let outcome = apply_watch_stream(&mut cache, &bytes).expect("apply");
    assert_eq!(outcome, WatchOutcome::MustRelist);
    // A relist demand must not silently empty the cache.
    assert_eq!(cache.snapshot().expect("snapshot").len(), before);
}

/// The default `StdCgroupFs` must walk a real tree; inode values are not
/// asserted, only the identities they resolve to.
#[test]
fn std_cgroup_fs_walks_a_materialized_tree() {
    let root = std::env::temp_dir().join(format!("ferrum-cgroup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let text = std::fs::read_to_string(fixture("cgroup-systemd.paths")).expect("fixture");
    std::fs::create_dir_all(&root).expect("mkdir");
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let path = root.join(line.trim());
        if path.extension().map(|e| e == "procs").unwrap_or(false)
            || path
                .file_name()
                .map(|n| n == "cgroup.controllers")
                .unwrap_or(false)
        {
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, b"").expect("write");
        } else {
            std::fs::create_dir_all(&path).expect("mkdir");
        }
    }

    let entries = scan(&StdCgroupFs, &root).expect("scan");
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(entries.len(), 3, "{entries:#?}");
    let mut inodes: Vec<u64> = entries.iter().map(|e| e.inode).collect();
    inodes.sort_unstable();
    inodes.dedup();
    assert_eq!(inodes.len(), 3, "each cgroup directory has its own inode");
    assert!(entries.iter().any(|e| e.pod_uid == WEB_UID));
}

#[test]
fn modified_updates_metadata_and_foreign_added_is_ignored() {
    let stream = std::fs::read(fixture("pod-watch.jsonl")).expect("watch fixture");
    let lines: Vec<&[u8]> = stream
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    let mut cache = list_into_cache();

    let modified = parse_watch_event(lines[1]).expect("parse MODIFIED");
    assert!(matches!(modified, PodWatchEvent::Modified(_)));
    assert_eq!(
        apply_watch_event(&mut cache, modified),
        WatchOutcome::Applied
    );
    let web = cache.get(WEB_UID).expect("web-0");
    assert_eq!(web.labels.get("version").map(String::as_str), Some("v2"));
    assert_eq!(
        web.container_by_id(&"a".repeat(64)).expect("app").image,
        "registry.example.com/app:1.5"
    );

    let foreign = parse_watch_event(lines[3]).expect("parse foreign ADDED");
    assert_eq!(
        apply_watch_event(&mut cache, foreign),
        WatchOutcome::Ignored,
        "a pod scheduled elsewhere must never enter this node's cache"
    );
    assert!(cache.get("feedface-0000-1111-2222-333344445555").is_none());
}
